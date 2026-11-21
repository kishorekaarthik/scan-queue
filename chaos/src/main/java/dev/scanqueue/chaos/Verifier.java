package dev.scanqueue.chaos;

import dev.scanqueue.chaos.Monkey.Kill;
import dev.scanqueue.chaos.Uploader.Upload;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Computes every reported number from the two databases (scanqueue + webhook) and
 * the harness's own records (acknowledged uploads, kill log). All times are DB clock.
 */
final class Verifier {

    private static final Pattern WOULD_HAVE = Pattern.compile("would have been (MALICIOUS|CLEAN) sha256=([0-9a-f]+)");

    /** docker kill via the CLI on Windows takes ~100-300 ms; a restarted JVM needs > 5 s to claim anything. */
    private static final double KILL_SLACK_MILLIS = 1_500;

    private final Db q;
    private final Db w;
    private final long workerLeaseMillis;
    private final long senderLeaseMillis;

    Verifier(Db scanqueue, Db webhook, long workerLeaseMillis, long senderLeaseMillis) {
        this.q = scanqueue;
        this.w = webhook;
        this.workerLeaseMillis = workerLeaseMillis;
        this.senderLeaseMillis = senderLeaseMillis;
    }

    record Check(String name, boolean pass, String detail) {
    }

    Map<String, Object> verify(List<Upload> uploads, List<Kill> kills) {
        Map<String, Object> m = new LinkedHashMap<>();
        List<Check> checks = new ArrayList<>();

        // ---- uploads & jobs ----
        List<UUID> acked = uploads.stream().filter(u -> u.jobId() != null).map(Upload::jobId).toList();
        m.put("uploads_attempted", uploads.size());
        m.put("uploads_acknowledged", acked.size());
        m.put("uploads_failed", uploads.size() - acked.size());
        m.put("jobs", q.count("SELECT count(*) FROM scan_job"));
        m.put("client_duplicate_uploads", q.count("""
                SELECT coalesce(sum(n - 1), 0) FROM (SELECT count(*) AS n FROM scan_job GROUP BY original_filename) x"""));

        long verdicts = q.count("SELECT count(*) FROM scan_verdict");
        m.put("verdicts", verdicts);
        m.put("malicious", q.count("SELECT count(*) FROM scan_verdict WHERE verdict = 'MALICIOUS'"));
        m.put("expected_malicious", q.count("SELECT count(*) FROM scan_job WHERE original_filename LIKE '%eicar%'"));
        m.put("dead_jobs", q.count("SELECT count(*) FROM scan_job WHERE status = 'DEAD'"));

        // ---- the five ablation outcomes ----
        long lost = acked.isEmpty() ? 0 : q.count("""
                SELECT count(*) FROM unnest(?::uuid[]) AS a(id)
                LEFT JOIN scan_verdict v ON v.job_id = a.id WHERE v.job_id IS NULL""", q.uuidArray(acked));
        long ackedNotDone = acked.isEmpty() ? 0 : q.count("""
                SELECT count(*) FROM unnest(?::uuid[]) AS a(id)
                LEFT JOIN scan_job j ON j.id = a.id WHERE j.id IS NULL OR j.status <> 'DONE'""", q.uuidArray(acked));
        long stuck = q.count("SELECT count(*) FROM scan_job WHERE status IN ('QUEUED', 'RUNNING')");
        // A verdict committed by a claim that was no longer the current one (the job had
        // been re-claimed): the stale owner's write won. Fencing exists to make this 0.
        long staleAccepted = q.count("""
                SELECT count(*) FROM scan_verdict v JOIN scan_job j ON j.id = v.job_id WHERE v.claim_token < j.attempts""");
        long multiVerdict = q.count("SELECT count(*) FROM (SELECT job_id FROM scan_verdict GROUP BY job_id HAVING count(*) > 1) x");
        m.put("lost_jobs", lost);
        m.put("stuck_jobs", stuck);
        m.put("duplicate_or_stale_verdict_writes_accepted", staleAccepted + multiVerdict);
        m.put("second_verdict_writes_rejected", q.count(
                "SELECT count(*) FROM queue_event WHERE kind = 'FENCED_WRITE' AND detail LIKE 'verdict%'"));

        Set<String> expectedKeys = new TreeSet<>(q.strings(
                "SELECT 'alert:' || job_id FROM scan_verdict WHERE verdict = 'MALICIOUS'"));
        Map<String, Long> acceptedPerKey = new HashMap<>();
        for (Map<String, Object> r : w.rows(
                "SELECT idempotency_key AS k, count(*) AS n FROM delivery_log WHERE outcome = 'ACCEPTED' GROUP BY 1")) {
            acceptedPerKey.put((String) r.get("k"), ((Number) r.get("n")).longValue());
        }
        long missingAlerts = expectedKeys.stream().filter(k -> acceptedPerKey.getOrDefault(k, 0L) == 0).count();
        long duplicateAccepted = acceptedPerKey.values().stream().mapToLong(n -> Math.max(0, n - 1)).sum();
        Set<String> extra = new HashSet<>(acceptedPerKey.keySet());
        extra.removeAll(expectedKeys);
        m.put("missing_alerts", missingAlerts);
        m.put("duplicate_alerts_accepted", duplicateAccepted);
        m.put("alerts_for_non_malicious", extra.size());
        m.put("stuck_alerts", q.count("SELECT count(*) FROM alert_outbox WHERE status IN ('PENDING', 'SENDING')"));
        m.put("alerts_dropped_by_worker", q.count(
                "SELECT count(*) FROM queue_event WHERE kind = 'ALERT_SEND_FAILED' AND detail LIKE 'direct alert dropped%'"));

        // ---- events ----
        long accepted = w.count("SELECT count(*) FROM delivery_log WHERE outcome = 'ACCEPTED'");
        m.put("alerts_accepted", accepted);
        m.put("duplicates_rejected", w.count("SELECT count(*) FROM delivery_log WHERE outcome = 'DUPLICATE_REJECTED'"));
        m.put("fenced_writes", count("FENCED_WRITE"));
        m.put("fenced_alert_marks", q.count("SELECT count(*) FROM queue_event WHERE kind = 'FENCED_WRITE' AND detail LIKE 'alert%'"));
        m.put("lease_expiries", count("LEASE_EXPIRED"));
        m.put("lease_lost_heartbeats", count("LEASE_LOST"));
        m.put("scan_retries", count("RETRY"));
        m.put("alert_lease_expiries", count("ALERT_LEASE_EXPIRED"));
        m.put("alert_send_failures", count("ALERT_SEND_FAILED"));
        m.put("outbox_rows", q.count("SELECT count(*) FROM alert_outbox"));
        m.put("dead_alerts", q.count("SELECT count(*) FROM alert_outbox WHERE status = 'DEAD'"));

        // ---- timing: processing (headline) vs queue wait vs end to end ----
        m.putAll(percentiles("processing", """
                SELECT extract(epoch FROM v.scanned_at - j.claimed_at) * 1000
                FROM scan_job j JOIN scan_verdict v ON v.job_id = j.id WHERE j.status = 'DONE'"""));
        m.putAll(percentiles("queue_wait", """
                SELECT extract(epoch FROM started_at - created_at) * 1000 FROM scan_job WHERE started_at IS NOT NULL"""));
        m.putAll(percentiles("end_to_end", """
                SELECT extract(epoch FROM finished_at - created_at) * 1000 FROM scan_job WHERE status = 'DONE'"""));
        m.putAll(percentiles("crash_delay", """
                SELECT extract(epoch FROM claimed_at - started_at) * 1000 FROM scan_job WHERE status = 'DONE' AND attempts > 1"""));
        m.put("jobs_reclaimed", q.count("SELECT count(*) FROM scan_job WHERE attempts > 1"));
        double span = q.num("SELECT extract(epoch FROM max(finished_at) - min(created_at)) FROM scan_job");
        long done = q.count("SELECT count(*) FROM scan_job WHERE status = 'DONE'");
        m.put("throughput_jobs_per_sec", round(done / span, 1));
        m.put("processing_span_sec", round(span, 1));

        // ---- kills ----
        m.putAll(killStats(kills));

        // ---- checks ----
        long verdictRowsPerJobOver1 = multiVerdict;
        checks.add(new Check("every acknowledged upload has exactly one final verdict",
                ackedNotDone == 0 && lost == 0 && verdictRowsPerJobOver1 == 0,
                acked.size() + " acknowledged, " + lost + " without a verdict, " + ackedNotDone + " not DONE, "
                        + verdictRowsPerJobOver1 + " jobs with >1 verdict row"));

        long wrong = q.count("""
                SELECT count(*) FROM scan_job j JOIN scan_verdict v ON v.job_id = j.id
                WHERE (j.original_filename LIKE '%eicar%') <> (v.verdict = 'MALICIOUS')""");
        checks.add(new Check("every verdict matches ground truth (EICAR -> MALICIOUS, else CLEAN)", wrong == 0,
                wrong + " wrong of " + verdicts));

        int disagree = 0, fencedVerdicts = 0;
        for (Map<String, Object> r : q.rows("""
                SELECT e.detail, v.verdict, v.sha256 FROM queue_event e JOIN scan_verdict v ON v.job_id = e.job_id
                WHERE e.kind = 'FENCED_WRITE' AND e.detail LIKE 'verdict%'""")) {
            Matcher mt = WOULD_HAVE.matcher((String) r.get("detail"));
            fencedVerdicts++;
            if (!mt.find() || !mt.group(1).equals(r.get("verdict")) || !mt.group(2).equals(((String) r.get("sha256")).strip())) {
                disagree++;
            }
        }
        checks.add(new Check("no second completed scan changed a result",
                disagree == 0 && staleAccepted == 0,
                fencedVerdicts + " second scans rejected (" + disagree + " disagree), "
                        + staleAccepted + " stale-owner verdicts accepted"));

        long notExactlyOnce = expectedKeys.stream().filter(k -> acceptedPerKey.getOrDefault(k, 0L) != 1).count();
        checks.add(new Check("every malicious job has exactly one accepted alert", notExactlyOnce == 0,
                expectedKeys.size() + " malicious jobs, " + missingAlerts + " missing, "
                        + (notExactlyOnce - missingAlerts) + " accepted more than once"));
        checks.add(new Check("zero alerts for non-malicious jobs", extra.isEmpty(), extra.size() + " unexpected keys"));
        checks.add(new Check("zero duplicate alerts accepted", duplicateAccepted == 0,
                accepted + " accepted, " + acceptedPerKey.size() + " distinct keys, " + duplicateAccepted + " extra acceptances"));

        List<Map<String, Object>> dead = new ArrayList<>();
        dead.addAll(q.rows("SELECT 'job' AS kind, id::text AS id, attempts, last_error FROM scan_job WHERE status = 'DEAD'"));
        dead.addAll(q.rows("SELECT 'alert' AS kind, job_id::text AS id, attempts, last_error FROM alert_outbox WHERE status = 'DEAD'"));
        checks.add(new Check("zero dead or stuck jobs and alerts", dead.isEmpty() && stuck == 0,
                dead.size() + " dead, " + stuck + " jobs stuck QUEUED/RUNNING"));
        m.put("dead_items", dead);

        m.put("checks", checks);
        m.put("all_checks_pass", checks.stream().allMatch(Check::pass));
        Set<String> missing = new TreeSet<>(expectedKeys);
        missing.removeIf(k -> acceptedPerKey.getOrDefault(k, 0L) > 0);
        m.put("missing_alert_keys", sample(missing));
        m.put("unexpected_alert_keys", sample(extra));
        return m;
    }

    private Map<String, Object> percentiles(String name, String valuesSql) {
        Map<String, Object> r = q.rows("SELECT percentile_cont(0.50) WITHIN GROUP (ORDER BY v) AS p50, "
                + "percentile_cont(0.95) WITHIN GROUP (ORDER BY v) AS p95, max(v) AS max FROM (" + valuesSql + ") AS x(v)").get(0);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(name + "_p50_ms", round(num(r.get("p50")), 0));
        out.put(name + "_p95_ms", round(num(r.get("p95")), 0));
        out.put(name + "_max_ms", round(num(r.get("max")), 0));
        return out;
    }

    /**
     * Attributes every lease expiry to the kill/pause that interrupted it. Recovery of
     * one interrupted item is split into measured segments:
     * kill -> lease expiry -> reaped -> re-claimed (final claim) -> done.
     */
    private Map<String, Object> killStats(List<Kill> kills) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kills_worker", kills.stream().filter(k -> k.target().equals("worker")).count());
        m.put("kills_sender", kills.stream().filter(k -> k.target().equals("sender")).count());
        m.put("webhook_restarts", kills.stream().filter(k -> k.target().equals("webhook")).count());
        m.put("kills_worker_holding_lease_observed", kills.stream().filter(k -> k.target().equals("worker") && k.inWindow()).count());
        m.put("kills_sender_alert_in_flight_observed", kills.stream().filter(k -> k.target().equals("sender") && k.inWindow()).count());
        m.put("webhook_restarts_alert_in_flight_observed", kills.stream().filter(k -> k.target().equals("webhook") && k.inWindow()).count());
        m.put("pauses_worker", kills.stream().filter(k -> k.target().equals("worker_pause")).count());
        m.put("pauses_sender", kills.stream().filter(k -> k.target().equals("sender_pause")).count());

        Attribution jobs = attribute(kills, "worker", q.rows("""
                SELECT e.worker_id AS owner, e.claim_token AS token,
                       extract(epoch FROM e.lease_expires_at) * 1000 AS expires,
                       extract(epoch FROM e.at) * 1000 AS reaped,
                       extract(epoch FROM j.claimed_at) * 1000 AS reclaimed,
                       extract(epoch FROM j.finished_at) * 1000 AS done_at,
                       j.attempts AS final_attempts
                FROM queue_event e JOIN scan_job j ON j.id = e.job_id
                WHERE e.kind = 'LEASE_EXPIRED'"""), "", workerLeaseMillis);
        Attribution alerts = attribute(kills, "sender", q.rows("""
                SELECT e.worker_id AS owner, e.claim_token AS token,
                       extract(epoch FROM e.lease_expires_at) * 1000 AS expires,
                       extract(epoch FROM e.at) * 1000 AS reaped,
                       extract(epoch FROM o.claimed_at) * 1000 AS reclaimed,
                       extract(epoch FROM o.delivered_at) * 1000 AS done_at,
                       o.attempts AS final_attempts
                FROM queue_event e JOIN alert_outbox o ON o.job_id = e.job_id
                WHERE e.kind = 'ALERT_LEASE_EXPIRED'"""), "sender-", senderLeaseMillis);

        m.put("kills_worker_holding_lease_confirmed", jobs.confirmedKills);
        m.put("kills_sender_alert_in_flight_confirmed", alerts.confirmedKills);
        m.put("pauses_worker_lease_reclaimed", jobs.confirmedPauses);
        m.put("pauses_sender_lease_reclaimed", alerts.confirmedPauses);
        m.put("lease_expiries_unattributed", jobs.unattributed);
        m.put("alert_lease_expiries_unattributed", alerts.unattributed);
        m.put("recovery_worker_p50_ms", round(percentile(jobs.recovery, 0.50), 0));
        m.put("recovery_worker_p95_ms", round(percentile(jobs.recovery, 0.95), 0));
        m.put("recovery_worker_max_ms", round(percentile(jobs.recovery, 1.0), 0));
        m.put("recovery_alert_p50_ms", round(percentile(alerts.recovery, 0.50), 0));
        m.put("recovery_alert_p95_ms", round(percentile(alerts.recovery, 0.95), 0));
        m.put("recovery_alert_max_ms", round(percentile(alerts.recovery, 1.0), 0));
        m.put("recovery_worker_segments", segments(jobs.items));
        m.put("recovery_alert_segments", segments(alerts.items));
        return m;
    }

    /** One interrupted item, timestamps in DB-clock millis. */
    record Item(double kill, double expires, double reaped, double reclaimed, double done, boolean reinterrupted) {
    }

    private record Attribution(long confirmedKills, long confirmedPauses, long unattributed,
                               List<Double> recovery, List<Item> items) {
    }

    /**
     * Each expiry is attributed to the earliest kill/pause of the owning container
     * between the lease's last renewal (expires - lease) and its expiry. Recovery of a
     * kill = time until the last item it interrupted was finished elsewhere. Pauses
     * take part in attribution but are excluded from recovery numbers.
     */
    private static Attribution attribute(List<Kill> kills, String target, List<Map<String, Object>> expiries,
                                         String ownerPrefix, long leaseMillis) {
        List<Kill> ks = kills.stream().filter(k -> k.target().startsWith(target))
                .sorted(Comparator.comparingDouble(Kill::atMillis)).toList();
        Map<Kill, Double> recoveryByKill = new HashMap<>();
        List<Item> items = new ArrayList<>();
        long unattributed = 0;
        for (Map<String, Object> e : expiries) {
            String owner = (String) e.get("owner");
            double expires = num(e.get("expires"));
            double lastSet = expires - leaseMillis;
            Kill match = null;
            for (Kill k : ks) {
                if (owner != null && owner.startsWith(ownerPrefix + k.host())
                        && k.atMillis() >= lastSet - KILL_SLACK_MILLIS && k.atMillis() < expires) {
                    match = k;
                    break;
                }
            }
            if (match == null) {
                unattributed++;
                continue;
            }
            double done = num(e.get("done_at"));
            recoveryByKill.merge(match, done - match.atMillis(), (a, b) -> Double.isNaN(a) ? b : Double.isNaN(b) ? a : Math.max(a, b));
            if (match.target().equals(target) && !Double.isNaN(done)) {
                int token = ((Number) e.get("token")).intValue();
                int finalAttempts = ((Number) e.get("final_attempts")).intValue();
                items.add(new Item(match.atMillis(), expires, num(e.get("reaped")), num(e.get("reclaimed")), done,
                        finalAttempts > token + 1));
            }
        }
        long confirmedKills = recoveryByKill.keySet().stream().filter(k -> k.target().equals(target)).count();
        long confirmedPauses = recoveryByKill.size() - confirmedKills;
        List<Double> rec = recoveryByKill.entrySet().stream()
                .filter(en -> en.getKey().target().equals(target))
                .map(Map.Entry::getValue).filter(d -> !d.isNaN()).sorted().toList();
        return new Attribution(confirmedKills, confirmedPauses, unattributed, rec, items);
    }

    /** Medians of each recovery segment over interrupted items; re-interrupted items reported separately. */
    private static Map<String, Object> segments(List<Item> items) {
        Map<String, Object> s = new LinkedHashMap<>();
        List<Item> clean = items.stream().filter(i -> !i.reinterrupted()).toList();
        s.put("items", items.size());
        s.put("items_interrupted_again", items.size() - clean.size());
        s.put("p50_kill_to_lease_expiry_ms", med(clean, i -> i.expires() - i.kill()));
        s.put("p50_lease_expiry_to_reaped_ms", med(clean, i -> i.reaped() - i.expires()));
        s.put("p50_reaped_to_reclaimed_ms", med(clean, i -> i.reclaimed() - i.reaped()));
        s.put("p50_reclaimed_to_done_ms", med(clean, i -> i.done() - i.reclaimed()));
        s.put("p50_total_ms", med(clean, i -> i.done() - i.kill()));
        s.put("p50_total_interrupted_again_ms", med(items.stream().filter(Item::reinterrupted).toList(), i -> i.done() - i.kill()));
        return s;
    }

    private static double med(List<Item> items, Function<Item, Double> f) {
        return round(percentile(items.stream().map(f).filter(d -> !d.isNaN()).sorted().toList(), 0.5), 0);
    }

    private long count(String kind) {
        return q.count("SELECT count(*) FROM queue_event WHERE kind = ?", kind);
    }

    static double percentile(List<Double> sorted, double p) {
        if (sorted.isEmpty()) return Double.NaN;
        int idx = (int) Math.ceil(p * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, idx)));
    }

    private static List<String> sample(Collection<String> s) {
        return s.stream().limit(10).toList();
    }

    static double num(Object o) {
        return o == null ? Double.NaN : ((Number) o).doubleValue();
    }

    static double round(double v, int digits) {
        if (Double.isNaN(v) || Double.isInfinite(v)) return v;
        double f = Math.pow(10, digits);
        return Math.round(v * f) / f;
    }
}
