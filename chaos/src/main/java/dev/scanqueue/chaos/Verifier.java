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
        long jobs = q.count("SELECT count(*) FROM scan_job");
        long clientDupUploads = q.count("""
                SELECT coalesce(sum(n - 1), 0) FROM (SELECT count(*) AS n FROM scan_job GROUP BY original_filename) x""");
        m.put("uploads_attempted", uploads.size());
        m.put("uploads_acknowledged", acked.size());
        m.put("uploads_failed", uploads.size() - acked.size());
        m.put("jobs", jobs);
        m.put("client_duplicate_uploads", clientDupUploads);

        long verdicts = q.count("SELECT count(*) FROM scan_verdict");
        long malicious = q.count("SELECT count(*) FROM scan_verdict WHERE verdict = 'MALICIOUS'");
        long expectedMalicious = q.count("SELECT count(*) FROM scan_job WHERE original_filename LIKE '%eicar%'");
        long done = q.count("SELECT count(*) FROM scan_job WHERE status = 'DONE'");
        long deadJobs = q.count("SELECT count(*) FROM scan_job WHERE status = 'DEAD'");
        m.put("verdicts", verdicts);
        m.put("malicious", malicious);
        m.put("expected_malicious", expectedMalicious);
        m.put("dead_jobs", deadJobs);

        // ---- events ----
        m.put("fenced_writes", count("FENCED_WRITE"));
        m.put("fenced_verdict_writes", q.count("SELECT count(*) FROM queue_event WHERE kind = 'FENCED_WRITE' AND detail LIKE 'verdict%'"));
        m.put("fenced_alert_marks", q.count("SELECT count(*) FROM queue_event WHERE kind = 'FENCED_WRITE' AND detail LIKE 'alert%'"));
        m.put("lease_expiries", count("LEASE_EXPIRED"));
        m.put("lease_lost_heartbeats", count("LEASE_LOST"));
        m.put("scan_retries", count("RETRY"));
        m.put("alert_lease_expiries", count("ALERT_LEASE_EXPIRED"));
        m.put("alert_send_failures", count("ALERT_SEND_FAILED"));

        // ---- alerts ----
        long outbox = q.count("SELECT count(*) FROM alert_outbox");
        long deadAlerts = q.count("SELECT count(*) FROM alert_outbox WHERE status = 'DEAD'");
        long accepted = w.count("SELECT count(*) FROM delivery_log WHERE outcome = 'ACCEPTED'");
        long duplicates = w.count("SELECT count(*) FROM delivery_log WHERE outcome = 'DUPLICATE_REJECTED'");
        m.put("outbox_rows", outbox);
        m.put("alerts_accepted", accepted);
        m.put("duplicates_rejected", duplicates);
        m.put("dead_alerts", deadAlerts);

        // ---- timing ----
        Map<String, Object> lat = q.rows("""
                SELECT percentile_cont(0.50) WITHIN GROUP (ORDER BY ms) AS p50,
                       percentile_cont(0.95) WITHIN GROUP (ORDER BY ms) AS p95,
                       max(ms) AS max
                FROM (SELECT extract(epoch FROM finished_at - created_at) * 1000 AS ms
                      FROM scan_job WHERE status = 'DONE') x""").get(0);
        double span = q.num("SELECT extract(epoch FROM max(finished_at) - min(created_at)) FROM scan_job");
        m.put("throughput_jobs_per_sec", round(done / span, 1));
        m.put("latency_p50_ms", round(num(lat.get("p50")), 0));
        m.put("latency_p95_ms", round(num(lat.get("p95")), 0));
        m.put("latency_max_ms", round(num(lat.get("max")), 0));
        m.put("processing_span_sec", round(span, 1));

        // ---- kills ----
        m.putAll(killStats(kills));

        // ---- checks ----
        long ackedMissingVerdict = acked.isEmpty() ? 0 : q.count("""
                SELECT count(*) FROM unnest(?::uuid[]) AS a(id)
                LEFT JOIN scan_job j ON j.id = a.id
                LEFT JOIN scan_verdict v ON v.job_id = a.id
                WHERE j.id IS NULL OR v.job_id IS NULL OR j.status <> 'DONE'""", q.uuidArray(acked));
        long jobsWithoutVerdict = q.count("""
                SELECT count(*) FROM scan_job j LEFT JOIN scan_verdict v ON v.job_id = j.id WHERE v.job_id IS NULL""");
        long verdictRowsPerJobOver1 = q.count("SELECT count(*) FROM (SELECT job_id FROM scan_verdict GROUP BY job_id HAVING count(*) > 1) x");
        checks.add(new Check("every acknowledged upload has exactly one final verdict",
                ackedMissingVerdict == 0 && verdictRowsPerJobOver1 == 0,
                acked.size() + " acknowledged, " + ackedMissingVerdict + " without a DONE job + verdict, "
                        + verdictRowsPerJobOver1 + " jobs with >1 verdict; all jobs without verdict: " + jobsWithoutVerdict));

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
        checks.add(new Check("no second completed scan changed a result (fenced verdicts agree with committed)",
                disagree == 0, fencedVerdicts + " fenced-out verdicts, " + disagree + " disagree"));

        Set<String> expectedKeys = new TreeSet<>(q.strings(
                "SELECT 'alert:' || job_id FROM scan_verdict WHERE verdict = 'MALICIOUS'"));
        Set<String> receivedKeys = new TreeSet<>(w.strings("SELECT idempotency_key FROM received_alert"));
        Map<String, Long> acceptedPerKey = new HashMap<>();
        for (Map<String, Object> r : w.rows(
                "SELECT idempotency_key AS k, count(*) AS n FROM delivery_log WHERE outcome = 'ACCEPTED' GROUP BY 1")) {
            acceptedPerKey.put((String) r.get("k"), ((Number) r.get("n")).longValue());
        }
        long maliciousNotExactlyOnce = expectedKeys.stream().filter(k -> acceptedPerKey.getOrDefault(k, 0L) != 1).count();
        Set<String> extra = new HashSet<>(receivedKeys);
        extra.removeAll(expectedKeys);
        long duplicateAccepted = acceptedPerKey.values().stream().filter(n -> n > 1).count();
        checks.add(new Check("every malicious job has exactly one accepted alert", maliciousNotExactlyOnce == 0,
                expectedKeys.size() + " malicious jobs, " + maliciousNotExactlyOnce + " without exactly one ACCEPTED"));
        checks.add(new Check("zero alerts for non-malicious jobs", extra.isEmpty(), extra.size() + " unexpected keys"));
        checks.add(new Check("zero duplicate alerts accepted", duplicateAccepted == 0 && accepted == receivedKeys.size(),
                accepted + " accepted, " + receivedKeys.size() + " distinct keys, " + duplicateAccepted + " keys accepted twice"));

        List<Map<String, Object>> dead = new ArrayList<>();
        dead.addAll(q.rows("SELECT 'job' AS kind, id::text AS id, attempts, last_error FROM scan_job WHERE status = 'DEAD'"));
        dead.addAll(q.rows("SELECT 'alert' AS kind, job_id::text AS id, attempts, last_error FROM alert_outbox WHERE status = 'DEAD'"));
        checks.add(new Check("zero dead jobs and dead alerts", dead.isEmpty(),
                dead.isEmpty() ? "none" : dead.size() + " dead; see dead_items for last_error"));
        m.put("dead_items", dead);

        m.put("checks", checks);
        m.put("all_checks_pass", checks.stream().allMatch(Check::pass));
        m.put("missing_alert_keys", sample(diff(expectedKeys, receivedKeys)));
        m.put("unexpected_alert_keys", sample(extra));
        return m;
    }

    /**
     * Attributes every lease expiry to the most recent earlier kill of the container
     * that owned the lease. A kill "landed in the window" if at least one of the
     * leases it held expired (proof: the lease was never completed by its owner).
     */
    private Map<String, Object> killStats(List<Kill> kills) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kills_worker", kills.stream().filter(k -> k.target().equals("worker")).count());
        m.put("kills_sender", kills.stream().filter(k -> k.target().equals("sender")).count());
        m.put("webhook_restarts", kills.stream().filter(k -> k.target().equals("webhook")).count());
        m.put("kills_worker_holding_lease_observed", kills.stream().filter(k -> k.target().equals("worker") && k.inWindow()).count());
        m.put("kills_sender_alert_in_flight_observed", kills.stream().filter(k -> k.target().equals("sender") && k.inWindow()).count());
        m.put("webhook_restarts_alert_in_flight_observed", kills.stream().filter(k -> k.target().equals("webhook") && k.inWindow()).count());

        Attribution jobs = attribute(kills, "worker", q.rows("""
                SELECT e.worker_id AS owner, extract(epoch FROM e.lease_expires_at) * 1000 AS expires,
                       extract(epoch FROM j.finished_at) * 1000 AS done_at
                FROM queue_event e JOIN scan_job j ON j.id = e.job_id
                WHERE e.kind = 'LEASE_EXPIRED'"""), "", workerLeaseMillis);
        Attribution alerts = attribute(kills, "sender", q.rows("""
                SELECT e.worker_id AS owner, extract(epoch FROM e.lease_expires_at) * 1000 AS expires,
                       extract(epoch FROM o.delivered_at) * 1000 AS done_at
                FROM queue_event e JOIN alert_outbox o ON o.job_id = e.job_id
                WHERE e.kind = 'ALERT_LEASE_EXPIRED'"""), "sender-", senderLeaseMillis);

        m.put("kills_worker_holding_lease_confirmed", jobs.confirmedKills);
        m.put("kills_sender_alert_in_flight_confirmed", alerts.confirmedKills);
        m.put("pauses_worker", kills.stream().filter(k -> k.target().equals("worker_pause")).count());
        m.put("pauses_sender", kills.stream().filter(k -> k.target().equals("sender_pause")).count());
        m.put("pauses_worker_lease_reclaimed", jobs.confirmedPauses);
        m.put("pauses_sender_lease_reclaimed", alerts.confirmedPauses);
        m.put("lease_expiries_unattributed", jobs.unattributed);
        m.put("alert_lease_expiries_unattributed", alerts.unattributed);
        m.put("recovery_worker_p50_ms", round(percentile(jobs.recovery, 0.50), 0));
        m.put("recovery_worker_p95_ms", round(percentile(jobs.recovery, 0.95), 0));
        m.put("recovery_worker_max_ms", round(percentile(jobs.recovery, 1.0), 0));
        m.put("recovery_alert_p50_ms", round(percentile(alerts.recovery, 0.50), 0));
        m.put("recovery_alert_max_ms", round(percentile(alerts.recovery, 1.0), 0));
        return m;
    }

    private record Attribution(long confirmedKills, long confirmedPauses, long unattributed, List<Double> recovery) {
    }

    /**
     * Recovery time of one kill = time from the kill until the last piece of work it
     * interrupted was finished by someone else (job DONE / alert DELIVERED).
     * Pauses (target "worker_pause"/"sender_pause") take part in attribution so their
     * lease expiries are not blamed on an earlier kill, but are counted separately and
     * excluded from recovery times.
     */
    private static Attribution attribute(List<Kill> kills, String target, List<Map<String, Object>> expiries,
                                         String ownerPrefix, long leaseMillis) {
        List<Kill> ks = kills.stream().filter(k -> k.target().startsWith(target))
                .sorted(Comparator.comparingDouble(Kill::atMillis)).toList();
        Map<Kill, Double> recoveryByKill = new HashMap<>();
        long unattributed = 0;
        for (Map<String, Object> e : expiries) {
            String owner = (String) e.get("owner");
            double expires = num(e.get("expires"));
            // The lease was last claimed/renewed at expires - leaseMillis. The failure that
            // stopped it must fall between that moment and the expiry. KILL_SLACK covers a
            // renewal landing between the harness's snapshot and the SIGKILL taking effect.
            double lastSet = expires - leaseMillis;
            Kill match = null;
            for (Kill k : ks) {
                if (owner != null && owner.startsWith(ownerPrefix + k.host())
                        && k.atMillis() >= lastSet - KILL_SLACK_MILLIS && k.atMillis() < expires) {
                    match = k;    // earliest qualifying failure of this container
                    break;
                }
            }
            if (match == null) {
                unattributed++;
                continue;
            }
            Object doneAt = e.get("done_at");
            double rec = doneAt == null ? Double.NaN : num(doneAt) - match.atMillis();
            recoveryByKill.merge(match, rec, Math::max);
        }
        long confirmedKills = recoveryByKill.keySet().stream().filter(k -> k.target().equals(target)).count();
        long confirmedPauses = recoveryByKill.size() - confirmedKills;
        List<Double> rec = recoveryByKill.entrySet().stream()
                .filter(e -> e.getKey().target().equals(target))
                .map(Map.Entry::getValue).filter(d -> !d.isNaN()).sorted().toList();
        return new Attribution(confirmedKills, confirmedPauses, unattributed, rec);
    }

    private long count(String kind) {
        return q.count("SELECT count(*) FROM queue_event WHERE kind = ?", kind);
    }

    static double percentile(List<Double> sorted, double p) {
        if (sorted.isEmpty()) return Double.NaN;
        int idx = (int) Math.ceil(p * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, idx)));
    }

    private static Set<String> diff(Set<String> a, Set<String> b) {
        Set<String> d = new TreeSet<>(a);
        d.removeAll(b);
        return d;
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
