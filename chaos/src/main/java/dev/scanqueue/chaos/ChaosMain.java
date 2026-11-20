package dev.scanqueue.chaos;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.scanqueue.chaos.Uploader.Upload;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Chaos harness.
 *
 * <pre>
 * java -jar chaos/target/chaos.jar run    [--runs 10] [--files 10000] [--workers 5] [--out results/final]
 * java -jar chaos/target/chaos.jar report [--out results/final] [--readme README.md]
 * </pre>
 *
 * Every number it writes comes from the databases or from its own kill/upload log.
 */
public final class ChaosMain {

    static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** Must match the stack's WORKER_LEASE_MILLIS / SENDER_LEASE_MILLIS (application.yml defaults). */
    static final long WORKER_LEASE_MILLIS = 10_000;
    static final long SENDER_LEASE_MILLIS = 15_000;

    record Config(String command, int runs, int files, int eicarEvery, int workers, int webhookRestarts,
                  int uploadThreads, long webhookDelayMillis, long seed, String mode, Path out, Path readme,
                  long memLimitMb, String api, String webhookApi, String dbUrl, String webhookDbUrl) {

        static Config parse(String[] a) {
            Map<String, String> o = new LinkedHashMap<>();
            String cmd = a.length > 0 && !a[0].startsWith("--") ? a[0] : "run";
            for (int i = 0; i < a.length; i++) {
                if (a[i].startsWith("--") && i + 1 < a.length) {
                    o.put(a[i].substring(2), a[++i]);
                }
            }
            String mode = o.getOrDefault("mode", "final");
            return new Config(cmd,
                    Integer.parseInt(o.getOrDefault("runs", "10")),
                    Integer.parseInt(o.getOrDefault("files", "10000")),
                    Integer.parseInt(o.getOrDefault("eicar-every", "20")),     // 5 % EICAR
                    Integer.parseInt(o.getOrDefault("workers", "5")),
                    Integer.parseInt(o.getOrDefault("webhook-restarts", "3")),
                    Integer.parseInt(o.getOrDefault("upload-threads", "12")),
                    Long.parseLong(o.getOrDefault("webhook-delay-ms", "200")),  // realistic receiver latency
                    Long.parseLong(o.getOrDefault("seed", "20261120")),
                    mode,
                    Path.of(o.getOrDefault("out", "results/" + mode)),
                    o.containsKey("readme") ? Path.of(o.get("readme")) : null,
                    Long.parseLong(o.getOrDefault("mem-limit-mb", "4096")),
                    o.getOrDefault("api", "http://localhost:8080"),
                    o.getOrDefault("webhook", "http://localhost:8090"),
                    o.getOrDefault("db", "jdbc:postgresql://localhost:55432/scanqueue"),
                    o.getOrDefault("webhook-db", "jdbc:postgresql://localhost:55432/webhook?currentSchema=webhook"));
        }
    }

    public static void main(String[] args) throws Exception {
        Config cfg = Config.parse(args);
        if (cfg.command().equals("report")) {
            Report.write(cfg.out(), cfg.readme());
            return;
        }
        Files.createDirectories(cfg.out());
        Docker docker = new Docker(Map.of("WEBHOOK_RESPONSE_DELAY_MILLIS", Long.toString(cfg.webhookDelayMillis())));

        log("bringing up the stack with " + cfg.workers() + " workers");
        docker.compose("up", "-d", "--scale", "worker=" + cfg.workers());
        awaitHealthy(cfg);
        preflightMemory(cfg, docker);

        for (int run = 1; run <= cfg.runs(); run++) {
            Map<String, Object> result = runOnce(cfg, docker, run);
            Path file = cfg.out().resolve(String.format("run-%02d.json", run));
            JSON.writeValue(file.toFile(), result);
            log(String.format("run %d: checks %s | jobs %s verdicts %s malicious %s accepted %s dup-rejected %s fenced %s "
                            + "lease-exp %s | %s jobs/s p50 %s ms p95 %s ms | worker kills %s (in lease: %s confirmed) "
                            + "sender kills %s (in flight: %s confirmed) | peak mem %s MB",
                    run, (Boolean) result.get("all_checks_pass") ? "PASS" : "FAIL",
                    result.get("jobs"), result.get("verdicts"), result.get("malicious"), result.get("alerts_accepted"),
                    result.get("duplicates_rejected"), result.get("fenced_writes"), result.get("lease_expiries"),
                    result.get("throughput_jobs_per_sec"), result.get("latency_p50_ms"), result.get("latency_p95_ms"),
                    result.get("kills_worker"), result.get("kills_worker_holding_lease_confirmed"),
                    result.get("kills_sender"), result.get("kills_sender_alert_in_flight_confirmed"),
                    result.get("memory_peak_mb")));
            if (Boolean.TRUE.equals(result.get("aborted"))) {
                log("ABORTED: " + result.get("abort_reason"));
                break;
            }
        }
        Report.write(cfg.out(), cfg.readme());
        log("report written to " + cfg.out().resolve("summary.md"));
    }

    static Map<String, Object> runOnce(Config cfg, Docker docker, int run) throws Exception {
        long seed = cfg.seed() + run;
        log("run " + run + ": reset (seed " + seed + ")");
        try (Db q = new Db(cfg.dbUrl(), "scanqueue", "scanqueue");
             Db w = new Db(cfg.webhookDbUrl(), "scanqueue", "scanqueue");
             Db monkeyDb = new Db(cfg.dbUrl(), "scanqueue", "scanqueue")) {

            docker.compose("up", "-d", "--scale", "worker=" + cfg.workers());
            awaitHealthy(cfg);
            q.exec("TRUNCATE alert_outbox, scan_verdict, queue_event, scan_job");
            w.exec("TRUNCATE webhook.delivery_log, webhook.received_alert");

            MemoryWatch mem = new MemoryWatch(docker, cfg.memLimitMb() - 512);   // leave room for the harness JVM
            mem.start();
            Instant started = Instant.now();

            Monkey monkey = new Monkey(docker, monkeyDb, seed, cfg.webhookRestarts(), WORKER_LEASE_MILLIS, SENDER_LEASE_MILLIS);
            monkey.start();
            log("run " + run + ": uploading " + cfg.files() + " files (every " + cfg.eicarEvery() + "th is EICAR), chaos on");
            Uploader uploader = new Uploader(cfg.api());
            List<Upload> uploads = uploader.uploadAll(run, cfg.files(), cfg.eicarEvery(), cfg.uploadThreads());

            // Chaos runs for the whole scan phase. Alerts are produced throughout it (every
            // 20th job), so sender/webhook kills also cover the whole alert stream; alerts
            // interrupted by the last kills are recovered during the drain below.
            log("run " + run + ": uploads done; chaos continues until every scan job is finished");
            boolean settled = await(Duration.ofMinutes(15), mem.aborted, () ->
                    q.count("SELECT count(*) FROM scan_job WHERE status IN ('QUEUED', 'RUNNING')") == 0);
            monkey.stop();
            log("run " + run + ": chaos stopped, all containers restarted; draining");
            boolean drained = await(Duration.ofMinutes(10), mem.aborted, () ->
                    q.count("SELECT count(*) FROM scan_job WHERE status IN ('QUEUED', 'RUNNING')") == 0
                            && q.count("SELECT count(*) FROM alert_outbox WHERE status IN ('PENDING', 'SENDING')") == 0);
            mem.stop();

            Map<String, Object> r = new LinkedHashMap<>();
            r.put("run", run);
            r.put("mode", cfg.mode());
            r.put("seed", seed);
            r.put("started_at", started.toString());
            r.put("wall_clock_sec", Duration.between(started, Instant.now()).toSeconds());
            r.put("config", Map.of("files", cfg.files(), "eicar_every", cfg.eicarEvery(), "workers", cfg.workers(),
                    "webhook_restarts", cfg.webhookRestarts(), "webhook_delay_ms", cfg.webhookDelayMillis()));
            r.put("settled_before_timeout", settled);
            r.put("drained_before_timeout", drained);
            r.put("upload_client_retries", uploader.retries.get());
            r.putAll(new Verifier(q, w, WORKER_LEASE_MILLIS, SENDER_LEASE_MILLIS).verify(uploads, monkey.kills()));
            r.put("memory_peak_mb", Math.round(mem.peakMb));
            r.put("aborted", mem.aborted.get());
            r.put("abort_reason", mem.abortReason);
            r.put("kills", monkey.kills());
            return r;
        }
    }

    /** Before any run: the compose memory limits plus this JVM must fit in the budget. */
    static void preflightMemory(Config cfg, Docker docker) {
        List<String> ids = new ArrayList<>();
        for (String svc : List.of("postgres", "minio", "api", "worker", "sender", "webhook")) {
            ids.addAll(docker.running(svc));
        }
        long limits = docker.memLimitMb(ids);
        long harness = Runtime.getRuntime().maxMemory() / (1024 * 1024) + 100;  // heap + JVM overhead
        double used = docker.usedMb();
        log(String.format("memory preflight: %d containers, mem_limit sum %d MB + harness <= %d MB = %d MB "
                        + "(budget %d MB); current container use %.0f MB",
                ids.size(), limits, harness, limits + harness, cfg.memLimitMb(), used));
        if (limits + harness > cfg.memLimitMb()) {
            throw new IllegalStateException("worst-case memory " + (limits + harness) + " MB exceeds budget "
                    + cfg.memLimitMb() + " MB; not starting");
        }
    }

    /** Samples docker stats every 5 s; flags an abort if live container memory passes the limit. */
    static final class MemoryWatch {
        private final Docker docker;
        private final long limitMb;
        final AtomicBoolean aborted = new AtomicBoolean(false);
        volatile String abortReason;
        volatile double peakMb;
        private volatile boolean running = true;
        private Thread t;

        MemoryWatch(Docker docker, long limitMb) {
            this.docker = docker;
            this.limitMb = limitMb;
        }

        void start() {
            t = Thread.ofPlatform().daemon().name("mem-watch").start(() -> {
                while (running) {
                    try {
                        double used = docker.usedMb();
                        peakMb = Math.max(peakMb, used);
                        if (used > limitMb) {
                            abortReason = String.format("container memory %.0f MB > limit %d MB", used, limitMb);
                            aborted.set(true);
                        }
                        Thread.sleep(5_000);
                    } catch (InterruptedException e) {
                        return;
                    } catch (Exception e) {
                        // docker stats hiccup; try again next tick
                    }
                }
            });
        }

        void stop() throws InterruptedException {
            running = false;
            t.interrupt();
            t.join(10_000);
        }
    }

    static void awaitHealthy(Config cfg) throws InterruptedException {
        HttpClient http = HttpClient.newHttpClient();
        for (String url : List.of(cfg.api() + "/actuator/health", cfg.webhookApi() + "/actuator/health")) {
            boolean ok = await(Duration.ofMinutes(3), new AtomicBoolean(false), () -> {
                try {
                    HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(url))
                            .timeout(Duration.ofSeconds(3)).build(), HttpResponse.BodyHandlers.ofString());
                    return r.statusCode() == 200 && r.body().contains("UP");
                } catch (Exception e) {
                    return false;
                }
            });
            if (!ok) {
                throw new IllegalStateException("not healthy: " + url);
            }
        }
    }

    interface Cond {
        boolean get() throws Exception;
    }

    static boolean await(Duration timeout, AtomicBoolean abort, Cond c) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline && !abort.get()) {
            try {
                if (c.get()) {
                    return true;
                }
            } catch (Exception e) {
                // transient (e.g. DB connection); retry
            }
            Thread.sleep(500);
        }
        return false;
    }

    static void log(String s) {
        System.out.println("[" + Instant.now().toString().substring(11, 19) + "] " + s);
    }
}
