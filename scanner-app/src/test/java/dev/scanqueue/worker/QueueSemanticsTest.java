package dev.scanqueue.worker;

import dev.scanqueue.IntegrationTestBase;
import dev.scanqueue.job.Claim;
import dev.scanqueue.job.JobQueue;
import dev.scanqueue.job.JobRepository;
import dev.scanqueue.job.JobStatus;
import dev.scanqueue.job.QueueEvents;
import dev.scanqueue.job.QueueEvents.Kind;
import dev.scanqueue.job.VerdictRecord;
import dev.scanqueue.scan.HashList;
import dev.scanqueue.scan.ScanEngine;
import dev.scanqueue.scan.YaraRunner;
import dev.scanqueue.storage.ObjectStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Queue protocol against a real Postgres. YARA is replaced by an in-JVM fake
 * here (it lives in the worker container; see WorkerContainerIT for the real one),
 * so these tests can control scan duration precisely.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class QueueSemanticsTest extends IntegrationTestBase {

    static final YaraRunner NO_MATCH = (file, cancelled) -> List.of();

    @Autowired JdbcTemplate jdbc;
    @Autowired JobQueue queue;
    @Autowired JobRepository jobs;
    @Autowired QueueEvents events;
    @Autowired ObjectStore store;
    @Autowired HashList hashList;

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE alert_outbox, scan_verdict, queue_event, scan_job");
    }

    @Test
    void concurrentClaimersNeverGetTheSameJob() throws Exception {
        for (int i = 0; i < 60; i++) {
            newJob("file-" + i, 5);
        }
        List<Claim> claims = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            String worker = "w" + t;
            futures.add(pool.submit(() -> {
                Optional<Claim> c;
                while ((c = queue.claim(worker, 30_000)).isPresent()) {
                    claims.add(c.get());
                }
            }));
        }
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        Set<UUID> distinct = new HashSet<>();
        claims.forEach(c -> distinct.add(c.jobId()));
        assertThat(claims).hasSize(60);
        assertThat(distinct).hasSize(60);
        assertThat(claims).allMatch(c -> c.token() == 1);
    }

    @Test
    void leaseIsComputedByTheDatabaseClock() {
        UUID id = newJob("a", 5);
        queue.claim("w", 5_000).orElseThrow();

        // started_at and lease_expires_at both come from the same statement's now(),
        // so the lease is exactly now() + 5 s on the DB clock; no JVM time is involved.
        Boolean exact = jdbc.queryForObject(
                "SELECT lease_expires_at - started_at = interval '5000 milliseconds' FROM scan_job WHERE id = ?",
                Boolean.class, id);
        assertThat(exact).isTrue();
    }

    /** The zombie scenario, step by step against the queue API. */
    @Test
    void zombieWorkerWriteIsFencedOut() throws Exception {
        UUID id = newJob("zombie", 5);

        Claim zombie = queue.claim("worker-A", 300).orElseThrow();
        assertThat(zombie.token()).isEqualTo(1);

        Thread.sleep(700);                                  // A stalls; its lease runs out on the DB clock
        assertThat(queue.reapExpiredLeases(100)).isEqualTo(1);

        Claim fresh = queue.claim("worker-B", 30_000).orElseThrow();
        assertThat(fresh.jobId()).isEqualTo(id);
        assertThat(fresh.token()).isEqualTo(2);

        assertThat(queue.complete(fresh, verdict("bbbb", false))).isEqualTo(JobQueue.Outcome.COMMITTED);

        // A wakes up and tries to act on its stale lease: every write is rejected,
        // including its MALICIOUS verdict, so no alert is queued for it.
        assertThat(queue.renew(zombie, 30_000)).isFalse();
        assertThat(queue.complete(zombie, verdict("aaaa", true))).isEqualTo(JobQueue.Outcome.FENCED);
        assertThat(queue.fail(zombie, "late failure", 0)).isEqualTo(JobQueue.Outcome.FENCED);

        Map<String, Object> v = jdbc.queryForMap("SELECT * FROM scan_verdict WHERE job_id = ?", id);
        assertThat(v).containsEntry("worker_id", "worker-B")
                .containsEntry("claim_token", 2)
                .containsEntry("verdict", "CLEAN");
        assertThat(outboxRows()).isZero();
        assertThat(jobs.find(id).orElseThrow().status()).isEqualTo(JobStatus.DONE);
        assertThat(events.count(Kind.LEASE_EXPIRED)).isEqualTo(1);
        assertThat(events.count(Kind.FENCED_WRITE)).isEqualTo(2);
    }

    /**
     * Same scenario through the real JobProcessor. Worker A is "paused" inside its
     * scan (a stop-the-world GC or a network partition): its heartbeat is too slow
     * to save it, the lease is expired, B scans the job to completion, then A
     * resumes and tries to write its verdict.
     */
    @Test
    void zombieWorkerIsFencedOutEndToEnd() throws Exception {
        UUID id = newJob("zombie-e2e", 5);
        CountDownLatch aIsScanning = new CountDownLatch(1);
        CountDownLatch resumeA = new CountDownLatch(1);
        YaraRunner pausedYara = (file, cancelled) -> {
            aIsScanning.countDown();
            resumeA.await();                                 // A is frozen here
            return List.of("Would_Be_Wrong");
        };
        // A's heartbeat period (20 s) is longer than the whole test: it never renews.
        JobProcessor a = processor(pausedYara, 25_000, 20_000);
        JobProcessor b = processor(NO_MATCH, 30_000, 5_000);

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<Boolean> aRun = pool.submit(() -> a.processOne("worker-A"));
        assertThat(aIsScanning.await(10, TimeUnit.SECONDS)).isTrue();

        // A's lease runs out (simulated by moving its expiry into the past on the DB clock).
        jdbc.update("UPDATE scan_job SET lease_expires_at = now() - interval '1 second' WHERE id = ?", id);
        assertThat(queue.reapExpiredLeases(100)).isEqualTo(1);
        assertThat(b.processOne("worker-B")).isTrue();     // B claims (token 2) and finishes

        resumeA.countDown();                                 // A resumes and tries to write
        assertThat(aRun.get(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdown();
        a.close();
        b.close();

        Map<String, Object> v = jdbc.queryForMap("SELECT * FROM scan_verdict WHERE job_id = ?", id);
        assertThat(v).containsEntry("worker_id", "worker-B").containsEntry("claim_token", 2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM scan_verdict", Long.class)).isEqualTo(1);
        assertThat(events.count(Kind.FENCED_WRITE)).isEqualTo(1);
        String fencedWorker = jdbc.queryForObject(
                "SELECT worker_id FROM queue_event WHERE kind = 'FENCED_WRITE'", String.class);
        assertThat(fencedWorker).isEqualTo("worker-A");
        // A's (wrong) MALICIOUS verdict was fenced out: it created no outbox row.
        assertThat(outboxRows()).isZero();
    }

    /** Zombie and winner both find the file malicious: still exactly one alert, from the winner's transaction. */
    @Test
    void fencedZombieAddsNoSecondAlert() throws Exception {
        UUID id = newJob("both-malicious", 5);
        Claim zombie = queue.claim("worker-A", 300).orElseThrow();
        Thread.sleep(700);
        queue.reapExpiredLeases(100);
        Claim fresh = queue.claim("worker-B", 30_000).orElseThrow();

        assertThat(queue.complete(fresh, verdict("bbbb", true))).isEqualTo(JobQueue.Outcome.COMMITTED);
        assertThat(queue.complete(zombie, verdict("bbbb", true))).isEqualTo(JobQueue.Outcome.FENCED);

        assertThat(outboxRows()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT idempotency_key FROM alert_outbox", String.class))
                .isEqualTo("alert:" + id);
    }

    @Test
    void maliciousVerdictQueuesOneAlertInTheSameTransactionCleanQueuesNone() {
        UUID bad = newJob("bad", 5);
        UUID good = newJob("good", 5);
        Claim c1 = queue.claim("w", 30_000).orElseThrow();
        Claim c2 = queue.claim("w", 30_000).orElseThrow();
        Claim badClaim = c1.jobId().equals(bad) ? c1 : c2;
        Claim goodClaim = c1.jobId().equals(bad) ? c2 : c1;

        queue.complete(badClaim, new VerdictRecord("ab".repeat(32), true, "EICAR test file", List.of("EICAR_Test_File"), 3));
        queue.complete(goodClaim, verdict("cd".repeat(32), false));

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT job_id, idempotency_key, status, attempts, payload->>'hashMatch' AS hm, payload->'yaraMatches'->>0 AS rule FROM alert_outbox");
        assertThat(row).containsEntry("job_id", bad)
                .containsEntry("idempotency_key", "alert:" + bad)
                .containsEntry("status", "PENDING")
                .containsEntry("attempts", 0)
                .containsEntry("hm", "EICAR test file")
                .containsEntry("rule", "EICAR_Test_File");
        assertThat(outboxRows()).isEqualTo(1);
        assertThat(good).isNotEqualTo(bad);
    }

    /** Scan takes ~3x the lease; heartbeats keep it, and a competing worker never gets the job. */
    @Test
    void heartbeatKeepsASlowScanFromBeingStolen() throws Exception {
        UUID id = newJob("slow", 5);
        long lease = 1_500, heartbeat = 300, scanTime = 4_500;
        YaraRunner slowYara = (file, cancelled) -> {
            Thread.sleep(scanTime);
            return List.of();
        };
        JobProcessor owner = processor(slowYara, lease, heartbeat);

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<Boolean> run = pool.submit(() -> owner.processOne("owner"));

        // A competing worker reaps and tries to claim for the whole scan.
        long until = System.currentTimeMillis() + scanTime;
        int stealAttempts = 0;
        while (System.currentTimeMillis() < until) {
            queue.reapExpiredLeases(100);
            assertThat(queue.claim("thief", lease)).isEmpty();
            stealAttempts++;
            Thread.sleep(100);
        }
        assertThat(run.get(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdown();
        owner.close();

        assertThat(scanTime).isGreaterThan(2 * lease);
        assertThat(stealAttempts).isGreaterThan(20);
        assertThat(jobs.find(id).orElseThrow().status()).isEqualTo(JobStatus.DONE);
        assertThat(jobs.find(id).orElseThrow().attempts()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT worker_id FROM scan_verdict WHERE job_id = ?", String.class, id))
                .isEqualTo("owner");
        assertThat(events.count(Kind.LEASE_EXPIRED)).isZero();
        assertThat(events.count(Kind.FENCED_WRITE)).isZero();
    }

    @Test
    void failingScanIsRetriedThenDeadLettered() {
        UUID id = newJob("broken", 3);
        YaraRunner broken = (file, cancelled) -> {
            throw new IllegalStateException("yara crashed");
        };
        JobProcessor p = processor(broken, 10_000, 2_000);

        assertThat(p.processOne("w")).isTrue();
        assertThat(p.processOne("w")).isTrue();
        assertThat(p.processOne("w")).isTrue();
        assertThat(p.processOne("w")).isFalse();             // nothing left to claim
        p.close();

        var job = jobs.find(id).orElseThrow();
        assertThat(job.status()).isEqualTo(JobStatus.DEAD);
        assertThat(job.attempts()).isEqualTo(3);
        assertThat(job.lastError()).contains("yara crashed");
        assertThat(events.count(Kind.RETRY)).isEqualTo(2);
        assertThat(events.count(Kind.DEAD_LETTERED)).isEqualTo(1);
    }

    @Test
    void expiredLeaseOnFinalAttemptIsDeadLettered() throws Exception {
        UUID id = newJob("crashy", 1);
        queue.claim("w", 200).orElseThrow();
        Thread.sleep(500);
        assertThat(queue.reapExpiredLeases(100)).isEqualTo(1);

        assertThat(jobs.find(id).orElseThrow().status()).isEqualTo(JobStatus.DEAD);
        assertThat(events.count(Kind.LEASE_EXPIRED)).isEqualTo(1);
        assertThat(events.count(Kind.DEAD_LETTERED)).isEqualTo(1);
    }

    @Test
    void hashListFlagsListedContentEvenWithoutYaraMatch() throws Exception {
        UUID id = newJob("scan-queue harmless test sample A", 5);
        JobProcessor p = processor(NO_MATCH, 10_000, 2_000);
        assertThat(p.processOne("w")).isTrue();
        p.close();

        Map<String, Object> v = jdbc.queryForMap("SELECT * FROM scan_verdict WHERE job_id = ?", id);
        assertThat(v).containsEntry("verdict", "MALICIOUS")
                .containsEntry("hash_match", "test sample A (harmless)")
                .containsEntry("sha256", "b18e081077d9e3f773059570c0dd0bbada48b425fa628078fd88ea87ffe44d0c");
    }

    // ---- helpers ----

    private UUID newJob(String content, int maxAttempts) {
        UUID id = UUID.randomUUID();
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        String key = "uploads/" + id;
        store.put(key, new ByteArrayInputStream(bytes), bytes.length, "text/plain");
        jobs.insertQueued(id, key, content + ".txt", bytes.length, maxAttempts);
        return id;
    }

    private JobProcessor processor(YaraRunner yara, long leaseMillis, long heartbeatMillis) {
        return new JobProcessor(queue, new ScanEngine(store, hashList, yara), events,
                new WorkerProperties(1, leaseMillis, heartbeatMillis, 50, 100, 0));
    }

    private long outboxRows() {
        return jdbc.queryForObject("SELECT count(*) FROM alert_outbox", Long.class);
    }

    private static VerdictRecord verdict(String sha, boolean malicious) {
        return new VerdictRecord(sha, malicious, null, List.of(), 1);
    }
}
