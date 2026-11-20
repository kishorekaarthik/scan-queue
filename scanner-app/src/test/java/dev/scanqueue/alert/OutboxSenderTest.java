package dev.scanqueue.alert;

import com.sun.net.httpserver.HttpServer;
import dev.scanqueue.IntegrationTestBase;
import dev.scanqueue.alert.OutboxSender.Lease;
import dev.scanqueue.alert.OutboxSender.Outcome;
import dev.scanqueue.job.QueueEvents;
import dev.scanqueue.job.QueueEvents.Kind;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Outbox sender protocol against real Postgres and an in-process stub webhook. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class OutboxSenderTest extends IntegrationTestBase {

    static HttpServer stub;
    static volatile int stubStatus = 201;
    static volatile CountDownLatch stubEntered = new CountDownLatch(0);
    static volatile CountDownLatch stubRelease = new CountDownLatch(0);

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired QueueEvents events;

    @BeforeAll
    static void startStub() throws Exception {
        stub = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        stub.createContext("/alerts", ex -> {
            ex.getRequestBody().readAllBytes();
            stubEntered.countDown();
            try {
                stubRelease.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            ex.sendResponseHeaders(stubStatus, -1);
            ex.close();
        });
        stub.setExecutor(Executors.newFixedThreadPool(4));
        stub.start();
    }

    @AfterAll
    static void stopStub() {
        stub.stop(0);
    }

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE alert_outbox, queue_event, scan_verdict, scan_job");
        stubStatus = 201;
        stubEntered = new CountDownLatch(0);
        stubRelease = new CountDownLatch(0);
    }

    @Test
    void noDatabaseTransactionIsHeldWhileTheAlertIsInFlight() throws Exception {
        UUID job = insertOutboxRow(20);
        stubEntered = new CountDownLatch(1);
        stubRelease = new CountDownLatch(1);
        OutboxSender sender = sender(10_000, 2_000, 0);

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<Boolean> run = pool.submit(() -> sender.deliverOne("s1"));
        assertThat(stubEntered.await(10, TimeUnit.SECONDS)).isTrue();

        // The POST is in flight. The claim is committed and visible, nothing holds
        // the row lock, and no session in this database is idle in a transaction.
        assertThat(row(job)).containsEntry("status", "SENDING").containsEntry("attempts", 1)
                .containsEntry("lease_owner", "s1");
        assertThat(jdbc.queryForList("SELECT id FROM alert_outbox WHERE job_id = ? FOR UPDATE NOWAIT", job)).hasSize(1);
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM pg_stat_activity
                WHERE datname = current_database() AND state LIKE 'idle in transaction%'
                """, Long.class)).isZero();

        stubRelease.countDown();
        assertThat(run.get(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdown();
        assertThat(row(job)).containsEntry("status", "DELIVERED").containsEntry("lease_owner", null);
        assertThat(events.count(Kind.ALERT_DELIVERED)).isEqualTo(1);
    }

    /** A sender stalls after sending; its lease is reclaimed and the alert resent. Its late mark is fenced out. */
    @Test
    void zombieSenderCannotMarkTheAlertAfterItsLeaseWasReclaimed() throws Exception {
        UUID job = insertOutboxRow(20);
        OutboxSender sender = sender(300, 200, 0);

        Lease a = sender.claim("sender-A").orElseThrow();
        assertThat(sender.send(a).status()).isEqualTo(201);    // webhook got it...
        Thread.sleep(700);                                      // ...but A stalls past its lease
        assertThat(sender.reapExpiredLeases(100)).isEqualTo(1);

        Lease b = sender.claim("sender-B").orElseThrow();
        assertThat(b.token()).isEqualTo(2);
        stubStatus = 200;                                       // the webhook would answer "duplicate"
        assertThat(sender.markDelivered(b, sender.send(b).status())).isEqualTo(Outcome.COMMITTED);

        assertThat(sender.markDelivered(a, 201)).isEqualTo(Outcome.FENCED);
        assertThat(sender.markFailed(a, "late")).isEqualTo(Outcome.FENCED);

        assertThat(row(job)).containsEntry("status", "DELIVERED").containsEntry("attempts", 2);
        assertThat(events.count(Kind.ALERT_LEASE_EXPIRED)).isEqualTo(1);
        assertThat(events.count(Kind.FENCED_WRITE)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT worker_id FROM queue_event WHERE kind = 'ALERT_DELIVERED'", String.class))
                .isEqualTo("sender-B");
    }

    @Test
    void alertGoesDeadAfterMaxAttempts() {
        UUID job = insertOutboxRow(3);
        stubStatus = 500;
        OutboxSender sender = sender(10_000, 2_000, 0);

        assertThat(sender.deliverOne("s")).isTrue();
        assertThat(sender.deliverOne("s")).isTrue();
        assertThat(sender.deliverOne("s")).isTrue();
        assertThat(sender.deliverOne("s")).isFalse();          // DEAD rows are never claimed again

        assertThat(row(job)).containsEntry("status", "DEAD").containsEntry("attempts", 3);
        assertThat(events.count(Kind.ALERT_SEND_FAILED)).isEqualTo(2);
        assertThat(events.count(Kind.ALERT_DEAD)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT detail FROM queue_event WHERE kind = 'ALERT_DEAD'", String.class))
                .contains("gave up after 3 attempts").contains("HTTP 500");
    }

    @Test
    void expiredAlertLeaseOnFinalAttemptGoesDead() throws Exception {
        UUID job = insertOutboxRow(1);
        OutboxSender sender = sender(300, 200, 0);
        sender.claim("s").orElseThrow();                        // sender "dies" holding the lease
        Thread.sleep(700);
        assertThat(sender.reapExpiredLeases(100)).isEqualTo(1);

        assertThat(row(job)).containsEntry("status", "DEAD");
        assertThat(events.count(Kind.ALERT_LEASE_EXPIRED)).isEqualTo(1);
        assertThat(events.count(Kind.ALERT_DEAD)).isEqualTo(1);
    }

    @Test
    void concurrentClaimsGetDifferentRows() {
        insertOutboxRow(20);
        insertOutboxRow(20);
        OutboxSender sender = sender(10_000, 2_000, 0);
        Lease x = sender.claim("x").orElseThrow();
        Lease y = sender.claim("y").orElseThrow();
        assertThat(x.id()).isNotEqualTo(y.id());
        assertThat(sender.claim("z")).isEmpty();
    }

    // ---- helpers ----

    private OutboxSender sender(long leaseMillis, long httpTimeoutMillis, long backoffBaseMillis) {
        String url = "http://127.0.0.1:" + stub.getAddress().getPort() + "/alerts";
        return new OutboxSender(jdbc, tx, events,
                new SenderProperties(url, 1, 50, leaseMillis, 100, backoffBaseMillis, 1_000, httpTimeoutMillis));
    }

    private UUID insertOutboxRow(int maxAttempts) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO scan_job (id, object_key, original_filename, size_bytes, status, attempts, finished_at)
                VALUES (?, ?, 'eicar.com.txt', 68, 'DONE', 1, now())
                """, id, "uploads/" + id);
        jdbc.update("""
                INSERT INTO alert_outbox (job_id, idempotency_key, payload, max_attempts)
                VALUES (?, 'alert:' || ?::text, '{}'::jsonb, ?)
                """, id, id, maxAttempts);
        return id;
    }

    private Map<String, Object> row(UUID job) {
        return jdbc.queryForMap("SELECT status, attempts, lease_owner FROM alert_outbox WHERE job_id = ?", job);
    }
}
