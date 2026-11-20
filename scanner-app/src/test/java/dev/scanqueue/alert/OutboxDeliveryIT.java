package dev.scanqueue.alert;

import dev.scanqueue.it.Images;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.lifecycle.Startables;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Outbox delivery with real processes: the sender is the scanner-app image with
 * the "sender" profile; the webhook is the mock-webhook image. Both talk to one
 * Postgres (scanner tables in public, webhook tables in the webhook schema).
 */
class OutboxDeliveryIT {

    static final Network NET = Network.newNetwork();
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine")
            .withNetwork(NET).withNetworkAliases("postgres");
    static JdbcTemplate jdbc;

    @BeforeAll
    static void start() {
        POSTGRES.start();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load().migrate();
        jdbc = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    @AfterAll
    static void stop() {
        POSTGRES.stop();
        NET.close();
    }

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE alert_outbox, queue_event, scan_verdict, scan_job");
        jdbc.execute("""
                DO $$ BEGIN
                  IF to_regclass('webhook.delivery_log') IS NOT NULL THEN
                    TRUNCATE webhook.delivery_log, webhook.received_alert;
                  END IF;
                END $$""");
    }

    /**
     * The webhook records the alert, then holds its response for 6 s. During that
     * window the sender (which has not yet marked the row delivered) is SIGKILLed.
     * A fresh sender resends with the same key; the webhook rejects the duplicate.
     */
    @Test
    void senderKilledAfterDeliveryBeforeMarkingResendsAndDuplicateIsRejected() {
        UUID job = insertOutboxRow();
        GenericContainer<?> webhook = webhook(6_000);
        GenericContainer<?> first = sender("s1");
        GenericContainer<?> second = sender("s2");
        try {
            webhook.start();
            first.start();
            await("webhook accepted the first delivery", () -> webhookCount("ACCEPTED") == 1, 60);
            assertThat(outbox(job)).containsEntry("status", "PENDING");   // sender still waiting on the response

            DockerClientFactory.lazyClient().killContainerCmd(first.getContainerId()).withSignal("KILL").exec();

            // The dead sender's transaction is rolled back by Postgres: the row is
            // unlocked, still PENDING, and not counted as delivered.
            await("row unlocked after sender death", () -> rowUnlocked(job), 30);
            assertThat(outbox(job)).containsEntry("status", "PENDING").containsEntry("attempts", 0);

            second.start();
            await("row delivered by the restarted sender", () -> "DELIVERED".equals(outbox(job).get("status")), 60);

            assertThat(webhookCount("ACCEPTED")).isEqualTo(1);
            assertThat(webhookCount("DUPLICATE_REJECTED")).isEqualTo(1);
            assertThat(jdbc.queryForMap("SELECT count(*) AS keys, max(delivery_count) AS deliveries FROM webhook.received_alert"))
                    .containsEntry("keys", 1L).containsEntry("deliveries", 2);
            assertThat(jdbc.queryForObject("SELECT detail FROM queue_event WHERE kind = 'ALERT_DELIVERED'", String.class))
                    .startsWith("duplicate");
        } finally {
            second.stop();
            first.stop();
            webhook.stop();
        }
    }

    @Test
    void webhookDownSenderRetriesWithBackoffThenDeliversOnceItIsBack() {
        UUID job = insertOutboxRow();
        GenericContainer<?> sender = sender("s1");
        GenericContainer<?> webhook = webhook(0);
        try {
            sender.start();                                    // no webhook: every send fails
            await("4 failed attempts", () -> ((Integer) outbox(job).get("attempts")) >= 4, 60);

            // Each retry happens no earlier than the backoff scheduled by the previous
            // failure (both timestamps are from the DB clock), and the delays double.
            List<Map<String, Object>> fails = jdbc.queryForList(
                    "SELECT at, detail FROM queue_event WHERE kind = 'ALERT_SEND_FAILED' ORDER BY at");
            List<Long> scheduled = new ArrayList<>();
            for (int i = 0; i < fails.size(); i++) {
                String detail = (String) fails.get(i).get("detail");
                long delay = Long.parseLong(detail.substring("retry in ".length(), detail.indexOf(" ms")));
                scheduled.add(delay);
                if (i > 0) {
                    long gap = ((Timestamp) fails.get(i).get("at")).getTime() - ((Timestamp) fails.get(i - 1).get("at")).getTime();
                    assertThat(gap).as("gap before attempt %d", i + 1).isGreaterThanOrEqualTo(scheduled.get(i - 1));
                }
            }
            assertThat(scheduled.subList(0, 4)).containsExactly(200L, 400L, 800L, 1600L);

            webhook.start();
            await("delivered after webhook came back", () -> "DELIVERED".equals(outbox(job).get("status")), 60);
            assertThat(webhookCount("ACCEPTED")).isEqualTo(1);
            assertThat(webhookCount("DUPLICATE_REJECTED")).isZero();
            assertThat(outbox(job).get("last_error")).isNull();
        } finally {
            sender.stop();
            webhook.stop();
        }
    }

    @Test
    void webhookRestartedBetweenTwoDeliveriesOfTheSameKeyStillRejectsTheDuplicate() throws Exception {
        String key = "alert:" + UUID.randomUUID();
        GenericContainer<?> before = webhook(0);
        before.start();
        HttpResponse<String> r1 = post(before, key);
        before.stop();                                         // container removed; only Postgres remembers

        GenericContainer<?> after = webhook(0);
        try {
            after.start();
            HttpResponse<String> r2 = post(after, key);

            assertThat(r1.statusCode()).isEqualTo(201);
            assertThat(r2.statusCode()).isEqualTo(200);
            assertThat(r2.body()).contains("duplicate_rejected");
            assertThat(jdbc.queryForList("SELECT outcome FROM webhook.delivery_log ORDER BY id", String.class))
                    .containsExactly("ACCEPTED", "DUPLICATE_REJECTED");
        } finally {
            after.stop();
        }
    }

    @Test
    void twoSendersRunningAtOnceNeverDoubleSend() {
        for (int i = 0; i < 40; i++) {
            insertOutboxRow();
        }
        GenericContainer<?> webhook = webhook(300);            // slow receiver keeps both senders busy
        GenericContainer<?> s1 = sender("s1");
        GenericContainer<?> s2 = sender("s2");
        try {
            webhook.start();
            Startables.deepStart(s1, s2).join();
            await("all 40 delivered", () -> jdbc.queryForObject(
                    "SELECT count(*) FROM alert_outbox WHERE status = 'DELIVERED'", Long.class) == 40, 120);

            assertThat(webhookCount("ACCEPTED")).isEqualTo(40);
            assertThat(webhookCount("DUPLICATE_REJECTED")).isZero();
            List<String> perSender = jdbc.queryForList("""
                    SELECT split_part(worker_id, '-', 2) || ':' || count(*)
                    FROM queue_event WHERE kind = 'ALERT_DELIVERED' GROUP BY split_part(worker_id, '-', 2)
                    """, String.class);
            LoggerFactory.getLogger(getClass()).info("deliveries per sender container: {}", perSender);
            assertThat(perSender).as("both senders delivered").hasSize(2);
        } finally {
            s1.stop();
            s2.stop();
            webhook.stop();
        }
    }

    // ---- helpers ----

    private static GenericContainer<?> webhook(long responseDelayMillis) {
        return new GenericContainer<>(Images.WEBHOOK)
                .withNetwork(NET).withNetworkAliases("webhook")
                .withEnv(Map.of(
                        "DB_URL", "jdbc:postgresql://postgres:5432/" + POSTGRES.getDatabaseName(),
                        "DB_USER", POSTGRES.getUsername(),
                        "DB_PASSWORD", POSTGRES.getPassword(),
                        "WEBHOOK_RESPONSE_DELAY_MILLIS", Long.toString(responseDelayMillis)))
                .withExposedPorts(8080)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("webhook")))
                .waitingFor(Wait.forHttp("/actuator/health").forStatusCode(200).withStartupTimeout(Duration.ofMinutes(2)));
    }

    private static GenericContainer<?> sender(String name) {
        return new GenericContainer<>(Images.SCANNER)
                .withNetwork(NET)
                .withCreateContainerCmdModifier(cmd -> cmd.withHostName(name))
                .withEnv(Map.of(
                        "SPRING_PROFILES_ACTIVE", "sender",
                        "DB_URL", "jdbc:postgresql://postgres:5432/" + POSTGRES.getDatabaseName(),
                        "DB_USER", POSTGRES.getUsername(),
                        "DB_PASSWORD", POSTGRES.getPassword(),
                        "WEBHOOK_URL", "http://webhook:8080/alerts",
                        "SENDER_POLL_MILLIS", "100",
                        "SENDER_BACKOFF_BASE_MILLIS", "200",
                        "SENDER_BACKOFF_MAX_MILLIS", "3200",
                        "SENDER_HTTP_TIMEOUT_MILLIS", "10000"))
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(name)))
                .waitingFor(Wait.forLogMessage(".*sender started.*", 1).withStartupTimeout(Duration.ofMinutes(2)));
    }

    private static UUID insertOutboxRow() {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO scan_job (id, object_key, original_filename, size_bytes, status, attempts, finished_at)
                VALUES (?, ?, 'eicar.com.txt', 68, 'DONE', 1, now())
                """, id, "uploads/" + id);
        jdbc.update("""
                INSERT INTO alert_outbox (job_id, idempotency_key, payload)
                VALUES (?, 'alert:' || ?::text, jsonb_build_object('jobId', ?::text))
                """, id, id, id);
        return id;
    }

    private static Map<String, Object> outbox(UUID job) {
        return jdbc.queryForMap("SELECT status, attempts, last_error, delivered_at FROM alert_outbox WHERE job_id = ?", job);
    }

    /** True once no transaction holds the row lock (NOWAIT fails fast if one does). */
    private static boolean rowUnlocked(UUID job) {
        try {
            jdbc.queryForList("SELECT id FROM alert_outbox WHERE job_id = ? FOR UPDATE NOWAIT", job);
            return true;
        } catch (Exception lockedByAnotherTx) {
            return false;
        }
    }

    private static long webhookCount(String outcome) {
        if (jdbc.queryForObject("SELECT to_regclass('webhook.delivery_log') IS NOT NULL", Boolean.class)) {
            return jdbc.queryForObject("SELECT count(*) FROM webhook.delivery_log WHERE outcome = ?", Long.class, outcome);
        }
        return 0;
    }

    private static HttpResponse<String> post(GenericContainer<?> webhook, String key) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(
                        "http://" + webhook.getHost() + ":" + webhook.getMappedPort(8080) + "/alerts"))
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", key)
                .POST(HttpRequest.BodyPublishers.ofString("{\"jobId\":\"x\"}"))
                .build();
        return HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static void await(String what, BooleanSupplier condition, int seconds) {
        long deadline = System.nanoTime() + Duration.ofSeconds(seconds).toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
            }
        }
        throw new AssertionError("timed out after " + seconds + " s waiting for: " + what);
    }
}
