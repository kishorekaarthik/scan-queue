package dev.scanqueue.alert;

import dev.scanqueue.job.QueueEvents;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * Delivers one outbox row per call: at-least-once.
 *
 * <pre>
 * BEGIN
 *   SELECT ... FROM alert_outbox WHERE status='PENDING' AND available_at <= now()
 *     ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED      -- other senders skip this row
 *   POST webhook, Idempotency-Key: alert:&lt;job_id&gt;
 *   2xx  -> UPDATE status='DELIVERED'
 *   else -> UPDATE attempts+1, available_at = now() + backoff
 * COMMIT
 * </pre>
 *
 * The row lock is held while the POST is in flight, so two senders never send
 * the same row concurrently. If the sender dies after the webhook got the alert
 * but before COMMIT, Postgres rolls back when the connection drops, the row is
 * PENDING again, and the next send carries the same key, so the webhook rejects it
 * as a duplicate. At-least-once delivery + idempotent receiver = effectively once.
 */
@Component
public class OutboxSender {

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final QueueEvents events;
    private final SenderProperties props;
    private final RestClient http;

    public OutboxSender(JdbcTemplate jdbc, TransactionTemplate tx, QueueEvents events, SenderProperties props) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.events = events;
        this.props = props;
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(props.httpTimeoutMillis()))
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(Duration.ofMillis(props.httpTimeoutMillis()));
        this.http = RestClient.builder().requestFactory(factory).build();
    }

    record Row(long id, UUID jobId, String key, String payload, int attempts) {
    }

    /** @return true if a row was attempted, false if nothing was ready */
    public boolean deliverOne(String senderId) {
        return Boolean.TRUE.equals(tx.execute(status -> {
            List<Row> rows = jdbc.query("""
                    SELECT id, job_id, idempotency_key, payload::text AS payload, attempts
                    FROM alert_outbox
                    WHERE status = 'PENDING' AND available_at <= now()
                    ORDER BY id
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                    """, (rs, i) -> new Row(rs.getLong("id"), rs.getObject("job_id", UUID.class),
                    rs.getString("idempotency_key"), rs.getString("payload"), rs.getInt("attempts")));
            if (rows.isEmpty()) {
                return false;
            }
            Row row = rows.get(0);
            int attempt = row.attempts() + 1;
            HttpStatusCode code;
            try {
                code = http.post().uri(props.webhookUrl())
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Idempotency-Key", row.key())
                        .body(row.payload())
                        .retrieve()
                        .onStatus(s -> true, (req, res) -> { })   // inspect the status ourselves
                        .toBodilessEntity()
                        .getStatusCode();
            } catch (Exception e) {
                scheduleRetry(row, attempt, senderId, e.toString());
                return true;
            }
            if (!code.is2xxSuccessful()) {
                scheduleRetry(row, attempt, senderId, "HTTP " + code.value());
                return true;
            }
            jdbc.update("""
                    UPDATE alert_outbox
                    SET status = 'DELIVERED', delivered_at = now(), attempts = ?, last_error = NULL
                    WHERE id = ?
                    """, attempt, row.id());
            // 201 = webhook acted on it; 200 = it already had this key (duplicate rejected).
            events.record(QueueEvents.Kind.ALERT_DELIVERED, row.jobId(), attempt, senderId,
                    code.value() == 201 ? "accepted" : "duplicate (HTTP " + code.value() + ")");
            return true;
        }));
    }

    /** Exponential backoff on the DB clock: base * 2^(attempt-1), capped. */
    private void scheduleRetry(Row row, int attempt, String senderId, String error) {
        long delay = Math.min(props.backoffMaxMillis(),
                props.backoffBaseMillis() * (1L << Math.min(attempt - 1, 20)));
        jdbc.update("""
                UPDATE alert_outbox
                SET attempts = ?, last_error = ?, available_at = now() + ? * interval '1 millisecond'
                WHERE id = ?
                """, attempt, error.length() > 500 ? error.substring(0, 500) : error, delay, row.id());
        events.record(QueueEvents.Kind.ALERT_SEND_FAILED, row.jobId(), attempt, senderId,
                "retry in " + delay + " ms: " + error);
    }
}
