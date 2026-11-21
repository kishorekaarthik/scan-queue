package dev.scanqueue.alert;

import dev.scanqueue.job.QueueEvents;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * At-least-once alert delivery with leases and fencing, and no transaction held
 * open across the network call:
 *
 * <pre>
 * 1. claim   (one autocommit statement)
 *      UPDATE alert_outbox SET status='SENDING', attempts=attempts+1, lease=now()+L
 *      WHERE id = (SELECT ... WHERE status='PENDING' AND available_at<=now()
 *                  ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
 * 2. POST    Idempotency-Key: alert:&lt;job_id&gt;      -- no DB transaction open
 * 3. mark    UPDATE ... SET status='DELIVERED'
 *            WHERE id=? AND attempts=&lt;token&gt; AND status='SENDING'   -- fenced
 * </pre>
 *
 * If the sender dies between 2 and 3 the row stays SENDING until its lease expires;
 * the reaper returns it to PENDING, another claim (new token) resends it with the
 * same key, and the webhook rejects the duplicate. A sender that wakes up after its
 * lease was reclaimed cannot mark the row: its token is stale (fenced write).
 */
@Component
public class OutboxSender {

    public enum Outcome { COMMITTED, FENCED }

    /** A sender's hold on one outbox row; {@code token} is the attempts value from its claim. */
    public record Lease(long id, UUID jobId, String key, String payload, int token, String owner) {
    }

    /** Result of the HTTP call: a status code, or the exception if there was no response. */
    public record SendResult(int status, String error) {
        boolean ok() {
            return status >= 200 && status < 300;
        }
    }

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

    /** @return true if a row was attempted, false if nothing was ready */
    public boolean deliverOne(String senderId) {
        Optional<Lease> lease = claim(senderId);
        if (lease.isEmpty()) {
            return false;
        }
        Lease l = lease.get();
        SendResult r = send(l);
        if (r.ok()) {
            markDelivered(l, r.status());
        } else {
            markFailed(l, r.error() != null ? r.error() : "HTTP " + r.status());
        }
        return true;
    }

    public Optional<Lease> claim(String senderId) {
        return jdbc.query("""
                WITH next AS (
                    SELECT id FROM alert_outbox
                    WHERE status = 'PENDING' AND available_at <= now()
                    ORDER BY id
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE alert_outbox o
                SET status           = 'SENDING',
                    attempts         = o.attempts + 1,
                    lease_owner      = ?,
                    lease_expires_at = now() + ? * interval '1 millisecond',
                    claimed_at       = now()
                FROM next
                WHERE o.id = next.id
                RETURNING o.id, o.job_id, o.idempotency_key, o.payload::text AS payload, o.attempts, o.lease_owner
                """,
                (rs, i) -> new Lease(rs.getLong("id"), rs.getObject("job_id", UUID.class),
                        rs.getString("idempotency_key"), rs.getString("payload"),
                        rs.getInt("attempts"), rs.getString("lease_owner")),
                senderId, props.leaseMillis()).stream().findFirst();
    }

    /** The network call. Deliberately touches no database state. */
    public SendResult send(Lease l) {
        try {
            int status = http.post().uri(props.webhookUrl())
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Idempotency-Key", l.key())
                    .body(l.payload())
                    .retrieve()
                    .onStatus(s -> true, (req, res) -> { })   // inspect the status ourselves
                    .toBodilessEntity()
                    .getStatusCode().value();
            return new SendResult(status, null);
        } catch (Exception e) {
            return new SendResult(0, e.toString());
        }
    }

    public Outcome markDelivered(Lease l, int httpStatus) {
        Outcome outcome = tx.execute(s -> {
            int n = jdbc.update("""
                    UPDATE alert_outbox
                    SET status = 'DELIVERED', delivered_at = now(), last_error = NULL,
                        lease_owner = NULL, lease_expires_at = NULL
                    WHERE id = ? AND attempts = ? AND status = 'SENDING'
                    """, l.id(), l.token());
            if (n == 0) {
                return Outcome.FENCED;
            }
            // 201 = webhook acted on it; 200 = it already had this key (duplicate rejected).
            events.record(QueueEvents.Kind.ALERT_DELIVERED, l.jobId(), l.token(), l.owner(),
                    httpStatus == 201 ? "accepted" : "duplicate (HTTP " + httpStatus + ")");
            return Outcome.COMMITTED;
        });
        if (outcome == Outcome.FENCED) {
            events.record(QueueEvents.Kind.FENCED_WRITE, l.jobId(), l.token(), l.owner(),
                    "alert mark-delivered rejected: token no longer current");
        }
        return outcome;
    }

    /** Re-queue with exponential backoff (DB clock), or DEAD once attempts reach max_attempts. */
    public Outcome markFailed(Lease l, String error) {
        long delay = Math.min(props.backoffMaxMillis(),
                props.backoffBaseMillis() * (1L << Math.min(l.token() - 1, 20)));
        String err = error.length() > 500 ? error.substring(0, 500) : error;
        List<String> status = jdbc.queryForList("""
                UPDATE alert_outbox
                SET status           = CASE WHEN attempts >= max_attempts THEN 'DEAD' ELSE 'PENDING' END,
                    last_error       = ?,
                    available_at     = now() + ? * interval '1 millisecond',
                    lease_owner      = NULL,
                    lease_expires_at = NULL
                WHERE id = ? AND attempts = ? AND status = 'SENDING'
                RETURNING status
                """, String.class, err, delay, l.id(), l.token());
        if (status.isEmpty()) {
            events.record(QueueEvents.Kind.FENCED_WRITE, l.jobId(), l.token(), l.owner(),
                    "alert mark-failed rejected: token no longer current");
            return Outcome.FENCED;
        }
        if ("DEAD".equals(status.get(0))) {
            events.record(QueueEvents.Kind.ALERT_DEAD, l.jobId(), l.token(), l.owner(),
                    "gave up after " + l.token() + " attempts: " + err);
        } else {
            events.record(QueueEvents.Kind.ALERT_SEND_FAILED, l.jobId(), l.token(), l.owner(),
                    "retry in " + delay + " ms: " + err);
        }
        return Outcome.COMMITTED;
    }

    /**
     * SENDING rows whose lease expired (sender died or stalled mid-send) go back to
     * PENDING for an immediate resend, or to DEAD on the last attempt. Events are
     * inserted by the same statement.
     *
     * @return number of expired alert leases reclaimed
     */
    public int reapExpiredLeases(int batchSize) {
        List<String> kinds = jdbc.queryForList("""
                WITH expired AS (
                    SELECT id, lease_owner, lease_expires_at FROM alert_outbox
                    WHERE status = 'SENDING' AND lease_expires_at < now()
                    ORDER BY lease_expires_at
                    LIMIT ?
                    FOR UPDATE SKIP LOCKED
                ), upd AS (
                    UPDATE alert_outbox o
                    SET status           = CASE WHEN o.attempts >= o.max_attempts THEN 'DEAD' ELSE 'PENDING' END,
                        last_error       = 'lease expired (owner ' || expired.lease_owner || ')',
                        available_at     = now(),
                        lease_owner      = NULL,
                        lease_expires_at = NULL
                    FROM expired
                    WHERE o.id = expired.id
                    RETURNING o.job_id, o.attempts, o.status, expired.lease_owner, expired.lease_expires_at
                )
                INSERT INTO queue_event (kind, job_id, claim_token, worker_id, detail, lease_expires_at)
                SELECT 'ALERT_LEASE_EXPIRED', job_id, attempts, lease_owner, 'returned as ' || status, lease_expires_at FROM upd
                UNION ALL
                SELECT 'ALERT_DEAD', job_id, attempts, lease_owner, 'lease expired on final attempt', lease_expires_at
                FROM upd WHERE status = 'DEAD'
                RETURNING kind
                """, String.class, batchSize);
        return (int) kinds.stream().filter("ALERT_LEASE_EXPIRED"::equals).count();
    }
}
