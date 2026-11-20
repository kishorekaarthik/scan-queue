package dev.scanqueue.job;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Array;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The queue protocol, all in SQL.
 *
 * <p><b>Clock rule:</b> every lease timestamp is computed and compared with
 * Postgres {@code now()}. The worker's clock is never written or compared, so
 * clock skew between workers cannot make a lease look valid or expired.
 *
 * <p><b>Fencing rule:</b> every write a worker makes after claiming is
 * conditional on {@code id = ? AND attempts = <token> AND status = 'RUNNING'}.
 * A write that matches 0 rows came from a stale owner and is discarded.
 */
@Repository
public class JobQueue {

    public enum Outcome { COMMITTED, FENCED }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final QueueEvents events;

    public JobQueue(JdbcTemplate jdbc, TransactionTemplate tx, QueueEvents events) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.events = events;
    }

    /**
     * Claim the oldest claimable job. One statement: the CTE locks one QUEUED row,
     * skipping rows other workers have locked, and the UPDATE takes the lease and
     * bumps the fencing token. Concurrent claimers never block on, or double-claim, a row.
     */
    public Optional<Claim> claim(String workerId, long leaseMillis) {
        return jdbc.query("""
                WITH next AS (
                    SELECT id FROM scan_job
                    WHERE status = 'QUEUED' AND available_at <= now()
                    ORDER BY created_at
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE scan_job j
                SET status           = 'RUNNING',
                    attempts         = j.attempts + 1,
                    lease_owner      = ?,
                    lease_expires_at = now() + ? * interval '1 millisecond',
                    started_at       = coalesce(j.started_at, now())
                FROM next
                WHERE j.id = next.id
                RETURNING j.id, j.object_key, j.attempts, j.lease_owner, j.lease_expires_at
                """,
                (rs, i) -> new Claim(
                        rs.getObject("id", UUID.class),
                        rs.getString("object_key"),
                        rs.getInt("attempts"),
                        rs.getString("lease_owner"),
                        rs.getObject("lease_expires_at", OffsetDateTime.class)),
                workerId, leaseMillis).stream().findFirst();
    }

    /** Heartbeat. Returns false if the lease is no longer ours (fenced). */
    public boolean renew(Claim c, long leaseMillis) {
        return jdbc.update("""
                UPDATE scan_job
                SET lease_expires_at = now() + ? * interval '1 millisecond'
                WHERE id = ? AND attempts = ? AND status = 'RUNNING'
                """, leaseMillis, c.jobId(), c.token()) == 1;
    }

    /**
     * Save the verdict and finish the job in one transaction, but only if the
     * caller's fencing token is still current. Phase 3 adds the outbox row here.
     */
    public Outcome complete(Claim c, VerdictRecord v) {
        Outcome outcome = tx.execute(status -> {
            int updated = jdbc.update("""
                    UPDATE scan_job
                    SET status = 'DONE', lease_owner = NULL, lease_expires_at = NULL,
                        finished_at = now(), last_error = NULL
                    WHERE id = ? AND attempts = ? AND status = 'RUNNING'
                    """, c.jobId(), c.token());
            if (updated == 0) {
                return Outcome.FENCED;
            }
            jdbc.update(con -> {
                var ps = con.prepareStatement("""
                        INSERT INTO scan_verdict
                            (job_id, sha256, verdict, hash_match, yara_matches, worker_id, claim_token, scan_millis)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """);
                Array rules = con.createArrayOf("text", v.yaraMatches().toArray());
                ps.setObject(1, c.jobId());
                ps.setString(2, v.sha256());
                ps.setString(3, v.malicious() ? "MALICIOUS" : "CLEAN");
                ps.setString(4, v.hashMatch());
                ps.setArray(5, rules);
                ps.setString(6, c.workerId());
                ps.setInt(7, c.token());
                ps.setLong(8, v.scanMillis());
                return ps;
            });
            return Outcome.COMMITTED;
        });
        if (outcome == Outcome.FENCED) {
            events.record(QueueEvents.Kind.FENCED_WRITE, c, "verdict write rejected: token no longer current");
        }
        return outcome;
    }

    /**
     * Record a failed attempt. Re-queues with linear backoff, or dead-letters when
     * attempts (= claims so far) has reached max_attempts. Fenced like every other write.
     */
    public Outcome fail(Claim c, String error, long backoffMillis) {
        List<String> newStatus = jdbc.queryForList("""
                UPDATE scan_job
                SET status           = CASE WHEN attempts >= max_attempts THEN 'DEAD' ELSE 'QUEUED' END,
                    lease_owner      = NULL,
                    lease_expires_at = NULL,
                    last_error       = ?,
                    available_at     = now() + attempts * ? * interval '1 millisecond',
                    finished_at      = CASE WHEN attempts >= max_attempts THEN now() END
                WHERE id = ? AND attempts = ? AND status = 'RUNNING'
                RETURNING status
                """, String.class, truncate(error), backoffMillis, c.jobId(), c.token());
        if (newStatus.isEmpty()) {
            events.record(QueueEvents.Kind.FENCED_WRITE, c, "failure write rejected: token no longer current");
            return Outcome.FENCED;
        }
        boolean dead = "DEAD".equals(newStatus.get(0));
        events.record(dead ? QueueEvents.Kind.DEAD_LETTERED : QueueEvents.Kind.RETRY, c, truncate(error));
        return Outcome.COMMITTED;
    }

    /**
     * Return RUNNING jobs whose lease has expired (by the DB clock) to the queue,
     * or to DEAD if that was their last attempt. The event rows are inserted in the
     * same statement, so the metric can never disagree with the state change.
     *
     * @return number of expired leases reclaimed
     */
    public int reapExpiredLeases(int batchSize) {
        List<String> kinds = jdbc.queryForList("""
                WITH expired AS (
                    SELECT id, lease_owner FROM scan_job
                    WHERE status = 'RUNNING' AND lease_expires_at < now()
                    ORDER BY lease_expires_at
                    LIMIT ?
                    FOR UPDATE SKIP LOCKED
                ), upd AS (
                    UPDATE scan_job j
                    SET status           = CASE WHEN j.attempts >= j.max_attempts THEN 'DEAD' ELSE 'QUEUED' END,
                        lease_owner      = NULL,
                        lease_expires_at = NULL,
                        last_error       = 'lease expired (owner ' || expired.lease_owner || ')',
                        available_at     = now(),
                        finished_at      = CASE WHEN j.attempts >= j.max_attempts THEN now() END
                    FROM expired
                    WHERE j.id = expired.id
                    RETURNING j.id, j.attempts, j.status, expired.lease_owner
                )
                INSERT INTO queue_event (kind, job_id, claim_token, worker_id, detail)
                SELECT 'LEASE_EXPIRED', id, attempts, lease_owner, 'returned as ' || status FROM upd
                UNION ALL
                SELECT 'DEAD_LETTERED', id, attempts, lease_owner, 'lease expired on final attempt'
                FROM upd WHERE status = 'DEAD'
                RETURNING kind
                """, String.class, batchSize);
        int expired = (int) kinds.stream().filter("LEASE_EXPIRED"::equals).count();
        events.countReaped(expired, kinds.size() - expired);
        return expired;
    }

    private static String truncate(String s) {
        return s == null || s.length() <= 1000 ? s : s.substring(0, 1000);
    }
}
