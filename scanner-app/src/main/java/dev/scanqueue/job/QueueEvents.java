package dev.scanqueue.job;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.Map;

/**
 * Queue metrics, kept two ways:
 * <ul>
 *   <li>durably, as queue_event rows (survive SIGKILL; the chaos report counts these)</li>
 *   <li>in memory, as Micrometer counters {@code scanqueue.events{kind=...}} for live monitoring</li>
 * </ul>
 */
@Component
public class QueueEvents {

    private static final Logger log = LoggerFactory.getLogger(QueueEvents.class);

    public enum Kind { LEASE_EXPIRED, FENCED_WRITE, LEASE_LOST, RETRY, DEAD_LETTERED }

    private final JdbcTemplate jdbc;
    private final Map<Kind, Counter> counters = new EnumMap<>(Kind.class);

    public QueueEvents(JdbcTemplate jdbc, MeterRegistry registry) {
        this.jdbc = jdbc;
        for (Kind k : Kind.values()) {
            counters.put(k, Counter.builder("scanqueue.events").tag("kind", k.name()).register(registry));
        }
    }

    public void record(Kind kind, Claim c, String detail) {
        counters.get(kind).increment();
        if (kind == Kind.FENCED_WRITE || kind == Kind.LEASE_LOST) {
            log.warn("{} job={} token={} worker={}: {}", kind, c.jobId(), c.token(), c.workerId(), detail);
        } else {
            log.info("{} job={} token={} worker={}: {}", kind, c.jobId(), c.token(), c.workerId(), detail);
        }
        jdbc.update("INSERT INTO queue_event (kind, job_id, claim_token, worker_id, detail) VALUES (?, ?, ?, ?, ?)",
                kind.name(), c.jobId(), c.token(), c.workerId(), detail);
    }

    /** Reaper events are inserted by the reap statement itself; only bump the counters here. */
    void countReaped(int leaseExpired, int deadLettered) {
        if (leaseExpired > 0) {
            counters.get(Kind.LEASE_EXPIRED).increment(leaseExpired);
            log.info("reaped {} expired lease(s), {} dead-lettered", leaseExpired, deadLettered);
        }
        if (deadLettered > 0) {
            counters.get(Kind.DEAD_LETTERED).increment(deadLettered);
        }
    }

    public long count(Kind kind) {
        Long n = jdbc.queryForObject("SELECT count(*) FROM queue_event WHERE kind = ?", Long.class, kind.name());
        return n == null ? 0 : n;
    }
}
