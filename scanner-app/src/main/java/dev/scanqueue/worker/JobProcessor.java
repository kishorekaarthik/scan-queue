package dev.scanqueue.worker;

import dev.scanqueue.job.Claim;
import dev.scanqueue.job.JobQueue;
import dev.scanqueue.job.QueueEvents;
import dev.scanqueue.job.VerdictRecord;
import dev.scanqueue.scan.ScanEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Processes one job end to end: claim -> heartbeat while scanning -> fenced write.
 *
 * <p>The heartbeat only decides <i>when</i> to renew; whether the lease is still
 * valid is decided by the database. If a renewal matches 0 rows the lease is gone,
 * the scan is cancelled, and the eventual write is rejected by the fencing token.
 */
@Component
public class JobProcessor implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(JobProcessor.class);

    private final JobQueue queue;
    private final ScanEngine engine;
    private final QueueEvents events;
    private final WorkerProperties props;
    private final ScheduledExecutorService heartbeats;

    public JobProcessor(JobQueue queue, ScanEngine engine, QueueEvents events, WorkerProperties props) {
        this.queue = queue;
        this.engine = engine;
        this.events = events;
        this.props = props;
        this.heartbeats = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "heartbeat");
            t.setDaemon(true);
            return t;
        });
    }

    /** @return true if a job was claimed (whatever the outcome), false if the queue was empty */
    public boolean processOne(String workerId) {
        Optional<Claim> maybe = queue.claim(workerId, props.leaseMillis());
        if (maybe.isEmpty()) {
            return false;
        }
        Claim claim = maybe.get();
        AtomicBoolean leaseLost = new AtomicBoolean(false);
        ScheduledFuture<?> heartbeat = heartbeats.scheduleAtFixedRate(
                () -> renew(claim, leaseLost), props.heartbeatMillis(), props.heartbeatMillis(), TimeUnit.MILLISECONDS);
        try {
            VerdictRecord verdict = engine.scan(claim.objectKey(), leaseLost::get);
            heartbeat.cancel(false);
            // Always attempt the write, even if a heartbeat saw the lease go:
            // the database, not this process, decides whether we still own the job.
            JobQueue.Outcome outcome = queue.complete(claim, verdict);
            if (outcome == JobQueue.Outcome.COMMITTED) {
                log.debug("job {} token {} -> {}", claim.jobId(), claim.token(), verdict.malicious() ? "MALICIOUS" : "CLEAN");
            }
        } catch (Exception e) {
            heartbeat.cancel(false);
            log.warn("job {} token {} failed: {}", claim.jobId(), claim.token(), e.toString());
            queue.fail(claim, e.toString(), props.retryBackoffMillis());
        }
        return true;
    }

    private void renew(Claim claim, AtomicBoolean leaseLost) {
        if (leaseLost.get()) {
            return;
        }
        try {
            if (!queue.renew(claim, props.leaseMillis())) {
                leaseLost.set(true);
                events.record(QueueEvents.Kind.LEASE_LOST, claim, "heartbeat matched 0 rows; cancelling scan");
            }
        } catch (Exception e) {
            // Transient DB error: keep trying on the next tick. If the DB stays
            // unreachable the lease expires and the job is re-queued, which is safe.
            log.warn("heartbeat for job {} failed: {}", claim.jobId(), e.toString());
        }
    }

    @Override
    public void close() {
        heartbeats.shutdownNow();
    }
}
