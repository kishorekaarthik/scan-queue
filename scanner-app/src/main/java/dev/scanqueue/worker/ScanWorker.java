package dev.scanqueue.worker;

import dev.scanqueue.job.JobQueue;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/** Worker role: N claim loops plus one lease reaper loop. */
@Component
@Profile("worker")
public class ScanWorker {

    private static final Logger log = LoggerFactory.getLogger(ScanWorker.class);

    private final JobProcessor processor;
    private final JobQueue queue;
    private final WorkerProperties props;
    private final List<Thread> threads = new ArrayList<>();
    private volatile boolean running = true;

    public ScanWorker(JobProcessor processor, JobQueue queue, WorkerProperties props) {
        this.processor = processor;
        this.queue = queue;
        this.props = props;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void start() throws Exception {
        String base = InetAddress.getLocalHost().getHostName() + "-" + ProcessHandle.current().pid();
        for (int i = 0; i < props.concurrency(); i++) {
            String id = base + "-" + i;
            threads.add(Thread.ofPlatform().name("claim-" + i).start(() -> claimLoop(id)));
        }
        threads.add(Thread.ofPlatform().name("reaper").start(this::reaperLoop));
        log.info("worker started: id={} concurrency={} lease={}ms heartbeat={}ms",
                base, props.concurrency(), props.leaseMillis(), props.heartbeatMillis());
    }

    private void claimLoop(String workerId) {
        while (running) {
            try {
                if (!processor.processOne(workerId)) {
                    Thread.sleep(props.pollMillis());
                }
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                // DB/MinIO hiccup outside a claimed job: back off and retry.
                log.warn("claim loop error: {}", e.toString());
                sleepQuietly(props.pollMillis() * 4);
            }
        }
    }

    private void reaperLoop() {
        while (running) {
            try {
                while (queue.reapExpiredLeases(100) == 100) {
                    // keep draining while full batches come back
                }
                Thread.sleep(props.reaperMillis());
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                log.warn("reaper error: {}", e.toString());
                sleepQuietly(props.reaperMillis());
            }
        }
    }

    /** Graceful stop (SIGTERM). Unfinished jobs simply keep their lease until it expires. */
    @PreDestroy
    public void stop() throws InterruptedException {
        running = false;
        for (Thread t : threads) {
            t.join(10_000);
        }
    }

    private void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
