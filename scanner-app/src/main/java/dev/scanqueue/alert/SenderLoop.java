package dev.scanqueue.alert;

import dev.scanqueue.Ablation;
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

/** Sender role: N delivery loops over the outbox. */
@Component
@Profile("sender")
public class SenderLoop {

    private static final Logger log = LoggerFactory.getLogger(SenderLoop.class);

    private final OutboxSender sender;
    private final SenderProperties props;
    private final Ablation ablation;
    private final List<Thread> threads = new ArrayList<>();
    private volatile boolean running = true;

    public SenderLoop(OutboxSender sender, SenderProperties props, Ablation ablation) {
        this.sender = sender;
        this.props = props;
        this.ablation = ablation;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void start() throws Exception {
        String base = "sender-" + InetAddress.getLocalHost().getHostName();
        for (int i = 0; i < props.concurrency(); i++) {
            String id = base + "-" + i;
            threads.add(Thread.ofPlatform().name("send-" + i).start(() -> loop(id)));
        }
        if (ablation.reaper()) {
            threads.add(Thread.ofPlatform().name("alert-reaper").start(this::reaperLoop));
        }
        log.info("sender started: id={} concurrency={} lease={}ms webhook={}",
                base, props.concurrency(), props.leaseMillis(), props.webhookUrl());
    }

    private void reaperLoop() {
        while (running) {
            try {
                while (sender.reapExpiredLeases(100) == 100) {
                    // keep draining while full batches come back
                }
                Thread.sleep(props.reaperMillis());
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                log.warn("alert reaper error: {}", e.toString());
                try {
                    Thread.sleep(props.reaperMillis());
                } catch (InterruptedException ie) {
                    return;
                }
            }
        }
    }

    private void loop(String senderId) {
        while (running) {
            try {
                if (!sender.deliverOne(senderId)) {
                    Thread.sleep(props.pollMillis());
                }
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                log.warn("sender loop error: {}", e.toString());
                try {
                    Thread.sleep(props.pollMillis() * 5);
                } catch (InterruptedException ie) {
                    return;
                }
            }
        }
    }

    @PreDestroy
    public void stop() throws InterruptedException {
        running = false;
        for (Thread t : threads) {
            t.join(15_000);
        }
    }
}
