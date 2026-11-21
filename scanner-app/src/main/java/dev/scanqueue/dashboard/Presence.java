package dev.scanqueue.dashboard;

import jakarta.annotation.PreDestroy;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.Arrays;

/** Worker / sender processes check in once a second so the dashboard can show who is alive. */
@Component
@Profile({"worker", "sender"})
public class Presence {

    private final JdbcTemplate jdbc;
    private final String role;
    private volatile boolean running = true;
    private Thread thread;

    public Presence(JdbcTemplate jdbc, Environment env) {
        this.jdbc = jdbc;
        this.role = Arrays.asList(env.getActiveProfiles()).contains("worker") ? "worker" : "sender";
    }

    @EventListener(ApplicationReadyEvent.class)
    public void start() throws Exception {
        String id = InetAddress.getLocalHost().getHostName() + "-" + ProcessHandle.current().pid();
        thread = Thread.ofPlatform().daemon().name("presence").start(() -> {
            while (running) {
                try {
                    jdbc.update("""
                            INSERT INTO process_presence (process_id, role, last_seen) VALUES (?, ?, now())
                            ON CONFLICT (process_id) DO UPDATE SET last_seen = now(), role = EXCLUDED.role
                            """, id, role);
                    Thread.sleep(1_000);
                } catch (InterruptedException e) {
                    return;
                } catch (Exception e) {
                    // dashboard only; try again next second
                }
            }
        });
    }

    @PreDestroy
    public void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
        }
    }
}
