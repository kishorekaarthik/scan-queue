package dev.scanqueue;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * One codebase, several roles. The role is picked with a Spring profile:
 * <ul>
 *   <li>{@code api}    - upload endpoint, creates jobs</li>
 *   <li>{@code worker} - claims and scans jobs (phase 2)</li>
 *   <li>{@code sender} - delivers outbox entries to the webhook (phase 3)</li>
 * </ul>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class ScanQueueApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScanQueueApplication.class, args);
    }
}
