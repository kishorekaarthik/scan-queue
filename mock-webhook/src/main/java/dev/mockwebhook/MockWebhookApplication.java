package dev.mockwebhook;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Stand-in for a real alert receiver (Slack, PagerDuty, SIEM...) that honours Idempotency-Key. */
@SpringBootApplication
public class MockWebhookApplication {
    public static void main(String[] args) {
        SpringApplication.run(MockWebhookApplication.class, args);
    }
}
