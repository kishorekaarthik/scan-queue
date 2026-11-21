package dev.mockwebhook;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@RestController
public class AlertController {

    private static final Logger log = LoggerFactory.getLogger(AlertController.class);

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final Counter accepted;
    private final Counter duplicates;
    private final long responseDelayMillis;
    private final double failAfterCommitRate;
    private final boolean dedup;

    public AlertController(JdbcTemplate jdbc, TransactionTemplate tx, MeterRegistry registry,
                           @Value("${webhook.response-delay-millis:0}") long responseDelayMillis,
                           @Value("${webhook.fail-after-commit-rate:0}") double failAfterCommitRate,
                           @Value("${webhook.dedup:true}") boolean dedup) {
        this.dedup = dedup;
        this.jdbc = jdbc;
        this.tx = tx;
        this.accepted = Counter.builder("webhook.deliveries").tag("outcome", "ACCEPTED").register(registry);
        this.duplicates = Counter.builder("webhook.deliveries").tag("outcome", "DUPLICATE_REJECTED").register(registry);
        this.responseDelayMillis = responseDelayMillis;
        this.failAfterCommitRate = failAfterCommitRate;
    }

    /**
     * 201 = first delivery of this key (the alert is acted on).
     * 200 = duplicate; already have it, nothing done. Both are success to the sender,
     *       so a sender that lost our earlier response stops retrying.
     */
    @PostMapping(path = "/alerts", consumes = "application/json")
    public ResponseEntity<Map<String, String>> receive(
            @RequestHeader(name = "Idempotency-Key", required = false) String key,
            @RequestBody String payload) throws InterruptedException {
        if (key == null || key.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Idempotency-Key header required"));
        }
        boolean first = Boolean.TRUE.equals(tx.execute(s -> {
            boolean inserted = jdbc.update("""
                    INSERT INTO received_alert (idempotency_key, payload) VALUES (?, ?::jsonb)
                    ON CONFLICT (idempotency_key) DO NOTHING
                    """, key, payload) == 1;
            if (!inserted) {
                jdbc.update("""
                        UPDATE received_alert SET delivery_count = delivery_count + 1, last_received_at = now()
                        WHERE idempotency_key = ?
                        """, key);
            }
            // Ablation (webhook.dedup=false): a receiver without dedup acts on every copy.
            boolean accepted = inserted || !dedup;
            jdbc.update("INSERT INTO delivery_log (idempotency_key, outcome) VALUES (?, ?)",
                    key, accepted ? "ACCEPTED" : "DUPLICATE_REJECTED");
            return accepted;
        }));
        (first ? accepted : duplicates).increment();
        log.info("{} {}", first ? "ACCEPTED" : "DUPLICATE_REJECTED", key);

        // Fault-injection knobs (default off), used by tests and the chaos run:
        // the alert is already committed, but the sender does not learn that.
        if (responseDelayMillis > 0) {
            Thread.sleep(responseDelayMillis);
        }
        if (failAfterCommitRate > 0 && ThreadLocalRandom.current().nextDouble() < failAfterCommitRate) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", "injected failure"));
        }
        return first
                ? ResponseEntity.status(HttpStatus.CREATED).body(Map.of("status", "accepted"))
                : ResponseEntity.ok(Map.of("status", "duplicate_rejected"));
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        return jdbc.queryForMap("""
                SELECT (SELECT count(*) FROM delivery_log WHERE outcome = 'ACCEPTED')           AS accepted,
                       (SELECT count(*) FROM delivery_log WHERE outcome = 'DUPLICATE_REJECTED') AS duplicates_rejected,
                       (SELECT count(*) FROM received_alert)                                    AS distinct_keys
                """);
    }
}
