package dev.scanqueue;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Switches used ONLY by the Phase 5 ablation study, to remove one safety mechanism
 * at a time and measure the failure it prevents. All default to true (the real
 * design). Never turn these off outside the chaos comparison.
 *
 * @param fencing worker writes (verdict / failure) check the claim token
 * @param outbox  alerts go through the transactional outbox; false = the worker
 *                POSTs the alert itself right after committing the verdict
 * @param reaper  expired job and alert leases are returned to the queue
 */
@ConfigurationProperties(prefix = "scanqueue.ablation")
public record Ablation(
        @DefaultValue("true") boolean fencing,
        @DefaultValue("true") boolean outbox,
        @DefaultValue("true") boolean reaper) {

    public static Ablation none() {
        return new Ablation(true, true, true);
    }
}
