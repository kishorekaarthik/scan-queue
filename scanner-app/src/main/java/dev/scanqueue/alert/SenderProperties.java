package dev.scanqueue.alert;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param webhookUrl        alert receiver endpoint
 * @param concurrency       delivery loops per sender process
 * @param pollMillis        sleep when nothing is ready to send
 * @param leaseMillis       alert lease per claim; must exceed httpTimeoutMillis
 * @param reaperMillis      how often this process looks for expired alert leases
 * @param backoffBaseMillis first retry delay; doubles per failed attempt
 * @param backoffMaxMillis  retry delay cap
 * @param httpTimeoutMillis connect + read timeout per delivery
 */
@ConfigurationProperties(prefix = "scanqueue.sender")
public record SenderProperties(
        String webhookUrl,
        int concurrency,
        long pollMillis,
        long leaseMillis,
        long reaperMillis,
        long backoffBaseMillis,
        long backoffMaxMillis,
        long httpTimeoutMillis) {

    public SenderProperties {
        if (leaseMillis <= httpTimeoutMillis) {
            // Otherwise a slow-but-alive send could lose its lease mid-request and be
            // re-sent in parallel. Still safe (webhook dedup), just wasteful.
            throw new IllegalArgumentException("leaseMillis must be > httpTimeoutMillis");
        }
    }
}
