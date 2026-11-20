package dev.scanqueue.worker;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param concurrency       jobs scanned in parallel per worker process
 * @param leaseMillis       lease length granted on claim and on every renewal
 * @param heartbeatMillis   renewal period; must be well under leaseMillis
 * @param pollMillis        sleep when the queue is empty
 * @param reaperMillis      how often this process looks for expired leases
 * @param retryBackoffMillis re-queue delay per attempt after a failed scan
 */
@ConfigurationProperties(prefix = "scanqueue.worker")
public record WorkerProperties(
        int concurrency,
        long leaseMillis,
        long heartbeatMillis,
        long pollMillis,
        long reaperMillis,
        long retryBackoffMillis) {

    public WorkerProperties {
        if (heartbeatMillis >= leaseMillis) {
            throw new IllegalArgumentException("heartbeatMillis must be < leaseMillis");
        }
    }
}
