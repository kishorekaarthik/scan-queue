package dev.scanqueue.job;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * A worker's hold on one job. {@code token} is the value of scan_job.attempts
 * produced by this claim: the fencing token every later write must present.
 */
public record Claim(UUID jobId, String objectKey, int token, String workerId, OffsetDateTime leaseExpiresAt) {
}
