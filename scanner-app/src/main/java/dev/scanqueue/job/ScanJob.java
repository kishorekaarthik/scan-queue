package dev.scanqueue.job;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ScanJob(
        UUID id,
        String objectKey,
        String originalFilename,
        long sizeBytes,
        JobStatus status,
        int attempts,
        int maxAttempts,
        String leaseOwner,
        OffsetDateTime leaseExpiresAt,
        String lastError,
        OffsetDateTime createdAt,
        OffsetDateTime startedAt,
        OffsetDateTime finishedAt) {
}
