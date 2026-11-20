package dev.scanqueue.alert;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param webhookUrl        alert receiver endpoint
 * @param concurrency       delivery loops per sender process
 * @param pollMillis        sleep when nothing is ready to send
 * @param backoffBaseMillis first retry delay; doubles per failed attempt
 * @param backoffMaxMillis  retry delay cap
 * @param httpTimeoutMillis connect + read timeout per delivery
 */
@ConfigurationProperties(prefix = "scanqueue.sender")
public record SenderProperties(
        String webhookUrl,
        int concurrency,
        long pollMillis,
        long backoffBaseMillis,
        long backoffMaxMillis,
        long httpTimeoutMillis) {
}
