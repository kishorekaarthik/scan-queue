package dev.scanqueue.alert;

import dev.scanqueue.job.QueueEvents;
import dev.scanqueue.job.VerdictRecord;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.UUID;

/**
 * ABLATION ONLY (scanqueue.ablation.outbox=false): the "no outbox" design, where the
 * worker POSTs the alert itself right after committing the verdict. Up to 3 tries,
 * 500 ms apart, in memory only. If the worker dies after the commit, or the webhook
 * is down for longer than the retries, the alert is lost: nothing durable records
 * that it still has to be sent.
 */
@Component
public class DirectAlerter {

    private static final int TRIES = 3;

    private final QueueEvents events;
    private final SenderProperties props;
    private final RestClient http;

    public DirectAlerter(QueueEvents events, SenderProperties props) {
        this.events = events;
        this.props = props;
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(props.httpTimeoutMillis())).build();
        JdkClientHttpRequestFactory f = new JdkClientHttpRequestFactory(client);
        f.setReadTimeout(Duration.ofMillis(props.httpTimeoutMillis()));
        this.http = RestClient.builder().requestFactory(f).build();
    }

    public void send(UUID jobId, VerdictRecord v, String workerId) {
        String payload = "{\"jobId\":\"" + jobId + "\",\"sha256\":\"" + v.sha256() + "\",\"direct\":true}";
        String last = null;
        for (int attempt = 1; attempt <= TRIES; attempt++) {
            try {
                int status = http.post().uri(props.webhookUrl())
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Idempotency-Key", "alert:" + jobId)
                        .body(payload)
                        .retrieve()
                        .onStatus(s -> true, (req, res) -> { })
                        .toBodilessEntity().getStatusCode().value();
                if (status >= 200 && status < 300) {
                    events.record(QueueEvents.Kind.ALERT_DELIVERED, jobId, attempt, workerId,
                            status == 201 ? "accepted (direct)" : "duplicate (direct, HTTP " + status + ")");
                    return;
                }
                last = "HTTP " + status;
            } catch (Exception e) {
                last = e.toString();
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        events.record(QueueEvents.Kind.ALERT_SEND_FAILED, jobId, TRIES, workerId, "direct alert dropped: " + last);
    }
}
