package dev.scanqueue.dashboard;

import dev.scanqueue.alert.SenderProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Live numbers for the dashboard page (static/index.html, served at /). Reads
 * the scanqueue database and proxies the webhook's /stats, so the browser
 * talks to one origin.
 */
@RestController
@Profile("api")
public class DashboardController {

    private final JdbcTemplate jdbc;
    private final RestClient http;
    private final String webhookStatsUrl;

    public DashboardController(JdbcTemplate jdbc, SenderProperties sender) {
        this.jdbc = jdbc;
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(500)).build();
        JdkClientHttpRequestFactory f = new JdkClientHttpRequestFactory(client);
        f.setReadTimeout(Duration.ofMillis(800));
        this.http = RestClient.builder().requestFactory(f).build();
        this.webhookStatsUrl = sender.webhookUrl().replaceAll("/alerts$", "/stats");
    }

    @GetMapping("/dashboard/stats")
    public Map<String, Object> stats() {
        Map<String, Object> s = new LinkedHashMap<>();
        Map<String, Object> jobs = new LinkedHashMap<>();
        for (String st : List.of("QUEUED", "RUNNING", "DONE", "DEAD")) {
            jobs.put(st, 0L);
        }
        jdbc.query("SELECT status, count(*) AS n FROM scan_job GROUP BY status",
                rs -> { jobs.put(rs.getString("status"), rs.getLong("n")); });
        s.put("jobs", jobs);
        s.putAll(jdbc.queryForMap("""
                SELECT
                  (SELECT count(*) FROM process_presence WHERE role = 'worker' AND last_seen > now() - interval '3 seconds') AS workers_alive,
                  (SELECT count(*) FROM process_presence WHERE role = 'sender' AND last_seen > now() - interval '3 seconds') AS senders_alive,
                  (SELECT count(*) FROM scan_verdict WHERE verdict = 'MALICIOUS')                AS malicious,
                  (SELECT count(*) FROM alert_outbox WHERE status IN ('PENDING', 'SENDING'))       AS alerts_pending,
                  (SELECT count(*) FROM alert_outbox WHERE status = 'DELIVERED')                   AS alerts_delivered,
                  (SELECT count(*) FROM queue_event WHERE kind = 'FENCED_WRITE')                   AS fenced_writes,
                  (SELECT count(*) FROM queue_event WHERE kind = 'LEASE_EXPIRED')                  AS lease_expiries,
                  (SELECT count(*) FROM queue_event WHERE kind = 'ALERT_LEASE_EXPIRED')            AS alert_lease_expiries,
                  (SELECT count(*) FROM scan_job WHERE finished_at > now() - interval '5 seconds') / 5.0 AS jobs_per_sec
                """));
        s.put("recent_events", jdbc.queryForList("""
                SELECT kind, left(coalesce(worker_id, ''), 24) AS who, (extract(epoch FROM at) * 1000)::bigint AS at_ms
                FROM queue_event
                WHERE kind IN ('FENCED_WRITE', 'LEASE_EXPIRED', 'ALERT_LEASE_EXPIRED', 'LEASE_LOST', 'DEAD_LETTERED', 'ALERT_DEAD')
                ORDER BY id DESC LIMIT 8
                """));
        try {
            s.put("webhook", http.get().uri(webhookStatsUrl).retrieve().body(Map.class));
        } catch (Exception e) {
            s.put("webhook", null);   // webhook down (e.g. being restarted by the chaos demo)
        }
        return s;
    }
}
