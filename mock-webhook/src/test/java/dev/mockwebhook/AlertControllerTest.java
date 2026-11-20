package dev.mockwebhook;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AlertControllerTest {

    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired TestRestTemplate http;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE received_alert, delivery_log");
    }

    @Test
    void firstDeliveryAcceptedThenDuplicateRejectedButStillSuccess() {
        assertThat(post("alert:1").value()).isEqualTo(201);
        assertThat(post("alert:1").value()).isEqualTo(200);
        assertThat(post("alert:1").value()).isEqualTo(200);

        assertThat(jdbc.queryForObject("SELECT delivery_count FROM received_alert WHERE idempotency_key = 'alert:1'", Integer.class))
                .isEqualTo(3);
        assertThat(jdbc.queryForList("SELECT outcome FROM delivery_log ORDER BY id", String.class))
                .containsExactly("ACCEPTED", "DUPLICATE_REJECTED", "DUPLICATE_REJECTED");
    }

    @Test
    void concurrentDeliveriesOfOneKeyAcceptExactlyOnce() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(10);
        List<Future<Integer>> results = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            results.add(pool.submit(() -> post("alert:race").value()));
        }
        int created = 0, ok = 0;
        for (Future<Integer> f : results) {
            int code = f.get();
            if (code == 201) created++;
            if (code == 200) ok++;
        }
        pool.shutdown();
        assertThat(created).isEqualTo(1);
        assertThat(ok).isEqualTo(29);
    }

    @Test
    void missingKeyIsRejected() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        assertThat(http.postForEntity("/alerts", new HttpEntity<>("{}", h), String.class).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    private org.springframework.http.HttpStatusCode post(String key) {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        h.set("Idempotency-Key", key);
        return http.postForEntity("/alerts", new HttpEntity<>("{\"k\":\"" + key + "\"}", h), String.class).getStatusCode();
    }
}
