package dev.scanqueue.api;

import dev.scanqueue.IntegrationTestBase;
import dev.scanqueue.job.JobRepository;
import dev.scanqueue.job.JobStatus;
import dev.scanqueue.job.ScanJob;
import dev.scanqueue.storage.ObjectStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("api")
class UploadApiTest extends IntegrationTestBase {

    @Autowired TestRestTemplate http;
    @Autowired JobRepository jobs;
    @Autowired ObjectStore store;

    @Test
    void uploadStoresObjectAndQueuesJob() throws Exception {
        byte[] content = "hello, scan-queue".getBytes(StandardCharsets.UTF_8);

        ResponseEntity<UploadController.UploadResponse> res = upload("hello.txt", content);

        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        UUID id = res.getBody().jobId();
        assertThat(res.getHeaders().getLocation()).hasToString("/jobs/" + id);

        ScanJob job = jobs.find(id).orElseThrow();
        assertThat(job.status()).isEqualTo(JobStatus.QUEUED);
        assertThat(job.attempts()).isZero();
        assertThat(job.maxAttempts()).isEqualTo(5);
        assertThat(job.leaseOwner()).isNull();
        assertThat(job.leaseExpiresAt()).isNull();
        assertThat(job.sizeBytes()).isEqualTo(content.length);
        assertThat(job.originalFilename()).isEqualTo("hello.txt");

        try (InputStream in = store.get(job.objectKey())) {
            assertThat(in.readAllBytes()).isEqualTo(content);
        }
    }

    @Test
    void getJobReturnsRowAnd404ForUnknown() {
        UUID id = upload("a.bin", new byte[]{1, 2, 3}).getBody().jobId();

        ResponseEntity<Map> found = http.getForEntity("/jobs/" + id, Map.class);
        assertThat(found.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(found.getBody()).containsEntry("status", "QUEUED");

        assertThat(http.getForEntity("/jobs/" + UUID.randomUUID(), Map.class).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void emptyFileIsRejected() {
        assertThat(upload("empty.txt", new byte[0], String.class).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    private ResponseEntity<UploadController.UploadResponse> upload(String name, byte[] bytes) {
        return upload(name, bytes, UploadController.UploadResponse.class);
    }

    private <T> ResponseEntity<T> upload(String name, byte[] bytes, Class<T> type) {
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new ByteArrayResource(bytes) {
            @Override
            public String getFilename() {
                return name;
            }
        });
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        return http.postForEntity("/files", new HttpEntity<>(body, headers), type);
    }
}
