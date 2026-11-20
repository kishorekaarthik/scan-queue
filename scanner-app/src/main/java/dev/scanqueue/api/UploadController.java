package dev.scanqueue.api;

import dev.scanqueue.job.JobRepository;
import dev.scanqueue.job.JobStatus;
import dev.scanqueue.job.ScanJob;
import dev.scanqueue.storage.ObjectStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Map;
import java.util.UUID;

@RestController
@Profile("api")
public class UploadController {

    private final ObjectStore store;
    private final JobRepository jobs;
    private final int maxAttempts;

    public UploadController(ObjectStore store, JobRepository jobs,
                            @Value("${scanqueue.jobs.max-attempts:5}") int maxAttempts) {
        this.store = store;
        this.jobs = jobs;
        this.maxAttempts = maxAttempts;
    }

    /**
     * Store the bytes first, then enqueue. The reverse order would let a worker
     * claim a job whose object does not exist yet. The cost of this order is a
     * possible orphan object if the INSERT fails; orphans are harmless (never scanned).
     */
    @PostMapping(path = "/files", consumes = "multipart/form-data")
    public ResponseEntity<UploadResponse> upload(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "file is empty");
        }
        UUID id = UUID.randomUUID();
        String key = "uploads/" + id;
        try (InputStream in = file.getInputStream()) {
            store.put(key, in, file.getSize(), file.getContentType());
        }
        jobs.insertQueued(id, key, file.getOriginalFilename(), file.getSize(), maxAttempts);
        return ResponseEntity.created(URI.create("/jobs/" + id))
                .body(new UploadResponse(id, JobStatus.QUEUED));
    }

    @GetMapping("/jobs/{id}")
    public ScanJob job(@PathVariable UUID id) {
        return jobs.find(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @GetMapping("/stats")
    public Map<JobStatus, Long> stats() {
        return jobs.countByStatus();
    }

    public record UploadResponse(UUID jobId, JobStatus status) {
    }
}
