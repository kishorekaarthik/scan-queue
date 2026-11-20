package dev.scanqueue.job;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Repository
public class JobRepository {

    static final RowMapper<ScanJob> MAPPER = (rs, i) -> new ScanJob(
            rs.getObject("id", UUID.class),
            rs.getString("object_key"),
            rs.getString("original_filename"),
            rs.getLong("size_bytes"),
            JobStatus.valueOf(rs.getString("status")),
            rs.getInt("attempts"),
            rs.getInt("max_attempts"),
            rs.getString("lease_owner"),
            rs.getObject("lease_expires_at", OffsetDateTime.class),
            rs.getString("last_error"),
            rs.getObject("created_at", OffsetDateTime.class),
            rs.getObject("started_at", OffsetDateTime.class),
            rs.getObject("finished_at", OffsetDateTime.class));

    private final JdbcTemplate jdbc;

    public JobRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insertQueued(UUID id, String objectKey, String originalFilename, long sizeBytes, int maxAttempts) {
        jdbc.update("""
                INSERT INTO scan_job (id, object_key, original_filename, size_bytes, status, max_attempts)
                VALUES (?, ?, ?, ?, 'QUEUED', ?)
                """, id, objectKey, originalFilename, sizeBytes, maxAttempts);
    }

    public Optional<ScanJob> find(UUID id) {
        return jdbc.query("SELECT * FROM scan_job WHERE id = ?", MAPPER, id).stream().findFirst();
    }

    public Map<JobStatus, Long> countByStatus() {
        Map<JobStatus, Long> counts = new EnumMap<>(JobStatus.class);
        for (JobStatus s : JobStatus.values()) {
            counts.put(s, 0L);
        }
        jdbc.query("SELECT status, count(*) AS n FROM scan_job GROUP BY status",
                rs -> {
                    counts.put(JobStatus.valueOf(rs.getString("status")), rs.getLong("n"));
                });
        return counts;
    }
}
