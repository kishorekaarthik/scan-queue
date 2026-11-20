package dev.scanqueue.worker;

import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MinIOContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import dev.scanqueue.it.Images;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the real worker image (built from scanner-app/Dockerfile, with the yara
 * package installed) against real Postgres and MinIO, and checks the verdicts
 * YARA and the hash list produce inside the container.
 */
class WorkerContainerIT {

    /**
     * The EICAR anti-malware TEST string (harmless by design), assembled at runtime
     * from two halves so no source or class file contains it whole (String.join is
     * not a compile-time constant, unlike "a" + "b"). It goes from memory straight
     * to MinIO; it is never written to the host's disk.
     */
    static final byte[] EICAR = String.join("", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-",
            "ANTIVIRUS-TEST-FILE!$H+H*").getBytes(StandardCharsets.US_ASCII);

    static final Network NET = Network.newNetwork();

    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine")
            .withNetwork(NET).withNetworkAliases("postgres");

    static final MinIOContainer MINIO = new MinIOContainer(
            DockerImageName.parse("chainguard/minio@sha256:e9cf6b99c226e9539ed0f14b6f00e37b07da153c7ba1f4f8709c807574b471ec")
                    .asCompatibleSubstituteFor("minio/minio"))
            .withNetwork(NET).withNetworkAliases("minio");

    static GenericContainer<?> worker;

    @BeforeAll
    static void start() {
        POSTGRES.start();
        MINIO.start();
        worker = new GenericContainer<>(Images.SCANNER)
                .withNetwork(NET)
                .withEnv(Map.of(
                        "SPRING_PROFILES_ACTIVE", "worker",
                        "DB_URL", "jdbc:postgresql://postgres:5432/" + POSTGRES.getDatabaseName(),
                        "DB_USER", POSTGRES.getUsername(),
                        "DB_PASSWORD", POSTGRES.getPassword(),
                        "MINIO_ENDPOINT", "http://minio:9000",
                        "MINIO_ACCESS_KEY", MINIO.getUserName(),
                        "MINIO_SECRET_KEY", MINIO.getPassword()))
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("worker")))
                .waitingFor(Wait.forLogMessage(".*worker started.*", 1).withStartupTimeout(Duration.ofMinutes(3)));
        worker.start();
    }

    @AfterAll
    static void stop() {
        if (worker != null) {
            worker.stop();
        }
        MINIO.stop();
        POSTGRES.stop();
        NET.close();
    }

    @Test
    void yaraIsInstalledInTheWorkerImage() throws Exception {
        Container.ExecResult r = worker.execInContainer("yara", "--version");
        assertThat(r.getExitCode()).isZero();
        assertThat(r.getStdout()).matches("(?s)\\d+\\.\\d+.*");
    }

    @Test
    void eicarIsFlaggedAndHarmlessFilesAreNot() throws Exception {
        UUID eicar = enqueue("eicar.com.txt", EICAR);
        UUID harmless = enqueue("hello.txt", "hello, scan-queue\n".getBytes(StandardCharsets.UTF_8));
        // Mentions EICAR but is not the test file: YARA's "at 0" condition must not fire.
        UUID lookalike = enqueue("notes.txt", "this file talks about EICAR but is not it\n".getBytes(StandardCharsets.UTF_8));
        UUID sampleA = enqueue("sample-a.txt", "scan-queue harmless test sample A".getBytes(StandardCharsets.UTF_8));

        Map<UUID, Verdict> v = awaitVerdicts(List.of(eicar, harmless, lookalike, sampleA), Duration.ofSeconds(60));

        assertThat(v.get(eicar).verdict()).isEqualTo("MALICIOUS");
        assertThat(v.get(eicar).yaraMatches()).containsExactly("EICAR_Test_File");
        assertThat(v.get(eicar).hashMatch()).isEqualTo("EICAR test file");
        assertThat(v.get(eicar).sha256()).isEqualTo("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

        assertThat(v.get(harmless).verdict()).isEqualTo("CLEAN");
        assertThat(v.get(harmless).yaraMatches()).isEmpty();
        assertThat(v.get(harmless).hashMatch()).isNull();

        assertThat(v.get(lookalike).verdict()).isEqualTo("CLEAN");
        assertThat(v.get(lookalike).yaraMatches()).isEmpty();

        // Hash-list-only hit: YARA has no rule for it, the hash list does.
        assertThat(v.get(sampleA).verdict()).isEqualTo("MALICIOUS");
        assertThat(v.get(sampleA).yaraMatches()).isEmpty();
        assertThat(v.get(sampleA).hashMatch()).isEqualTo("test sample A (harmless)");
    }

    // ---- helpers ----

    record Verdict(String verdict, String sha256, String hashMatch, List<String> yaraMatches) {
    }

    private static UUID enqueue(String name, byte[] bytes) throws Exception {
        UUID id = UUID.randomUUID();
        String key = "uploads/" + id;
        MinioClient minio = MinioClient.builder().endpoint(MINIO.getS3URL())
                .credentials(MINIO.getUserName(), MINIO.getPassword()).build();
        minio.putObject(PutObjectArgs.builder().bucket("uploads").object(key)
                .stream(new ByteArrayInputStream(bytes), bytes.length, -1).build());
        try (Connection c = db();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO scan_job (id, object_key, original_filename, size_bytes) VALUES (?, ?, ?, ?)")) {
            ps.setObject(1, id);
            ps.setString(2, key);
            ps.setString(3, name);
            ps.setLong(4, bytes.length);
            ps.executeUpdate();
        }
        return id;
    }

    private static Map<UUID, Verdict> awaitVerdicts(List<UUID> ids, Duration timeout) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        Map<UUID, Verdict> found = new HashMap<>();
        while (found.size() < ids.size() && System.nanoTime() < deadline) {
            try (Connection c = db();
                 PreparedStatement ps = c.prepareStatement(
                         "SELECT job_id, verdict, sha256, hash_match, yara_matches FROM scan_verdict WHERE job_id = ANY (?)")) {
                ps.setArray(1, c.createArrayOf("uuid", ids.toArray()));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        found.put(rs.getObject(1, UUID.class), new Verdict(rs.getString(2), rs.getString(3),
                                rs.getString(4), Arrays.asList((String[]) rs.getArray(5).getArray())));
                    }
                }
            }
            Thread.sleep(250);
        }
        assertThat(found.keySet()).containsExactlyInAnyOrderElementsOf(ids);
        return found;
    }

    private static Connection db() throws Exception {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }
}
