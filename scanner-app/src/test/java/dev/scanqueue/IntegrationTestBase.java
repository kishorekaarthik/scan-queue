package dev.scanqueue;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MinIOContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Real Postgres and MinIO in containers, shared by every test class in the JVM
 * (singleton pattern: started once, stopped by Testcontainers' Ryuk at exit).
 */
public abstract class IntegrationTestBase {

    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    static final MinIOContainer MINIO = new MinIOContainer(
            DockerImageName.parse("chainguard/minio@sha256:e9cf6b99c226e9539ed0f14b6f00e37b07da153c7ba1f4f8709c807574b471ec")
                    .asCompatibleSubstituteFor("minio/minio"));

    static {
        POSTGRES.start();
        MINIO.start();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
        r.add("scanqueue.storage.endpoint", MINIO::getS3URL);
        r.add("scanqueue.storage.access-key", MINIO::getUserName);
        r.add("scanqueue.storage.secret-key", MINIO::getPassword);
    }
}
