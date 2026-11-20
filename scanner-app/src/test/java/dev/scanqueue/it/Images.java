package dev.scanqueue.it;

import org.testcontainers.images.builder.ImageFromDockerfile;

import java.nio.file.Path;

/**
 * Images built from this repo's Dockerfiles and the jars `mvn package` just produced.
 * Each instance builds once (lazily) and is reused by every container that uses it.
 */
public final class Images {

    public static final ImageFromDockerfile SCANNER = new ImageFromDockerfile("scan-queue/app-it", false)
            .withFileFromPath("Dockerfile", Path.of("Dockerfile"))
            .withFileFromPath("target/scanner-app.jar", Path.of("target/scanner-app.jar"));

    public static final ImageFromDockerfile WEBHOOK = new ImageFromDockerfile("scan-queue/webhook-it", false)
            .withFileFromPath("Dockerfile", Path.of("../mock-webhook/Dockerfile"))
            .withFileFromPath("target/mock-webhook.jar", Path.of("../mock-webhook/target/mock-webhook.jar"));

    private Images() {
    }
}
