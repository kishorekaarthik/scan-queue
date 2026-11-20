package dev.scanqueue.chaos;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Uploads the run's files concurrently. An upload counts as accepted only when the
 * API answered 201 with a job id. Transport errors are retried; a retry after an
 * ambiguous error can create a second job for the same file (the first request may
 * have committed), which the report counts separately as a client-side duplicate.
 */
final class Uploader {

    /**
     * The EICAR anti-malware TEST string (harmless by design), assembled at runtime
     * from two halves so no source or class file contains it whole. In memory only.
     */
    static final byte[] EICAR = String.join("", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-",
            "ANTIVIRUS-TEST-FILE!$H+H*").getBytes(StandardCharsets.US_ASCII);

    private static final Pattern JOB_ID = Pattern.compile("\"jobId\"\\s*:\\s*\"([0-9a-f-]{36})\"");

    record Upload(int index, String filename, boolean eicar, UUID jobId, int tries) {
    }

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final String api;
    final AtomicInteger retries = new AtomicInteger();

    Uploader(String api) {
        this.api = api;
    }

    List<Upload> uploadAll(int run, int files, int eicarEvery, int threads) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<Upload>> futures = new ArrayList<>(files);
        for (int i = 1; i <= files; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> uploadOne(run, idx, idx % eicarEvery == 0)));
        }
        List<Upload> out = new ArrayList<>(files);
        for (Future<Upload> f : futures) {
            out.add(f.get());
        }
        pool.shutdown();
        return Collections.unmodifiableList(out);
    }

    private Upload uploadOne(int run, int i, boolean eicar) throws InterruptedException {
        String name = String.format("r%02d-f%05d-%s", run, i, eicar ? "eicar.com.txt" : "clean.txt");
        byte[] content = eicar ? EICAR
                : ("scan-queue chaos run " + run + " file " + i + " " + UUID.randomUUID() + "\n").getBytes(StandardCharsets.UTF_8);
        String boundary = "----chaos" + UUID.randomUUID();
        byte[] body = multipart(boundary, name, content);
        for (int attempt = 1; attempt <= 8; attempt++) {
            try {
                HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(api + "/files"))
                                .timeout(Duration.ofSeconds(30))
                                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),
                        HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() == 201) {
                    Matcher m = JOB_ID.matcher(r.body());
                    if (m.find()) {
                        return new Upload(i, name, eicar, UUID.fromString(m.group(1)), attempt);
                    }
                }
            } catch (java.io.IOException e) {
                // connection reset etc.: retry below
            }
            retries.incrementAndGet();
            Thread.sleep(100L * attempt);
        }
        return new Upload(i, name, eicar, null, 8);
    }

    private static byte[] multipart(String boundary, String filename, byte[] content) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
                + "Content-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        b.writeBytes(content);
        b.writeBytes(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        return b.toByteArray();
    }
}
