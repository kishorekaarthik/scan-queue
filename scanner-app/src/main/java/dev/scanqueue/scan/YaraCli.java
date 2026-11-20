package dev.scanqueue.scan;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

/**
 * Shells out to the {@code yara} CLI (installed in the worker image with apk).
 * Output is one line per match: {@code <rule> <file>}.
 */
@Component
public class YaraCli implements YaraRunner {

    private final String binary;
    private final long timeoutMillis;
    private volatile Path rulesFile;

    public YaraCli(@Value("${scanqueue.yara.binary:yara}") String binary,
                   @Value("${scanqueue.yara.timeout-millis:30000}") long timeoutMillis) {
        this.binary = binary;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public List<String> matchingRules(Path file, BooleanSupplier cancelled) throws Exception {
        Process p = new ProcessBuilder(binary, "-w", rules().toString(), file.toString())
                .redirectErrorStream(true)
                .start();
        try {
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
            while (!p.waitFor(100, TimeUnit.MILLISECONDS)) {
                if (cancelled.getAsBoolean()) {
                    throw new CancelledScanException("lease lost; yara aborted");
                }
                if (System.nanoTime() > deadline) {
                    throw new TimeoutException("yara exceeded " + timeoutMillis + " ms");
                }
            }
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (p.exitValue() != 0) {
                throw new IOException("yara exited " + p.exitValue() + ": " + out.strip());
            }
            List<String> rules = new ArrayList<>();
            for (String line : out.split("\\R")) {
                if (!line.isBlank()) {
                    rules.add(line.strip().split("\\s+", 2)[0]);
                }
            }
            return rules;
        } finally {
            p.destroyForcibly();
        }
    }

    /** Copy the bundled rules out of the jar once, so the CLI can read them. */
    private Path rules() throws IOException {
        Path r = rulesFile;
        if (r == null) {
            synchronized (this) {
                if (rulesFile == null) {
                    Path tmp = Files.createTempFile("scanqueue-rules-", ".yar");
                    try (InputStream in = new ClassPathResource("yara/rules.yar").getInputStream()) {
                        Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
                    }
                    tmp.toFile().deleteOnExit();
                    rulesFile = tmp;
                }
                r = rulesFile;
            }
        }
        return r;
    }

    public static class CancelledScanException extends Exception {
        public CancelledScanException(String message) {
            super(message);
        }
    }
}
