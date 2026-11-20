package dev.scanqueue.scan;

import dev.scanqueue.job.VerdictRecord;
import dev.scanqueue.storage.ObjectStore;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;

/**
 * Download -> SHA-256 -> hash list -> YARA. Pure function of the file's bytes,
 * so re-scanning the same file after a crash always yields the same verdict.
 */
@Component
public class ScanEngine {

    private final ObjectStore store;
    private final HashList hashList;
    private final YaraRunner yara;

    public ScanEngine(ObjectStore store, HashList hashList, YaraRunner yara) {
        this.store = store;
        this.hashList = hashList;
        this.yara = yara;
    }

    public VerdictRecord scan(String objectKey, BooleanSupplier cancelled) throws Exception {
        long start = System.nanoTime();
        Path tmp = Files.createTempFile("scan-", ".bin");
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            try (InputStream in = new DigestInputStream(store.get(objectKey), sha);
                 OutputStream out = Files.newOutputStream(tmp)) {
                in.transferTo(out);
            }
            String hex = HexFormat.of().formatHex(sha.digest());
            Optional<String> listed = hashList.lookup(hex);
            List<String> rules = yara.matchingRules(tmp, cancelled);
            boolean malicious = listed.isPresent() || !rules.isEmpty();
            long millis = (System.nanoTime() - start) / 1_000_000;
            return new VerdictRecord(hex, malicious, listed.orElse(null), rules, millis);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
