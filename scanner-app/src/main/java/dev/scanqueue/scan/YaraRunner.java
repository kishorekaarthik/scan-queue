package dev.scanqueue.scan;

import java.nio.file.Path;
import java.util.List;
import java.util.function.BooleanSupplier;

/** Runs YARA rules against a file. The real implementation shells out to the yara CLI. */
public interface YaraRunner {

    /**
     * @param cancelled polled while the scan runs; when it returns true the scan is abandoned
     * @return names of the rules that matched (empty if none)
     */
    List<String> matchingRules(Path file, BooleanSupplier cancelled) throws Exception;
}
