package dev.scanqueue.job;

import java.util.List;

/** What a worker wants to persist for a job. */
public record VerdictRecord(String sha256, boolean malicious, String hashMatch, List<String> yaraMatches, long scanMillis) {
    public VerdictRecord {
        yaraMatches = List.copyOf(yaraMatches);
    }
}
