package dev.scanqueue.scan;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/** Known-bad SHA-256 list (EICAR + harmless test samples), stored in known_bad_hash. */
@Component
public class HashList {

    private final JdbcTemplate jdbc;

    public HashList(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** @return the list label if the hash is listed */
    public Optional<String> lookup(String sha256) {
        List<String> labels = jdbc.queryForList("SELECT label FROM known_bad_hash WHERE sha256 = ?", String.class, sha256);
        return labels.stream().findFirst();
    }
}
