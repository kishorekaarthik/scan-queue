package dev.scanqueue.chaos;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Thin wrapper over the docker / docker compose CLI. */
final class Docker {

    private final Map<String, String> composeEnv;

    Docker(Map<String, String> composeEnv) {
        this.composeEnv = composeEnv;
    }

    String run(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
            pb.environment().putAll(composeEnv);
            Process p = pb.start();
            byte[] out = p.getInputStream().readAllBytes();
            if (!p.waitFor(5, TimeUnit.MINUTES)) {
                p.destroyForcibly();
                throw new IllegalStateException("timed out: " + Arrays.toString(cmd));
            }
            String s = new String(out, StandardCharsets.UTF_8);
            if (p.exitValue() != 0) {
                throw new IllegalStateException(Arrays.toString(cmd) + " exited " + p.exitValue() + ": " + s.strip());
            }
            return s;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    String compose(String... args) {
        List<String> cmd = new ArrayList<>(List.of("docker", "compose"));
        cmd.addAll(Arrays.asList(args));
        return run(cmd.toArray(String[]::new));
    }

    /** Full ids of the service's running containers. */
    List<String> running(String service) {
        return lines(compose("ps", "-q", service));
    }

    /** Full ids of the service's containers, running or not. */
    List<String> all(String service) {
        return lines(compose("ps", "-a", "-q", service));
    }

    void kill(String id) {
        run("docker", "kill", "-s", "KILL", id);
    }

    void start(String id) {
        run("docker", "start", id);
    }

    /** Sum of HostConfig.Memory (the compose mem_limit) over the given containers, in MB. */
    long memLimitMb(List<String> ids) {
        List<String> cmd = new ArrayList<>(List.of("docker", "inspect", "--format", "{{.HostConfig.Memory}}"));
        cmd.addAll(ids);
        long bytes = 0;
        for (String l : lines(run(cmd.toArray(String[]::new)))) {
            bytes += Long.parseLong(l.strip());
        }
        return bytes / (1024 * 1024);
    }

    /** Current memory use of all running containers, in MB (docker stats). */
    double usedMb() {
        double total = 0;
        for (String l : lines(run("docker", "stats", "--no-stream", "--format", "{{.MemUsage}}"))) {
            total += toMb(l.split("/")[0].strip());
        }
        return total;
    }

    static double toMb(String v) {
        String num = v.replaceAll("[^0-9.]", "");
        double d = Double.parseDouble(num);
        if (v.endsWith("GiB")) return d * 1024;
        if (v.endsWith("MiB")) return d;
        if (v.endsWith("KiB")) return d / 1024;
        if (v.endsWith("B")) return d / (1024 * 1024);
        return d;
    }

    private static List<String> lines(String s) {
        List<String> out = new ArrayList<>();
        for (String l : s.split("\\R")) {
            if (!l.isBlank()) {
                out.add(l.strip());
            }
        }
        return out;
    }
}
