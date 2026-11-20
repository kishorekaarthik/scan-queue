package dev.scanqueue.chaos;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Injects failures while the run is in progress, aiming at the dangerous windows:
 * <ul>
 *   <li>worker SIGKILL: targets a worker that holds a job lease; if none does within 2 s, no kill</li>
 *   <li>sender SIGKILL: waits up to 3 s for an alert in flight (row SENDING); if none, no kill</li>
 *   <li>webhook SIGKILL + restart: 3 per run, preferring a moment with an alert in flight</li>
 *   <li>worker/sender freeze (docker pause) for lease + 3 s while holding a lease: a zombie</li>
 * </ul>
 *
 * <p>A lease counts as held by the <i>live</i> process only if it was claimed or renewed
 * after the harness last (re)started that container: a restarted container keeps its
 * hostname, so its dead predecessor's unexpired leases carry the same owner prefix.
 * Lease snapshot and timestamp come from one query on the DB clock, right before the action.
 */
final class Monkey {

    record Held(UUID id, int token) {
    }

    /** One injected failure. {@code atMillis} is the DB clock just before it was issued. */
    record Kill(String target, String container, String host, double atMillis, List<Held> held) {
        boolean inWindow() {
            return !held.isEmpty();
        }
    }

    private static final String JOB_LEASES = """
            SELECT id, attempts, extract(epoch FROM clock_timestamp()) * 1000 AS t
            FROM scan_job
            WHERE status = 'RUNNING' AND lease_owner LIKE ?
              AND extract(epoch FROM lease_expires_at) * 1000 - ? >= ?""";
    private static final String ALERT_LEASES = """
            SELECT job_id AS id, attempts, extract(epoch FROM clock_timestamp()) * 1000 AS t
            FROM alert_outbox
            WHERE status = 'SENDING' AND lease_owner LIKE ?
              AND extract(epoch FROM lease_expires_at) * 1000 - ? >= ?""";

    private final Docker docker;
    private final Db db;
    private final Random rnd;
    private final int webhookRestarts;
    private final long workerLeaseMillis;
    private final long senderLeaseMillis;
    private final List<Kill> kills = Collections.synchronizedList(new ArrayList<>());
    private final Set<String> touched = ConcurrentHashMap.newKeySet();
    private final Set<String> paused = ConcurrentHashMap.newKeySet();
    /** container id -> DB-clock millis just before the harness last started it */
    private final Map<String, Double> restartedAt = new ConcurrentHashMap<>();
    private final ScheduledExecutorService restarter = Executors.newSingleThreadScheduledExecutor();
    private final List<Thread> threads = new ArrayList<>();
    private volatile boolean running = true;

    Monkey(Docker docker, Db db, long seed, int webhookRestarts, long workerLeaseMillis, long senderLeaseMillis) {
        this.docker = docker;
        this.db = db;
        this.rnd = new Random(seed);
        this.webhookRestarts = webhookRestarts;
        this.workerLeaseMillis = workerLeaseMillis;
        this.senderLeaseMillis = senderLeaseMillis;
    }

    void start() {
        threads.add(Thread.ofPlatform().name("kill-workers").start(this::workerLoop));
        threads.add(Thread.ofPlatform().name("kill-sender").start(this::senderLoop));
        threads.add(Thread.ofPlatform().name("kill-webhook").start(this::webhookLoop));
        threads.add(Thread.ofPlatform().name("pause").start(this::pauseLoop));
    }

    // ---- live-lease snapshots ----

    private List<Map<String, Object>> workerLeases(String id) {
        return db.rows(JOB_LEASES, host(id) + "-%", workerLeaseMillis, restartedAt.getOrDefault(id, 0.0));
    }

    private List<Map<String, Object>> senderLeases(String id) {
        return db.rows(ALERT_LEASES, "sender-" + host(id) + "-%", senderLeaseMillis, restartedAt.getOrDefault(id, 0.0));
    }

    private List<Map<String, Object>> anySenderLeases() {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (String s : docker.running("sender")) {
            rows.addAll(senderLeases(s));
        }
        return rows;
    }

    // ---- loops ----

    private void workerLoop() {
        while (running) {
            sleep(uniform(1_500, 3_500));
            List<String> workers = liveTargets("worker");
            if (!running || workers.isEmpty()) {
                continue;
            }
            List<String> holders = workers.stream().filter(w -> !workerLeases(w).isEmpty()).toList();
            String id = holders.isEmpty() ? workers.get(rnd.nextInt(workers.size())) : holders.get(rnd.nextInt(holders.size()));
            act("worker", id, () -> workerLeases(id), 2_000, false, this::killAndRestart);
        }
    }

    private void senderLoop() {
        while (running) {
            sleep(uniform(3_000, 6_000));
            List<String> senders = liveTargets("sender");
            if (!running || senders.isEmpty()) {
                continue;
            }
            String id = senders.get(0);
            act("sender", id, () -> senderLeases(id), 3_000, false, this::killAndRestart);
        }
    }

    private void webhookLoop() {
        for (int i = 0; i < webhookRestarts && running; i++) {
            sleep(uniform(8_000, 15_000));
            List<String> hooks = docker.running("webhook");
            if (!running || hooks.isEmpty()) {
                continue;
            }
            act("webhook", hooks.get(0), this::anySenderLeases, 3_000, true, this::killAndRestart);
        }
    }

    /**
     * Zombies. A SIGKILLed process never writes again, so it cannot exercise fencing.
     * A frozen one can: `docker pause` (cgroup freezer, like a long GC pause or VM
     * stall) holds a lease-holding worker/sender past its lease; the lease is reclaimed
     * and the work redone elsewhere; on unpause the zombie resumes and tries to write.
     */
    private void pauseLoop() {
        for (String target : new String[]{"worker", "sender", "worker"}) {
            sleep(uniform(10_000, 25_000));
            if (!running) {
                return;
            }
            boolean worker = target.equals("worker");
            List<String> ids = liveTargets(target);
            if (ids.isEmpty()) {
                continue;
            }
            List<String> holders = worker ? ids.stream().filter(w -> !workerLeases(w).isEmpty()).toList() : ids;
            String id = (holders.isEmpty() ? ids : holders).get(rnd.nextInt((holders.isEmpty() ? ids : holders).size()));
            long freeze = (worker ? workerLeaseMillis : senderLeaseMillis) + 3_000;
            int before = kills.size();
            try {
                act(target + "_pause", id, () -> worker ? workerLeases(id) : senderLeases(id), 5_000, false,
                        cid -> freeze(cid, freeze));
            } catch (RuntimeException e) {
                ChaosMain.log("pause " + target + " " + host(id) + " failed: " + e);
            }
            ChaosMain.log("pause " + target + " " + host(id) + (kills.size() > before
                    ? ": frozen for " + freeze + " ms holding " + kills.get(kills.size() - 1).held().size() + " lease(s)"
                    : ": skipped (no live lease within 5 s, or pause failed)"));
        }
    }

    // ---- actions ----

    interface Snapshot {
        List<Map<String, Object>> take();
    }

    interface Action {
        boolean apply(String containerId);
    }

    /** Poll until the target holds a live lease (or the wait runs out), then act on it. */
    private void act(String target, String id, Snapshot snapshot, long maxWaitMillis, boolean actIfIdle, Action action) {
        long deadline = System.currentTimeMillis() + maxWaitMillis;
        List<Map<String, Object>> rows;
        while (true) {
            rows = snapshot.take();
            if (!rows.isEmpty() || System.currentTimeMillis() > deadline || !running) {
                break;
            }
            sleep(10);
        }
        if (!running || (rows.isEmpty() && !actIfIdle)) {
            return;
        }
        double at = rows.isEmpty() ? db.nowMillis() : ((Number) rows.get(0).get("t")).doubleValue();
        List<Held> held = new ArrayList<>();
        for (Map<String, Object> r : rows) {
            held.add(new Held((UUID) r.get("id"), ((Number) r.get("attempts")).intValue()));
        }
        if (action.apply(id)) {
            kills.add(new Kill(target, id, host(id), at, held));
        }
    }

    private boolean killAndRestart(String id) {
        try {
            docker.kill(id);
        } catch (IllegalStateException e) {
            return false;    // already dead (e.g. restarting): not a kill
        }
        touched.add(id);
        restarter.schedule(() -> safeStart(id), uniform(1_000, 3_000), TimeUnit.MILLISECONDS);
        return true;
    }

    private boolean freeze(String id, long millis) {
        try {
            docker.run("docker", "pause", id);
        } catch (IllegalStateException e) {
            ChaosMain.log("docker pause " + host(id) + " failed: " + e.getMessage());
            return false;
        }
        paused.add(id);
        restarter.schedule(() -> unpause(id), millis, TimeUnit.MILLISECONDS);
        return true;
    }

    private void unpause(String id) {
        try {
            docker.run("docker", "unpause", id);
        } catch (IllegalStateException ignored) {
            // not paused any more
        }
        paused.remove(id);
    }

    private void safeStart(String id) {
        try {
            restartedAt.put(id, db.nowMillis());    // leases set after this belong to the new process
            docker.start(id);
        } catch (IllegalStateException ignored) {
            // retried by stop()
        }
    }

    /** Running, not frozen (a zombie must stay alive to wake up), not mid-restart. */
    private List<String> liveTargets(String service) {
        List<String> ids = new ArrayList<>(docker.running(service));
        ids.removeAll(paused);
        return ids;
    }

    /** Stop injecting, unfreeze everything, make sure every touched container runs. */
    void stop() throws InterruptedException {
        running = false;
        for (Thread t : threads) {
            t.join(30_000);
        }
        restarter.shutdown();
        restarter.awaitTermination(30, TimeUnit.SECONDS);
        for (String id : List.copyOf(paused)) {
            unpause(id);
        }
        for (String id : touched) {
            safeStart(id);
        }
    }

    List<Kill> kills() {
        return List.copyOf(kills);
    }

    private static String host(String containerId) {
        return containerId.substring(0, 12);
    }

    private long uniform(long lo, long hi) {
        synchronized (rnd) {
            return lo + (long) (rnd.nextDouble() * (hi - lo));
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
