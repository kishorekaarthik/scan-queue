# scan-queue

A distributed file-scanning job queue in Java. Every uploaded file is scanned
and every alert is sent exactly once, even when workers crash at any moment.

> Work in progress: built in phases. This README is expanded at the end with the
> architecture, measured chaos-test results and design decisions.

## Stack

Java 21, Spring Boot 3.5, PostgreSQL 16 (the job table is the queue), Flyway,
MinIO (object storage), YARA CLI, Docker Compose, JUnit 5 + Testcontainers.

## Phase 1: upload and queue

`POST /files` stores the file in MinIO under `uploads/<jobId>` and inserts a
`scan_job` row with `status=QUEUED`, `attempts=0`, `max_attempts=5` and an empty
lease (`lease_owner`, `lease_expires_at`). The object is written **before** the
row, so a worker can never claim a job whose bytes are missing.

| Endpoint | Purpose |
|---|---|
| `POST /files` (multipart `file`) | Upload, returns `201` + `{jobId, status}` |
| `GET /jobs/{id}` | Job row |
| `GET /stats` | Job count per status |

### Run it

```bash
./mvnw package                 # builds the jar and runs the Testcontainers tests
docker compose up -d --build   # postgres, minio, api
bash scripts/smoke-phase1.sh   # uploads a harmless file and the EICAR test string
```

## Phase 2: workers, leases and fencing

Workers (`SPRING_PROFILES_ACTIVE=worker`, 3 replicas in compose, 2 claim loops
each) run this protocol, entirely in SQL against the **database clock**
(`now()`); the worker's own clock is never written or compared:

| Step | SQL (abridged) |
|---|---|
| Claim | `WITH next AS (SELECT id … WHERE status='QUEUED' AND available_at<=now() ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE … SET status='RUNNING', attempts=attempts+1, lease_expires_at=now()+lease` |
| Heartbeat | `UPDATE … SET lease_expires_at=now()+lease WHERE id=? AND attempts=<token> AND status='RUNNING'` every 3 s (lease 10 s) |
| Verdict | one transaction: `UPDATE … SET status='DONE' WHERE id=? AND attempts=<token> AND status='RUNNING'`, then `INSERT INTO scan_verdict` only if that matched 1 row |
| Failure | same fence; re-queue with backoff, or `DEAD` once `attempts >= max_attempts` |
| Reaper | `RUNNING` rows with `lease_expires_at < now()` go back to `QUEUED` (or `DEAD` on the last attempt), with a `queue_event` row in the same statement |

**Fencing token.** `attempts` is incremented by every claim, so the value a
worker got at claim time identifies its lease. A worker that stalls past its
lease (GC pause, partition) and wakes up after another worker re-claimed the
job presents a stale token; its write matches 0 rows, is discarded and is
logged/recorded as `FENCED_WRITE`.

**Scan.** Download from MinIO → SHA-256 → `known_bad_hash` lookup → `yara`
CLI (installed in the worker image) with `scanner-app/src/main/resources/yara/rules.yar`.
Verdict is `MALICIOUS` if either matches. The hash list holds only EICAR's hash
and three harmless made-up samples.

**Metrics.** `queue_event` rows (`LEASE_EXPIRED`, `FENCED_WRITE`, `LEASE_LOST`,
`RETRY`, `DEAD_LETTERED`) survive `kill -9`; the same events are also Micrometer
counters (`scanqueue.events{kind}`).

### Tests (`./mvnw verify`)

| Test | Proves |
|---|---|
| `concurrentClaimersNeverGetTheSameJob` | 8 threads, 60 jobs: 60 claims, 60 distinct |
| `leaseIsComputedByTheDatabaseClock` | `lease_expires_at - started_at` is exactly the lease, both from `now()` |
| `zombieWorkerWriteIsFencedOut` | A claims, lease expires, B claims and finishes; A's renew/verdict/failure writes are all rejected |
| `zombieWorkerIsFencedOutEndToEnd` | same through the real `JobProcessor`, with A frozen mid-scan |
| `heartbeatKeepsASlowScanFromBeingStolen` | 4.5 s scan, 1.5 s lease: a competing worker never gets the job, 0 lease expiries |
| `failingScanIsRetriedThenDeadLettered` | 3 failures → `RETRY`, `RETRY`, `DEAD` |
| `expiredLeaseOnFinalAttemptIsDeadLettered` | crash on the last attempt → `DEAD` |
| `hashListFlagsListedContentEvenWithoutYaraMatch` | hash-only hit → `MALICIOUS` |
| `WorkerContainerIT` | real worker image: YARA installed; EICAR → `MALICIOUS` (`EICAR_Test_File` + hash); harmless and an EICAR look-alike → `CLEAN` |

### Demo

```bash
docker compose up -d --build
bash scripts/demo-phase2.sh   # 1000 files, kill -9 one busy worker, drain, report
```

## Phase 3: exactly-once alerts (transactional outbox)

```
worker ── one transaction ──────────────────────────────┐
  UPDATE scan_job SET status='DONE'                     │ fenced: id + token + RUNNING
     WHERE id=? AND attempts=<token> AND status='RUNNING'│ 0 rows -> rollback, nothing below happens
  INSERT INTO scan_verdict ...                          │
  INSERT INTO alert_outbox (idempotency_key='alert:'||job_id)   (MALICIOUS only)
COMMIT ─────────────────────────────────────────────────┘

sender ── one transaction per row ──────────────────────┐
  SELECT ... FROM alert_outbox WHERE status='PENDING'   │
     AND available_at<=now() LIMIT 1 FOR UPDATE SKIP LOCKED
  POST /alerts  Idempotency-Key: alert:<job_id>         │ row stays locked while in flight
  2xx  -> UPDATE status='DELIVERED'                      │
  else -> UPDATE attempts+1, available_at=now()+backoff  │ 200, 400, 800 ... capped at 30 s
COMMIT ─────────────────────────────────────────────────┘

mock-webhook (own database)
  INSERT INTO received_alert (idempotency_key ...) ON CONFLICT DO NOTHING
  1 row -> 201 accepted       0 rows -> 200 "duplicate_rejected"   (+ delivery_log row)
```

### Why "at-least-once + idempotency = effectively exactly once"

Exactly-once *delivery* over a network is impossible. After the sender
POSTs, it can crash (or lose the response) before recording success. From the
sender's point of view, "the receiver got it" and "the receiver never got it"
look the same, so it must either resend, risking a duplicate, or not resend,
risking a lost alert. No protocol avoids that choice; it is the Two Generals
problem.

So this system splits the guarantee in two:

1. **At-least-once delivery.** The alert row is committed atomically with the
   verdict (outbox), so it cannot be lost. It stays `PENDING` until a 2xx is
   recorded. A sender that dies mid-send leaves it `PENDING`, because Postgres
   rolls back the dead connection's transaction, and the next sender resends it.
2. **Idempotent processing.** Every resend carries the same key, derived from
   the job (`alert:<job_id>`) and never from the attempt. The receiver keeps
   keys under a unique constraint in its own database, so it acts on the first
   copy and rejects the rest, even across its own restarts and even when two
   copies race.

Messages may be *delivered* more than once, but each is *processed* exactly
once. That is the property that matters (one page, one ticket, one SIEM
event), and it is what "exactly once" means in Kafka, Stripe's API and
similar systems.

What makes it hold:

| Failure | Handled by |
|---|---|
| Worker crashes after verdict, before alert send | Outbox row committed with the verdict; sender picks it up |
| Zombie worker writes late | Fenced update matches 0 rows, so no verdict and no outbox row |
| Sender crashes after webhook got it, before marking | Tx rolled back, row `PENDING`, resend, webhook rejects the duplicate |
| Sender hangs mid-transaction | `idle_in_transaction_session_timeout=30s` kills the session; same as above |
| Two senders | `FOR UPDATE SKIP LOCKED`: a row being sent is invisible to the other |
| Webhook down | Exponential backoff on the DB clock; delivered when it returns |
| Webhook restarts | Keys live in Postgres, not in memory |

### Tests

| Test | Proves |
|---|---|
| `zombieWorkerWriteIsFencedOut`, `zombieWorkerIsFencedOutEndToEnd` | the zombie's MALICIOUS verdict creates **no outbox row** |
| `fencedZombieAddsNoSecondAlert` | both find it malicious: exactly 1 outbox row |
| `maliciousVerdictQueuesOneAlert…CleanQueuesNone` | outbox row with key `alert:<job_id>` only for MALICIOUS |
| `senderKilledAfterDeliveryBeforeMarking…` | webhook records the alert, sender is `docker kill -s KILL`ed while waiting for the response, row is unlocked and still `PENDING`, new sender resends, webhook: 1 accepted + 1 duplicate rejected |
| `webhookDownSenderRetriesWithBackoff…` | retries at ≥ 200/400/800/1600 ms (DB-clock gaps), delivered once the webhook starts, 0 duplicates |
| `webhookRestartedBetweenTwoDeliveries…` | key accepted by one webhook container, rejected by a brand-new one |
| `twoSendersRunningAtOnceNeverDoubleSend` | 2 sender containers, 40 alerts: 40 accepted, 0 duplicates, both senders did work |
| `AlertControllerTest` (mock-webhook) | 30 concurrent POSTs of one key: exactly one `201` |

The webhook's `delivery_log` table counts **duplicates rejected**, the metric
that shows the dedup is doing real work (`GET :8090/stats`).

### Demo

```bash
docker compose up -d --build
bash scripts/demo-phase3.sh   # 400 files, sender kill -9 mid-delivery, restart, reconcile
```

## Phase 4: chaos test

`chaos/` is a standalone harness. Each run: reset the tables, upload 10,000
files (every 20th is the EICAR test string, so 5%) through the API with 12
client threads, and inject failures for the whole scan phase:

| Failure | How it is aimed at the dangerous window |
|---|---|
| `kill -9` a worker (every 1.5–3.5 s) | target only a worker that holds a **live** job lease in Postgres right now; restart it 1–3 s later |
| `kill -9` the sender (every 3–6 s) | wait until an alert is **in flight** (row `SENDING` under the live sender's lease) |
| `kill -9` + restart the webhook (3 per run) | prefer a moment with an alert in flight |
| `docker pause` a worker (2 per run) and the sender (1 per run) for lease + 3 s | freeze it **while it holds a lease**, so the lease is reclaimed and the work redone; on unpause the zombie tries to write and must be fenced out |

"Live" lease means claimed or renewed after the harness last (re)started that
container: a restarted container keeps its hostname, so its dead predecessor's
unexpired leases would otherwise look held. A kill is **confirmed** to have
interrupted real work when a lease it held later expires. Each expiry is
attributed to the failure between the lease's last renewal
(`lease_expires_at − lease`) and its expiry. All timestamps come from the
Postgres clock.

Then: stop injecting, restart everything, drain, and verify. Pass/fail checks:
every acknowledged upload has exactly one final verdict; every verdict matches
ground truth; no fenced-out (second) scan disagreed with the committed verdict;
every malicious job has exactly one accepted alert; zero alerts for
non-malicious jobs; zero duplicate alerts accepted; zero dead jobs/alerts
(any dead item is listed with its `last_error`).

Memory: the harness refuses to start if the containers' `mem_limit` sum plus
its own heap exceeds 4 GB (measured: 2,844 MB + 356 MB), and aborts a run if
live container memory passes 3.5 GB.

```bash
./mvnw package -DskipTests && docker compose build
java -Xmx256m -jar chaos/target/chaos.jar run --runs 10 --files 10000 --out results/final
java -jar chaos/target/chaos.jar report --out results/final --readme README.md   # regenerates the block below
```

### Results (10 runs × 10,000 files)

Raw per-run data (every kill with its DB-clock timestamp and the leases it
held): `results/final/run-*.json`. Log: `results/final/harness.log`.

<!-- chaos:final:begin -->
_Generated by `java -jar chaos/target/chaos.jar report --out results/final` from 10 run files. 10000 files per run (every 20th is EICAR), 5 workers, 1 sender, webhook response delay 200 ms._

**Correctness**

| metric | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | total |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| jobs | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 100000 |
| verdicts | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 10000 | 100000 |
| malicious | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 5000 |
| alerts accepted | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 500 | 5000 |
| duplicates rejected | 16 | 19 | 15 | 13 | 14 | 13 | 13 | 21 | 19 | 16 | 159 |
| fenced-out writes | 0 | 4 | 4 | 1 | 0 | 1 | 3 | 2 | 4 | 1 | 20 |
| job lease expiries | 70 | 92 | 71 | 62 | 76 | 78 | 92 | 98 | 112 | 127 | 878 |
| alert lease expiries | 22 | 32 | 20 | 23 | 23 | 21 | 26 | 34 | 34 | 35 | 270 |
| dead jobs | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| dead alerts | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| all checks | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | 10/10 |

**Performance and recovery** (latency = upload to verdict; recovery = kill to last interrupted item finished elsewhere; DB clock)

| metric | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | min / median / max |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| jobs/sec | 62.6 | 46.3 | 66.1 | 63.8 | 62.2 | 63.2 | 53 | 43.7 | 21.3 | 41.1 | 21.3 / 62.2 / 66.1 |
| p50 latency ms | 59376 | 60544 | 53423 | 60573 | 61662 | 58274 | 66384 | 81304 | 85179 | 88510 | 53423 / 61662 / 88510 |
| p95 latency ms | 78237 | 63705 | 66811 | 65548 | 70389 | 69317 | 91677 | 96735 | 355399 | 126633 | 63705 / 78237 / 355399 |
| worker recovery p50 ms | 10585 | 10558 | 10621 | 10656 | 10503 | 10455 | 10486 | 10678 | 10717 | 10652 | 10455 / 10621 / 10717 |
| worker recovery max ms | 12673 | 13342 | 21322 | 23482 | 23882 | 14395 | 13542 | 24161 | 244714 | 22562 | 12673 / 22562 / 244714 |
| alert recovery p50 ms | 26861 | 25614 | 25349 | 24431 | 24544 | 26336 | 25646 | 25407 | 35596 | 27654 | 24431 / 25646 / 35596 |
| alert recovery max ms | 57087 | 69168 | 85187 | 62611 | 78516 | 94576 | 66499 | 90194 | 340348 | 130922 | 57087 / 85187 / 340348 |
| peak container MB | 1374 | 1355 | 1381 | 1378 | 1385 | 1376 | 1393 | 1432 | 1408 | 1407 | 1355 / 1385 / 1432 |

**Chaos** (observed = lease seen held in the DB right before SIGKILL; confirmed = that container's lease later expired, i.e. the kill interrupted real work; pauses = `docker pause` for lease + 3 s while holding a lease, then unpause: the zombie whose late write must be fenced)

| metric | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | total |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| worker kills | 42 | 54 | 38 | 39 | 45 | 42 | 49 | 58 | 63 | 71 | 501 |
| worker kills holding a lease (observed) | 42 | 54 | 38 | 39 | 45 | 42 | 49 | 58 | 63 | 71 | 501 |
| worker kills holding a lease (confirmed) | 41 | 48 | 37 | 36 | 43 | 40 | 47 | 52 | 62 | 69 | 475 |
| sender kills | 11 | 17 | 12 | 12 | 12 | 11 | 14 | 17 | 18 | 18 | 142 |
| sender kills with alert in flight (observed) | 11 | 17 | 12 | 12 | 12 | 11 | 14 | 17 | 18 | 18 | 142 |
| sender kills with alert in flight (confirmed) | 11 | 17 | 11 | 11 | 12 | 11 | 13 | 17 | 18 | 18 | 139 |
| webhook restarts | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 30 |
| webhook restarts with alert in flight (observed) | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 5 |
| worker pauses (zombies) | 1 | 2 | 2 | 2 | 0 | 1 | 2 | 2 | 2 | 1 | 15 |
| worker pauses whose lease was reclaimed | 0 | 2 | 2 | 1 | 0 | 1 | 2 | 2 | 2 | 1 | 13 |
| sender pauses (zombies) | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 2 |
| sender pauses whose lease was reclaimed | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 2 |
| heartbeats that found the lease gone | 0 | 2 | 3 | 1 | 0 | 1 | 2 | 2 | 2 | 1 | 14 |
| unattributed lease expiries | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| upload client retries | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

**Pass/fail checks**

| check | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| every acknowledged upload has exactly one final verdict | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| every verdict matches ground truth (EICAR -> MALICIOUS, else CLEAN) | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| no second completed scan changed a result (fenced verdicts agree with committed) | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| every malicious job has exactly one accepted alert | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| zero alerts for non-malicious jobs | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| zero duplicate alerts accepted | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| zero dead jobs and dead alerts | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

<!-- chaos:final:end -->

### Reading the results

- **Correctness held in every run**: all seven checks passed in all 10 runs,
  with 0 dead jobs and 0 dead alerts. The "duplicates rejected" row is the
  webhook dedup doing real work. Each one is an alert the webhook had already
  accepted that a sender re-sent after a crash, a freeze, or a webhook restart
  that came before its response arrived.
- **Fenced-out writes come from the pauses.** A process killed with `kill -9`
  never writes again. The frozen (`docker pause`) workers and sender woke up and
  tried to write. Every one of those writes was rejected by the token check, and
  every rejected verdict agreed with the committed one.
- **Latency includes queueing.** The 10,000 uploads arrive faster than 5 workers
  (2 slots each) scan them on this laptop, so most of the p50/p95 is time spent
  waiting in the queue, not scan time.
- **Worker recovery ≈ lease length.** A killed worker's jobs come back after its
  10 s lease expires, plus up to 1 s for the reaper. That gives the ~10.5 s p50.
  Alert recovery is longer, because the 15 s alert lease is followed by the
  sender's own restart and backoff.
- **Run 9 includes a ~4-minute stall of the whole Docker VM.** Every container,
  Postgres included, wrote no log lines for that period (see
  `results/final/log-silence.txt`, produced by `scripts/log-silence.sh`). That
  stall explains its throughput and its max recovery times. The run is kept as
  measured: correctness held through a whole-system freeze too.
- **Throughput varied between the other runs.** The longest log silence in every
  other run is in line with webhook restarts, so no stall explains that spread.
  One observation: kills are paced per second, so a slower run also takes more
  kills, but that is not established as the cause. Peak container memory stayed
  under 1.5 GB in every run.

### Safety

No real malware is used anywhere. The "malicious" sample is the
[EICAR test string](https://www.eicar.org/download-anti-malware-testfile/),
which antivirus products detect by design and which is harmless.
