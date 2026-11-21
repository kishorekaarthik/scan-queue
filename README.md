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
| duplicates rejected | 15 | 10 | 20 | 21 | 20 | 19 | 11 | 14 | 20 | 12 | 162 |
| fenced-out writes | 2 | 0 | 3 | 3 | 3 | 2 | 4 | 2 | 2 | 2 | 23 |
| job lease expiries | 60 | 63 | 90 | 102 | 112 | 108 | 89 | 104 | 86 | 96 | 910 |
| alert lease expiries | 16 | 19 | 27 | 30 | 30 | 27 | 28 | 28 | 27 | 28 | 260 |
| dead jobs | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| dead alerts | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| all checks | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | 10/10 |

**Latency** (headline: processing = final claim to committed verdict. Queue wait = upload to first claim. End to end = upload to verdict, which also includes time lost to crashes. DB clock)

| metric | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | min / median / max |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| processing p50 ms | 27 | 30 | 44 | 45 | 43 | 43 | 43 | 44 | 43 | 45 | 27 / 43 / 45 |
| processing p95 ms | 70 | 73 | 90 | 92 | 91 | 100 | 90 | 94 | 92 | 93 | 70 / 92 / 100 |
| queue wait p50 ms | 53596 | 58746 | 62762 | 67290 | 81260 | 78948 | 72304 | 79423 | 66754 | 62531 | 53596 / 67290 / 81260 |
| queue wait p95 ms | 63721 | 70034 | 86779 | 93985 | 110890 | 106010 | 88743 | 102796 | 96828 | 96717 | 63721 / 96717 / 110890 |
| end-to-end p50 ms | 53624 | 58898 | 62843 | 67342 | 81316 | 79011 | 72513 | 79470 | 66803 | 62585 | 53624 / 67342 / 81316 |
| end-to-end p95 ms | 63875 | 70181 | 86831 | 94197 | 111182 | 106222 | 88989 | 102848 | 96928 | 96772 | 63875 / 96772 / 111182 |
| jobs re-claimed after a crash/freeze | 59 | 63 | 88 | 102 | 108 | 107 | 86 | 104 | 86 | 96 | 59 / 96 / 108 |
| their first-to-final claim delay p50 ms | 10442 | 10396 | 10407 | 10427 | 10404 | 10489 | 10376 | 10445 | 10442 | 10463 | 10376 / 10442 / 10489 |
| jobs/sec | 69.4 | 66.2 | 50.6 | 46.4 | 44.1 | 42.5 | 49.6 | 46.8 | 49.3 | 47.5 | 42.5 / 49.3 / 69.4 |
| peak container MB | 1360 | 1390 | 1408 | 1384 | 1416 | 1406 | 1415 | 1417 | 1420 | 1459 | 1360 / 1415 / 1459 |

**Recovery** (per kill: from the SIGKILL to the last item it interrupted being finished elsewhere. Segments: medians over interrupted items that were not interrupted again)

| metric | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | min / median / max |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| worker recovery p50 ms | 10605 | 10588 | 10569 | 10592 | 10546 | 10689 | 10552 | 10565 | 10629 | 10651 | 10546 / 10592 / 10689 |
| worker recovery max ms | 20648 | 13665 | 21259 | 13213 | 24737 | 20805 | 23895 | 14266 | 15681 | 11400 | 11400 / 20648 / 24737 |
| job: kill -> lease expiry | 10117 | 10119 | 10122 | 10119 | 10107 | 10107 | 10113 | 10110 | 10114 | 10111 | 10107 / 10114 / 10122 |
| job: lease expiry -> reaped | 421 | 375 | 339 | 396 | 360 | 451 | 317 | 385 | 418 | 380 | 317 / 385 / 451 |
| job: reaped -> re-claimed | 28 | 32 | 31 | 28 | 33 | 34 | 35 | 32 | 30 | 30 | 28 / 32 / 35 |
| job: re-claimed -> verdict | 38 | 36 | 44 | 50 | 44 | 45 | 48 | 42 | 45 | 44 | 36 / 44 / 50 |
| alert recovery p50 ms | 24398 | 27505 | 26523 | 36581 | 25405 | 25975 | 40750 | 36249 | 25495 | 35697 | 24398 / 27505 / 40750 |
| alert recovery max ms | 58376 | 92343 | 101494 | 91702 | 112927 | 116442 | 111502 | 126327 | 109479 | 98702 | 58376 / 109479 / 126327 |
| alert: kill -> lease expiry | 15030 | 14984 | 14983 | 15013 | 14975 | 14942 | 14983 | 14984 | 15054 | 14977 | 14942 / 14984 / 15054 |
| alert: lease expiry -> reaped | 5871 | 7143 | 10018 | 8416 | 9570 | 9532 | 9323 | 8834 | 9558 | 8827 | 5871 / 9323 / 10018 |
| alert: reaped -> re-claimed | 390 | 533 | 461 | 479 | 454 | 458 | 460 | 505 | 485 | 523 | 390 / 479 / 533 |
| alert: re-claimed -> delivered | 225 | 244 | 240 | 245 | 234 | 238 | 247 | 236 | 261 | 231 | 225 / 240 / 261 |
| alerts interrupted | 14 | 19 | 25 | 30 | 30 | 26 | 28 | 28 | 27 | 26 | 14 / 27 / 30 |
| ...of which interrupted again | 1 | 7 | 1 | 11 | 5 | 4 | 12 | 13 | 4 | 6 | 1 / 6 / 13 |
| ...their kill -> delivered p50 ms | 58376 | 63905 | 52601 | 48429 | 85137 | 98998 | 68744 | 96966 | 47576 | 60896 | 47576 / 63905 / 98998 |

**Chaos** (observed = lease seen held in the DB right before SIGKILL; confirmed = that container's lease later expired, i.e. the kill interrupted real work; pauses = `docker pause` for lease + 3 s while holding a lease, then unpause: the zombie whose late write must be fenced)

| metric | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 | total |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| worker kills | 37 | 38 | 50 | 57 | 61 | 62 | 51 | 56 | 51 | 55 | 518 |
| worker kills holding a lease (observed) | 37 | 38 | 50 | 57 | 61 | 62 | 51 | 56 | 51 | 55 | 518 |
| worker kills holding a lease (confirmed) | 35 | 37 | 50 | 54 | 60 | 60 | 48 | 54 | 49 | 52 | 499 |
| sender kills | 8 | 10 | 13 | 16 | 17 | 16 | 15 | 15 | 15 | 15 | 140 |
| sender kills with alert in flight (observed) | 8 | 10 | 13 | 16 | 17 | 16 | 15 | 15 | 15 | 15 | 140 |
| sender kills with alert in flight (confirmed) | 8 | 10 | 13 | 16 | 16 | 14 | 15 | 15 | 14 | 14 | 135 |
| webhook restarts | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 30 |
| webhook restarts with alert in flight (observed) | 1 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 4 |
| worker pauses (zombies) | 1 | 0 | 1 | 2 | 2 | 1 | 2 | 1 | 2 | 2 | 14 |
| worker pauses whose lease was reclaimed | 1 | 0 | 1 | 2 | 2 | 1 | 2 | 1 | 2 | 1 | 13 |
| sender pauses (zombies) | 1 | 0 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 5 |
| sender pauses whose lease was reclaimed | 1 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 4 |
| heartbeats that found the lease gone | 0 | 0 | 0 | 3 | 2 | 1 | 3 | 2 | 2 | 1 | 14 |
| unattributed lease expiries | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| upload client retries | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

**Pass/fail checks**

| check | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8 | r9 | r10 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| every acknowledged upload has exactly one final verdict | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| every verdict matches ground truth (EICAR -> MALICIOUS, else CLEAN) | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| no second completed scan changed a result | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| every malicious job has exactly one accepted alert | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| zero alerts for non-malicious jobs | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| zero duplicate alerts accepted | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| zero dead or stuck jobs and alerts | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

<!-- chaos:final:end -->

### Reading the results

- **Correctness held in every run.** All seven checks passed in all 10 runs:
  100,000 jobs and 100,000 verdicts; 5,000 malicious jobs and 5,000 alerts
  accepted, each exactly once; 0 dead jobs and 0 dead alerts. The 162
  "duplicates rejected" are the webhook dedup doing real work. Each one is an
  alert the webhook had already accepted that a sender re-sent after a crash, a
  freeze, or a webhook restart that came before its response arrived.
- **The kills hit real work.** 499 of 518 worker kills and 135 of 140 sender
  kills are confirmed to have interrupted a live lease (the lease later
  expired), and 0 lease expiries were left unattributed.
- **Fenced-out writes come from the pauses.** A process killed with `kill -9`
  never writes again. The 14 worker and 5 sender freezes (`docker pause` past
  the lease) produced zombies that woke up and tried to write. All 23 of those
  writes were rejected by the token check, and every rejected verdict agreed
  with the committed one. Some planned pauses are skipped when the kill loop
  happened to kill the same container first, so the pause count varies by run.
- **Latency: processing is milliseconds, the rest is queueing.** Processing
  time (final claim to committed verdict) has a median p50 of 43 ms and a
  median p95 of 92 ms across runs. Queue wait (upload to first claim) has a
  median p50 of about 67 s: the 10,000 uploads arrive in about 75 s, faster than
  5 workers × 2 slots scan them on this laptop, so jobs wait their turn.
  End-to-end latency is almost entirely that wait. Jobs re-claimed after a
  crash or freeze lost a median of about 10.4 s (one lease) between their first
  and final claim.
- **Worker recovery ≈ the lease.** Median segments for an interrupted job:
  kill → lease expiry 10.1 s (the 10 s lease), expiry → reaped 0.39 s (some
  live worker's reaper, which runs every 1 s), reaped → re-claimed 0.03 s,
  re-claimed → verdict 0.04 s. Total ≈ 10.6 s.
- **Alert recovery (median ~27.5 s) is the 15 s lease plus ~9.3 s waiting for
  a reaper.** Median segments for an interrupted alert: kill → lease expiry
  15.0 s, expiry → reaped **9.3 s**, reaped → re-claimed 0.48 s, re-claimed →
  delivered 0.24 s (including the webhook's 200 ms delay). Jobs and alerts
  both reap every second. Expiry → reaped is 0.4 s for jobs, because all 5
  workers reap jobs, but 9.3 s for alerts, because the only alert reaper runs
  inside the single sender. The harness keeps killing that sender (every
  3–6 s while an alert is in flight), and each restart costs 1–3 s plus a JVM
  boot of several seconds, so for long stretches no live process is reaping
  alerts. A median of 6 of the ~27 interrupted alerts per run were interrupted
  again before delivery; those took a median of ~64 s and set the maximums.
  Running the alert reaper in the workers too would remove most of the 9.3 s
  (see Limitations).
- **No VM stalls this time.** `results/final/log-silence.txt`
  (`scripts/log-silence.sh`) shows the longest webhook log silence in any
  run's scan window was 57 s, in line with webhook restarts and sender
  outages. Peak container memory stayed under 1.5 GB in every run.
- **Throughput (median 49 jobs/s).** The first two runs ran at 66–69 jobs/s
  and the other eight at 42–51. Kills are paced per second, so a slower run
  also takes more kills, which slows it further. Why the later runs started
  slower is not established.

## Phase 5: ablation, what each mechanism prevents

<!-- chaos:ablation:begin -->
_Generated by `java -jar chaos/target/chaos.jar ablation-report --out results/ablation`. Each variant: 3 runs x 10000 files, same seeds and failure schedule. Cells: total (run 1 / run 2 / run 3)._

**What breaks when each mechanism is removed**

| variant | lost jobs | stuck jobs | duplicate/stale verdict writes accepted | missing alerts | duplicate alerts accepted | alerts for clean files | checks passed |
|---|--:|--:|--:|--:|--:|--:|--:|
| **A** final design | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 3/3 |
| **B** no fencing (leases kept; writes not token-checked) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 1 (1 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 2/3 |
| **C** no outbox (worker POSTs the alert after the verdict) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 87 (36 / 33 / 18) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0/3 |
| **D** no webhook dedup (outbox kept, duplicates accepted) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 46 (18 / 13 / 15) | 0 (0 / 0 / 0) | 0/3 |
| **E** naive (no lease reaper, no fencing, no outbox) | 292 (112 / 87 / 93) | 292 (112 / 87 / 93) | 0 (0 / 0 / 0) | 115 (32 / 48 / 35) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 0/3 |

**Safety work done and failures injected** (same seeds; the schedule is randomized from the seed but targets depend on live state, so counts differ slightly between variants)

| variant | second scans rejected by fencing | duplicates rejected by webhook | alerts dropped by worker | worker kills (confirmed in lease) | sender kills (confirmed in flight) | worker pauses | sender pauses | webhook restarts |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| **A** | 3 (3 / 0 / 0) | 36 (12 / 16 / 8) | 0 (0 / 0 / 0) | 177 (51 / 66 / 60) | 47 (14 / 16 / 17) | 2 (2 / 0 / 0) | 1 (0 / 1 / 0) | 9 (3 / 3 / 3) |
| **B** | 7 (0 / 3 / 4) | 38 (16 / 9 / 13) | 0 (0 / 0 / 0) | 201 (56 / 66 / 79) | 54 (16 / 19 / 19) | 5 (1 / 2 / 2) | 1 (0 / 0 / 1) | 9 (3 / 3 / 3) |
| **C** | 4 (1 / 0 / 3) | 1 (1 / 0 / 0) | 62 (23 / 26 / 13) | 194 (67 / 60 / 67) | 0 (0 / 0 / 0) | 4 (1 / 1 / 2) | 0 (0 / 0 / 0) | 9 (3 / 3 / 3) |
| **D** | 4 (0 / 0 / 4) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 229 (84 / 74 / 71) | 56 (19 / 19 / 18) | 3 (1 / 0 / 2) | 3 (1 / 1 / 1) | 9 (3 / 3 / 3) |
| **E** | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 93 (24 / 41 / 28) | 0 (0 / 0 / 0) | 0 (0 / 0 / 0) | 2 (0 / 1 / 1) | 0 (0 / 0 / 0) | 9 (3 / 3 / 3) |

**Failed checks**

- B run 1: no second completed scan changed a result: 0 second scans rejected (0 disagree), 1 stale-owner verdicts accepted
- C run 1: every malicious job has exactly one accepted alert: 500 malicious jobs, 36 missing, 0 accepted more than once
- C run 2: every malicious job has exactly one accepted alert: 500 malicious jobs, 33 missing, 0 accepted more than once
- C run 3: every malicious job has exactly one accepted alert: 500 malicious jobs, 18 missing, 0 accepted more than once
- D run 1: every malicious job has exactly one accepted alert: 500 malicious jobs, 0 missing, 15 accepted more than once
- D run 1: zero duplicate alerts accepted: 518 accepted, 500 distinct keys, 18 extra acceptances
- D run 2: every malicious job has exactly one accepted alert: 500 malicious jobs, 0 missing, 13 accepted more than once
- D run 2: zero duplicate alerts accepted: 513 accepted, 500 distinct keys, 13 extra acceptances
- D run 3: every malicious job has exactly one accepted alert: 500 malicious jobs, 0 missing, 14 accepted more than once
- D run 3: zero duplicate alerts accepted: 515 accepted, 500 distinct keys, 15 extra acceptances
- E run 1: every acknowledged upload has exactly one final verdict: 10000 acknowledged, 112 without a verdict, 112 not DONE, 0 jobs with >1 verdict row
- E run 1: every malicious job has exactly one accepted alert: 494 malicious jobs, 32 missing, 0 accepted more than once
- E run 1: zero dead or stuck jobs and alerts: 0 dead, 112 jobs stuck QUEUED/RUNNING
- E run 2: every acknowledged upload has exactly one final verdict: 10000 acknowledged, 87 without a verdict, 87 not DONE, 0 jobs with >1 verdict row
- E run 2: every malicious job has exactly one accepted alert: 495 malicious jobs, 48 missing, 0 accepted more than once
- E run 2: zero dead or stuck jobs and alerts: 0 dead, 87 jobs stuck QUEUED/RUNNING
- E run 3: every acknowledged upload has exactly one final verdict: 10000 acknowledged, 93 without a verdict, 93 not DONE, 0 jobs with >1 verdict row
- E run 3: every malicious job has exactly one accepted alert: 493 malicious jobs, 35 missing, 0 accepted more than once
- E run 3: zero dead or stuck jobs and alerts: 0 dead, 93 jobs stuck QUEUED/RUNNING

<!-- chaos:ablation:end -->

### What each mechanism prevents

Each variant removes one mechanism with an environment switch on the same
images (`scanqueue.ablation.*`, `webhook.dedup`). Every variant uses the same
seeds and the same kill/pause/restart schedule. The schedule targets live
leases, so exact counts differ a little between variants.

- **A, final design.** 0 failures in all 3 runs.
- **B, no fencing token → 1 stale verdict accepted in 3 runs.** Fencing
  protects a narrow window. B still requires `status = 'RUNNING'`, so a zombie
  that wakes after the job is already `DONE` is rejected anyway (7 such
  rejections in B). The token only matters when the zombie writes while the job
  is `RUNNING` under its new owner. With 13 s freezes and ~40 ms re-scans, the
  harness hit that window once in 3 runs: the committed verdict carries a
  claim token older than the job's current attempt, i.e. a superseded owner's
  write won. The logs do not show whether the newer owner's own write was then
  rejected or never happened because it was killed first. The verdict content was
  still correct, because scanning is deterministic. If the result could differ
  between attempts (rules updated mid-flight, a flaky scanner), the stale
  result would win.
- **C, no outbox → 87 missing alerts (36 / 33 / 18), 0 of 3 runs pass.** The
  worker POSTs after committing the verdict, with up to 3 tries in memory. 62
  alerts were recorded as dropped after the tries failed. The other 25 have no drop event, which fits a worker killed
  between the commit and the POST, where nothing durable remembers the alert.
  The verdicts themselves were all correct; only the alerts were lost.
- **D, no webhook dedup → 46 duplicate alerts accepted (18 / 13 / 15), 0 of 3
  runs pass.** These are the same resends that A's webhook rejects (36
  rejected in A's 3 runs). The outbox guarantees at-least-once delivery; without
  the receiver's dedup, at-least-once turns into "more than once".
- **E, naive → 292 jobs never get a verdict (112 / 87 / 93) and 115 alerts are
  missing.** Without the reaper, every job a killed worker held stays `RUNNING`
  forever. Those are uploads the API acknowledged and never scanned. Without the
  outbox, alerts are lost as in C. E shows 0 stale verdicts and 0 "confirmed"
  kills, because nothing is ever re-claimed and no lease ever expires. Its
  failure is losing work, not duplicating it.

```bash
java -Xmx256m -jar chaos/target/chaos.jar ablation --runs 3 --files 10000 --out results/ablation
java -jar chaos/target/chaos.jar ablation-report --out results/ablation --readme README.md
# or everything (Phase 4 + Phase 5) in one go:
bash scripts/run-all-chaos.sh
```


### Safety

No real malware is used anywhere. The "malicious" sample is the
[EICAR test string](https://www.eicar.org/download-anti-malware-testfile/),
which antivirus products detect by design and which is harmless.
