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

### Safety

No real malware is used anywhere. The "malicious" sample is the
[EICAR test string](https://www.eicar.org/download-anti-malware-testfile/),
which antivirus products detect by design and which is harmless.
