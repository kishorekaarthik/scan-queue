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

### Safety

No real malware is used anywhere. The "malicious" sample is the
[EICAR test string](https://www.eicar.org/download-anti-malware-testfile/),
which antivirus products detect by design and which is harmless.
