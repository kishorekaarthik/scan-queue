# scan-queue: design decisions

Each section names the choice, the alternatives considered, and why they lost.
Where the Phase 5 ablation measured a choice, the result is quoted with its
source (`results/ablation/summary.md`, 3 runs × 10,000 files per variant).

**Invariants the design must hold under any crash:**

1. Every acknowledged upload ends with exactly one verdict.
2. A verdict is never written by a worker that no longer owns the job.
3. Every malicious verdict produces exactly one *processed* alert, and clean files produce none.
4. No timing decision depends on a worker's clock.

---

## 1. PostgreSQL as the queue (not Kafka, RabbitMQ or SQS)

**Chosen:** the `scan_job` table is the queue. A job's state, lease, attempts,
verdict and alert live in one transactional store.

**Why:** the hard part of this system is not moving messages. It is changing
several pieces of state atomically: the job finishes, the verdict is saved and
the alert is queued, all or nothing. In Postgres that is one local transaction.
With a broker, the job state lives in the broker and the verdict in a database,
so "ack the message" and "commit the verdict" are two systems, and you are back
to needing an outbox or a distributed transaction to keep them consistent.
Postgres also gives the claim primitive for free (`FOR UPDATE SKIP LOCKED`, §2),
ad-hoc visibility (`SELECT status, count(*)`), and one fewer moving part.

**Rejected:**
- **Kafka.** Partitions are consumed in order by one consumer per group, so a
  slow or poisoned scan blocks its partition. There is no per-message lease or
  retry count without building them yourself. Exactly-once in Kafka covers
  Kafka-to-Kafka; the verdict lives outside it.
- **RabbitMQ / SQS.** Both have a visibility timeout, roughly a lease, but on
  the broker's clock and without a fencing token: a redelivered message carries
  nothing that lets the database reject the first, slower consumer's late
  write. Their ack is also not atomic with our database commit.

**Cost:** Postgres is the throughput ceiling and the single point of failure.
At this scale that is fine. The usual next step is partitioning the table or
moving to a broker plus outbox once one database can't keep up.

## 2. Claiming with `SELECT … FOR UPDATE SKIP LOCKED`

```sql
WITH next AS (SELECT id FROM scan_job
              WHERE status='QUEUED' AND available_at <= now()
              ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
UPDATE scan_job j SET status='RUNNING', attempts=attempts+1,
       lease_owner=?, lease_expires_at=now()+?, claimed_at=now()
FROM next WHERE j.id = next.id RETURNING …
```

**Why:** one statement that never blocks and never double-claims. Rows another
worker is claiming right now are skipped rather than waited on, so N workers
make progress in parallel. A partial index on `QUEUED` rows keeps the scan
small as `DONE` rows pile up. Tested with 8 threads × 60 jobs: 60 claims, 60
distinct (`QueueSemanticsTest`).

**Rejected:**
- **`SELECT` then `UPDATE … WHERE status='QUEUED'` (optimistic).** Correct, but
  every worker races for the same oldest row, and all but one get 0 rows and
  retry. That's wasted round trips that grow with the number of workers.
- **Plain `FOR UPDATE`.** Workers queue up behind each other's row locks.
- **Advisory locks.** Locks live outside the row, need careful release on
  every path, and do not survive a crash any better than a lease does.
- **`LISTEN/NOTIFY` push.** It would cut the poll delay, but notifications are
  lost while nobody listens, so you still need the poll. Polling every 200 ms
  was simpler and good enough.

## 3. Leases timed by the database clock

**Chosen:** claim and heartbeat set `lease_expires_at = now() + lease` and the
reaper compares `lease_expires_at < now()`, all in SQL, all on the Postgres
clock. The worker's clock only decides *when to send* the next heartbeat. Lease
10 s, heartbeat every 3 s (two heartbeats can be missed). The reaper runs in
every worker every second.

**Why:** a lease is a promise between processes, so it needs one clock that all
of them agree on. If workers compared their own clocks, a worker whose clock
runs behind would think a lease is still valid after another worker (on the
database's time) has already reclaimed it. Tested:
`lease_expires_at − started_at` is exactly the lease, both from the same
`now()`.

**Rejected:**
- **Worker-side timestamps.** Clock skew silently breaks mutual exclusion.
- **No lease; rely on the connection dying.** A hung or partitioned worker
  keeps its connection, and the job stays stuck. Variant E (no reaper) shows
  what that costs: **292 acknowledged uploads never scanned** in 3 runs.

**Trade-off (measured):** recovery after a worker crash takes about one lease:
median 10.6 s, of which 10.1 s is waiting for the lease to expire and 0.39 s
for a reaper to notice (`results/final/summary.md`, Recovery). A shorter lease
recovers faster but would steal slow-but-alive scans more often. The heartbeat
lets a scan run longer than one lease: a 4.5 s scan on a 1.5 s lease is never
stolen (`heartbeatKeepsASlowScanFromBeingStolen`).

## 4. Fencing tokens

**Chosen:** `attempts` is incremented on every claim and returned to the
worker as its token. Every later write (heartbeat, verdict, failure) is
`… WHERE id=? AND attempts=<token> AND status='RUNNING'`. A write that matches
0 rows is discarded and logged as `FENCED_WRITE`.

**Why:** a lease alone can't stop a **zombie**, a worker that paused (GC, VM
stall, partition) past its lease, was replaced, and then wakes up mid-task
still believing it owns the job. The token makes "am I still the owner?" part
of the write itself, checked atomically by the database. Using the attempt
counter means no extra column, and it grows on every claim. In the chaos runs,
23 zombie writes were fenced out and every rejected verdict agreed with the
committed one (`results/final/summary.md`).

**Rejected:**
- **Check ownership, then write (two statements).** The lease can expire
  between the check and the write; the race is exactly what fencing closes.
- **Status-only guard (`status='RUNNING'`).** That's variant B. It catches a
  zombie that wakes after the job is `DONE`, but not one that writes while the
  job is `RUNNING` under its new owner. **Measured: 1 stale-owner verdict
  accepted in 3 runs.** The window is narrow (freezes of lease + 3 s mostly land
  after the re-scan has finished), so it rarely fires here. The verdict was
  still correct because scanning is deterministic; with a result that can
  change between attempts, the stale one would win.
- **Owner-name check (`lease_owner = me`).** A restarted container keeps its
  hostname, so its new process has the same owner name as the dead one. The
  harness ran into exactly this when deciding which leases were "live".

**Defence in depth:** `scan_verdict.job_id` is the primary key, so even a bug
in the fence could not create a second verdict row.

## 5. Transactional outbox for alerts

**Chosen:** a `MALICIOUS` verdict inserts its `alert_outbox` row inside the
worker's fenced finish transaction. A separate sender delivers outbox rows.

**Why:** the alert must exist if and only if the verdict does. Sending from the
worker after the commit leaves a gap: commit, then crash before the POST, and
the alert is gone with nothing that remembers it. Sending before the commit
risks alerting on a verdict that then rolls back or is fenced out. The outbox
makes "verdict committed" and "alert owed" one fact. A fenced-out zombie
creates neither (`zombieWorkerWriteIsFencedOut`, `fencedZombieAddsNoSecondAlert`).

**Rejected:**
- **Direct send from the worker.** That's variant C. **Measured: 87 missing
  alerts in 3 runs**: 62 logged as dropped after 3 in-memory tries, and 25 with
  no trace at all, which fits a worker killed between commit and POST.
- **Two-phase commit / XA** between the database and the webhook. HTTP
  receivers don't take part in XA, and 2PC blocks when the coordinator dies.
- **CDC (Debezium) on the verdict table.** It works and avoids the poller, but
  it adds Kafka Connect and a broker to a project that needs one table and one
  loop.

## 6. Deterministic idempotency keys and durable dedup at the receiver

**Chosen:** the key is `'alert:' || job_id`, enforced by a `CHECK` on the outbox
table. Every resend of the same alert carries the same key. The webhook keeps
keys in its own Postgres table under a primary key:
`INSERT … ON CONFLICT DO NOTHING` returns `201` for a new key and `200
duplicate_rejected` for a known one. Both mean success to the sender.

**Why:** at-least-once delivery creates duplicates by design (the sender can't
tell "the receiver didn't get it" from "I lost the response"). Dedup works only
if every copy has the same key. A per-attempt UUID would make every resend look
new. Keeping the keys in the receiver's database (not memory) survives receiver
restarts and is race-free when two copies arrive at once. 30 parallel POSTs of
one key give exactly one `201` (`AlertControllerTest`), and a key accepted by one
webhook container is rejected by a brand-new one (`OutboxDeliveryIT`).

**Rejected:**
- **Key per send attempt.** It defeats dedup.
- **In-memory or TTL cache at the receiver.** It is lost on restart, which is
  exactly when resends arrive.
- **No receiver dedup.** That's variant D. **Measured: 46 duplicate alerts
  accepted in 3 runs.** These are the same resends the final design rejected
  (36 in its 3 runs; 162 in the 10 Phase 4 runs).

**Exactly once, precisely:** exactly-once *delivery* over a network is
impossible (Two Generals). This system gives at-least-once delivery plus
idempotent processing, so each alert is *acted on* exactly once. That is the
property users care about, and it is what "exactly once" means in practice in
Kafka, Stripe and similar systems.

## 7. Outbox delivery with a lease and a token, not a lock held across HTTP

### Chosen

1. **Claim** (autocommit): `SKIP LOCKED` the oldest `PENDING` row, set it
   `SENDING`, `attempts+1` (token), and give it a 15 s lease.
2. **Send** the POST with no transaction open and no lock held.
3. **Mark** with a token-checked `UPDATE … SET status='DELIVERED'` (or
   re-queue with backoff, or `DEAD`). 0 rows = this sender lost its lease.

A crash between 2 and 3 leaves the row `SENDING` until the lease expires; then
a new claim resends it with the same key and the webhook rejects the duplicate.
Test: the sender is `kill -9`ed while the webhook holds its response; the row
stays `SENDING`, the lease expires, token 2 resends, and the webhook shows 1
accepted and 1 duplicate (`OutboxDeliveryIT`).

### Rejected: hold a row lock in a transaction across the POST

This was the first Phase 3 version:
`BEGIN; SELECT … FOR UPDATE SKIP LOCKED; POST; UPDATE DELIVERED; COMMIT`. It is
correct (a crash rolls back and the row is resent), but:

- **The transaction lives as long as a remote call.** A slow webhook keeps a
  transaction open, a row locked and a pool connection checked out per
  in-flight alert, so throughput is capped by someone else's latency.
- **Long transactions hurt the whole database.** They hold back the xmin
  horizon, so `VACUUM` can't clean dead tuples anywhere, including the busy
  `scan_job`.
- **Failure detection depends on TCP.** A hung or half-open connection keeps
  the lock until Postgres notices, which needed an
  `idle_in_transaction_session_timeout` backstop. A lease expires on the DB
  clock regardless.
- **It is the same problem jobs already solve.** One pattern (claim, lease,
  token, reaper) for both queues means one set of invariants to test and
  explain.

**Cost:** after a sender crash the resend waits for the lease. Measured median
for an interrupted alert: 15.0 s to lease expiry, **9.3 s** until a reaper
notices, 0.48 s to re-claim, 0.24 s to deliver (`results/final/summary.md`).
The 9.3 s happens because the alert reaper runs only in the sender, which the
chaos test keeps killing (job reaping, done by all 5 workers, takes 0.39 s).
Running the alert reaper in the workers too would remove most of it; see
README → Limitations.

## 8. Retry limits and dead-lettering

- **Jobs:** every claim counts as an attempt, including one ended by a crash.
  After `max_attempts = 5` the job is `DEAD` with its `last_error`. A failed
  scan is re-queued with linear backoff (2 s × attempts).
- **Alerts:** exponential backoff on the DB clock (500 ms doubling, capped at
  30 s) for up to `max_attempts = 20`, which is about 7 minutes of backoff, enough
  to ride out a webhook restart or short outage. Then `DEAD` with an
  `ALERT_DEAD` event.

**Why:** without caps, a poison file or a receiver that always rejects a
payload pins capacity forever. Counting crashes as attempts also bounds a
poison message that crashes its consumer. Dead items need a human; the chaos
runs ended with 0 dead jobs and 0 dead alerts.

**Rejected:** infinite retries (the first Phase 3 version), and retrying only
on explicit failures (a crash-looping poison message would never hit the cap).

## 9. File before row

**Chosen:** the upload stores the object in MinIO first, then inserts the
`QUEUED` job row.

**Why:** the row is what makes a job claimable. Row-first would let a worker
claim a job whose bytes are not there yet. That's a spurious failure, or a race
the worker has to retry around.

**Rejected:**
- **Row first, with status `UPLOADING`, flipped to `QUEUED` after the put.**
  It works, but it costs a second write per upload and a sweeper for rows stuck
  in `UPLOADING`.
- **One transaction across both.** MinIO is not transactional with Postgres.

**Cost:** if the insert fails after the put, the object is orphaned: harmless,
never scanned, and not cleaned up (a known limitation). An upload is
"accepted" only when the API returns `201`; the chaos harness counts exactly
those.

## 10. Smaller choices

- **One codebase, three roles** (`api`, `worker`, `sender` Spring profiles) and
  one image: fewer builds, and the roles share the queue code they must agree on.
- **Durable metrics:** `queue_event` rows (lease expiries, fenced writes,
  retries, dead letters, deliveries) survive `kill -9`, so the chaos report can
  count them. Reapers insert their events in the same SQL statement as the state
  change, so the metric can't disagree with the state. Micrometer counters
  mirror them for live monitoring.
- **EICAR only.** The "malicious" sample is the EICAR test string, stored as hex
  in the YARA rule and assembled at runtime in tests and scripts, so no file in
  the repo is flagged by antivirus.

## 11. How the claims are tested

- **Unit and integration tests** (Testcontainers; real Postgres, MinIO, worker
  and webhook images): SKIP LOCKED, the DB-clock lease, zombie fencing (step by
  step and through the real processor), heartbeats under a slow scan,
  dead-lettering, the outbox inside the fence, no transaction open during a
  send, `kill -9` of the sender between send and mark, webhook down, webhook
  restarted, two concurrent senders.
- **Chaos harness:** 10 runs × 10,000 files. It kills workers that hold a live
  lease, kills the sender with an alert in flight, restarts the webhook, and
  freezes lease holders into zombies. Each kill is confirmed by attributing the
  later lease expiry to it, and every verdict and alert is checked against
  ground truth.
- **Ablation:** the same harness and seeds with one mechanism off, to show
  each one is load-bearing.

### Chaos method details

- **Targeted kills.** Killing an idle worker proves nothing. The harness reads
  Postgres and kills only a worker holding a live lease, or the sender while an
  alert is `SENDING`. The snapshot and the DB-clock timestamp come from one
  query right before `docker kill -s KILL`.
- **Observed vs confirmed.** `docker kill` through the Windows CLI is not
  instant, so the item can finish in between. "Confirmed" means a lease the
  killed process held later expired. Both are reported.
- **Live leases only.** A restarted container keeps its hostname, so a dead
  predecessor's unexpired lease looks held. The first version of the harness
  counted those, and once froze a still-booting JVM instead of a real lease
  holder. It now counts only leases set after the container's last restart, and
  attributes each expiry using the `lease_expires_at` stored on the event.
- **Zombies need a freeze, not a kill.** A killed process never writes again;
  `docker pause` (the cgroup freezer) stalls it past its lease like a long GC
  pause, and on unpause it tries to write.

## 12. Questions to be ready for

- *"Isn't exactly-once impossible?"* Exactly-once delivery is; exactly-once
  processing isn't. See §6, and variants C and D for what each half prevents.
- *"Why not just Kafka?"* See §1: the atomic unit is "job done + verdict +
  alert owed", which is one Postgres transaction and a distributed one with a
  broker.
- *"What if the database clock jumps?"* Every lease decision uses the same
  clock, so a jump affects all workers equally. A large forward jump expires
  leases early; fencing then rejects the original owner's late write, so the
  outcome is a wasted re-scan, not a wrong result.
- *"Why is alert recovery slower than job recovery?"* See §7: one reaper in a
  process the test keeps killing; the measured breakdown shows it.
- *"Did fencing ever matter?"* Yes: 23 zombie writes were rejected in Phase 4,
  and removing the token let 1 stale verdict through in the ablation (§4).
