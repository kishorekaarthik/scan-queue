# scan-queue design notes

> Expanded in Phase 6. This file records each design decision, the
> alternatives considered, and why they were rejected.

## Outbox delivery: lease + fencing token, no transaction across the HTTP call

### Chosen

The sender handles each outbox row in three short, separate steps:

1. **Claim** (one autocommit statement): pick the oldest `PENDING` row with
   `FOR UPDATE SKIP LOCKED`, set `status='SENDING'`, `attempts=attempts+1`
   (the fencing token), and `lease_expires_at = now() + 15 s`. Commit.
2. **Send**: `POST /alerts` with `Idempotency-Key: alert:<job_id>`. No
   database transaction is open and no row lock is held.
3. **Mark**: `UPDATE ... SET status='DELIVERED' WHERE id=? AND attempts=<token>
   AND status='SENDING'` (or re-queue with backoff, or `DEAD` after
   `max_attempts = 20`). If it matches 0 rows, this sender lost its lease and
   the write is discarded as a `FENCED_WRITE`.

If the sender crashes between 2 and 3, the row stays `SENDING` until its lease
expires. The reaper then returns it to `PENDING`, another claim (new token)
resends it with the **same key**, and the webhook rejects the duplicate. Crash
safety after sending comes from the receiver's dedup, not from the sender's
database transaction.

### Rejected: hold a row lock in a transaction across the POST

Phase 3 first shipped this simpler version:

```
BEGIN
  SELECT ... FOR UPDATE SKIP LOCKED      -- lock the row
  POST /alerts                           -- network call inside the transaction
  UPDATE status='DELIVERED'
COMMIT
```

It is correct: a crash rolls the transaction back, and the row is resent and
deduplicated. It was replaced for these reasons:

- **A transaction's lifetime is tied to a remote system's latency.** A slow
  webhook (or a 10 s timeout) keeps a transaction open, a row locked and a pool
  connection checked out for that whole time. With N concurrent sends that is N
  pinned connections. The pool and Postgres `max_connections` become the
  throughput limit, set by someone else's latency.
- **Long transactions hurt the whole database.** An open transaction holds back
  the xmin horizon, so `VACUUM` cannot clean dead tuples anywhere, including the
  busy `scan_job` table. It also shows up as `idle in transaction` sessions.
- **Failure detection depends on TCP, not on the application.** If the sender
  hangs, or a network partition leaves its connection half-open, the lock stays
  until Postgres notices. That needed an extra
  `idle_in_transaction_session_timeout` as a backstop. A lease expires on the
  database clock no matter what state the connection is in.
- **It is the same problem jobs already solve.** Jobs use claim, lease, fencing
  token and reaper. Using one pattern for both queues means one set of
  invariants to reason about, test and explain.

Cost of the chosen design: after a crash, the resend waits for the lease to
expire (up to 15 s plus up to 1 s for the reaper) instead of happening as soon as
the connection drops. That is bounded and configurable, and alerts are still
never lost or processed twice.

## Alert attempt limit

Alerts are retried with exponential backoff on the DB clock (500 ms doubling,
capped at 30 s) up to `alert_outbox.max_attempts = 20`. The alert then goes to
`DEAD` with an `ALERT_DEAD` event instead of retrying forever, so a receiver
that permanently rejects a payload cannot pin a sender slot indefinitely.
Every claim counts as an attempt, including one ended by a crash and lease
expiry, so the limit also bounds poison messages that crash the sender.
20 attempts at those delays is about 8 minutes of retrying, which rides out a
webhook restart or a short outage. `DEAD` alerts are visible to operators and
are counted by the chaos report.
