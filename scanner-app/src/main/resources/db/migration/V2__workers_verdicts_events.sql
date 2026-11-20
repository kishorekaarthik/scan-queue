-- Phase 2: workers, verdicts, hash list, durable queue events.
--
-- Fencing token: scan_job.attempts. Every claim increments it, so the value a
-- worker received at claim time identifies *its* lease. Every write a worker
-- makes afterwards (renew, verdict, failure) is conditional on
--   id = ? AND attempts = <its token> AND status = 'RUNNING'
-- so a worker whose lease expired and was re-claimed (a "zombie") can never
-- overwrite the newer owner's work.
COMMENT ON COLUMN scan_job.attempts IS
    'Claim counter. Incremented on every claim; doubles as the fencing token.';

-- Retry backoff: a failed attempt is re-queued but not claimable until available_at.
ALTER TABLE scan_job ADD COLUMN available_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- One verdict per job, enforced by the primary key (defence in depth behind fencing).
CREATE TABLE scan_verdict (
    job_id        UUID        PRIMARY KEY REFERENCES scan_job (id),
    sha256        CHAR(64)    NOT NULL,
    verdict       TEXT        NOT NULL CHECK (verdict IN ('CLEAN', 'MALICIOUS')),
    hash_match    TEXT,                               -- label from known_bad_hash, if any
    yara_matches  TEXT[]      NOT NULL DEFAULT '{}',  -- rule names that matched
    worker_id     TEXT        NOT NULL,
    claim_token   INT         NOT NULL,               -- the fencing token that won
    scan_millis   BIGINT      NOT NULL,
    scanned_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hash list. Only the EICAR test file and harmless made-up samples: no real malware.
CREATE TABLE known_bad_hash (
    sha256 CHAR(64) PRIMARY KEY,
    label  TEXT     NOT NULL
);

INSERT INTO known_bad_hash (sha256, label) VALUES
    -- sha256 of the 68-byte EICAR anti-malware test string
    ('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR test file'),
    -- sha256 of the ASCII strings 'scan-queue harmless test sample A/B/C' (no trailing newline).
    -- Harmless content listed as "bad" so tests can exercise a hash-only match.
    ('b18e081077d9e3f773059570c0dd0bbada48b425fa628078fd88ea87ffe44d0c', 'test sample A (harmless)'),
    ('1798b0930670bf64798f3ff5df4a156e480c573da50e02e52ffb0b233bc438b8', 'test sample B (harmless)'),
    ('98c1ff3019054cf8a43392e682e781ff745bf6e81125a3560d82fb1425fd32ef', 'test sample C (harmless)');

-- Durable metrics. Workers are killed with SIGKILL in the chaos test, so in-memory
-- counters would be lost; these rows survive and are what the chaos report counts.
CREATE TABLE queue_event (
    id          BIGSERIAL   PRIMARY KEY,
    kind        TEXT        NOT NULL CHECK (kind IN (
                    'LEASE_EXPIRED',   -- reaper returned a RUNNING job whose lease ran out
                    'FENCED_WRITE',    -- a worker's verdict/failure write matched 0 rows
                    'LEASE_LOST',      -- a heartbeat found the lease already gone
                    'RETRY',           -- a scan failed and the job was re-queued
                    'DEAD_LETTERED')), -- job hit max_attempts
    job_id      UUID,
    claim_token INT,
    worker_id   TEXT,
    detail      TEXT,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX queue_event_kind_idx ON queue_event (kind);
