-- The job table IS the queue. Workers claim rows with
-- SELECT ... FOR UPDATE SKIP LOCKED and hold them via a time-bounded lease.

CREATE TABLE scan_job (
    id                UUID        PRIMARY KEY,
    object_key        TEXT        NOT NULL UNIQUE,      -- key in the MinIO bucket
    original_filename TEXT,
    size_bytes        BIGINT      NOT NULL,
    status            TEXT        NOT NULL DEFAULT 'QUEUED'
                      CHECK (status IN ('QUEUED', 'RUNNING', 'DONE', 'DEAD')),
    attempts          INT         NOT NULL DEFAULT 0,   -- incremented on every claim
    max_attempts      INT         NOT NULL DEFAULT 5,
    lease_owner       TEXT,                             -- worker id holding the lease
    lease_expires_at  TIMESTAMPTZ,                      -- NULL unless RUNNING
    last_error        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at        TIMESTAMPTZ,                      -- first claim
    finished_at       TIMESTAMPTZ,                      -- DONE or DEAD

    CONSTRAINT running_has_lease CHECK (
        (status = 'RUNNING') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    )
);

-- Claim path: oldest QUEUED jobs first. Partial index stays small as jobs finish.
CREATE INDEX scan_job_queued_idx  ON scan_job (created_at) WHERE status = 'QUEUED';
-- Reaper path: RUNNING jobs whose lease has expired.
CREATE INDEX scan_job_running_idx ON scan_job (lease_expires_at) WHERE status = 'RUNNING';
