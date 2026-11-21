-- Liveness for the dashboard: every worker / sender process upserts its row once
-- a second. "Alive" = seen within the last 3 s (DB clock). Not used for any
-- correctness decision; leases and fencing do that.
CREATE TABLE process_presence (
    process_id TEXT        PRIMARY KEY,    -- hostname-pid
    role       TEXT        NOT NULL CHECK (role IN ('worker', 'sender')),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);
