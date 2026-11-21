-- When the current (most recent) claim was taken. started_at keeps the FIRST claim.
-- Lets the report separate processing time (final claim -> verdict) from queue
-- wait (upload -> first claim) and from time lost to crashes in between.
ALTER TABLE scan_job     ADD COLUMN claimed_at TIMESTAMPTZ;
ALTER TABLE alert_outbox ADD COLUMN claimed_at TIMESTAMPTZ;
