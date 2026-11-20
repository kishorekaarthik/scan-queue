-- Lease-expiry events record when the expired lease was due. With the lease
-- length, that pins down when the lease was last claimed/renewed, so an expiry
-- can be attributed to the exact crash or stall that interrupted it.
ALTER TABLE queue_event ADD COLUMN lease_expires_at TIMESTAMPTZ;
