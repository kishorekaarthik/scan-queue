-- Outbox rows are now claimed with a lease + fencing token, exactly like jobs,
-- so no database transaction is held open across the HTTP call.
--
--   PENDING --claim (attempts+1, lease)--> SENDING --token-checked mark--> DELIVERED
--      ^                                     |
--      +---- failure / lease expired --------+--> DEAD (attempts >= max_attempts)
--
-- attempts is the fencing token: incremented by every claim; the mark-delivered /
-- mark-failed UPDATEs require id + attempts = <token> + status = 'SENDING'.

ALTER TABLE alert_outbox DROP CONSTRAINT alert_outbox_status_check;
ALTER TABLE alert_outbox ADD CONSTRAINT alert_outbox_status_check
    CHECK (status IN ('PENDING', 'SENDING', 'DELIVERED', 'DEAD'));

ALTER TABLE alert_outbox
    ADD COLUMN max_attempts     INT NOT NULL DEFAULT 20,
    ADD COLUMN lease_owner      TEXT,
    ADD COLUMN lease_expires_at TIMESTAMPTZ;

ALTER TABLE alert_outbox ADD CONSTRAINT sending_has_lease CHECK (
    (status = 'SENDING') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL));

COMMENT ON COLUMN alert_outbox.attempts IS
    'Send claims so far. Incremented on every claim; doubles as the fencing token.';

CREATE INDEX alert_outbox_sending_idx ON alert_outbox (lease_expires_at) WHERE status = 'SENDING';

ALTER TABLE queue_event DROP CONSTRAINT queue_event_kind_check;
ALTER TABLE queue_event ADD CONSTRAINT queue_event_kind_check CHECK (kind IN (
    'LEASE_EXPIRED', 'FENCED_WRITE', 'LEASE_LOST', 'RETRY', 'DEAD_LETTERED',
    'ALERT_DELIVERED',       -- webhook answered 2xx; detail = accepted | duplicate
    'ALERT_SEND_FAILED',     -- network error / non-2xx; re-queued with backoff
    'ALERT_LEASE_EXPIRED',   -- a sender died (or stalled) holding an alert lease
    'ALERT_DEAD'));          -- alert hit max_attempts; needs a human
