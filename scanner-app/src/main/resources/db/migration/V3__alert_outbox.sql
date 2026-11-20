-- Phase 3: transactional outbox for alerts.
--
-- A MALICIOUS verdict and its outbox row are inserted in the SAME transaction as
-- the fenced UPDATE that finishes the job. Either all three commit or none do:
-- no alert without a verdict, no verdict without its alert, and a fenced-out
-- (zombie) worker produces neither.
CREATE TABLE alert_outbox (
    id               BIGSERIAL   PRIMARY KEY,
    job_id           UUID        NOT NULL UNIQUE REFERENCES scan_job (id),  -- at most one alert per job
    idempotency_key  TEXT        NOT NULL UNIQUE,                           -- 'alert:' || job_id, never per attempt
    payload          JSONB       NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED')),
    attempts         INT         NOT NULL DEFAULT 0,                        -- send attempts
    available_at     TIMESTAMPTZ NOT NULL DEFAULT now(),                    -- retry backoff
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at     TIMESTAMPTZ,
    CONSTRAINT key_is_derived_from_job CHECK (idempotency_key = 'alert:' || job_id::text)
);

CREATE INDEX alert_outbox_pending_idx ON alert_outbox (available_at, id) WHERE status = 'PENDING';

-- Sender-side events, for the same durable metrics table.
ALTER TABLE queue_event DROP CONSTRAINT queue_event_kind_check;
ALTER TABLE queue_event ADD CONSTRAINT queue_event_kind_check CHECK (kind IN (
    'LEASE_EXPIRED', 'FENCED_WRITE', 'LEASE_LOST', 'RETRY', 'DEAD_LETTERED',
    'ALERT_DELIVERED',     -- webhook answered 2xx; detail = accepted | duplicate
    'ALERT_SEND_FAILED')); -- network error / non-2xx; retried with backoff
