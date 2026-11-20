-- The webhook's own dedup store. The PRIMARY KEY on idempotency_key is what makes
-- deduplication durable: it survives webhook restarts and is race-free under
-- concurrent deliveries (INSERT ... ON CONFLICT DO NOTHING).

CREATE TABLE received_alert (
    idempotency_key   TEXT        PRIMARY KEY,
    payload           JSONB       NOT NULL,
    first_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivery_count    INT         NOT NULL DEFAULT 1      -- 1 + number of duplicates rejected
);

-- One row per HTTP delivery, so duplicates rejected can be counted (the metric).
CREATE TABLE delivery_log (
    id              BIGSERIAL   PRIMARY KEY,
    idempotency_key TEXT        NOT NULL,
    outcome         TEXT        NOT NULL CHECK (outcome IN ('ACCEPTED', 'DUPLICATE_REJECTED')),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX delivery_log_outcome_idx ON delivery_log (outcome);
