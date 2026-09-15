CREATE TABLE IF NOT EXISTS wake_on_lan_receipts (
    request_id TEXT PRIMARY KEY NOT NULL,
    mac TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('sent', 'failed')),
    error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wake_on_lan_receipts_updated
    ON wake_on_lan_receipts(updated_at, request_id);
