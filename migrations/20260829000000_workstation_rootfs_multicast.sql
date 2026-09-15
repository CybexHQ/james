ALTER TABLE james_boot_sessions ADD COLUMN multicast_join_token_sha256 TEXT;
ALTER TABLE james_boot_sessions ADD COLUMN multicast_finalized_at TEXT;

CREATE UNIQUE INDEX idx_james_boot_sessions_multicast_join_token
    ON james_boot_sessions(multicast_join_token_sha256)
    WHERE multicast_join_token_sha256 IS NOT NULL;

CREATE TABLE workstation_multicast_policy (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    generation INTEGER NOT NULL DEFAULT -1 CHECK (generation >= -1),
    policy_sha256 TEXT NOT NULL DEFAULT '',
    policy_json TEXT,
    lane_authorized INTEGER NOT NULL DEFAULT 0 CHECK (lane_authorized IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO workstation_multicast_policy(singleton_id) VALUES (1);

CREATE TABLE workstation_multicast_transfers (
    transfer_id TEXT PRIMARY KEY,
    bundle_sha256 TEXT NOT NULL,
    component_sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    interface_fingerprint TEXT NOT NULL,
    policy_generation INTEGER NOT NULL CHECK (policy_generation >= 0),
    state TEXT NOT NULL CHECK (state IN (
        'gathering', 'sender_starting', 'sending', 'completed', 'failed',
        'interrupted', 'cooldown'
    )),
    registered_sessions INTEGER NOT NULL DEFAULT 0 CHECK (registered_sessions >= 0),
    sender_outcome TEXT NOT NULL DEFAULT '',
    started_at TEXT,
    sender_finished_at TEXT,
    receipt_deadline INTEGER,
    finalized_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_workstation_multicast_transfers_state
    ON workstation_multicast_transfers(state, created_at);

CREATE TABLE workstation_multicast_registrations (
    transfer_id TEXT NOT NULL REFERENCES workstation_multicast_transfers(transfer_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES james_boot_sessions(session_id) ON DELETE CASCADE,
    registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    multicast_outcome TEXT,
    fallback_outcome TEXT,
    receipt_recorded_at TEXT,
    PRIMARY KEY (transfer_id, session_id),
    UNIQUE (session_id)
);

CREATE TABLE workstation_multicast_report_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    report_instance_id TEXT NOT NULL DEFAULT '',
    next_event_id INTEGER NOT NULL DEFAULT 1 CHECK (next_event_id > 0),
    acknowledged_through INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_through >= 0),
    events_omitted INTEGER NOT NULL DEFAULT 0 CHECK (events_omitted >= 0),
    late_receipts INTEGER NOT NULL DEFAULT 0 CHECK (late_receipts >= 0),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO workstation_multicast_report_state(singleton_id) VALUES (1);

CREATE TABLE workstation_multicast_report_events (
    event_id INTEGER PRIMARY KEY CHECK (event_id > 0),
    event_json TEXT NOT NULL,
    event_size_bytes INTEGER NOT NULL CHECK (event_size_bytes > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

