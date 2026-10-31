-- Nest-driven software updates: NixOS channel commits this Nest has checked.
-- `profile` and `tiaris_derivations` are set only for ready commits; they are
-- the derived build profile the preflight selects by `spec.nixpkgs_commit`.
CREATE TABLE IF NOT EXISTS detected_nixpkgs_commits (
    commit_rev TEXT PRIMARY KEY NOT NULL CHECK (length(commit_rev) = 40),
    channel TEXT NOT NULL,
    last_modified TEXT NOT NULL,
    nar_hash TEXT NOT NULL,
    kernel_version TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('ready', 'blocked')),
    reason TEXT CHECK (
        reason IS NULL
        OR reason IN ('build_script_changed', 'source_build_required', 'evaluation_failed')
    ),
    reason_details TEXT NOT NULL DEFAULT '[]',
    profile TEXT,
    tiaris_derivations TEXT NOT NULL DEFAULT '[]',
    detected_at TEXT NOT NULL,
    CHECK ((state = 'ready') = (reason IS NULL)),
    CHECK (state = 'blocked' OR profile IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_detected_nixpkgs_commits_last_modified
    ON detected_nixpkgs_commits(last_modified DESC, commit_rev);

-- Single row: the channel and on-demand check request Manage last sent, the
-- outcome of the last check, and when a check last completed (reported to
-- Manage as software_update_checked_at).
CREATE TABLE IF NOT EXISTS software_update_check_state (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    channel TEXT,
    check_requested_at TEXT,
    check_handled_at TEXT,
    last_checked_at TEXT,
    last_completed_at TEXT,
    last_error TEXT NOT NULL DEFAULT ''
);
