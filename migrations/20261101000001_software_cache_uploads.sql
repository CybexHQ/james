-- Off-site downloads: what this Nest may upload to its organization's tree
-- of the Tiaris software cache. Each row is one Manage-signed upload grant
-- (`tug1.<payload>.<mac>`) from `software_cache.upload.grants`; the grants
-- Manage stops sending are removed. `grant_id` is the first 32 hex of the
-- SHA-256 of the encoded payload, as the cache server names it; `tree` is
-- `<issuer>/<scope>` of the organization tree it is for.
CREATE TABLE IF NOT EXISTS software_cache_upload_grants (
    grant_id TEXT PRIMARY KEY NOT NULL CHECK (length(grant_id) = 32),
    grant_text TEXT NOT NULL,
    manifest_id TEXT,
    tree TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'uploading', 'uploaded', 'failed', 'expired')),
    registered INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    bytes_uploaded INTEGER NOT NULL DEFAULT 0,
    received_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Per granted item (`<hash>.narinfo` for a store path, or a file path such
-- as `manage-source/<rev>.tar`): uploaded, or refused for good.
CREATE TABLE IF NOT EXISTS software_cache_upload_items (
    grant_id TEXT NOT NULL REFERENCES software_cache_upload_grants(grant_id) ON DELETE CASCADE,
    item TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('uploaded', 'failed')),
    error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (grant_id, item)
);
