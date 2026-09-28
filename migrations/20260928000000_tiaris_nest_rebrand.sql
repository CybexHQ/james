-- Preserve applied SQLx history. Only the new Nest namespace remains active.

ALTER TABLE james_build_jobs RENAME TO nest_build_jobs;

ALTER TABLE james_cache_artifacts RENAME TO nest_cache_artifacts;

ALTER TABLE james_boot_sessions RENAME TO nest_boot_sessions;

DROP INDEX idx_james_build_jobs_status_updated;

CREATE INDEX idx_nest_build_jobs_status_updated
ON nest_build_jobs(status, updated_at DESC);

DROP INDEX idx_james_cache_artifacts_created;

CREATE INDEX idx_nest_cache_artifacts_created
ON nest_cache_artifacts(created_at DESC);

DROP TRIGGER james_cache_inventory_insert;

CREATE TRIGGER nest_cache_inventory_insert
AFTER INSERT ON nest_cache_artifacts
BEGIN
    UPDATE cache_inventory_state SET generation = generation + 1 WHERE singleton = 1;
END;

DROP TRIGGER james_cache_inventory_update;

CREATE TRIGGER nest_cache_inventory_update
AFTER UPDATE ON nest_cache_artifacts
BEGIN
    UPDATE cache_inventory_state SET generation = generation + 1 WHERE singleton = 1;
END;

DROP TRIGGER james_cache_inventory_delete;

CREATE TRIGGER nest_cache_inventory_delete
AFTER DELETE ON nest_cache_artifacts
BEGIN
    UPDATE cache_inventory_state SET generation = generation + 1 WHERE singleton = 1;
END;

DROP INDEX idx_james_cache_artifacts_verification;

CREATE INDEX idx_nest_cache_artifacts_verification
    ON nest_cache_artifacts(last_verified_at, created_at, id);

DROP INDEX idx_james_boot_sessions_cleanup;

CREATE INDEX idx_nest_boot_sessions_cleanup ON nest_boot_sessions(cleanup_after);

DROP INDEX idx_james_boot_sessions_multicast_join_token;

CREATE UNIQUE INDEX idx_nest_boot_sessions_multicast_join_token
    ON nest_boot_sessions(multicast_join_token_sha256)
    WHERE multicast_join_token_sha256 IS NOT NULL;

-- SQLite cannot alter a CHECK constraint. Preserve every child assignment
-- explicitly: dropping the original parent otherwise invokes ON DELETE SET NULL.
CREATE TEMP TABLE tiaris_device_boot_assignments AS
SELECT id, default_profile_id, one_time_profile_id, last_selected_profile_id FROM devices;
CREATE TEMP TABLE tiaris_boot_event_assignments AS
SELECT id, selected_profile_id FROM boot_events;
CREATE TEMP TABLE tiaris_boot_profile_sequence AS
SELECT seq FROM sqlite_sequence WHERE name='boot_profiles';
CREATE TABLE tiaris_boot_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    profile_type TEXT NOT NULL CHECK (profile_type IN ('local_disk', 'nest_installer', 'custom_ipxe')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    one_time INTEGER NOT NULL DEFAULT 0 CHECK (one_time IN (0, 1)),
    raw_script TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    managed_profile_id TEXT
);
INSERT INTO tiaris_boot_profiles
SELECT id, name, description,
       CASE profile_type WHEN 'james_installer' THEN 'nest_installer' ELSE profile_type END,
       enabled, is_default, one_time, raw_script, created_at, updated_at, managed_profile_id
FROM boot_profiles;
DROP TABLE boot_profiles;
ALTER TABLE tiaris_boot_profiles RENAME TO boot_profiles;
UPDATE sqlite_sequence SET seq=MAX(seq,COALESCE((SELECT seq FROM tiaris_boot_profile_sequence),0))
WHERE name='boot_profiles';
INSERT INTO sqlite_sequence (name,seq)
SELECT 'boot_profiles',seq FROM tiaris_boot_profile_sequence
WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='boot_profiles');
DROP TABLE tiaris_boot_profile_sequence;
CREATE UNIQUE INDEX idx_boot_profiles_single_default ON boot_profiles(is_default) WHERE is_default=1;
CREATE UNIQUE INDEX idx_boot_profiles_managed_profile_id ON boot_profiles(managed_profile_id) WHERE managed_profile_id IS NOT NULL;
UPDATE devices SET
    default_profile_id=(SELECT default_profile_id FROM tiaris_device_boot_assignments a WHERE a.id=devices.id),
    one_time_profile_id=(SELECT one_time_profile_id FROM tiaris_device_boot_assignments a WHERE a.id=devices.id),
    last_selected_profile_id=(SELECT last_selected_profile_id FROM tiaris_device_boot_assignments a WHERE a.id=devices.id);
UPDATE boot_events SET selected_profile_id=(SELECT selected_profile_id FROM tiaris_boot_event_assignments a WHERE a.id=boot_events.id);
DROP TABLE tiaris_device_boot_assignments;
DROP TABLE tiaris_boot_event_assignments;
