-- Nest-driven software updates: vulnerability scans of update candidates.
--
-- Manage names the release an update-only candidate was prepared from
-- (`software_update.release_blueprint_revision_id` on the build job). Nest
-- keeps it by managed job, because the build spec itself is the cohort
-- identity and carries no such field.
CREATE TABLE IF NOT EXISTS software_update_candidate_hints (
    managed_job_id TEXT PRIMARY KEY NOT NULL,
    release_blueprint_revision_id TEXT NOT NULL
);

-- One scan per candidate (commit and Blueprint revision). A failed scan
-- keeps its reason and is retried at most daily, three attempts in all; it
-- never produces a finding. Advisories are those the candidate no longer
-- has; package delivery is the status of the job's App List package refs at
-- the commit.
CREATE TABLE IF NOT EXISTS software_update_scans (
    commit_rev TEXT NOT NULL CHECK (length(commit_rev) = 40),
    blueprint_revision_id TEXT NOT NULL,
    candidate_job_id INTEGER NOT NULL,
    release_job_id INTEGER,
    state TEXT NOT NULL CHECK (state IN ('succeeded', 'failed')),
    reason TEXT,
    detail TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 1,
    advisories TEXT NOT NULL DEFAULT '[]',
    package_delivery TEXT NOT NULL DEFAULT '[]',
    scanned_at TEXT NOT NULL,
    PRIMARY KEY (commit_rev, blueprint_revision_id),
    CHECK ((state = 'succeeded') = (reason IS NULL))
);
