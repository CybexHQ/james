//! Egress accounting for the unauthenticated `/cache/*` binary-cache route.
//!
//! Tiaris receives these totals inside the `cache` object of every Nest
//! report so workstation closure-transfer telemetry can be reconciled against
//! what this appliance actually served. The totals survive restarts: every
//! report first writes them to the state record `cache-egress.json` (data
//! directory, see `state_files`), and the process resumes from that record,
//! keeping its `counters_since` epoch. Tiaris therefore never sees a total
//! go backwards; what was served after the last report and before a crash
//! is lost. A new epoch starts only without a usable record.

use std::{
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::Result;
use axum::{
    http::{StatusCode, header},
    response::Response,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::{error::AppError, state_files};

/// State record of the persisted totals, in the data directory.
const RECORD: &str = "cache-egress.json";
const RECORD_SCHEMA: &str = "tiaris.nest.cache-egress";
const RECORD_MAX_BYTES: u64 = 4096;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedTotals {
    served_bytes_total: u64,
    served_requests_total: u64,
    missing_requests_total: u64,
    counters_since: DateTime<Utc>,
}

#[derive(Debug)]
pub struct CacheEgressCounters {
    served_bytes: AtomicU64,
    served_requests: AtomicU64,
    missing_requests: AtomicU64,
    counters_since: DateTime<Utc>,
    /// The totals last written to the record, so an idle Nest does not
    /// rewrite it on every report.
    persisted: Mutex<Option<CacheEgressSnapshot>>,
}

/// Point-in-time copy of the counters. Field names are the wire names Tiaris
/// expects inside the report's `cache` object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CacheEgressSnapshot {
    pub served_bytes_total: u64,
    pub served_requests_total: u64,
    pub missing_requests_total: u64,
    /// RFC 3339 (second precision, UTC) process start of the counter epoch.
    pub counters_since: String,
}

/// What a single `/cache/*` request contributes to the counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Egress {
    /// A 200 or 206 response carrying this many body bytes.
    Served(u64),
    /// A well-formed binary-cache member path that is not present locally.
    Missing,
    /// Everything else: garbage paths, unsatisfiable ranges, refused symlinks,
    /// I/O failures. Never counted so probes cannot skew the totals.
    None,
}

impl Default for CacheEgressCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheEgressCounters {
    pub fn new() -> Self {
        Self::starting_at(Utc::now())
    }

    pub fn starting_at(counters_since: DateTime<Utc>) -> Self {
        Self {
            served_bytes: AtomicU64::new(0),
            served_requests: AtomicU64::new(0),
            missing_requests: AtomicU64::new(0),
            counters_since,
            persisted: Mutex::new(None),
        }
    }

    /// The totals persisted in `data_dir`, or a new epoch starting now when
    /// there is no usable record (absent, corrupt, or dated in the future).
    pub fn restore(data_dir: &Path) -> Self {
        Self::restore_at(data_dir, Utc::now())
    }

    fn restore_at(data_dir: &Path, now: DateTime<Utc>) -> Self {
        let Some(totals) =
            state_files::read::<PersistedTotals>(data_dir, RECORD, RECORD_SCHEMA, RECORD_MAX_BYTES)
                .filter(|totals| totals.counters_since <= now + chrono::Duration::days(1))
        else {
            return Self::starting_at(now);
        };
        let counters = Self::starting_at(totals.counters_since);
        counters
            .served_bytes
            .store(totals.served_bytes_total, Ordering::Relaxed);
        counters
            .served_requests
            .store(totals.served_requests_total, Ordering::Relaxed);
        counters
            .missing_requests
            .store(totals.missing_requests_total, Ordering::Relaxed);
        *counters.persisted.lock().expect("egress persistence state") = Some(counters.snapshot());
        counters
    }

    /// A snapshot that is already persisted in `data_dir`: report only what
    /// a restart resumes from. A failed write is returned; the caller logs
    /// it and reports the in-memory totals anyway.
    pub fn persisted_snapshot(&self, data_dir: &Path) -> (CacheEgressSnapshot, Result<()>) {
        let snapshot = self.snapshot();
        let mut persisted = self.persisted.lock().expect("egress persistence state");
        if persisted.as_ref() == Some(&snapshot) {
            return (snapshot, Ok(()));
        }
        let written = state_files::write(
            data_dir,
            RECORD,
            RECORD_SCHEMA,
            RECORD_MAX_BYTES,
            &PersistedTotals {
                served_bytes_total: snapshot.served_bytes_total,
                served_requests_total: snapshot.served_requests_total,
                missing_requests_total: snapshot.missing_requests_total,
                counters_since: self.counters_since,
            },
        );
        if written.is_ok() {
            *persisted = Some(snapshot.clone());
        }
        (snapshot, written)
    }

    pub fn record_served(&self, bytes: u64) {
        saturating_add(&self.served_bytes, bytes);
        saturating_add(&self.served_requests, 1);
    }

    pub fn record_missing(&self) {
        saturating_add(&self.missing_requests, 1);
    }

    pub fn record(&self, egress: Egress) {
        match egress {
            Egress::Served(bytes) => self.record_served(bytes),
            Egress::Missing => self.record_missing(),
            Egress::None => {}
        }
    }

    pub fn snapshot(&self) -> CacheEgressSnapshot {
        CacheEgressSnapshot {
            served_bytes_total: self.served_bytes.load(Ordering::Relaxed),
            served_requests_total: self.served_requests.load(Ordering::Relaxed),
            missing_requests_total: self.missing_requests.load(Ordering::Relaxed),
            counters_since: self
                .counters_since
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }
}

fn saturating_add(counter: &AtomicU64, delta: u64) {
    // The closure always returns `Some`, so `fetch_update` cannot fail; the
    // result is only ignored to keep the call site free of an unused warning.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(delta))
    });
}

/// Decide what a finished `/cache/*` request contributes. `path_valid` is the
/// result of `assets::is_binary_cache_member_path` for the requested path so
/// a 404 for a garbage path is distinguishable from a genuinely missing
/// member; only the latter is a cache miss worth reporting.
pub fn classify_cache_response(result: &Result<Response, AppError>, path_valid: bool) -> Egress {
    match result {
        Ok(response) => match response.status() {
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => {
                Egress::Served(content_length(response))
            }
            _ => Egress::None,
        },
        Err(AppError::NotFound) if path_valid => Egress::Missing,
        Err(_) => Egress::None,
    }
}

fn content_length(response: &Response) -> u64 {
    response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{CacheEgressCounters, CacheEgressSnapshot, Egress, classify_cache_response};
    use crate::error::AppError;
    use axum::{
        body::Body,
        http::{StatusCode, header},
        response::Response,
    };
    use chrono::{TimeZone, Utc};

    fn counters() -> CacheEgressCounters {
        CacheEgressCounters::starting_at(Utc.with_ymd_and_hms(2026, 9, 3, 12, 34, 56).unwrap())
    }

    fn response(status: StatusCode, content_length: Option<&str>) -> Result<Response, AppError> {
        let mut builder = Response::builder().status(status);
        if let Some(length) = content_length {
            builder = builder.header(header::CONTENT_LENGTH, length);
        }
        Ok(builder.body(Body::empty()).unwrap())
    }

    #[test]
    fn fresh_counters_are_zero_and_carry_the_epoch() {
        assert_eq!(
            counters().snapshot(),
            CacheEgressSnapshot {
                served_bytes_total: 0,
                served_requests_total: 0,
                missing_requests_total: 0,
                counters_since: "2026-09-03T12:34:56Z".to_string(),
            }
        );
    }

    #[test]
    fn served_and_missing_accumulate_independently() {
        let counters = counters();

        counters.record_served(1_000);
        counters.record_served(24);
        counters.record_served(0);
        counters.record_missing();
        counters.record(Egress::Served(6));
        counters.record(Egress::Missing);
        counters.record(Egress::None);

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.served_bytes_total, 1_030);
        assert_eq!(snapshot.served_requests_total, 4);
        assert_eq!(snapshot.missing_requests_total, 2);
        assert_eq!(snapshot.counters_since, "2026-09-03T12:34:56Z");
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let counters = counters();

        counters.record_served(u64::MAX - 1);
        counters.record_served(10);
        counters.record_served(u64::MAX);

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.served_bytes_total, u64::MAX);
        assert_eq!(snapshot.served_requests_total, 3);
    }

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tiaris-nest-cache-egress-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn totals_and_their_epoch_survive_a_restart() {
        let dir = TestDir::new("restart");
        let first = counters();
        first.record_served(1_000);
        first.record_missing();
        let (reported, written) = first.persisted_snapshot(dir.path());
        written.unwrap();
        // Served after the last report and before the restart: lost. The
        // restarted totals are exactly what Tiaris last saw, never less.
        first.record_served(5);

        let restarted = CacheEgressCounters::restore(dir.path());
        assert_eq!(restarted.snapshot(), reported);
        restarted.record_served(24);
        let (next, written) = restarted.persisted_snapshot(dir.path());
        written.unwrap();
        assert_eq!(next.served_bytes_total, 1_024);
        assert_eq!(next.served_requests_total, 2);
        assert_eq!(next.missing_requests_total, 1);
        assert_eq!(next.counters_since, "2026-09-03T12:34:56Z");
    }

    #[test]
    fn an_unchanged_snapshot_is_not_rewritten() {
        let dir = TestDir::new("unchanged");
        let counters = counters();
        counters.record_served(7);
        counters.persisted_snapshot(dir.path()).1.unwrap();
        let record = dir.path().join(super::RECORD);
        std::fs::remove_file(&record).unwrap();
        counters.persisted_snapshot(dir.path()).1.unwrap();
        assert!(!record.exists(), "an idle Nest does not rewrite the record");
        counters.record_missing();
        counters.persisted_snapshot(dir.path()).1.unwrap();
        assert!(record.exists());
    }

    #[test]
    fn a_missing_corrupt_or_future_record_starts_a_new_epoch() {
        let dir = TestDir::new("epoch");
        let now = Utc.with_ymd_and_hms(2026, 11, 4, 9, 0, 0).unwrap();
        let fresh = CacheEgressCounters::restore_at(dir.path(), now);
        assert_eq!(fresh.snapshot().counters_since, "2026-11-04T09:00:00Z");
        assert_eq!(fresh.snapshot().served_bytes_total, 0);

        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.path().join(super::RECORD), b"{not json").unwrap();
        let corrupt = CacheEgressCounters::restore_at(dir.path(), now);
        assert_eq!(corrupt.snapshot().served_requests_total, 0);

        let future = CacheEgressCounters::starting_at(now + chrono::Duration::days(30));
        future.record_served(9);
        future.persisted_snapshot(dir.path()).1.unwrap();
        let restored = CacheEgressCounters::restore_at(dir.path(), now);
        assert_eq!(restored.snapshot().served_bytes_total, 0);
        assert_eq!(restored.snapshot().counters_since, "2026-11-04T09:00:00Z");
    }

    #[test]
    fn snapshot_serializes_with_the_manage_wire_names() {
        let counters = counters();
        counters.record_served(7);
        counters.record_missing();

        let json = serde_json::to_value(counters.snapshot()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "served_bytes_total": 7,
                "served_requests_total": 1,
                "missing_requests_total": 1,
                "counters_since": "2026-09-03T12:34:56Z",
            })
        );
    }

    #[test]
    fn full_and_partial_responses_count_their_content_length() {
        assert_eq!(
            classify_cache_response(&response(StatusCode::OK, Some("4096")), true),
            Egress::Served(4096)
        );
        assert_eq!(
            classify_cache_response(&response(StatusCode::PARTIAL_CONTENT, Some("512")), true),
            Egress::Served(512)
        );
        assert_eq!(
            classify_cache_response(&response(StatusCode::OK, None), true),
            Egress::Served(0),
            "a success without Content-Length still counts the request"
        );
        assert_eq!(
            classify_cache_response(&response(StatusCode::OK, Some("not-a-number")), true),
            Egress::Served(0)
        );
    }

    #[test]
    fn unsatisfiable_ranges_and_other_statuses_are_not_counted() {
        assert_eq!(
            classify_cache_response(&response(StatusCode::RANGE_NOT_SATISFIABLE, None), true),
            Egress::None
        );
        assert_eq!(
            classify_cache_response(&response(StatusCode::NOT_MODIFIED, Some("0")), true),
            Egress::None
        );
    }

    #[test]
    fn only_missing_members_with_valid_paths_are_misses() {
        assert_eq!(
            classify_cache_response(&Err(AppError::NotFound), true),
            Egress::Missing
        );
        assert_eq!(
            classify_cache_response(&Err(AppError::NotFound), false),
            Egress::None,
            "garbage paths are refused before the cache is consulted"
        );
        assert_eq!(
            classify_cache_response(&Err(AppError::UnsafePath), true),
            Egress::None
        );
        assert_eq!(
            classify_cache_response(&Err(AppError::Forbidden), true),
            Egress::None
        );
        assert_eq!(
            classify_cache_response(
                &Err(AppError::Io(std::io::Error::other("disk unplugged"))),
                true
            ),
            Egress::None
        );
    }
}
