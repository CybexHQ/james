//! Exercise the HTTP route, SQLite-backed application state and durable
//! egress record together, without an appliance or external service.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use std::{fs, path::PathBuf};
use tiaris_nest::{AppState, cache, config::AppConfig, db, routes};
use tower::ServiceExt;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn cache_http_totals_and_report_epoch_survive_two_database_reopens() {
    let dir =
        Directory(std::env::temp_dir().join(format!("nest-egress-http-{}", uuid::Uuid::new_v4())));
    let mut config = AppConfig::default();
    config.paths.data_dir = dir.0.join("state");
    config.paths.database_path = dir.0.join("state/nest.sqlite");
    config.cache.root_dir = dir.0.join("cache");
    config.cache.enabled = false; // Reporting disabled cache state still includes egress.
    fs::create_dir_all(&config.paths.data_dir).unwrap();
    fs::create_dir_all(config.cache.root_dir.join("nar")).unwrap();
    let member = format!("nar/{}.nar.zst", "a".repeat(52));
    fs::write(config.cache.root_dir.join(&member), vec![b'n'; 1024]).unwrap();
    let db = db::connect(&config).await.unwrap();
    db::migrate(&db).await.unwrap();
    let state = AppState::new(config.clone(), db.clone());
    let app = routes::router(state.clone());
    for (path, range, status) in [
        (format!("/cache/{member}"), None, StatusCode::OK),
        (
            format!("/cache/{member}"),
            Some("bytes=100-299"),
            StatusCode::PARTIAL_CONTENT,
        ),
        (
            format!("/cache/{}.narinfo", "b".repeat(32)),
            None,
            StatusCode::NOT_FOUND,
        ),
        ("/cache/private-key.pem".into(), None, StatusCode::NOT_FOUND),
        (
            format!("/cache/{member}"),
            Some("bytes=5000-"),
            StatusCode::RANGE_NOT_SATISFIABLE,
        ),
    ] {
        let mut request = Request::builder().uri(path);
        if let Some(range) = range {
            request = request.header("range", range);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        to_bytes(response.into_body(), 2048).await.unwrap();
    }
    let (reported, persisted) = state
        .cache_egress
        .persisted_snapshot(&config.paths.data_dir);
    persisted.unwrap();
    assert_eq!(reported.served_bytes_total, 1224);
    assert_eq!(reported.served_requests_total, 2);
    assert_eq!(reported.missing_requests_total, 1);
    let report = cache::status_report(&config, &db, reported.clone()).await;
    assert_eq!(report.served_bytes_total, reported.served_bytes_total);
    assert_eq!(report.counters_since, reported.counters_since);
    // Unreported transfers may be lost, but already reported totals survive.
    state.cache_egress.record_served(999);
    drop(app);
    drop(state);
    db.close().await;
    let db = db::connect(&config).await.unwrap();
    db::migrate(&db).await.unwrap();
    let restarted = AppState::new(config.clone(), db.clone());
    assert_eq!(restarted.cache_egress.snapshot(), reported);
    restarted.cache_egress.record_served(12);
    restarted.cache_egress.record_missing();
    let (next, persisted) = restarted
        .cache_egress
        .persisted_snapshot(&config.paths.data_dir);
    persisted.unwrap();
    assert_eq!(next.served_bytes_total, 1236);
    assert_eq!(next.served_requests_total, 3);
    assert_eq!(next.missing_requests_total, 2);
    assert_eq!(next.counters_since, reported.counters_since);
    drop(restarted);
    db.close().await;
    let db = db::connect(&config).await.unwrap();
    let restarted = AppState::new(config, db.clone());
    assert_eq!(restarted.cache_egress.snapshot(), next);
    drop(restarted);
    db.close().await;
}
