//! A failed Nest build job logs its persisted reason, without secrets.
//!
//! This lives in its own test binary on purpose. `tracing` caches each callsite's
//! interest process-wide: when another test thread registers the same `warn!`
//! callsite while this test installs its scoped subscriber, the callsite can be
//! cached as disabled and the event never reaches this subscriber. That made the
//! test fail in about one of three runs inside the library test binary.
use serde_json::json;
use std::sync::{Arc, Mutex};
use tiaris_nest::db::{
    claim_next_build_job, connect_with_url, create_build_job, finish_build_job, migrate,
};
use tiaris_nest::models::CreateBuildJobRequest;
use tracing::instrument::WithSubscriber;

#[derive(Clone)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn terminal_build_failure_logs_the_persisted_reason_without_secrets() {
    let log = Log(Arc::new(Mutex::new(Vec::new())));
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    let pool = connect_with_url("sqlite::memory:").await.unwrap();
    migrate(&pool).await.unwrap();
    let job = create_build_job(
        &pool,
        CreateBuildJobRequest {
            requested_artifact_type: "nixos_closure".into(),
            build_spec: None,
            target: Some("desktop_experience".into()),
            system: Some("x86_64-linux".into()),
            input_revision: "failed-installation".into(),
            input_config_hash: "a".repeat(64),
            cache_metadata: None,
        },
    )
    .await
    .unwrap();
    claim_next_build_job(&pool).await.unwrap().unwrap();
    let finished = finish_build_job(
        &pool,
        job.id,
        "failed",
        "",
        "Blocked: cage-0.3.0 would compile from source; token=private-test-token",
        "",
        "",
        0,
        None,
        Some(json!({"error_kind": "source_build_blocked"})),
    )
    .with_subscriber(subscriber)
    .await
    .unwrap();
    assert_eq!(finished.status, "failed");
    let output = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("Nest build job failed"), "{output}");
    assert!(output.contains(&format!("job_id={}", job.id)), "{output}");
    assert!(output.contains("source_build_blocked"), "{output}");
    assert!(
        output.contains("cage-0.3.0 would compile from source"),
        "{output}"
    );
    assert!(!output.contains("private-test-token"), "{output}");
}
