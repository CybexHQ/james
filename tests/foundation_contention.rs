//! File-backed contention probe for the operations active during first Blueprint preparation.
use std::time::Duration;
use tiaris_nest::{db, models::CreateBuildJobRequest};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foundation_publications_survive_concurrent_file_database_users() {
    let root = std::env::temp_dir().join(format!("nest-foundation-db-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let pool = db::connect_with_url(&format!("sqlite://{}", root.join("state.sqlite").display()))
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let job = db::create_build_job(
        &pool,
        CreateBuildJobRequest {
            requested_artifact_type: "nixos_closure".into(),
            build_spec: None,
            target: Some("desktop_experience".into()),
            system: Some("x86_64-linux".into()),
            input_revision: "foundation-probe".into(),
            input_config_hash: "a".repeat(64),
            cache_metadata: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        db::claim_next_build_job(&pool).await.unwrap().unwrap().id,
        job.id
    );
    let mut tasks = tokio::task::JoinSet::new();
    for lane in 0..8 {
        let pool = pool.clone();
        tasks.spawn(async move {
            for round in 0..100 {
                match lane % 4 {
                    0 => {
                        db::update_build_job_logs(
                            &pool,
                            job.id,
                            &format!("build output {round}\n").repeat(1000),
                        )
                        .await
                        .unwrap();
                    }
                    1 => {
                        db::update_build_job_progress(
                            &pool,
                            job.id,
                            Some(42),
                            "building",
                            "Building closure",
                        )
                        .await
                        .unwrap();
                    }
                    2 => {
                        assert_eq!(db::get_build_job(&pool, job.id).await.unwrap().status, "running");
                    }
                    _ => {
                        db::create_cache_artifact(&pool, serde_json::from_value(serde_json::json!({
                            "artifact_type": "nixos_closure", "hash": "b".repeat(64), "size_bytes": 1,
                            "path": "/disposable/cache/concurrent-closure"
                        })).unwrap()).await.unwrap();
                    }
                }
                assert_eq!(
                    db::get_build_job(&pool, job.id).await.unwrap().status,
                    "running"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    pool.close().await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foundation_progress_survives_a_writer_longer_than_sqlite_busy_timeout() {
    let root = std::env::temp_dir().join(format!("nest-foundation-delay-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let url = format!("sqlite://{}", root.join("state.sqlite").display());
    let pool = db::connect_with_url(&url).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let job = db::create_build_job(
        &pool,
        CreateBuildJobRequest {
            requested_artifact_type: "nixos_closure".into(),
            build_spec: None,
            target: Some("desktop_experience".into()),
            system: Some("x86_64-linux".into()),
            input_revision: "foundation-delayed-commit".into(),
            input_config_hash: "c".repeat(64),
            cache_metadata: None,
        },
    )
    .await
    .unwrap();
    db::claim_next_build_job(&pool).await.unwrap().unwrap();
    let finishing = db::create_build_job(
        &pool,
        CreateBuildJobRequest {
            requested_artifact_type: "nixos_closure".into(),
            build_spec: None,
            target: Some("desktop_experience".into()),
            system: Some("x86_64-linux".into()),
            input_revision: "foundation-cancellation-race".into(),
            input_config_hash: "d".repeat(64),
            cache_metadata: None,
        },
    )
    .await
    .unwrap();
    db::claim_next_build_job(&pool).await.unwrap().unwrap();
    let writer = db::connect_with_url(&url).await.unwrap();
    let mut transaction = writer.begin().await.unwrap();
    sqlx::query("UPDATE boot_profiles SET is_default = 0")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE nest_build_jobs SET cancel_requested_at = '2026-10-11T00:00:00Z' WHERE id = ?",
    )
    .bind(finishing.id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    let log_write = tokio::spawn({
        let pool = pool.clone();
        async move { db::update_build_job_logs(&pool, job.id, "retained completed-build output").await }
    });
    let finish = tokio::spawn({
        let pool = pool.clone();
        async move {
            db::finish_build_job(
                &pool,
                finishing.id,
                "succeeded",
                "completed",
                "",
                "",
                "",
                0,
                Some(0),
                None,
            )
            .await
        }
    });
    let cache_write = tokio::spawn({
        let pool = pool.clone();
        async move {
            db::create_cache_artifact(
                &pool,
                serde_json::from_value(serde_json::json!({
                    "artifact_type": "nixos_closure", "hash": "e".repeat(64), "size_bytes": 1,
                    "path": "/disposable/cache/closure"
                }))
                .unwrap(),
            )
            .await
        }
    });
    let publication = tokio::spawn({
        let pool = pool.clone();
        async move {
            db::update_build_job_progress(
                &pool,
                job.id,
                Some(80),
                "inspecting",
                "Inspecting build output",
            )
            .await
        }
    });
    // The live WAL fsync held this same write lock for 31 seconds. Six seconds
    // deterministically crosses the unchanged five-second SQLite busy timeout.
    tokio::time::sleep(Duration::from_secs(6)).await;
    transaction.commit().await.unwrap();
    let result = publication.await.unwrap();
    let logs = log_write.await.unwrap();
    let finished = finish.await.unwrap();
    let cached = cache_write.await.unwrap();
    let state = db::get_build_job(&pool, job.id).await.unwrap();
    writer.close().await;
    pool.close().await;
    std::fs::remove_dir_all(root).unwrap();
    result.expect("Transient WAL commit contention must not discard the completed build");
    logs.expect("Completed-build logs survive transient contention");
    assert_eq!(
        finished
            .expect("Terminal publication survives contention")
            .status,
        "cancelled"
    );
    assert_eq!(
        cached.expect("Cache publication survives contention").hash,
        "e".repeat(64)
    );
    assert_eq!(state.logs, "retained completed-build output");
    assert_eq!(state.status, "running");
    assert_eq!(state.progress_percent, Some(80));
}
