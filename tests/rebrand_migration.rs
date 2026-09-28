//! A populated appliance upgrade must retain boot assignments and signing data.
use sqlx::sqlite::SqlitePoolOptions;
use std::borrow::Cow;

#[tokio::test]
async fn nest_rename_preserves_boot_assignments_and_user_data() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut previous = sqlx::migrate!();
    previous.migrations = Cow::Owned(
        previous
            .iter()
            .filter(|migration| migration.version < 20260928000000)
            .cloned()
            .collect(),
    );
    previous.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO boot_profiles (id,name,description,profile_type,created_at,updated_at,managed_profile_id) VALUES (42,'Preserved install profile','User description','james_installer','2026-09-28','2026-09-28','managed-profile')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO devices (id,mac,hostname,notes,default_profile_id,one_time_profile_id,last_selected_profile_id,created_at,updated_at) VALUES (42,'02:00:00:00:00:42','james-smith','Do not rename user data',42,42,42,'2026-09-28','2026-09-28')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO boot_events (device_id,selected_profile_id,known_device,created_at) VALUES (42,42,1,'2026-09-28')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO boot_profiles (id,name,profile_type,created_at,updated_at) VALUES (1000,'Deleted profile','local_disk','2026-09-28','2026-09-28')")
        .execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM boot_profiles WHERE id=1000")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();
    let device: (String,String,i64,i64,i64) = sqlx::query_as("SELECT hostname,notes,default_profile_id,one_time_profile_id,last_selected_profile_id FROM devices WHERE id=42")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(
        device,
        (
            "james-smith".into(),
            "Do not rename user data".into(),
            42,
            42,
            42
        )
    );
    let profile: String = sqlx::query_scalar("SELECT profile_type FROM boot_profiles WHERE id=42")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(profile, "nest_installer");
    let next_profile: i64 = sqlx::query_scalar("INSERT INTO boot_profiles (name,profile_type,created_at,updated_at) VALUES ('New profile','nest_installer','2026-09-28','2026-09-28') RETURNING id")
        .fetch_one(&pool).await.unwrap();
    assert!(
        next_profile > 1000,
        "renaming must never reuse a deleted profile identity"
    );
    let event: i64 =
        sqlx::query_scalar("SELECT selected_profile_id FROM boot_events WHERE device_id=42")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(event, 42);
    let old_tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name LIKE 'james_%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_tables, 0);
    sqlx::query("SELECT * FROM nest_build_jobs LIMIT 1")
        .fetch_optional(&pool)
        .await
        .unwrap();
    let violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(violations.is_empty());
}
