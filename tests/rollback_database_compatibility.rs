use cybex_james::db;

#[tokio::test]
async fn rollback_keeps_new_receipts_and_existing_multicast_policy() {
    let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    sqlx::query("INSERT INTO wake_on_lan_receipts VALUES ('after-upgrade', '00:11:22:33:44:55', 'sent', '', '2026-09-17', '2026-09-17')").execute(&pool).await.unwrap();
    sqlx::query("UPDATE workstation_multicast_policy SET generation=7, policy_sha256='retained', lane_authorized=1").execute(&pool).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let receipt: String = sqlx::query_scalar(
        "SELECT state FROM wake_on_lan_receipts WHERE request_id='after-upgrade'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM workstation_multicast_policy WHERE singleton_id=1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(receipt, "sent");
    assert_eq!(generation, 7);
}

#[tokio::test]
async fn rollback_still_rejects_changed_migration_checksums() {
    let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum=x'00' WHERE version=20260901000000")
        .execute(&pool)
        .await
        .unwrap();
    assert!(db::migrate(&pool).await.is_err());
}
