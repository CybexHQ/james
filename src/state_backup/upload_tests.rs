//! The upload client against a fake Manage: the signed contract, a repeated
//! and a conflicting upload, an older Manage without the route, retries with
//! back-off, and the `local_health` facts.
use std::{
    fs,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, Method as AxumMethod, StatusCode as AxumStatus, Uri},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, SigningKey, Verifier};

use super::*;

const SECRET: [u8; 32] = [7u8; 32];

#[derive(Default)]
struct FakeManage {
    /// Statuses answered before storing, in order.
    fail_with: Vec<u16>,
    stored: BTreeMap<String, String>,
    requests: Vec<Seen>,
}

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    sha256: Option<String>,
    created_at: Option<String>,
    format: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
    signed: bool,
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn signature_valid(method: &str, path: &str, headers: &HeaderMap, body: &[u8]) -> bool {
    let (Some(timestamp), Some(request_id), Some(signature), Some(device)) = (
        header(headers, "x-tiaris-timestamp"),
        header(headers, "x-tiaris-request-id"),
        header(headers, "x-tiaris-signature"),
        header(headers, "x-tiaris-device-id"),
    ) else {
        return false;
    };
    let Ok(signature) = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ())
        .and_then(|bytes| Signature::from_slice(&bytes).map_err(|_| ()))
    else {
        return false;
    };
    let canonical = crate::manage::canonical_agent_payload(
        method,
        path,
        &timestamp,
        &request_id,
        &hex::encode(Sha256::digest(body)),
    );
    device == "nest-1"
        && header(headers, "x-tiaris-organization").as_deref() == Some("org-1")
        && SigningKey::from_bytes(&SECRET)
            .verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .is_ok()
}

async fn serve(state: Arc<Mutex<FakeManage>>) -> String {
    let app = Router::new().fallback(
        move |method: AxumMethod, uri: Uri, headers: HeaderMap, body: Bytes| {
            let state = state.clone();
            async move {
                let mut server = state.lock().unwrap();
                let path = uri.path().to_string();
                server.requests.push(Seen {
                    path: path.clone(),
                    sha256: header(&headers, "x-tiaris-backup-sha256"),
                    created_at: header(&headers, "x-tiaris-backup-created-at"),
                    format: header(&headers, "x-tiaris-backup-format"),
                    content_type: header(&headers, "content-type"),
                    body: body.to_vec(),
                    signed: signature_valid(method.as_str(), &path, &headers, &body),
                });
                if !server.fail_with.is_empty() {
                    let status = server.fail_with.remove(0);
                    return (AxumStatus::from_u16(status).unwrap(), String::new());
                }
                let Some(id) = path.strip_prefix("/v1/agent/nest/state-backups/") else {
                    return (AxumStatus::NOT_FOUND, String::new());
                };
                let digest = hex::encode(Sha256::digest(&body));
                if method != AxumMethod::PUT
                    || header(&headers, "x-tiaris-backup-sha256").as_deref()
                        != Some(digest.as_str())
                {
                    return (AxumStatus::BAD_REQUEST, String::new());
                }
                match server.stored.get(id) {
                    Some(stored) if stored != &digest => {
                        return (AxumStatus::CONFLICT, String::new());
                    }
                    _ => {}
                }
                server.stored.insert(id.to_owned(), digest.clone());
                let receipt = json!({
                    "backup_id": id, "sha256": digest, "size_bytes": body.len(),
                    "stored_at": "2026-11-14T03:00:05Z",
                });
                (AxumStatus::OK, receipt.to_string())
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

struct Fixture {
    root: PathBuf,
    uploader: Uploader,
    server: Arc<Mutex<FakeManage>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

async fn fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "tiaris-state-backup-upload-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let (backup_dir, data_dir) = (root.join("backups"), root.join("agent"));
    fs::create_dir_all(&backup_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();
    fs::write(
        data_dir.join("manage-state.json"),
        json!({"device_id": "nest-1", "private_key_b64": STANDARD.encode(SECRET)}).to_string(),
    )
    .unwrap();
    let server = Arc::new(Mutex::new(FakeManage::default()));
    let mut config = AppConfig::default();
    config.manage.enabled = true;
    config.manage.api_url = serve(server.clone()).await;
    config.manage.organization_id = "org-1".into();
    config.manage.state_path = data_dir.join("manage-state.json");
    Fixture {
        root,
        uploader: Uploader {
            config,
            backup_dir,
            data_dir,
        },
        server,
    }
}

/// Writes a kept backup as the scheduled run leaves it.
fn kept(fixture: &Fixture, created_at: &str, body: &[u8]) -> BackupFile {
    let record = BackupFile {
        schema: schedule::FILE_SCHEMA.into(),
        backup_id: uuid::Uuid::new_v4().hyphenated().to_string(),
        created_at: created_at.into(),
        sha256: hex::encode(Sha256::digest(body)),
        size_bytes: body.len() as u64,
        recipient_fingerprint: "ab".repeat(32),
    };
    let dir = &fixture.uploader.backup_dir;
    fs::write(record.path(dir), body).unwrap();
    fs::write(
        dir.join(format!("{}.json", record.backup_id)),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    record
}

fn at(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .unwrap()
        .with_timezone(&Utc)
}

fn requests(fixture: &Fixture) -> Vec<Seen> {
    fixture.server.lock().unwrap().requests.clone()
}

fn health_of(fixture: &Fixture, uploads: &Uploads) -> Health {
    facts(
        true,
        &schedule::list(&fixture.uploader.backup_dir),
        uploads,
        None,
    )
}

#[tokio::test]
async fn a_backup_uploads_once_as_a_signed_request_with_the_contract_headers() {
    let fixture = fixture().await;
    let older = kept(
        &fixture,
        "2026-11-13T03:00:00+00:00",
        b"older encrypted bytes",
    );
    let newest = kept(
        &fixture,
        "2026-11-14T03:00:00+00:00",
        b"newest encrypted bytes",
    );
    let now = at("2026-11-14T04:00:00Z");

    let uploads = pass(&fixture.uploader, now).await.unwrap();
    let seen = requests(&fixture);
    assert_eq!(seen.len(), 2, "{seen:?}");
    // Newest first.
    assert_eq!(
        seen[0].path,
        format!("/v1/agent/nest/state-backups/{}", newest.backup_id)
    );
    assert_eq!(seen[0].body, b"newest encrypted bytes");
    assert_eq!(seen[0].sha256.as_deref(), Some(newest.sha256.as_str()));
    assert_eq!(
        seen[0].created_at.as_deref(),
        Some("2026-11-14T03:00:00+00:00")
    );
    assert_eq!(seen[0].format.as_deref(), Some(FORMAT));
    assert_eq!(
        seen[0].content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert!(seen.iter().all(|request| request.signed), "{seen:?}");
    let last = uploads.last_uploaded.clone().unwrap();
    assert_eq!(last.backup_id, newest.backup_id);
    assert_eq!(last.stored_at, "2026-11-14T03:00:05Z");
    assert_eq!(uploads.backups[&older.backup_id].status, Status::Uploaded);

    // Recorded: the next pass sends nothing.
    pass(&fixture.uploader, now).await.unwrap();
    assert_eq!(requests(&fixture).len(), 2);
    let health = health_of(&fixture, &load(&fixture.uploader.data_dir));
    assert_eq!(health.fact["status"], "uploaded");
    assert_eq!(health.fact["last_uploaded"]["backup_id"], newest.backup_id);
    assert_eq!(health.fact["last_local"]["backup_id"], newest.backup_id);
    assert!(health.attention.is_empty());

    // A lost record sends again; Manage answers the same receipt (idempotent).
    fs::remove_file(fixture.uploader.data_dir.join(UPLOADS)).unwrap();
    let again = pass(&fixture.uploader, now).await.unwrap();
    assert_eq!(requests(&fixture).len(), 4);
    assert_eq!(again.last_uploaded.unwrap().backup_id, newest.backup_id);

    // Retention removed the older backup: its record goes too.
    fs::remove_file(
        fixture
            .uploader
            .backup_dir
            .join(format!("{}.json", older.backup_id)),
    )
    .unwrap();
    let pruned = pass(&fixture.uploader, now).await.unwrap();
    assert!(!pruned.backups.contains_key(&older.backup_id));
    assert_eq!(requests(&fixture).len(), 4);
}

#[tokio::test]
async fn a_conflicting_digest_is_not_retried_and_is_attention() {
    let fixture = fixture().await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", b"our bytes");
    fixture
        .server
        .lock()
        .unwrap()
        .stored
        .insert(file.backup_id.clone(), "00".repeat(32));
    let now = at("2026-11-14T04:00:00Z");
    let uploads = pass(&fixture.uploader, now).await.unwrap();
    let attempt = &uploads.backups[&file.backup_id];
    assert_eq!(attempt.status, Status::Conflict);
    assert_eq!(attempt.last_error.as_deref(), Some("conflict"));
    assert_eq!(attempt.next_attempt_at, None);
    pass(&fixture.uploader, now + chrono::Duration::days(2))
        .await
        .unwrap();
    assert_eq!(requests(&fixture).len(), 1, "a conflict is never resent");
    let health = health_of(&fixture, &uploads);
    assert_eq!(health.fact["status"], "failing");
    assert_eq!(health.attention, ["backup_upload_failing"]);
}

#[tokio::test]
async fn an_older_manage_without_the_route_is_asked_once_a_day() {
    for status in [404u16, 405] {
        let fixture = fixture().await;
        kept(&fixture, "2026-11-13T03:00:00+00:00", b"one");
        let newest = kept(&fixture, "2026-11-14T03:00:00+00:00", b"two");
        fixture.server.lock().unwrap().fail_with = vec![status];
        let now = at("2026-11-14T04:00:00Z");
        let uploads = pass(&fixture.uploader, now).await.unwrap();
        // One request, then it stops asking: not an error loop.
        assert_eq!(requests(&fixture).len(), 1);
        assert_eq!(uploads.unsupported_since, Some(now));
        let health = health_of(&fixture, &uploads);
        assert_eq!(health.fact["status"], "unsupported");
        assert!(health.attention.is_empty(), "{:?}", health.attention);
        // Local backups stay.
        assert_eq!(schedule::list(&fixture.uploader.backup_dir).len(), 2);

        pass(&fixture.uploader, now + chrono::Duration::hours(23))
            .await
            .unwrap();
        assert_eq!(requests(&fixture).len(), 1);
        // A day later Manage has the route: both upload, the state clears.
        let later = pass(&fixture.uploader, now + chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(requests(&fixture).len(), 3);
        assert_eq!(later.unsupported_since, None);
        assert_eq!(later.last_uploaded.unwrap().backup_id, newest.backup_id);
    }
}

#[tokio::test]
async fn server_errors_retry_with_back_off_and_become_attention() {
    let fixture = fixture().await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", b"bytes");
    fixture.server.lock().unwrap().fail_with = vec![503, 500, 502];
    let mut now = at("2026-11-14T04:00:00Z");
    let mut waits = Vec::new();
    for attempt in 1..=3u32 {
        let uploads = pass(&fixture.uploader, now).await.unwrap();
        let record = &uploads.backups[&file.backup_id];
        assert_eq!(record.status, Status::Failing);
        assert_eq!(record.attempts, attempt);
        assert!(record.last_error.as_deref().unwrap().starts_with("http_5"));
        let next = record.next_attempt_at.unwrap();
        waits.push((next - now).num_seconds());
        // Not due yet: nothing is sent.
        pass(&fixture.uploader, next - chrono::Duration::seconds(1))
            .await
            .unwrap();
        assert_eq!(requests(&fixture).len(), attempt as usize);
        let health = health_of(&fixture, &uploads);
        if attempt < FAILING_AFTER_ATTEMPTS {
            assert_eq!(health.fact["status"], "pending");
            assert!(health.attention.is_empty());
        } else {
            assert_eq!(health.fact["status"], "failing");
            assert_eq!(health.attention, ["backup_upload_failing"]);
            assert_eq!(health.fact["last_error"], "http_502");
        }
        now = next;
    }
    assert_eq!(waits, [60, 120, 240]);
    let uploads = pass(&fixture.uploader, now).await.unwrap();
    assert_eq!(uploads.backups[&file.backup_id].status, Status::Uploaded);
    assert!(health_of(&fixture, &uploads).attention.is_empty());
    assert_eq!(backoff(40).num_seconds(), BACKOFF_MAX_SECONDS);
}

#[tokio::test]
async fn an_unreachable_manage_is_retried() {
    let mut fixture = fixture().await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", b"bytes");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    fixture.uploader.config.manage.api_url = format!("http://127.0.0.1:{port}");
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    let attempt = &uploads.backups[&file.backup_id];
    assert_eq!(attempt.status, Status::Failing);
    assert_eq!(attempt.last_error.as_deref(), Some("network"));
}

#[tokio::test]
async fn a_damaged_or_oversized_backup_is_never_sent() {
    let fixture = fixture().await;
    let damaged = kept(&fixture, "2026-11-14T03:00:00+00:00", b"original");
    fs::write(damaged.path(&fixture.uploader.backup_dir), b"altered!").unwrap();
    // Sparse: no 257 MiB are written.
    let large = kept(&fixture, "2026-11-13T03:00:00+00:00", b"");
    let mut record = large.clone();
    record.size_bytes = MAX_UPLOAD_BYTES + 1;
    fs::File::options()
        .write(true)
        .open(large.path(&fixture.uploader.backup_dir))
        .unwrap()
        .set_len(record.size_bytes)
        .unwrap();
    fs::write(
        fixture
            .uploader
            .backup_dir
            .join(format!("{}.json", large.backup_id)),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    assert_eq!(uploads.backups[&damaged.backup_id].status, Status::Damaged);
    assert_eq!(uploads.backups[&large.backup_id].status, Status::TooLarge);
    assert!(requests(&fixture).is_empty());
    assert_eq!(
        health_of(&fixture, &uploads).attention,
        ["backup_upload_failing"]
    );
}

#[test]
fn health_names_a_missing_key_and_reports_bounded_facts() {
    let none = facts(false, &[], &Uploads::default(), None);
    assert_eq!(none.attention, ["backup_key_missing"]);
    assert_eq!(none.fact["status"], "none");
    assert_eq!(none.fact["key_configured"], false);
    assert_eq!(none.fact["last_local"], Value::Null);
    assert_eq!(none.fact["last_uploaded"], Value::Null);

    let file = BackupFile {
        schema: schedule::FILE_SCHEMA.into(),
        backup_id: "0b6c4a4e-8d0f-4c55-9a51-6c1f3b7a2d10".into(),
        created_at: "2026-11-14T03:00:00+00:00".into(),
        sha256: "cd".repeat(32),
        size_bytes: 4096,
        recipient_fingerprint: "ab".repeat(32),
    };
    let pending = facts(
        true,
        std::slice::from_ref(&file),
        &Uploads::default(),
        Some(json!({"at": "2026-11-14T03:00:00Z", "outcome": "backed_up"})),
    );
    assert!(pending.attention.is_empty());
    assert_eq!(pending.fact["status"], "pending");
    assert_eq!(pending.fact["kept"], 1);
    assert_eq!(pending.fact["last_local"]["size_bytes"], 4096);
    assert_eq!(pending.fact["last_run"]["outcome"], "backed_up");
    // Nothing secret or unbounded: no digest, fingerprint or path.
    let text = pending.fact.to_string();
    assert!(!text.contains(&file.sha256) && !text.contains(&file.recipient_fingerprint));
}
