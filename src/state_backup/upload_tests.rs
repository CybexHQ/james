//! The upload client against a fake Manage: the signed contract, a repeated
//! and a conflicting upload, an older Manage without the route, retries with
//! back-off, the chunked upload (resume after a failed chunk, the single
//! request to a Manage without chunks), and the `local_health` facts.
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
    /// Bytes per chunk of the chunked upload; 0: Manage has no such routes.
    chunk_bytes: u64,
    /// Open chunked uploads: declared digest and size, chunks received.
    uploads: BTreeMap<String, (String, u64, BTreeMap<u64, Vec<u8>>)>,
    /// A chunk answered once with 503 before it is kept.
    fail_chunk: Option<u64>,
    /// A chunk answered 200 once but not kept.
    lose_chunk: Option<u64>,
}

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    sha256: Option<String>,
    chunk_sha256: Option<String>,
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
                    method: method.to_string(),
                    path: path.clone(),
                    sha256: header(&headers, "x-tiaris-backup-sha256"),
                    chunk_sha256: header(&headers, "x-tiaris-chunk-sha256"),
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
                if let Some((id, step)) = id.split_once('/') {
                    if server.chunk_bytes == 0 {
                        return (AxumStatus::NOT_FOUND, String::new());
                    }
                    return chunked(&mut server, id, step, &headers, &body);
                }
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
    serve_app(app).await
}

fn receipt_json(id: &str, digest: &str, size: usize) -> String {
    json!({
        "backup_id": id, "sha256": digest, "size_bytes": size,
        "stored_at": "2026-11-14T03:00:05Z",
    })
    .to_string()
}

/// The chunked upload's open, chunk and finalize requests.
fn chunked(
    server: &mut FakeManage,
    id: &str,
    step: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> (AxumStatus, String) {
    let chunk_bytes = server.chunk_bytes;
    let status = |server: &FakeManage| {
        let (_, size, chunks) = &server.uploads[id];
        let count = size.div_ceil(chunk_bytes);
        let received: Vec<u64> = chunks.keys().copied().collect();
        let next = (0..count).find(|index| !chunks.contains_key(index));
        json!({
            "backup_id": id, "state": "open", "chunk_bytes": chunk_bytes, "chunk_count": count,
            "received_chunks": received, "next_chunk": next, "expires_at": "2026-11-15T04:00:00Z",
            "receipt": null,
        })
        .to_string()
    };
    if step == "upload" {
        let declared: Value = serde_json::from_slice(body).unwrap();
        let digest = declared["sha256"].as_str().unwrap().to_owned();
        if let Some(stored) = server.stored.get(id) {
            if stored != &digest {
                return (AxumStatus::CONFLICT, String::new());
            }
            let size = declared["size_bytes"].as_u64().unwrap() as usize;
            let receipt: Value = serde_json::from_str(&receipt_json(id, &digest, size)).unwrap();
            let answer = json!({
                "backup_id": id, "state": "stored", "chunk_bytes": chunk_bytes, "chunk_count": 0,
                "received_chunks": [], "next_chunk": null, "expires_at": null, "receipt": receipt,
            });
            return (AxumStatus::OK, answer.to_string());
        }
        server.uploads.entry(id.to_owned()).or_insert((
            digest,
            declared["size_bytes"].as_u64().unwrap(),
            BTreeMap::new(),
        ));
        return (AxumStatus::OK, status(server));
    }
    if let Some(index) = step.strip_prefix("chunks/") {
        let index: u64 = index.parse().unwrap();
        if !server.uploads.contains_key(id)
            || header(headers, "x-tiaris-chunk-sha256").as_deref()
                != Some(hex::encode(Sha256::digest(body)).as_str())
        {
            return (AxumStatus::BAD_REQUEST, String::new());
        }
        if server.fail_chunk == Some(index) {
            server.fail_chunk = None;
            return (AxumStatus::SERVICE_UNAVAILABLE, String::new());
        }
        let lose = server.lose_chunk.take_if(|lost| *lost == index).is_some();
        let chunks = &mut server.uploads.get_mut(id).unwrap().2;
        if chunks.get(&index).is_some_and(|held| held != body) {
            return (AxumStatus::CONFLICT, String::new());
        }
        if !lose {
            chunks.insert(index, body.to_vec());
        }
        return (AxumStatus::OK, status(server));
    }
    let Some((digest, size, chunks)) = server.uploads.get(id).cloned() else {
        return match server.stored.get(id) {
            Some(digest) => (AxumStatus::OK, receipt_json(id, digest, 0)),
            None => (AxumStatus::NOT_FOUND, String::new()),
        };
    };
    let whole: Vec<u8> = chunks.values().flatten().copied().collect();
    if chunks.len() as u64 != size.div_ceil(chunk_bytes) {
        let code = json!({"diagnostic_code": "backup_upload_incomplete"}).to_string();
        return (AxumStatus::CONFLICT, code);
    }
    if hex::encode(Sha256::digest(&whole)) != digest {
        server.uploads.remove(id);
        return (AxumStatus::BAD_REQUEST, String::new());
    }
    server.uploads.remove(id);
    server.stored.insert(id.to_owned(), digest.clone());
    (AxumStatus::OK, receipt_json(id, &digest, whole.len()))
}

async fn serve_app(app: Router) -> String {
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
            single_request_max_bytes: SINGLE_REQUEST_MAX_BYTES,
        },
        server,
    }
}

/// A Manage that takes chunks of `chunk_bytes` (and advertised them in its
/// last configuration), for backups over `single_request_max_bytes`.
async fn chunked_fixture(chunk_bytes: u64, single_request_max_bytes: u64) -> Fixture {
    let mut fixture = fixture().await;
    fixture.server.lock().unwrap().chunk_bytes = chunk_bytes;
    fixture.uploader.single_request_max_bytes = single_request_max_bytes;
    advertise_chunks(&fixture, true);
    fixture
}

fn advertise_chunks(fixture: &Fixture, supported: bool) {
    fs::write(
        fixture.uploader.data_dir.join("manage-state.json"),
        json!({
            "device_id": "nest-1", "private_key_b64": STANDARD.encode(SECRET),
            "last_peer_contract": {
                "supports_scheduling": true, "accepts_uploads": false,
                "accepts_usb_installer": true, "runtime_epoch": true, "report_protocol": 1,
                "accepts_state_backup_chunks": supported,
            },
            "last_peer_contract_at": Utc::now().timestamp(),
        })
        .to_string(),
    )
    .unwrap();
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

const BIG: &[u8] = b"ten bytes!";

fn steps(fixture: &Fixture, file: &BackupFile) -> Vec<String> {
    let prefix = format!("/v1/agent/nest/state-backups/{}", file.backup_id);
    requests(fixture)
        .iter()
        .map(|seen| {
            let rest = seen.path.strip_prefix(&prefix).unwrap_or(&seen.path);
            format!("{} {}", seen.method, rest.trim_start_matches('/'))
        })
        .collect()
}

#[tokio::test]
async fn a_large_backup_goes_in_signed_chunks_with_their_own_digests() {
    let fixture = chunked_fixture(4, 4).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    assert_eq!(uploads.backups[&file.backup_id].status, Status::Uploaded);
    assert_eq!(
        steps(&fixture, &file),
        [
            "POST upload",
            "PUT chunks/0",
            "PUT chunks/1",
            "PUT chunks/2",
            "POST complete"
        ]
    );
    let seen = requests(&fixture);
    assert!(seen.iter().all(|request| request.signed), "{seen:?}");
    // Each chunk is at most one chunk long and carries its own digest.
    let chunks: Vec<&Seen> = seen
        .iter()
        .filter(|seen| seen.path.contains("/chunks/"))
        .collect();
    assert_eq!(
        chunks
            .iter()
            .map(|seen| seen.body.as_slice())
            .collect::<Vec<_>>(),
        [&b"ten "[..], b"byte", b"s!"]
    );
    for chunk in &chunks {
        assert_eq!(
            chunk.chunk_sha256.as_deref(),
            Some(hex::encode(Sha256::digest(&chunk.body)).as_str())
        );
    }
    let declaration: Value = serde_json::from_slice(&seen[0].body).unwrap();
    assert_eq!(declaration["sha256"], file.sha256);
    assert_eq!(declaration["size_bytes"], BIG.len());
    assert_eq!(declaration["created_at"], "2026-11-14T03:00:00+00:00");
    assert_eq!(declaration["format"], FORMAT);
    assert_eq!(
        fixture.server.lock().unwrap().stored.get(&file.backup_id),
        Some(&file.sha256)
    );
    assert_eq!(uploads.last_uploaded.unwrap().size_bytes, BIG.len() as u64);
}

#[tokio::test]
async fn a_failed_chunk_resumes_from_the_first_missing_chunk() {
    let fixture = chunked_fixture(4, 4).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    fixture.server.lock().unwrap().fail_chunk = Some(1);
    let now = at("2026-11-14T04:00:00Z");
    let uploads = pass(&fixture.uploader, now).await.unwrap();
    let attempt = &uploads.backups[&file.backup_id];
    assert_eq!(attempt.status, Status::Failing);
    assert_eq!(attempt.last_error.as_deref(), Some("http_503"));
    assert_eq!(
        steps(&fixture, &file),
        ["POST upload", "PUT chunks/0", "PUT chunks/1"]
    );
    // After the back-off: only the chunks Manage is missing go again.
    let later = pass(&fixture.uploader, now + chrono::Duration::minutes(2))
        .await
        .unwrap();
    assert_eq!(later.backups[&file.backup_id].status, Status::Uploaded);
    assert_eq!(
        steps(&fixture, &file)[3..],
        [
            "POST upload",
            "PUT chunks/1",
            "PUT chunks/2",
            "POST complete"
        ]
    );
    assert_eq!(
        fixture.server.lock().unwrap().stored.get(&file.backup_id),
        Some(&file.sha256)
    );
}

#[tokio::test]
async fn without_manages_chunk_capability_a_large_backup_goes_in_one_request() {
    // Manage has the routes but did not advertise them: one PUT.
    let fixture = chunked_fixture(4, 4).await;
    advertise_chunks(&fixture, false);
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    assert_eq!(uploads.backups[&file.backup_id].status, Status::Uploaded);
    assert_eq!(steps(&fixture, &file), ["PUT "]);
    assert_eq!(requests(&fixture)[0].body, BIG);

    // Advertised, but this Manage (rolled back) answers 404: the same attempt
    // falls back to the single PUT.
    let fixture = chunked_fixture(0, 4).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    assert_eq!(uploads.backups[&file.backup_id].status, Status::Uploaded);
    assert_eq!(uploads.unsupported_since, None);
    assert_eq!(steps(&fixture, &file), ["POST upload", "PUT "]);

    // A small backup goes in one request even to a Manage with chunks.
    let fixture = chunked_fixture(4, 64).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    assert_eq!(steps(&fixture, &file), ["PUT "]);
}

#[tokio::test]
async fn a_chunked_upload_of_a_stored_backup_takes_the_first_receipt() {
    let fixture = chunked_fixture(4, 4).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    fixture
        .server
        .lock()
        .unwrap()
        .stored
        .insert(file.backup_id.clone(), file.sha256.clone());
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    assert_eq!(uploads.backups[&file.backup_id].status, Status::Uploaded);
    assert_eq!(steps(&fixture, &file), ["POST upload"]);

    // Other bytes under that id: a conflict, never retried.
    let fixture = chunked_fixture(4, 4).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    fixture
        .server
        .lock()
        .unwrap()
        .stored
        .insert(file.backup_id.clone(), "00".repeat(32));
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    assert_eq!(uploads.backups[&file.backup_id].status, Status::Conflict);
}

#[tokio::test]
async fn an_upload_open_from_an_earlier_run_sends_only_the_missing_chunks() {
    let fixture = chunked_fixture(4, 4).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    // The Nest restarted after two chunks: it kept no record, Manage did.
    {
        let mut server = fixture.server.lock().unwrap();
        let chunks = BTreeMap::from([(0, b"ten ".to_vec()), (1, b"byte".to_vec())]);
        server
            .uploads
            .insert(file.backup_id.clone(), (file.sha256.clone(), 10, chunks));
    }
    let now = at("2026-11-14T04:00:00Z");
    let uploads = pass(&fixture.uploader, now).await.unwrap();
    // Only chunk 2 is sent, then the upload is finalized.
    assert_eq!(uploads.backups[&file.backup_id].status, Status::Uploaded);
    assert_eq!(
        steps(&fixture, &file),
        ["POST upload", "PUT chunks/2", "POST complete"]
    );
}

#[tokio::test]
async fn an_incomplete_finalize_is_retried_and_not_a_conflict() {
    let fixture = chunked_fixture(4, 4).await;
    let file = kept(&fixture, "2026-11-14T03:00:00+00:00", BIG);
    // Manage answers chunk 1 but does not keep it: finalize says incomplete.
    fixture.server.lock().unwrap().lose_chunk = Some(1);
    let uploads = pass(&fixture.uploader, at("2026-11-14T04:00:00Z"))
        .await
        .unwrap();
    let attempt = &uploads.backups[&file.backup_id];
    assert_eq!(attempt.status, Status::Failing);
    assert_eq!(attempt.last_error.as_deref(), Some("upload_incomplete"));
    assert!(attempt.next_attempt_at.is_some());
}
