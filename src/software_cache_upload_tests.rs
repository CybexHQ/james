use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, Method, StatusCode as AxumStatus, Uri},
};
use base64::engine::general_purpose::STANDARD;
use serde_json::json;

use super::*;

const SCOPE: &str = "o-0123456789abcdef0123456789abcdef";
const TOKEN: &str = "tsc2.dev.4102444800.o-0123456789abcdef0123456789abcdef.w.nest-1.MAC";
const REVISION: &str = "4826a578aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

async fn pool() -> SqlitePool {
    let pool = crate::db::connect_with_url("sqlite::memory:")
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let pad = |byte: u8| block.iter().map(|value| value ^ byte).collect::<Vec<_>>();
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

/// One store path in the Nest cache: its NAR file and signed narinfo.
struct CachedPath {
    store_path: String,
    nar_url: String,
    file_hash: String,
    file_size: u64,
    nar_hash: String,
    references: Vec<String>,
    narinfo: String,
}

struct Fixture {
    root: PathBuf,
    data_dir: PathBuf,
    uploader: Uploader,
    paths: Vec<CachedPath>,
    source: (String, u64),
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn cached_path(cache: &Path, hash_char: char, name: &str, references: &[&str]) -> CachedPath {
    let hash = hash_char.to_string().repeat(32);
    let store_path = format!("/nix/store/{hash}-{name}");
    let bytes = format!("compressed NAR of {name}\n")
        .repeat(1000)
        .into_bytes();
    let file_digest: [u8; 32] = Sha256::digest(&bytes).into();
    let file_name = crate::cache::encode_nix_base32_sha256(&file_digest);
    let nar_url = format!("nar/{file_name}.nar.zst");
    fs::write(cache.join(&nar_url), &bytes).unwrap();
    let file_hash = format!("sha256:{file_name}");
    let nar_hash = format!(
        "sha256:{}",
        crate::cache::encode_nix_base32_sha256(&Sha256::digest(name.as_bytes()).into())
    );
    let references = references
        .iter()
        .map(|reference| format!("/nix/store/{reference}"))
        .collect::<Vec<_>>();
    let narinfo = format!(
        "StorePath: {store_path}\nURL: {nar_url}\nCompression: zstd\nFileHash: {file_hash}\n\
         FileSize: {}\nNarHash: {nar_hash}\nNarSize: 4096\nReferences: {}\n\
         Deriver: {hash}-{name}.drv\nSig: tiaris-nest-1:{}\n",
        bytes.len(),
        references
            .iter()
            .map(|reference| reference.trim_start_matches("/nix/store/"))
            .collect::<Vec<_>>()
            .join(" "),
        STANDARD.encode([7u8; 64]),
    );
    fs::write(cache.join(format!("{hash}.narinfo")), &narinfo).unwrap();
    CachedPath {
        store_path,
        nar_url,
        file_hash,
        file_size: bytes.len() as u64,
        nar_hash,
        references,
        narinfo,
    }
}

fn fixture(name: &str) -> Fixture {
    let root =
        std::env::temp_dir().join(format!("tiaris-nest-upload-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let cache = root.join("cache");
    fs::create_dir_all(cache.join("nar")).unwrap();
    fs::create_dir_all(root.join("data")).unwrap();
    fs::create_dir_all(root.join("source")).unwrap();
    let app = cached_path(&cache, 'a', "tiaris-agent-0.2", &[]);
    let units = cached_path(
        &cache,
        'b',
        "system-units",
        &["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tiaris-agent-0.2"],
    );
    // Built and cached, but not granted: never uploaded.
    let other = cached_path(&cache, 'c', "ungranted", &[]);
    let source = b"manage source archive".repeat(100);
    fs::write(root.join("source").join(format!("{REVISION}.tar")), &source).unwrap();
    Fixture {
        uploader: Uploader {
            cache_root: cache,
            source_dir: root.join("source"),
            bytes_per_second: 64 * 1024 * 1024,
            allow_loopback_http: true,
        },
        data_dir: root.join("data"),
        root,
        paths: vec![app, units, other],
        source: (hex::encode(Sha256::digest(&source)), source.len() as u64),
    }
}

fn grant_paths(paths: &[&CachedPath]) -> Value {
    paths
        .iter()
        .map(|path| {
            json!({
                "store_path": path.store_path,
                "nar_url": path.nar_url,
                "compression": "zstd",
                "file_hash": path.file_hash,
                "file_size": path.file_size,
                "nar_hash": path.nar_hash,
                "nar_size": 4096,
                "references": path.references,
            })
        })
        .collect()
}

fn sign_grant(payload: &Value) -> (String, String) {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let mac = URL_SAFE_NO_PAD.encode(hmac_sha256(
        KEY,
        &[
            b"TIARIS-SOFTWARE-CACHE-UPLOAD-GRANT-V1\n".as_slice(),
            encoded.as_bytes(),
        ]
        .concat(),
    ));
    let id = hex::encode(&Sha256::digest(encoded.as_bytes())[..16]);
    (format!("tug1.{encoded}.{mac}"), id)
}

fn grant(fixture: &Fixture, scope: &str, expires: i64, files: Value) -> (String, String) {
    let now = Utc::now().timestamp();
    sign_grant(&json!({
        "schema": GRANT_SCHEMA,
        "issuer": "dev",
        "scope": scope,
        "subject": "nest-1",
        "issued_at": now,
        "expires": expires,
        "manifest_id": "11111111-2222-4333-8444-555555555555",
        "paths": grant_paths(&[&fixture.paths[0], &fixture.paths[1]]),
        "files": files,
    }))
}

fn source_file(fixture: &Fixture) -> Value {
    json!([{"path": format!("manage-source/{REVISION}.tar"),
            "sha256": fixture.source.0, "size": fixture.source.1}])
}

fn upload_config(url: &str, token: &str, grants: &[(String, String)]) -> Value {
    json!({
        "url": url,
        "token": token,
        "expires_at": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "grants": grants.iter().map(|(grant, id)| json!({
            "grant": grant, "grant_id": id, "expires_at": "2026-11-07T00:00:00Z",
            "path_count": 2, "file_count": 1,
        })).collect::<Vec<_>>(),
    })
}

#[derive(Default)]
struct Server {
    requests: Vec<String>,
    stored: BTreeMap<String, Vec<u8>>,
    /// Statuses for the next PUTs, then 201.
    fail_puts: Vec<u16>,
}

/// An organization tree that behaves like `upload.py` for one Nest.
async fn serve(state: Arc<Mutex<Server>>) -> String {
    let app = Router::new().fallback(
        move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
            let state = state.clone();
            async move {
                let mut server = state.lock().unwrap();
                let path = uri.path().to_string();
                server.requests.push(format!("{method} {path}"));
                let expected = format!("Basic {}", STANDARD.encode(format!("nest:{TOKEN}")));
                if headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    != Some(expected.as_str())
                {
                    return (AxumStatus::UNAUTHORIZED, String::new());
                }
                let Some(name) = path.strip_prefix(&format!("/o/dev/{SCOPE}/")) else {
                    return (AxumStatus::NOT_FOUND, String::new());
                };
                let name = name.to_string();
                match method {
                    Method::POST if name == "upload-grants" => {
                        (AxumStatus::CREATED, "{\"result\": \"ok\"}".into())
                    }
                    Method::GET if server.stored.contains_key(&name) => {
                        (AxumStatus::OK, String::new())
                    }
                    Method::GET => (AxumStatus::NOT_FOUND, String::new()),
                    Method::PUT => {
                        if let Some(status) =
                            (!server.fail_puts.is_empty()).then(|| server.fail_puts.remove(0))
                        {
                            return (AxumStatus::from_u16(status).unwrap(), String::new());
                        }
                        let length = headers
                            .get("content-length")
                            .and_then(|value| value.to_str().ok())
                            .and_then(|value| value.parse::<usize>().ok());
                        if length != Some(body.len()) || headers.get(GRANT_HEADER).is_none() {
                            return (AxumStatus::LENGTH_REQUIRED, String::new());
                        }
                        if name.ends_with(".narinfo") {
                            let text = String::from_utf8_lossy(&body).to_string();
                            let url = text
                                .lines()
                                .find_map(|line| line.strip_prefix("URL: "))
                                .unwrap_or_default()
                                .to_string();
                            if !server.stored.contains_key(&url) {
                                return (AxumStatus::CONFLICT, String::new());
                            }
                        }
                        server.stored.insert(name, body.to_vec());
                        (AxumStatus::CREATED, String::new())
                    }
                    _ => (AxumStatus::NOT_FOUND, String::new()),
                }
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}/o/dev/{SCOPE}")
}

async fn grant_state(db: &SqlitePool) -> (String, String, i64) {
    sqlx::query_as("SELECT state, error, next_attempt_at FROM software_cache_upload_grants")
        .fetch_one(db)
        .await
        .unwrap()
}

#[tokio::test]
async fn apply_keeps_the_token_private_and_records_grants() {
    let db = pool().await;
    let fixture = fixture("apply");
    let url = format!("https://cache.tiaris.com/o/dev/{SCOPE}");
    let good = grant(&fixture, SCOPE, 4_102_444_800, json!([]));
    let other_tree = grant(
        &fixture,
        "o-ffffffffffffffffffffffffffffffff",
        4_102_444_800,
        json!([]),
    );
    let wrong_id = (good.0.clone(), "0".repeat(32));
    let config = upload_config(&url, TOKEN, &[good.clone(), other_tree, wrong_id]);
    apply_with(&db, &fixture.data_dir, Some(&config), false)
        .await
        .unwrap();

    let path = credentials_path(&fixture.data_dir);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let stored = read_credentials(&fixture.data_dir).unwrap();
    assert_eq!(
        (stored.url.as_str(), stored.token.as_str()),
        (url.as_str(), TOKEN)
    );
    assert!(!format!("{stored:?}").contains(TOKEN));
    let managed: ManagedUpload = serde_json::from_value(config.clone()).unwrap();
    assert!(!format!("{managed:?}").contains(TOKEN));

    let rows: Vec<(String, Option<String>, String)> =
        sqlx::query_as("SELECT grant_id, manifest_id, state FROM software_cache_upload_grants")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(
        rows,
        [(
            good.1.clone(),
            Some("11111111-2222-4333-8444-555555555555".into()),
            "pending".into()
        )]
    );

    // A grant Manage stops sending is forgotten; no upload access forgets all.
    apply_with(
        &db,
        &fixture.data_dir,
        Some(&upload_config(&url, TOKEN, &[])),
        false,
    )
    .await
    .unwrap();
    assert!(report(&db).await.unwrap().is_empty());
    apply_with(&db, &fixture.data_dir, Some(&config), false)
        .await
        .unwrap();
    apply_with(&db, &fixture.data_dir, None, false)
        .await
        .unwrap();
    assert!(!path.exists());
    assert!(report(&db).await.unwrap().is_empty());

    for (url, token) in [
        (format!("http://cache.tiaris.com/o/dev/{SCOPE}"), TOKEN),
        ("https://cache.tiaris.com/o/dev/o-123".to_string(), TOKEN),
        (format!("https://cache.tiaris.com/o/{SCOPE}"), TOKEN),
        (format!("https://cache.tiaris.com/o/Dev/{SCOPE}"), TOKEN),
        (
            format!("https://cache.tiaris.com:8443/o/dev/{SCOPE}"),
            TOKEN,
        ),
        (
            format!("https://user@cache.tiaris.com/o/dev/{SCOPE}"),
            TOKEN,
        ),
        (format!("https://cache.tiaris.com/o/dev/{SCOPE}?x=1"), TOKEN),
        (url.clone(), "tok en"),
        (url.clone(), "token\nmachine evil"),
    ] {
        let config = upload_config(&url, token, &[]);
        assert!(
            apply_with(&db, &fixture.data_dir, Some(&config), false)
                .await
                .is_err(),
            "{url} {token:?}"
        );
    }
    assert!(!path.exists());
}

#[tokio::test]
async fn uploads_granted_paths_nar_before_narinfo_and_files() {
    let db = pool().await;
    let fixture = fixture("upload");
    let server = Arc::new(Mutex::new(Server::default()));
    let url = serve(server.clone()).await;
    let granted = grant(&fixture, SCOPE, 4_102_444_800, source_file(&fixture));
    apply_with(
        &db,
        &fixture.data_dir,
        Some(&upload_config(&url, TOKEN, &[granted.clone()])),
        true,
    )
    .await
    .unwrap();
    upload_pass(&db, &fixture.data_dir, &fixture.uploader, Utc::now())
        .await
        .unwrap();

    let [app, units, _] = &fixture.paths[..] else {
        unreachable!()
    };
    let narinfo = |path: &CachedPath| format!("{}.narinfo", &path.store_path[11..43]);
    let requests = server.lock().unwrap().requests.clone();
    let prefix = format!("/o/dev/{SCOPE}");
    assert_eq!(
        requests,
        [
            format!("POST {prefix}/upload-grants"),
            format!("GET {prefix}/{}", narinfo(app)),
            format!("PUT {prefix}/{}", app.nar_url),
            format!("PUT {prefix}/{}", narinfo(app)),
            format!("GET {prefix}/{}", narinfo(units)),
            format!("PUT {prefix}/{}", units.nar_url),
            format!("PUT {prefix}/{}", narinfo(units)),
            format!("PUT {prefix}/manage-source/{REVISION}.tar"),
        ]
    );
    {
        let server = server.lock().unwrap();
        // The narinfo exactly as Nix wrote it, with the Nest signature.
        assert_eq!(server.stored[&narinfo(app)], app.narinfo.as_bytes());
        assert_eq!(
            server.stored[&app.nar_url],
            fs::read(fixture.uploader.cache_root.join(&app.nar_url)).unwrap()
        );
        assert!(!server.stored.keys().any(|key| key.contains("ccccc")));
    }
    let report = report(&db).await.unwrap();
    assert_eq!(report.len(), 1);
    let entry = &report[0];
    assert_eq!(entry.grant_id, granted.1);
    assert_eq!(entry.state, "uploaded");
    assert_eq!(
        (
            entry.paths_total,
            entry.paths_uploaded,
            entry.files_total,
            entry.files_uploaded
        ),
        (2, 2, 1, 1)
    );
    assert_eq!(entry.items_failed, 0);
    assert!(entry.bytes_uploaded > (app.file_size + units.file_size) as i64);
    assert_eq!(
        serde_json::to_value(entry).unwrap()["manifest_id"],
        "11111111-2222-4333-8444-555555555555"
    );

    // Done: a later pass sends nothing.
    server.lock().unwrap().requests.clear();
    upload_pass(
        &db,
        &fixture.data_dir,
        &fixture.uploader,
        Utc::now() + chrono::Duration::hours(1),
    )
    .await
    .unwrap();
    assert!(server.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn transient_failures_back_off_and_resume_where_they_stopped() {
    let db = pool().await;
    let fixture = fixture("retry");
    let server = Arc::new(Mutex::new(Server::default()));
    let url = serve(server.clone()).await;
    let granted = grant(&fixture, SCOPE, 4_102_444_800, json!([]));
    apply_with(
        &db,
        &fixture.data_dir,
        Some(&upload_config(&url, TOKEN, &[granted])),
        true,
    )
    .await
    .unwrap();
    // The first path goes through, then the service is unavailable.
    server.lock().unwrap().fail_puts = vec![201, 201, 503];
    let start = Utc::now();
    upload_pass(&db, &fixture.data_dir, &fixture.uploader, start)
        .await
        .unwrap();
    let (state, error, next) = grant_state(&db).await;
    assert_eq!((state.as_str(), error.as_str()), ("uploading", "http_503"));
    assert_eq!(next, start.timestamp() + BACKOFF_BASE_SECONDS);

    server.lock().unwrap().requests.clear();
    upload_pass(
        &db,
        &fixture.data_dir,
        &fixture.uploader,
        start + chrono::Duration::seconds(30),
    )
    .await
    .unwrap();
    assert!(server.lock().unwrap().requests.is_empty());

    upload_pass(
        &db,
        &fixture.data_dir,
        &fixture.uploader,
        start + chrono::Duration::seconds(61),
    )
    .await
    .unwrap();
    let requests = server.lock().unwrap().requests.clone();
    // Registered once; the first path is not sent again.
    assert!(
        !requests
            .iter()
            .any(|request| request.contains("upload-grants"))
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.contains(&fixture.paths[0].nar_url))
    );
    assert_eq!(grant_state(&db).await.0, "uploaded");
}

#[tokio::test]
async fn items_that_do_not_match_their_grant_are_never_sent() {
    let db = pool().await;
    let fixture = fixture("mismatch");
    let server = Arc::new(Mutex::new(Server::default()));
    let url = serve(server.clone()).await;
    let now = Utc::now().timestamp();
    let mut paths = grant_paths(&[&fixture.paths[0], &fixture.paths[1]]);
    paths[0]["file_hash"] = json!(format!("sha256:{}", "0".repeat(52)));
    let granted = sign_grant(&json!({
        "schema": GRANT_SCHEMA, "issuer": "dev", "scope": SCOPE, "subject": "nest-1",
        "issued_at": now, "expires": 4_102_444_800i64, "paths": paths,
        "files": [{"path": format!("manage-source/{REVISION}.tar"),
                   "sha256": "f".repeat(64), "size": fixture.source.1}],
    }));
    apply_with(
        &db,
        &fixture.data_dir,
        Some(&upload_config(&url, TOKEN, &[granted])),
        true,
    )
    .await
    .unwrap();
    upload_pass(&db, &fixture.data_dir, &fixture.uploader, Utc::now())
        .await
        .unwrap();
    let requests = server.lock().unwrap().requests.clone();
    assert!(
        !requests
            .iter()
            .any(|request| request.contains(&fixture.paths[0].nar_url))
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.contains("manage-source"))
    );
    assert!(
        requests
            .iter()
            .any(|request| request.contains(&fixture.paths[1].nar_url))
    );
    let (state, error, _) = grant_state(&db).await;
    assert_eq!(state, "failed");
    let entry = report(&db).await.unwrap().remove(0);
    assert_eq!((entry.paths_uploaded, entry.items_failed), (1, 2));
    assert!(
        ["file_mismatch", "narinfo_mismatch"].contains(&error.as_str()),
        "{error}"
    );
}

#[tokio::test]
async fn quota_expiry_and_missing_tokens_stop_uploads() {
    let db = pool().await;
    let fixture = fixture("stop");
    let server = Arc::new(Mutex::new(Server::default()));
    let url = serve(server.clone()).await;
    let granted = grant(&fixture, SCOPE, 4_102_444_800, json!([]));
    apply_with(
        &db,
        &fixture.data_dir,
        Some(&upload_config(&url, TOKEN, &[granted])),
        true,
    )
    .await
    .unwrap();
    server.lock().unwrap().fail_puts = vec![507];
    upload_pass(&db, &fixture.data_dir, &fixture.uploader, Utc::now())
        .await
        .unwrap();
    assert_eq!(grant_state(&db).await.0, "failed");
    assert_eq!(grant_state(&db).await.1, "quota_exceeded");

    // An expired grant is never uploaded.
    let db = pool().await;
    let soon = Utc::now().timestamp() + 60;
    let expiring = grant(&fixture, SCOPE, soon, json!([]));
    apply_with(
        &db,
        &fixture.data_dir,
        Some(&upload_config(&url, TOKEN, &[expiring])),
        true,
    )
    .await
    .unwrap();
    server.lock().unwrap().requests.clear();
    upload_pass(
        &db,
        &fixture.data_dir,
        &fixture.uploader,
        Utc::now() + chrono::Duration::minutes(5),
    )
    .await
    .unwrap();
    assert_eq!(grant_state(&db).await.0, "expired");
    assert!(server.lock().unwrap().requests.is_empty());

    // Without a current write token nothing is sent.
    let db = pool().await;
    let granted = grant(&fixture, SCOPE, 4_102_444_800, json!([]));
    let mut config = upload_config(&url, TOKEN, &[granted]);
    config["expires_at"] = json!((Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
    apply_with(&db, &fixture.data_dir, Some(&config), true)
        .await
        .unwrap();
    upload_pass(&db, &fixture.data_dir, &fixture.uploader, Utc::now())
        .await
        .unwrap();
    assert!(server.lock().unwrap().requests.is_empty());
    assert_eq!(grant_state(&db).await.0, "pending");
}

#[tokio::test]
async fn uploads_are_limited_to_the_upload_rate() {
    let data = vec![7u8; 25_000];
    let mut reader = Throttled::new(&data[..], 10_000);
    let started = Instant::now();
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, data);
    // One second of burst, then 10 000 bytes per second.
    assert!(
        started.elapsed() >= Duration::from_millis(1400),
        "{:?}",
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// #298's `deploy/software-cache/server/upload.py` as the server:
/// `TIARIS_NEST_UPLOAD_PY=…/upload.py cargo test -- --ignored real_upload_service`.
#[tokio::test]
#[ignore = "needs python3 and the Manage cache server's upload.py"]
async fn real_upload_service_accepts_nest_uploads() {
    let script = std::env::var("TIARIS_NEST_UPLOAD_PY").expect("set TIARIS_NEST_UPLOAD_PY");
    let fixture = fixture("real-service");
    let server_root = fixture.root.join("server");
    fs::create_dir_all(server_root.join("secrets")).unwrap();
    fs::create_dir_all(server_root.join("orgs")).unwrap();
    fs::write(
        server_root.join("secrets/issuers.conf"),
        format!(
            "js_var $tiaris_cache_key_dev \"{}\";\n",
            STANDARD.encode(KEY)
        ),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = tokio::process::Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--root")
        .arg(&server_root)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let expires = Utc::now().timestamp() + 3600;
    let claims = format!("tsc2.dev.{expires}.{SCOPE}.w.nest-1");
    let token = format!(
        "{claims}.{}",
        URL_SAFE_NO_PAD.encode(hmac_sha256(KEY, claims.as_bytes()))
    );
    let granted = grant(&fixture, SCOPE, expires, source_file(&fixture));
    let db = pool().await;
    let url = format!("http://127.0.0.1:{port}/o/dev/{SCOPE}");
    apply_with(
        &db,
        &fixture.data_dir,
        Some(&upload_config(&url, &token, &[granted])),
        true,
    )
    .await
    .unwrap();
    upload_pass(&db, &fixture.data_dir, &fixture.uploader, Utc::now())
        .await
        .unwrap();
    let entry = report(&db).await.unwrap().remove(0);
    assert_eq!(entry.state, "uploaded", "{entry:?}");
    let tree = server_root.join("orgs").join("dev").join(SCOPE);
    for path in &fixture.paths[..2] {
        assert!(tree.join(&path.nar_url).is_file());
        assert_eq!(
            fs::read_to_string(tree.join(format!("{}.narinfo", &path.store_path[11..43]))).unwrap(),
            path.narinfo
        );
    }
    assert!(tree.join(format!("manage-source/{REVISION}.tar")).is_file());
    assert!(!tree.join(&fixture.paths[2].nar_url).exists());
    child.kill().await.unwrap();
}
