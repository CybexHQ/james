use std::os::unix::fs::PermissionsExt;

use axum::{
    Router,
    http::{HeaderMap, StatusCode, Uri},
};
use base64::Engine as _;
use serde_json::json;

use super::*;
use crate::build::ReviewedContent;

const COMMIT: &str = "6f06d204d8f2d8761d9da78778745974a3216381";
const OLDER_COMMIT: &str = "1111111111111111111111111111111111111111";
const PIN: &str = "74cc63f7a4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8";
const NAR_HASH: &str = "sha256-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMeE=";
const RELEASE_REVISION: &str = "aaaaaaaa-bbbb-4ccc-8ddd-000000000002";
const EARLIER_CANDIDATE: &str = "aaaaaaaa-bbbb-4ccc-8ddd-000000000003";
const CANDIDATE_REVISION: &str = "aaaaaaaa-bbbb-4ccc-8ddd-000000000004";
const RELEASE_OUT: &str = "/nix/store/1111111111111111111111111111111a-nixos-system-release";
const EARLIER_OUT: &str = "/nix/store/1111111111111111111111111111111b-nixos-system-earlier";
const CANDIDATE_OUT: &str = "/nix/store/1111111111111111111111111111111c-nixos-system-candidate";
const FIREFOX_OUT: &str = "/nix/store/2222222222222222222222222222222a-firefox-145.0";
const CHROME_OUT: &str = "/nix/store/2222222222222222222222222222222b-google-chrome-141";
const VSCODE_OUT: &str = "/nix/store/2222222222222222222222222222222c-vscode-1.105";
const BROKEN_OUT: &str = "/nix/store/2222222222222222222222222222222d-flaky-1.0";
const TOKEN: &str = "tsc1.dev.1.nest.AAA";

/// The job database and a private Nest state directory, removed on drop.
struct TestDb {
    pool: SqlitePool,
    data: PathBuf,
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

async fn pool() -> TestDb {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let pool = crate::db::connect_with_url("sqlite::memory:")
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let data = std::env::temp_dir().join(format!(
        "tiaris-nest-findings-state-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&data);
    TestDb { pool, data }
}

/// Changes the stored record of a detected commit.
fn tamper_detected(db: &TestDb, commit: &str, change: impl FnOnce(&mut Value)) {
    let dir = super::super::detected_dir(&db.data);
    let name = format!("{commit}.json");
    let mut record: Value = state_files::read(
        &dir,
        &name,
        super::super::DETECTED_SCHEMA,
        super::super::MAX_DETECTED_RECORD_BYTES,
    )
    .unwrap();
    change(&mut record);
    state_files::write(
        &dir,
        &name,
        super::super::DETECTED_SCHEMA,
        super::super::MAX_DETECTED_RECORD_BYTES,
        &record,
    )
    .unwrap();
}

/// A scan record written directly, as an earlier scan would have.
fn insert_scan(
    db: &TestDb,
    commit: &str,
    revision: &str,
    job: i64,
    delivery: Value,
    scanned_at: &str,
) {
    let record = ScanFile {
        commit_rev: commit.into(),
        blueprint_revision_id: revision.into(),
        candidate_job_id: job,
        release_job_id: None,
        state: "succeeded".into(),
        reason: None,
        detail: String::new(),
        attempts: 0,
        advisories: Vec::new(),
        package_delivery: serde_json::from_value(delivery).unwrap(),
        scanned_at: scanned_at.into(),
    };
    state_files::write(
        &scans_dir(&db.data),
        &ScanFile::name(commit, revision),
        SCAN_SCHEMA,
        MAX_SCAN_BYTES,
        &record,
    )
    .unwrap();
}

async fn insert_detected(db: &TestDb, commit: &str, ready: bool) {
    let profile = serde_json::to_string(&super::super::StoredProfile {
        schema: super::super::PROFILE_SCHEMA,
        nest_build: super::super::nest_build_identity(),
        identities: BTreeMap::new(),
        reviewed: ReviewedContent::default(),
    })
    .unwrap();
    let record = super::super::DetectedRow {
        commit_rev: commit.into(),
        channel: "nixos-26.05".into(),
        last_modified: "2026-10-29T17:25:25Z".into(),
        nar_hash: NAR_HASH.into(),
        kernel_version: String::new(),
        state: if ready { "ready" } else { "blocked" }.into(),
        reason: (!ready).then(|| "source_build_required".into()),
        reason_details: "[]".into(),
        profile: ready.then_some(profile),
        tiaris_derivations: "[]".into(),
        detected_at: "2026-10-31T03:12:00Z".into(),
        derived_by: String::new(),
    };
    state_files::write(
        &super::super::detected_dir(&db.data),
        &format!("{commit}.json"),
        super::super::DETECTED_SCHEMA,
        super::super::MAX_DETECTED_RECORD_BYTES,
        &record,
    )
    .unwrap();
}

fn spec(revision_id: &str, revision: i64, commit: &str, refs: &[&str]) -> Value {
    json!({
        "artifact_type": "nixos_closure",
        "target": "blueprint",
        "system": "x86_64-linux",
        "blueprint_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "blueprint_revision_id": revision_id,
        "nixpkgs_commit": commit,
        "software_package_refs": refs,
        "build_input": {"kind": "blueprint_nixos_module", "blueprint_revision": revision},
    })
}

async fn insert_job(db: &TestDb, managed: &str, spec: Value, output: &str, completed: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO nest_build_jobs
             (managed_job_id, requested_artifact_type, build_spec, target, system, status,
              output_path, completed_at, created_at, updated_at)
         VALUES (?, 'nixos_closure', ?, 'blueprint', 'x86_64-linux', 'succeeded', ?, ?, ?, ?)
         RETURNING id",
    )
    .bind(managed)
    .bind(spec.to_string())
    .bind(output)
    .bind(completed)
    .bind(completed)
    .bind(completed)
    .fetch_one(&db.pool)
    .await
    .unwrap()
}

async fn name_release(db: &TestDb, managed: &str, release: &str) {
    record_hint(
        &db.data,
        managed,
        Some(&json!({"release_blueprint_revision_id": release})),
    )
    .await
    .unwrap();
}

/// The release at the pin and its candidate at the detected commit, which
/// names the release.
async fn release_and_candidate(db: &TestDb) -> (i64, i64) {
    insert_detected(db, COMMIT, true).await;
    let release = insert_job(
        db,
        "release-job",
        spec(RELEASE_REVISION, 2, PIN, &["firefox"]),
        RELEASE_OUT,
        "2026-10-20T10:00:00Z",
    )
    .await;
    let candidate = insert_job(
        db,
        "candidate-job",
        spec(
            CANDIDATE_REVISION,
            4,
            COMMIT,
            &[
                "firefox",
                "google-chrome",
                "vscode",
                "flaky",
                "missing",
                "bad\"ref",
            ],
        ),
        CANDIDATE_OUT,
        "2026-10-31T05:00:00Z",
    )
    .await;
    name_release(db, "candidate-job", RELEASE_REVISION).await;
    (release, candidate)
}

fn vulnix_entry(pname: &str, scores: &[(&str, Option<f64>)]) -> Value {
    json!({
        "name": format!("{pname}-1.0"),
        "pname": pname,
        "version": "1.0",
        "derivation": format!("/nix/store/3333333333333333333333333333333a-{pname}-1.0.drv"),
        "affected_by": scores.iter().map(|(id, _)| id).collect::<Vec<_>>(),
        "whitelisted": [],
        "cvssv3_basescore": scores.iter()
            .filter_map(|(id, score)| score.map(|score| (id.to_string(), json!(score))))
            .collect::<serde_json::Map<_, _>>(),
        "description": {scores[0].0: "A crafted file\nmay crash the parser."},
    })
}

fn release_scan() -> Value {
    json!([
        vulnix_entry(
            "firefox",
            &[("CVE-2026-0001", Some(9.8)), ("CVE-2026-0002", Some(7.0))]
        ),
        vulnix_entry(
            "glibc",
            &[("CVE-2026-0003", Some(4.0)), ("CVE-2026-0004", Some(3.9))]
        ),
        vulnix_entry(
            "zlib",
            &[("CVE-2026-0005", None), ("not an id!", Some(9.0))]
        ),
        vulnix_entry("openssl", &[("CVE-2026-0006", Some(8.1))]),
    ])
}

fn candidate_scan() -> Value {
    json!([vulnix_entry("openssl", &[("CVE-2026-0006", Some(8.1))])])
}

struct Fake {
    root: PathBuf,
    scanner: Scanner,
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A `nix` answering `path-info` and the package `eval` from files, and a
/// `vulnix` printing the release or candidate scan by the scanned path.
async fn fake(name: &str) -> Fake {
    let root = std::env::temp_dir().join(format!(
        "tiaris-nest-findings-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("drv")).unwrap();
    for drv in ["system", "firefox-local", "glibc"] {
        std::fs::write(root.join("drv").join(format!("{drv}.drv")), "Derive()").unwrap();
    }
    let drv = |name: &str| {
        root.join("drv")
            .join(format!("{name}.drv"))
            .display()
            .to_string()
    };
    // Firefox's recorded deriver (from the binary cache) is gone; a valid
    // local derivation declares its output, as after a local evaluation.
    let path_info = json!({
        "/nix/store/4444444444444444444444444444444a-system": {"deriver": drv("system")},
        "/nix/store/4444444444444444444444444444444b-firefox": {"deriver": drv("firefox-hydra")},
        "/nix/store/4444444444444444444444444444444c-glibc": {"deriver": drv("glibc")},
    });
    std::fs::write(
        root.join("valid-derivers"),
        format!("{}\n", drv("firefox-local")),
    )
    .unwrap();
    std::fs::write(
        root.join("derivation-show.json"),
        json!({"derivations": {drv("firefox-local"): {"outputs": {
            "out": {"path": "4444444444444444444444444444444b-firefox"}}}}})
        .to_string(),
    )
    .unwrap();
    std::fs::write(root.join("path-info.json"), path_info.to_string()).unwrap();
    std::fs::write(
        root.join("eval.json"),
        json!({
            "firefox": FIREFOX_OUT,
            "google-chrome": CHROME_OUT,
            "vscode": VSCODE_OUT,
            "flaky": BROKEN_OUT,
            "missing": null,
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(root.join("release.json"), release_scan().to_string()).unwrap();
    std::fs::write(root.join("candidate.json"), candidate_scan().to_string()).unwrap();
    write_executable(
        &root.join("nix"),
        &format!(
            r#"#!/bin/sh
root='{root}'
printf '%s nice=%s\n' "$*" "$(cut -d' ' -f19 /proc/$$/stat)" >> "$root/nix-calls"
case " $* " in
  *" eval "*'" "'*) [ -f "$root/fail-batch" ] && exit 1 ;;
esac
case " $* " in
  *" eval "*'"flaky"'*) [ -f "$root/fail-batch" ] && exit 1 ;;
esac
case " $* " in
  *" path-info "*) [ -f "$root/fail-path-info" ] && exit 1; cat "$root/path-info.json" ;;
  *" derivation show "*) cat "$root/derivation-show.json" ;;
  *" eval "*) cat "$root/eval.json" ;;
  *) exit 5 ;;
esac
"#,
            root = root.display()
        ),
    );
    write_executable(
        &root.join("nix-store"),
        &format!(
            r#"#!/bin/sh
root='{root}'
[ "$1 $2" = "--query --valid-derivers" ] || exit 5
[ -f "$root/valid-derivers" ] && cat "$root/valid-derivers"
exit 0
"#,
            root = root.display()
        ),
    );
    write_executable(
        &root.join("vulnix"),
        &format!(
            r#"#!/bin/sh
root='{root}'
printf '%s nice=%s\n' "$*" "$(cut -d' ' -f19 /proc/$$/stat)" >> "$root/vulnix-calls"
[ -f "$root/fail-vulnix" ] && {{ echo 'Traceback: NVD download failed' >&2; exit 2; }}
cache=''; previous=''
for argument; do [ "$previous" = --cache-dir ] && cache="$argument"; previous="$argument"; done
for last; do :; done
case "$last" in *candidate*) [ -f "$root/touch-db-once" ] && {{ echo x >> "$cache/Data.fs"; rm "$root/touch-db-once"; }} ;; esac
[ -f "$root/touch-db-always" ] && echo x >> "$cache/Data.fs"
case "$last" in
  *release*|*earlier*) cat "$root/release.json" ;;
  *candidate*) cat "$root/candidate.json" ;;
esac
exit 2
"#,
            root = root.display()
        ),
    );
    let public = serve_cache(None).await;
    let software = serve_cache(Some(TOKEN)).await;
    let scanner = Scanner {
        nix: root.join("nix").display().to_string(),
        vulnix: root.join("vulnix").display().to_string(),
        vulnix_cache: root.join("vulnix-cache"),
        public_cache: public,
        software_cache: Some((software, TOKEN.to_string())),
        memory_limit_bytes: VULNIX_MEMORY_LIMIT_BYTES,
    };
    Fake { root, scanner }
}

/// cache.nixos.org has Firefox; the software cache, behind its token, has
/// Chrome and fails for the flaky package.
async fn serve_cache(token: Option<&'static str>) -> String {
    let hash = |path: &str| path["/nix/store/".len()..][..32].to_string();
    let (firefox, chrome, broken) = (hash(FIREFOX_OUT), hash(CHROME_OUT), hash(BROKEN_OUT));
    let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
        let (firefox, chrome, broken) = (firefox.clone(), chrome.clone(), broken.clone());
        async move {
            let requested = uri
                .path()
                .trim_start_matches('/')
                .trim_end_matches(".narinfo");
            match token {
                None if requested == firefox => StatusCode::OK,
                None => StatusCode::NOT_FOUND,
                Some(token) => {
                    let expected = format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(format!("nest:{token}"))
                    );
                    if headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        != Some(expected.as_str())
                    {
                        StatusCode::UNAUTHORIZED
                    } else if requested == chrome {
                        StatusCode::OK
                    } else if requested == broken {
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        StatusCode::NOT_FOUND
                    }
                }
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

async fn scan_once(db: &TestDb, fake: &Fake, now: chrono::DateTime<Utc>) -> bool {
    match next_candidate(&db.pool, &db.data, &[PIN.to_string()], now)
        .await
        .unwrap()
    {
        Some(candidate) => {
            scan_and_record(&db.pool, &db.data, &fake.scanner, &candidate)
                .await
                .unwrap();
            true
        }
        None => false,
    }
}

async fn stored_scan_of(db: &TestDb, revision: &str) -> ScanFile {
    all_scans(&db.data)
        .into_iter()
        .map(|(_, scan)| scan)
        .find(|scan| scan.blueprint_revision_id == revision)
        .unwrap()
}

async fn stored_scan(db: &TestDb) -> ScanFile {
    let mut scans = all_scans(&db.data);
    assert_eq!(scans.len(), 1);
    scans.remove(0).1
}

#[test]
fn severity_follows_the_cvss_v3_base_score() {
    assert_eq!(severity(Some(9.8)), "critical");
    assert_eq!(severity(Some(9.0)), "critical");
    assert_eq!(severity(Some(8.9)), "important");
    assert_eq!(severity(Some(7.0)), "important");
    assert_eq!(severity(Some(4.0)), "moderate");
    assert_eq!(severity(Some(3.9)), "low");
    assert_eq!(severity(Some(0.0)), "low");
    assert_eq!(severity(None), "moderate");
}

#[test]
fn fixed_advisories_are_the_releases_the_candidate_no_longer_has() {
    let release = vulnix_advisories(release_scan().to_string().as_bytes()).unwrap();
    let candidate = vulnix_advisories(candidate_scan().to_string().as_bytes()).unwrap();
    assert!(!release.contains_key("not an id!"));
    let fixed = fixed_advisories(&release, &candidate);
    assert_eq!(
        fixed
            .iter()
            .map(|advisory| (advisory.id.as_str(), advisory.severity.as_str()))
            .collect::<Vec<_>>(),
        [
            ("CVE-2026-0001", "critical"),
            ("CVE-2026-0002", "important"),
            ("CVE-2026-0003", "moderate"),
            ("CVE-2026-0005", "moderate"),
            ("CVE-2026-0004", "low"),
        ]
    );
    let first = &fixed[0];
    assert_eq!(first.package, "firefox");
    assert_eq!(first.score, Some(9.8));
    assert_eq!(first.summary, "A crafted file may crash the parser.");
    assert_eq!(
        first.url.as_deref(),
        Some("https://nvd.nist.gov/vuln/detail/CVE-2026-0001")
    );
    assert_eq!(fixed[1].summary, "Fixed in firefox.");
    assert_eq!(fixed[3].score, None);

    let many = (0..MAX_ADVISORIES + 20)
        .map(|index| (format!("CVE-2026-{index:05}"), Some(5.0)))
        .collect::<Vec<_>>();
    let many = many
        .iter()
        .map(|(id, score)| (id.as_str(), *score))
        .collect::<Vec<_>>();
    let release =
        vulnix_advisories(json!([vulnix_entry("big", &many)]).to_string().as_bytes()).unwrap();
    assert_eq!(
        fixed_advisories(&release, &BTreeMap::new()).len(),
        MAX_ADVISORIES
    );
}

#[tokio::test]
async fn scans_a_built_candidate_once_and_reports_what_it_fixes() {
    let db = pool().await;
    let fake = fake("success").await;
    let (release, _) = release_and_candidate(&db).await;

    assert!(scan_once(&db, &fake, Utc::now()).await);
    let stored = stored_scan(&db).await;
    assert_eq!(
        (stored.state.as_str(), stored.reason, stored.release_job_id),
        ("succeeded", None, Some(release))
    );
    // Once per candidate.
    assert!(!scan_once(&db, &fake, Utc::now() + chrono::Duration::days(3)).await);

    let calls = std::fs::read_to_string(fake.root.join("vulnix-calls")).unwrap();
    let calls = calls.lines().collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    assert!(calls[0].starts_with("--json --closure --cache-dir "));
    assert!(calls[0].contains(&format!(" {RELEASE_OUT} ")));
    assert!(calls[1].contains(&format!(" {CANDIDATE_OUT} ")));
    assert!(calls.iter().all(|call| call.ends_with("nice=19")));
    assert!(fake.scanner.vulnix_cache.is_dir());
    let eval = std::fs::read_to_string(fake.root.join("nix-calls")).unwrap();
    // path-info, valid derivers and eval run at the same low priority.
    let niceness = eval
        .lines()
        .filter_map(|line| line.rsplit_once(" nice=").map(|(_, nice)| nice))
        .collect::<Vec<_>>();
    assert_eq!(niceness, ["19"; 5], "{eval}");
    assert!(eval.contains(&format!("github:NixOS/nixpkgs/{COMMIT}?narHash=")));
    assert!(!eval.contains("bad\"ref"));

    let findings = report(&db.pool, &db.data).await.unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.commit, COMMIT);
    assert_eq!(finding.blueprint_revision_id, CANDIDATE_REVISION);
    assert_eq!(finding.advisories.len(), 5);
    assert!(
        finding
            .advisories
            .iter()
            .all(|advisory| advisory.id != "CVE-2026-0006")
    );
    assert_eq!(
        finding
            .package_delivery
            .iter()
            .map(|item| (item.package_ref.as_str(), item.status.as_str()))
            .collect::<Vec<_>>(),
        [
            ("firefox", "public_cache"),
            ("google-chrome", "software_cache"),
            ("vscode", "preparation_required"),
        ]
    );
    let wire = serde_json::to_value(finding).unwrap();
    assert_eq!(
        wire["package_delivery"][0],
        json!({"ref": "firefox", "status": "public_cache"})
    );
    assert_eq!(wire["advisories"][3].get("score"), None);
}

#[tokio::test]
async fn without_software_cache_access_uncached_packages_need_preparation() {
    let db = pool().await;
    let mut fake = fake("no-software-cache").await;
    fake.scanner.software_cache = None;
    release_and_candidate(&db).await;
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let finding = report(&db.pool, &db.data).await.unwrap().remove(0);
    assert_eq!(
        finding
            .package_delivery
            .iter()
            .map(|item| (item.package_ref.as_str(), item.status.as_str()))
            .collect::<Vec<_>>(),
        [
            ("firefox", "public_cache"),
            ("flaky", "preparation_required"),
            ("google-chrome", "preparation_required"),
            ("vscode", "preparation_required"),
        ]
    );
}

#[tokio::test]
async fn a_failed_scan_reports_nothing_and_is_retried_daily_three_times() {
    let db = pool().await;
    let fake = fake("failure").await;
    release_and_candidate(&db).await;
    std::fs::write(fake.root.join("fail-vulnix"), "").unwrap();

    let start = Utc::now();
    assert!(scan_once(&db, &fake, start).await);
    let stored = stored_scan(&db).await;
    assert_eq!(stored.state, "failed");
    assert_eq!(stored.reason.as_deref(), Some(REASON_SCAN_FAILED));
    assert!(
        stored.detail.contains("NVD download failed"),
        "{}",
        stored.detail
    );
    assert!(report(&db.pool, &db.data).await.unwrap().is_empty());

    assert!(!scan_once(&db, &fake, start + chrono::Duration::hours(12)).await);
    assert!(scan_once(&db, &fake, start + chrono::Duration::hours(25)).await);
    assert!(scan_once(&db, &fake, start + chrono::Duration::hours(50)).await);
    assert_eq!(stored_scan(&db).await.attempts, MAX_ATTEMPTS);
    assert!(!scan_once(&db, &fake, start + chrono::Duration::days(10)).await);
}

#[tokio::test]
async fn missing_release_closures_and_derivations_fail_soft() {
    let db = pool().await;
    let fake = fake("missing").await;
    insert_detected(&db, COMMIT, true).await;
    insert_job(
        &db,
        "candidate-job",
        spec(CANDIDATE_REVISION, 4, COMMIT, &[]),
        CANDIDATE_OUT,
        "2026-10-31T05:00:00Z",
    )
    .await;
    name_release(&db, "candidate-job", RELEASE_REVISION).await;
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let stored = stored_scan(&db).await;
    assert_eq!(
        (stored.reason.as_deref(), stored.release_job_id),
        (Some(REASON_RELEASE_CLOSURE_UNAVAILABLE), None)
    );

    let db = pool().await;
    release_and_candidate(&db).await;
    std::fs::remove_file(fake.root.join("valid-derivers")).unwrap();
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let stored = stored_scan(&db).await;
    assert_eq!(
        stored.reason.as_deref(),
        Some(REASON_DERIVATIONS_UNAVAILABLE)
    );
    assert_eq!(
        stored.detail,
        "2 of 3 closure paths have their derivation in the store"
    );

    let db = pool().await;
    release_and_candidate(&db).await;
    std::fs::write(fake.root.join("fail-path-info"), "").unwrap();
    assert!(scan_once(&db, &fake, Utc::now()).await);
    assert_eq!(
        stored_scan(&db).await.reason.as_deref(),
        Some(REASON_CLOSURE_UNAVAILABLE)
    );
    assert!(!fake.root.join("vulnix-calls").exists());
    assert!(report(&db.pool, &db.data).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_candidate_without_its_release_is_skipped_until_manage_names_it() {
    let db = pool().await;
    let fake = fake("hint").await;
    insert_detected(&db, OLDER_COMMIT, true).await;
    let (release, _) = release_and_candidate(&db).await;
    record_hint(&db.data, "candidate-job", None).await.unwrap();
    // An earlier candidate that was never installed: never the baseline.
    let earlier = insert_job(
        &db,
        "earlier-job",
        spec(EARLIER_CANDIDATE, 3, OLDER_COMMIT, &[]),
        EARLIER_OUT,
        "2026-10-25T05:00:00Z",
    )
    .await;
    insert_scan(
        &db,
        OLDER_COMMIT,
        EARLIER_CANDIDATE,
        earlier,
        json!([]),
        "2026-10-25T06:00:00Z",
    );

    assert!(scan_once(&db, &fake, Utc::now()).await);
    let stored = stored_scan_of(&db, CANDIDATE_REVISION).await;
    assert_eq!(
        (
            stored.state.as_str(),
            stored.reason.as_deref(),
            stored.attempts
        ),
        ("skipped", Some(REASON_MISSING_RELEASE_HINT), 0)
    );
    assert!(!fake.root.join("vulnix-calls").exists());
    assert!(
        report(&db.pool, &db.data)
            .await
            .unwrap()
            .iter()
            .all(|finding| finding.blueprint_revision_id != CANDIDATE_REVISION)
    );
    // Not scanned again, however long it waits, until the release is named.
    assert!(!scan_once(&db, &fake, Utc::now() + chrono::Duration::days(10)).await);

    name_release(&db, "candidate-job", &RELEASE_REVISION.to_uppercase()).await;
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let stored = stored_scan_of(&db, CANDIDATE_REVISION).await;
    assert_eq!(
        (stored.state.as_str(), stored.release_job_id),
        ("succeeded", Some(release))
    );
    let calls = std::fs::read_to_string(fake.root.join("vulnix-calls")).unwrap();
    assert!(calls.contains(RELEASE_OUT) && !calls.contains(EARLIER_OUT));

    // A named release this Nest has not built is a retried failure.
    name_release(&db, "earlier-job", "aaaaaaaa-bbbb-4ccc-8ddd-000000000009").await;
    state_files::remove(
        &scans_dir(&db.data),
        &ScanFile::name(OLDER_COMMIT, EARLIER_CANDIDATE),
    )
    .unwrap();
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let stored = stored_scan_of(&db, EARLIER_CANDIDATE).await;
    assert_eq!(
        (stored.reason.as_deref(), stored.attempts),
        (Some(REASON_RELEASE_CLOSURE_UNAVAILABLE), 1)
    );
}

#[tokio::test]
async fn both_closures_are_judged_by_the_same_nvd_database() {
    let db = pool().await;
    let fake = fake("nvd").await;
    release_and_candidate(&db).await;
    // The candidate's run refreshed the database: the release is scanned
    // again with what the candidate saw.
    std::fs::write(fake.root.join("touch-db-once"), "").unwrap();
    assert!(scan_once(&db, &fake, Utc::now()).await);
    assert_eq!(stored_scan(&db).await.state, "succeeded");
    let calls = std::fs::read_to_string(fake.root.join("vulnix-calls")).unwrap();
    let scanned = calls
        .lines()
        .map(|line| {
            if line.contains(RELEASE_OUT) {
                "release"
            } else {
                "candidate"
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(scanned, ["release", "candidate", "release"]);
    assert_eq!(
        report(&db.pool, &db.data).await.unwrap()[0]
            .advisories
            .len(),
        5
    );

    // A database that keeps changing gives no finding.
    let db = pool().await;
    release_and_candidate(&db).await;
    std::fs::write(fake.root.join("touch-db-always"), "").unwrap();
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let stored = stored_scan(&db).await;
    assert_eq!(stored.reason.as_deref(), Some(REASON_SCAN_FAILED));
    assert!(
        stored.detail.contains("NVD database changed"),
        "{}",
        stored.detail
    );
}

#[tokio::test]
async fn a_build_that_starts_defers_the_scan_without_recording_it() {
    let db = pool().await;
    let fake = fake("deferred").await;
    release_and_candidate(&db).await;
    let candidate = next_candidate(&db.pool, &db.data, &[PIN.to_string()], Utc::now())
        .await
        .unwrap()
        .unwrap();
    sqlx::query("INSERT INTO nest_build_jobs (requested_artifact_type, status, created_at, updated_at) VALUES ('nixos_closure', 'running', '2026-10-31T06:00:00Z', '2026-10-31T06:00:00Z')")
        .execute(&db.pool).await.unwrap();
    assert!(
        !scan_and_record(&db.pool, &db.data, &fake.scanner, &candidate)
            .await
            .unwrap()
    );
    assert!(!fake.root.join("vulnix-calls").exists());
    assert!(all_scans(&db.data).is_empty());
}

#[tokio::test]
async fn package_lookups_survive_one_bad_ref_and_retry_when_nothing_is_decided() {
    let db = pool().await;
    let fake = fake("packages").await;
    release_and_candidate(&db).await;
    // The batch evaluation fails; each ref is evaluated on its own and only
    // the bad one is left out.
    std::fs::write(fake.root.join("fail-batch"), "").unwrap();
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let finding = report(&db.pool, &db.data).await.unwrap().remove(0);
    assert_eq!(
        finding
            .package_delivery
            .iter()
            .map(|item| item.package_ref.as_str())
            .collect::<Vec<_>>(),
        ["firefox", "google-chrome", "vscode"]
    );

    // No cache answers: nothing decided, so the scan failed and is retried.
    let db = pool().await;
    let mut fake = fake;
    fake.scanner.public_cache = "http://127.0.0.1:9".to_string();
    release_and_candidate(&db).await;
    let start = Utc::now();
    assert!(scan_once(&db, &fake, start).await);
    let stored = stored_scan(&db).await;
    assert_eq!(
        (stored.state.as_str(), stored.reason.as_deref()),
        ("failed", Some(REASON_PACKAGE_STATUS_UNAVAILABLE))
    );
    assert!(report(&db.pool, &db.data).await.unwrap().is_empty());
    assert!(scan_once(&db, &fake, start + chrono::Duration::hours(25)).await);
}

#[tokio::test]
async fn only_blueprint_jobs_at_ready_detected_commits_are_candidates() {
    let db = pool().await;
    insert_detected(&db, COMMIT, false).await;
    insert_detected(&db, PIN, true).await;
    insert_detected(&db, OLDER_COMMIT, true).await;
    insert_job(
        &db,
        "blocked",
        spec(CANDIDATE_REVISION, 4, COMMIT, &[]),
        CANDIDATE_OUT,
        "2026-10-31T05:00:00Z",
    )
    .await;
    insert_job(
        &db,
        "pin",
        spec(RELEASE_REVISION, 2, PIN, &[]),
        RELEASE_OUT,
        "2026-10-20T05:00:00Z",
    )
    .await;
    let mut installer = spec(EARLIER_CANDIDATE, 3, OLDER_COMMIT, &[]);
    installer["build_input"]["installer_target"] = json!({"schema": "x"});
    insert_job(
        &db,
        "installer",
        installer,
        EARLIER_OUT,
        "2026-10-21T05:00:00Z",
    )
    .await;
    assert!(
        next_candidate(&db.pool, &db.data, &[PIN.to_string()], Utc::now())
            .await
            .unwrap()
            .is_none()
    );
    // A ready commit whose profile another Nest build derived admits nothing.
    tamper_detected(&db, COMMIT, |record| {
        record["state"] = json!("ready");
        record["reason"] = Value::Null;
        record["profile"] =
            json!(r#"{"schema":0,"nest_build":"old","identities":{},"reviewed":{}}"#);
    });
    assert!(
        next_candidate(&db.pool, &db.data, &[PIN.to_string()], Utc::now())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_named_candidate_at_a_pinned_detected_commit_is_scanned() {
    // Manage pins the detected commit so the Nest can build its candidates;
    // the candidate it names a release for is still scanned.
    let db = pool().await;
    let pins = [PIN.to_string(), COMMIT.to_string()];
    insert_detected(&db, COMMIT, true).await;
    insert_job(
        &db,
        "ordinary",
        spec(EARLIER_CANDIDATE, 3, COMMIT, &[]),
        EARLIER_OUT,
        "2026-10-30T05:00:00Z",
    )
    .await;
    assert!(
        next_candidate(&db.pool, &db.data, &pins, Utc::now())
            .await
            .unwrap()
            .is_none()
    );
    let (_, candidate) = release_and_candidate(&db).await;
    let found = next_candidate(&db.pool, &db.data, &pins, Utc::now())
        .await
        .unwrap()
        .expect("the named candidate");
    assert_eq!(found.job.id, candidate);
}

#[tokio::test]
async fn the_report_shares_package_status_per_commit_and_drops_stale_scans() {
    let db = pool().await;
    let fake = fake("report").await;
    let (_, candidate) = release_and_candidate(&db).await;
    assert!(scan_once(&db, &fake, Utc::now()).await);
    // A second Blueprint's candidate at the same commit with other refs.
    let other = insert_job(
        &db,
        "other-job",
        spec(EARLIER_CANDIDATE, 7, COMMIT, &[]),
        EARLIER_OUT,
        "2026-10-31T06:00:00Z",
    )
    .await;
    insert_scan(
        &db,
        COMMIT,
        EARLIER_CANDIDATE,
        other,
        json!([{"ref": "libreoffice", "status": "public_cache"},
               {"ref": "vscode", "status": "software_cache"}]),
        "2999-01-01T00:00:00Z",
    );
    let findings = report(&db.pool, &db.data).await.unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].blueprint_revision_id, EARLIER_CANDIDATE);
    for finding in &findings {
        assert_eq!(
            finding
                .package_delivery
                .iter()
                .map(|item| (item.package_ref.as_str(), item.status.as_str()))
                .collect::<Vec<_>>(),
            [
                ("firefox", "public_cache"),
                ("google-chrome", "software_cache"),
                ("libreoffice", "public_cache"),
                ("vscode", "software_cache"),
            ]
        );
    }

    // A commit that is no longer ready is not reported; a job Nest dropped
    // takes its scan with it.
    sqlx::query("DELETE FROM nest_build_jobs WHERE id = ?")
        .bind(candidate)
        .execute(&db.pool)
        .await
        .unwrap();
    prune(&db.pool, &db.data).await.unwrap();
    assert_eq!(report(&db.pool, &db.data).await.unwrap().len(), 1);
    tamper_detected(&db, COMMIT, |record| {
        record["state"] = json!("blocked");
        record["reason"] = json!("evaluation_failed");
    });
    assert!(report(&db.pool, &db.data).await.unwrap().is_empty());
}

#[test]
fn package_refs_are_embedded_only_as_attribute_paths() {
    let flake = format!("github:NixOS/nixpkgs/{COMMIT}?narHash=x");
    let expression =
        package_outputs_expression(&flake, "x86_64-linux", &["python3Packages.numpy".into()])
            .unwrap();
    assert!(expression.contains("[ \"python3Packages.numpy\" ]"));
    assert!(expression.contains("allowUnfree = true"));
    for bad in ["a\"b", "${x}", "a b", "", "..a", "a..b", "1abc"] {
        assert!(
            package_outputs_expression(&flake, "x86_64-linux", &[bad.into()]).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn closure_derivers_read_both_path_info_shapes() {
    let object = json!({"/nix/store/a-x": {"deriver": "/nix/store/b-x.drv"}, "/nix/store/c-y": {"deriver": null}});
    assert_eq!(
        closure_derivers(&object).unwrap(),
        [
            (
                "/nix/store/a-x".to_string(),
                Some("/nix/store/b-x.drv".to_string())
            ),
            ("/nix/store/c-y".to_string(), None)
        ]
    );
    let list = json!([{"path": "a-x", "deriver": "b-x.drv"}]);
    assert_eq!(
        closure_derivers(&list).unwrap(),
        [(
            "/nix/store/a-x".to_string(),
            Some("/nix/store/b-x.drv".to_string())
        )]
    );
}

/// Real Nix and vulnix on a real closure:
/// `TIARIS_NEST_VULNIX=… TIARIS_NEST_VULNIX_PATH=/nix/store/… cargo test -- --ignored real_vulnix`.
#[tokio::test]
#[ignore = "needs Nix, vulnix and network access to the NVD feed"]
async fn real_vulnix_scans_a_store_closure() {
    let (Ok(vulnix), Ok(path)) = (
        std::env::var("TIARIS_NEST_VULNIX"),
        std::env::var("TIARIS_NEST_VULNIX_PATH"),
    ) else {
        panic!("set TIARIS_NEST_VULNIX and TIARIS_NEST_VULNIX_PATH");
    };
    let cache = std::env::var("TIARIS_NEST_VULNIX_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tiaris-nest-vulnix-cache"));
    let scanner = Scanner {
        nix: "nix".to_string(),
        vulnix,
        vulnix_cache: cache,
        public_cache: PUBLIC_CACHE.to_string(),
        software_cache: None,
        memory_limit_bytes: VULNIX_MEMORY_LIMIT_BYTES,
    };
    check_derivers(&scanner, &path).await.unwrap();
    let advisories = run_vulnix(&scanner, &path).await.unwrap();
    assert!(
        advisories
            .values()
            .all(|advisory| valid_advisory_id(&advisory.id))
    );
    eprintln!("{} advisories", advisories.len());
}

#[tokio::test]
async fn corrupt_scan_and_hint_records_are_ignored_and_rewritten() {
    let db = pool().await;
    let fake = fake("corrupt-records").await;
    release_and_candidate(&db).await;
    assert!(scan_once(&db, &fake, Utc::now()).await);
    let name = ScanFile::name(COMMIT, CANDIDATE_REVISION);
    let path = scans_dir(&db.data).join(&name);
    // A torn or garbage scan is no scan: the candidate is scanned again.
    std::fs::write(
        &path,
        b"{\"schema\":\"tiaris.nest.software-update-scan.v1\",",
    )
    .unwrap();
    assert!(report(&db.pool, &db.data).await.unwrap().is_empty());
    assert!(scan_once(&db, &fake, Utc::now()).await);
    assert_eq!(report(&db.pool, &db.data).await.unwrap().len(), 1);
    // A scan that breaks its rules is ignored as well.
    let mut record: Value =
        state_files::read(&scans_dir(&db.data), &name, SCAN_SCHEMA, MAX_SCAN_BYTES).unwrap();
    record["state"] = json!("succeeded");
    record["reason"] = json!("scan_failed");
    state_files::write(
        &scans_dir(&db.data),
        &name,
        SCAN_SCHEMA,
        MAX_SCAN_BYTES,
        &record,
    )
    .unwrap();
    assert!(report(&db.pool, &db.data).await.unwrap().is_empty());
    // Corrupt hints name no release: the candidate is skipped, not compared
    // against a guess.
    std::fs::write(
        super::super::state_dir(&db.data).join(HINTS_FILE),
        b"not json",
    )
    .unwrap();
    assert!(read_hints(&db.data).is_empty());
    assert!(scan_once(&db, &fake, Utc::now()).await);
    assert_eq!(
        stored_scan(&db).await.reason.as_deref(),
        Some(REASON_MISSING_RELEASE_HINT)
    );
}

#[tokio::test]
async fn scan_records_are_bounded_and_hints_follow_their_jobs() {
    let db = pool().await;
    let job = insert_job(
        &db,
        "kept-job",
        spec(CANDIDATE_REVISION, 4, COMMIT, &[]),
        CANDIDATE_OUT,
        "2026-10-31T05:00:00Z",
    )
    .await;
    for index in 0..MAX_SCAN_RECORDS + 3 {
        insert_scan(
            &db,
            COMMIT,
            &format!("aaaaaaaa-bbbb-4ccc-8ddd-{index:012}"),
            job,
            json!([]),
            &format!("2026-10-31T{:02}:{:02}:00Z", index / 60 % 24, index % 60),
        );
    }
    // Scans of a job Nest no longer holds go at once.
    insert_scan(
        &db,
        COMMIT,
        CANDIDATE_REVISION,
        job + 100,
        json!([]),
        "2026-10-31T23:59:00Z",
    );
    name_release(&db, "kept-job", RELEASE_REVISION).await;
    name_release(&db, "gone-job", RELEASE_REVISION).await;
    prune(&db.pool, &db.data).await.unwrap();
    let scans = all_scans(&db.data);
    assert_eq!(scans.len(), MAX_SCAN_RECORDS);
    assert!(scans.iter().all(|(_, scan)| scan.candidate_job_id == job));
    assert_eq!(
        read_hints(&db.data).keys().collect::<Vec<_>>(),
        ["kept-job"]
    );
}
