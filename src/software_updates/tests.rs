use std::os::unix::fs::PermissionsExt;

use chrono::Timelike;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::*;
use crate::build::{COMMIT_IDENTITIES, REVIEWED_BUILDER_FILES, store_path_item};

const COMMIT: &str = "6f06d204d8f2d8761d9da78778745974a3216381";
const NAR_HASH: &str = "sha256-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMeE=";
const AGENT_DRV: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tiaris-agent-0.1.0.drv";
const WRAPPER_DRV: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-tiaris-packages.drv";
const FIREFOX_DRV: &str = "/nix/store/cccccccccccccccccccccccccccccccc-firefox-unwrapped-145.0.drv";
const UNITS_DRV: &str = "/nix/store/dddddddddddddddddddddddddddddddd-system-units.drv";
const VENDOR_DRV: &str = "/nix/store/ffffffffffffffffffffffffffffffff-cargo-vendor-dir.drv";
const STAGING_DRV: &str =
    "/nix/store/gggggggggggggggggggggggggggggggg-tiaris-agent-vendor-staging.drv";

async fn pool() -> SqlitePool {
    let pool = crate::db::connect_with_url("sqlite::memory:")
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
}

/// The job database and a private Nest state directory, removed on drop.
struct Stores {
    pool: SqlitePool,
    data: PathBuf,
}

impl Drop for Stores {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

async fn stores(name: &str) -> Stores {
    let data = std::env::temp_dir().join(format!(
        "tiaris-nest-software-update-state-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&data);
    Stores {
        pool: pool().await,
        data,
    }
}

/// The stored record of `commit`, changed by `change`, written back.
fn tamper(data: &Path, commit: &str, change: impl FnOnce(&mut Value)) {
    let dir = detected_dir(data);
    let name = format!("{commit}.json");
    let mut record: Value =
        crate::state_files::read(&dir, &name, DETECTED_SCHEMA, MAX_DETECTED_RECORD_BYTES).unwrap();
    change(&mut record);
    crate::state_files::write(
        &dir,
        &name,
        DETECTED_SCHEMA,
        MAX_DETECTED_RECORD_BYTES,
        &record,
    )
    .unwrap();
}

/// Identities of a commit at which every reviewed provider has a new hash.
fn shifted_identities() -> BTreeMap<String, DerivedIdentity> {
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    let shift = |path: &str| {
        let item = store_path_item(path).unwrap();
        let hash = Sha256::digest(item.as_bytes())
            .iter()
            .take(32)
            .map(|byte| NIX_BASE32[usize::from(*byte) % 32] as char)
            .collect::<String>();
        path.replacen(&item[..32], &hash, 1)
    };
    COMMIT_IDENTITIES
        .iter()
        .map(|identity| {
            (
                identity.role.to_string(),
                DerivedIdentity {
                    path: shift(identity.path),
                    drv: identity.drv_path.map(shift),
                },
            )
        })
        .collect()
}

fn evaluated_identities(release: &str, files: &[(&str, &str)]) -> Value {
    let mut reviewed = REVIEWED_BUILDER_FILES
        .iter()
        .map(|(name, sha256)| (name.to_string(), sha256.to_string()))
        .collect::<BTreeMap<_, _>>();
    for (name, sha256) in files {
        reviewed.insert(name.to_string(), sha256.to_string());
    }
    json!({
        "release": release,
        "kernel_version": "6.18.59",
        "files": reviewed,
        "identities": shifted_identities(),
    })
}

fn compile(path: &str) -> Value {
    json!({
        "name": derivation_display_name(path),
        "builder": "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-bash-5.3p9/bin/bash",
        "env": {"buildPhase": "make"},
        "inputSrcs": [],
        "inputDrvs": {},
    })
}

/// A NixOS generator script run by the commit's own stdenv shell whose
/// content no reviewed fingerprint matches.
fn changed_script() -> Value {
    let identities = shifted_identities();
    let bash = &identities["stdenv.shell"];
    json!({
        "name": "system-units",
        "builder": bash.path,
        "env": {"preferLocalBuild": "1", "buildCommand": "mkdir -p $out\necho changed\n"},
        "inputSrcs": [],
        "inputDrvs": {bash.drv.clone().unwrap(): ["out"]},
    })
}

struct FakeNix {
    root: PathBuf,
    config: AppConfig,
}

/// A `nix` that answers the check's evaluation, dry runs and derivation
/// queries from files, so every outcome is reached without real Nix.
fn fake_nix(name: &str, identities: Option<Value>, blueprint_listing: &[&str]) -> FakeNix {
    fake_nix_with(
        name,
        identities,
        blueprint_listing,
        &[AGENT_DRV, WRAPPER_DRV],
        &[],
    )
}

/// `tiaris_listing` is what the Tiaris packages' dry run lists and
/// `agent_inputs` the agent's local inputs. Pin runs list nothing: the
/// reference jobs were fully admitted there.
fn fake_nix_with(
    name: &str,
    identities: Option<Value>,
    blueprint_listing: &[&str],
    tiaris_listing: &[&str],
    agent_inputs: &[&str],
) -> FakeNix {
    fake_nix_full(
        name,
        identities,
        blueprint_listing,
        tiaris_listing,
        agent_inputs,
        json!({}),
    )
}

fn fake_nix_full(
    name: &str,
    identities: Option<Value>,
    blueprint_listing: &[&str],
    tiaris_listing: &[&str],
    agent_inputs: &[&str],
    extra_derivations: Value,
) -> FakeNix {
    let root = std::env::temp_dir().join(format!(
        "tiaris-nest-software-updates-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    if let Some(identities) = identities {
        std::fs::write(root.join("identities.json"), identities.to_string()).unwrap();
    }
    let listing = |paths: &[&str]| {
        if paths.is_empty() {
            String::new()
        } else {
            format!(
                "these {} derivations will be built:\n{}\n",
                paths.len(),
                paths
                    .iter()
                    .map(|path| format!("  {path}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
    };
    std::fs::write(root.join("tiaris-listing"), listing(tiaris_listing)).unwrap();
    std::fs::write(root.join("references.json"), r#"["standard"]"#).unwrap();
    std::fs::write(root.join("blueprint-listing"), listing(blueprint_listing)).unwrap();
    let mut agent = compile(AGENT_DRV);
    agent["inputDrvs"] = agent_inputs
        .iter()
        .map(|path| (path.to_string(), json!(["out"])))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let mut list = compile(WRAPPER_DRV);
    list["inputDrvs"] = json!({ AGENT_DRV: ["out"] });
    // A fixed-output fetch whose builder is not `builtin:fetchurl`.
    let mut staging = compile(STAGING_DRV);
    staging["outputs"] = json!({"out": {"path": "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-staging",
        "method": "nar", "hashAlgo": "sha256", "hash": "0".repeat(64)}});
    let mut derivations = json!({
        AGENT_DRV: agent,
        WRAPPER_DRV: list,
        STAGING_DRV: staging,
        VENDOR_DRV: compile(VENDOR_DRV),
        FIREFOX_DRV: compile(FIREFOX_DRV),
        UNITS_DRV: changed_script(),
    });
    for (path, drv) in extra_derivations.as_object().unwrap() {
        derivations[path] = drv.clone();
    }
    std::fs::write(root.join("derivations.json"), derivations.to_string()).unwrap();
    let script = format!(
        r#"#!/bin/sh
set -eu
root='{root}'
printf '%s\n' "$*" >> "$root/calls"
for argument in "$@"; do
  case "$argument" in
    local\?root=*)
      store="${{argument#local?root=}}"
      ls -d "$(dirname "$store")"/source-policy-store-* | wc -l >> "$root/stores"
      ;;
  esac
done
case " $* " in
  *" eval "*referenceBlueprints*)
    cat "$root/references.json"
    ;;
  *" eval "*)
    [ -f "$root/identities.json" ] || exit 3
    cat "$root/identities.json"
    ;;
  *" derivation show "*)
    cat "$root/derivations.json"
    ;;
  *" build "*"tiaris-packages"*)
    cat "$root/tiaris-listing" >&2
    ;;
  *" build "*pin-*)
    [ -f "$root/fail-dry-run" ] && exit 4
    :
    ;;
  *" build "*)
    [ -f "$root/fail-dry-run" ] && exit 4
    cat "$root/blueprint-listing" >&2
    ;;
  *) exit 5 ;;
esac
"#,
        root = root.display()
    );
    let program = root.join("nix");
    std::fs::write(&program, script).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = AppConfig::default();
    config.build.nix_binary = program.display().to_string();
    config.build.work_dir = root.join("work");
    config.paths.data_dir = root.join("data");
    FakeNix { root, config }
}

async fn evaluate(fake: &FakeNix) -> Result<DetectedOutcome> {
    evaluate_with(fake, false).await
}

async fn evaluate_with(fake: &FakeNix, keep_root: bool) -> Result<DetectedOutcome> {
    let metadata = FlakeMetadata {
        path: "/nix/store/ydk30pf7qngrw0ws113m9p005p681rxy-source".to_string(),
        last_modified: 1_793_294_725,
        nar_hash: NAR_HASH.to_string(),
    };
    let work = fake.root.join("evaluation");
    create_private_dir(&work).unwrap();
    let outcome = evaluate_commit_in(
        &fake.config,
        COMMIT,
        &metadata,
        "tarball+file:///usr/share/tiaris-nest/manage-source/0000000000000000000000000000000000000000.tar",
        &work,
    )
    .await;
    let leftovers = std::fs::read_dir(&fake.config.build.work_dir)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("source-policy-store-")
                })
                .count()
        })
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "isolated stores must be removed");
    if !keep_root {
        let _ = std::fs::remove_dir_all(&fake.root);
    }
    outcome
}

#[tokio::test]
async fn a_commit_whose_builtin_blueprints_need_only_tiaris_packages_is_ready() {
    let fake = fake_nix(
        "ready",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV],
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.state(), "ready");
    assert_eq!(outcome.kernel_version, "6.18.59");
    assert_eq!(
        outcome.tiaris_derivations,
        BTreeSet::from([AGENT_DRV.to_string()])
    );
    assert_eq!(outcome.identities, Some(shifted_identities()));
}

#[tokio::test]
async fn a_compile_beyond_the_tiaris_packages_blocks_with_source_build_required() {
    let fake = fake_nix(
        "source",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV, FIREFOX_DRV],
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_SOURCE_BUILD_REQUIRED));
    assert_eq!(outcome.details, vec!["firefox-unwrapped-145.0"]);
    assert_eq!(outcome.identities, None);
}

#[tokio::test]
async fn a_changed_generator_script_blocks_with_its_name() {
    let fake = fake_nix(
        "script",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV, UNITS_DRV, FIREFOX_DRV],
    );
    let outcome = evaluate(&fake).await.unwrap();
    // A changed reviewed script outranks a compile: a Tiaris release must
    // review it before anything else matters.
    assert_eq!(outcome.reason, Some(REASON_BUILD_SCRIPT_CHANGED));
    assert_eq!(outcome.details, vec!["system-units"]);
}

#[tokio::test]
async fn a_changed_builder_file_no_admitted_derivation_uses_does_not_block() {
    let fake = fake_nix(
        "wrapper",
        Some(evaluated_identities(
            "26.05",
            &[("wrapper.c", &"0".repeat(64))],
        )),
        &[AGENT_DRV],
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.state(), "ready");
    assert!(outcome.reviewed.builder_files.is_empty());
}

#[tokio::test]
async fn the_tiaris_packages_build_closure_compiles() {
    // The agent's vendored crates are local work of the Tiaris packages'
    // closure, from the shipped Tiaris source and the commit's nixpkgs.
    let fake = fake_nix_with(
        "tiaris-closure",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV, VENDOR_DRV],
        &[AGENT_DRV, VENDOR_DRV, WRAPPER_DRV],
        &[VENDOR_DRV],
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.state(), "ready");
    assert_eq!(outcome.tiaris_closure_size, 2);
    assert_eq!(
        outcome.tiaris_derivations,
        BTreeSet::from([AGENT_DRV.to_string(), VENDOR_DRV.to_string()])
    );
}

#[tokio::test]
async fn fixed_output_derivations_of_the_closure_need_the_fetch_rules() {
    let fake = fake_nix_with(
        "tiaris-fixed-output",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV, STAGING_DRV],
        &[AGENT_DRV, STAGING_DRV, WRAPPER_DRV],
        &[STAGING_DRV],
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_SOURCE_BUILD_REQUIRED));
    assert_eq!(outcome.details, vec!["tiaris-agent-vendor-staging"]);
}

#[tokio::test]
async fn local_work_outside_the_tiaris_closure_stays_blocked() {
    // The seeds' dry run also lists a compile no Tiaris package reaches.
    let fake = fake_nix_with(
        "tiaris-outside",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV, FIREFOX_DRV],
        &[AGENT_DRV, FIREFOX_DRV, WRAPPER_DRV],
        &[],
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_SOURCE_BUILD_REQUIRED));
    assert_eq!(outcome.details, vec!["firefox-unwrapped-145.0"]);
}

#[tokio::test]
async fn a_tiaris_closure_over_the_bound_blocks_the_commit() {
    let crates = (0..build::MAX_TIARIS_PACKAGE_DERIVATIONS)
        .map(|index| {
            format!(
                "/nix/store/{}-crate-{index}.drv",
                format!("{index:0>32}").replace('e', "f")
            )
        })
        .collect::<Vec<_>>();
    let extra = crates
        .iter()
        .map(|path| (path.clone(), compile(path)))
        .collect::<serde_json::Map<_, _>>();
    let mut listing = vec![AGENT_DRV, WRAPPER_DRV];
    listing.extend(crates.iter().map(String::as_str));
    let fake = fake_nix_full(
        "tiaris-bound",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV],
        &listing,
        &crates.iter().map(String::as_str).collect::<Vec<_>>(),
        Value::Object(extra),
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_SOURCE_BUILD_REQUIRED));
    assert_eq!(
        outcome.tiaris_closure_size,
        build::MAX_TIARIS_PACKAGE_DERIVATIONS + 1
    );
    assert_eq!(outcome.details.len(), 50);
}

#[tokio::test]
async fn evaluation_failures_block_with_evaluation_failed() {
    let fake = fake_nix("eval", None, &[]);
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_EVALUATION_FAILED));
    assert_eq!(outcome.details, vec!["build identities"]);

    let mut incomplete = evaluated_identities("26.05", &[]);
    incomplete["identities"]
        .as_object_mut()
        .unwrap()
        .remove("stdenvNoCC");
    let fake = fake_nix("incomplete", Some(incomplete), &[]);
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_EVALUATION_FAILED));

    let fake = fake_nix("dry-run", Some(evaluated_identities("26.05", &[])), &[]);
    std::fs::write(fake.root.join("fail-dry-run"), "").unwrap();
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_EVALUATION_FAILED));
    assert_eq!(outcome.details, vec!["reference-standard"]);
}

#[tokio::test]
async fn a_commit_of_another_nixos_release_is_never_recorded() {
    let fake = fake_nix("release", Some(evaluated_identities("26.11", &[])), &[]);
    let error = evaluate(&fake).await.unwrap_err().to_string();
    assert!(error.contains("does not cross releases"), "{error}");
}

#[test]
fn reasons_are_bounded_and_ordered() {
    let many = (0..80)
        .map(|index| format!("drv-{index}"))
        .collect::<Vec<_>>();
    let outcome = decide(
        String::new(),
        BTreeSet::new(),
        many.clone(),
        BTreeMap::new(),
        BTreeSet::new(),
    );
    assert_eq!(outcome.reason, Some(REASON_SOURCE_BUILD_REQUIRED));
    assert_eq!(outcome.details, many[..50]);
    let outcome = decide(
        String::new(),
        BTreeSet::from(["etc".to_string()]),
        many,
        BTreeMap::new(),
        BTreeSet::new(),
    );
    assert_eq!(outcome.reason, Some(REASON_BUILD_SCRIPT_CHANGED));
    assert_eq!(outcome.details, vec!["etc"]);
}

#[test]
fn flake_metadata_must_name_the_commit_and_its_recorded_nar_hash() {
    let metadata = json!({
        "path": "/nix/store/ydk30pf7qngrw0ws113m9p005p681rxy-source",
        "locked": {"rev": COMMIT, "narHash": NAR_HASH, "lastModified": 1_793_294_725},
    });
    let bytes = metadata.to_string().into_bytes();
    let parsed = parse_flake_metadata(&bytes, COMMIT, None).unwrap();
    assert_eq!(parsed.nar_hash, NAR_HASH);
    assert_eq!(parsed.last_modified, 1_793_294_725);
    assert!(parse_flake_metadata(&bytes, COMMIT, Some(NAR_HASH)).is_ok());
    let other = "sha256-0XnckG4ZhBmAsYa9mLuEIFowBG0fDGPLHduQGsbMS4A=";
    assert!(parse_flake_metadata(&bytes, COMMIT, Some(other)).is_err());
    assert!(parse_flake_metadata(&bytes, &"1".repeat(40), None).is_err());
    let mut unsafe_path = metadata.clone();
    unsafe_path["path"] = json!("/tmp/source");
    assert!(parse_flake_metadata(unsafe_path.to_string().as_bytes(), COMMIT, None).is_err());
}

#[test]
fn the_daily_check_runs_between_one_and_five_in_the_schedule_time_zone() {
    let amsterdam: chrono_tz::Tz = "Europe/Amsterdam".parse().unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 31, 12, 0, 0).unwrap();
    for offset in [0, 1, 131, 239, 240, 500] {
        let next = next_daily_check(now, amsterdam, offset);
        let local = next.with_timezone(&amsterdam);
        assert!(next > now);
        assert!(next - now <= chrono::Duration::hours(24));
        let minute = local.hour() * 60 + local.minute();
        assert!((60..300).contains(&minute), "{local}");
    }
    // Before the window: today.
    let early = Utc.with_ymd_and_hms(2026, 10, 31, 0, 30, 0).unwrap();
    let next = next_daily_check(early, chrono_tz::UTC, 0);
    assert_eq!(next, Utc.with_ymd_and_hms(2026, 10, 31, 1, 0, 0).unwrap());
    // A local time skipped by the spring DST change runs an hour later.
    let new_york: chrono_tz::Tz = "America/New_York".parse().unwrap();
    let before = Utc.with_ymd_and_hms(2027, 3, 14, 5, 0, 0).unwrap();
    let next = next_daily_check(before, new_york, 60);
    assert_eq!(next.with_timezone(&new_york).hour(), 3);
}

#[tokio::test]
async fn manage_names_the_channel_and_requests_checks_without_crossing_releases() {
    let stores = stores("check-state").await;
    let data = stores.data.as_path();
    apply_managed(data, None, None).await.unwrap();
    assert_eq!(check_state(data).await.unwrap().channel, None);
    apply_managed(data, Some(&json!("nixos-26.05")), None)
        .await
        .unwrap();
    assert_eq!(
        check_state(data).await.unwrap().channel.as_deref(),
        Some("nixos-26.05")
    );
    for channel in [
        json!("nixos-26.11"),
        json!("nixos-unstable"),
        json!("nixos-26.05-small"),
        json!(5),
    ] {
        assert!(apply_managed(data, Some(&channel), None).await.is_err());
    }
    assert!(
        apply_managed(data, None, Some(&json!("yesterday")))
            .await
            .is_err()
    );

    let first = json!("2026-10-31T03:00:00Z");
    apply_managed(data, None, Some(&first)).await.unwrap();
    let state = check_state(data).await.unwrap();
    assert!(pending_request(&state).is_some());
    // An older request never replaces a newer one.
    apply_managed(data, None, Some(&json!("2026-10-30T03:00:00Z")))
        .await
        .unwrap();
    let state = check_state(data).await.unwrap();
    assert_eq!(
        parse_timestamp(state.check_requested_at.as_deref()),
        parse_timestamp(first.as_str())
    );
    assert_eq!(checked_at(data).await.unwrap(), None);
    // A failed check handles the request but is not a completed check.
    mark_checked(
        data,
        state.check_requested_at.as_deref(),
        Some(Err("network".to_string())),
    )
    .await
    .unwrap();
    assert_eq!(checked_at(data).await.unwrap(), None);
    mark_checked(data, None, Some(Ok(()))).await.unwrap();
    let completed = checked_at(data).await.unwrap().unwrap();
    assert!(parse_timestamp(Some(&completed)).is_some() && completed.ends_with('Z'));
    // A deduplicated wake-up records nothing about the last check.
    mark_checked(data, None, None).await.unwrap();
    assert_eq!(checked_at(data).await.unwrap(), Some(completed));
    assert!(pending_request(&check_state(data).await.unwrap()).is_none());
    // A later sync that omits the request keeps it handled.
    apply_managed(data, None, None).await.unwrap();
    assert!(pending_request(&check_state(data).await.unwrap()).is_none());
}

fn metadata(last_modified: i64) -> FlakeMetadata {
    FlakeMetadata {
        path: "/nix/store/ydk30pf7qngrw0ws113m9p005p681rxy-source".to_string(),
        last_modified,
        nar_hash: NAR_HASH.to_string(),
    }
}

fn ready_outcome() -> DetectedOutcome {
    decide(
        "6.18.59".to_string(),
        BTreeSet::new(),
        Vec::new(),
        shifted_identities(),
        BTreeSet::from([AGENT_DRV.to_string()]),
    )
}

#[tokio::test]
async fn ready_commits_are_admitted_reported_and_kept_while_used() {
    let stores = stores("ready").await;
    let (pool, data) = (&stores.pool, stores.data.as_path());
    let blocked = "1111111111111111111111111111111111111111";
    let older_ready = "2222222222222222222222222222222222222222";
    store_detected(
        pool,
        data,
        older_ready,
        DEFAULT_CHANNEL,
        &metadata(1_792_000_000),
        &ready_outcome(),
    )
    .await
    .unwrap();
    store_detected(
        pool,
        data,
        COMMIT,
        DEFAULT_CHANNEL,
        &metadata(1_793_294_725),
        &ready_outcome(),
    )
    .await
    .unwrap();
    store_detected(
        pool,
        data,
        blocked,
        DEFAULT_CHANNEL,
        &metadata(1_793_400_000),
        &DetectedOutcome::blocked(
            "6.18.60".to_string(),
            REASON_BUILD_SCRIPT_CHANGED,
            vec!["wrapper.c".to_string()],
        ),
    )
    .await
    .unwrap();

    let ready = ready_commit(data, COMMIT).await.unwrap().unwrap();
    assert_eq!(ready.nar_hash, NAR_HASH);
    assert_eq!(ready.profile.nixpkgs_commit(), COMMIT);
    assert!(ready.profile.admits_tiaris_package(AGENT_DRV));
    assert!(ready_commit(data, blocked).await.unwrap().is_none());
    assert!(ready_commit(data, &"3".repeat(40)).await.unwrap().is_none());

    let reported = report(pool, data).await.unwrap();
    assert_eq!(
        reported
            .iter()
            .map(|commit| commit.commit.as_str())
            .collect::<Vec<_>>(),
        [blocked, COMMIT, older_ready]
    );
    let value = serde_json::to_value(&reported).unwrap();
    assert_eq!(
        value[1],
        json!({
            "commit": COMMIT,
            "channel": "nixos-26.05",
            "last_modified": "2026-10-29T17:25:25Z",
            "nar_hash": NAR_HASH,
            "kernel_version": "6.18.59",
            "state": "ready",
            "detected_at": value[1]["detected_at"],
        })
    );
    assert_eq!(value[0]["reason"], "build_script_changed");
    // Manage's wire carries the reason only; the names stay local.
    assert!(value[0].get("reason_details").is_none());

    let mut config = AppConfig::default();
    config.build.targets = vec![crate::config::BuildTargetConfig {
        artifact_type: "nixos_closure".to_string(),
        target: "blueprint".to_string(),
        system: "x86_64-linux".to_string(),
        flake: format!("github:NixOS/nixpkgs/{}", build::BUILTIN_NIXPKGS_COMMIT),
        attr: "packages.x86_64-linux.desktop-experience".to_string(),
    }];
    config.paths.data_dir = data.to_path_buf();
    let state = AppState::new(config, pool.clone());
    assert_eq!(
        workstation_nixpkgs_commits(&state).await,
        [COMMIT, build::BUILTIN_NIXPKGS_COMMIT]
    );
    // An older ready commit stays while a Blueprint job this Nest holds uses it.
    sqlx::query(
        "INSERT INTO nest_build_jobs (requested_artifact_type, build_spec, status, created_at, updated_at)
         VALUES ('nixos_closure', ?, 'succeeded', '2026-10-31T00:00:00Z', '2026-10-31T00:00:00Z')",
    )
    .bind(json!({"nixpkgs_commit": older_ready}).to_string())
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        workstation_nixpkgs_commits(&state).await,
        [older_ready, COMMIT, build::BUILTIN_NIXPKGS_COMMIT]
    );
    // The full list goes first with the ready commits still in use.
    assert_eq!(
        report(pool, data)
            .await
            .unwrap()
            .iter()
            .map(|commit| commit.commit.as_str())
            .collect::<Vec<_>>(),
        [older_ready, blocked, COMMIT]
    );

    // A tampered profile fails closed.
    tamper(data, COMMIT, |record| record["profile"] = json!("{}"));
    assert!(ready_commit(data, COMMIT).await.is_err());
}

#[tokio::test]
async fn inconsistent_or_corrupt_detected_records_are_not_used() {
    let stores = stores("inconsistent").await;
    let (pool, data) = (&stores.pool, stores.data.as_path());
    store_detected(
        pool,
        data,
        COMMIT,
        DEFAULT_CHANNEL,
        &metadata(1_793_294_725),
        &ready_outcome(),
    )
    .await
    .unwrap();
    let good: Value = crate::state_files::read(
        &detected_dir(data),
        &format!("{COMMIT}.json"),
        DETECTED_SCHEMA,
        MAX_DETECTED_RECORD_BYTES,
    )
    .unwrap();
    // The rules the database used to enforce.
    for (state, reason, profile) in [
        ("ready", json!("evaluation_failed"), json!("{}")),
        ("blocked", Value::Null, Value::Null),
        ("ready", Value::Null, Value::Null),
        ("blocked", json!("other"), Value::Null),
        ("pending", Value::Null, json!("{}")),
    ] {
        tamper(data, COMMIT, |record| {
            *record = good.clone();
            record["state"] = json!(state);
            record["reason"] = reason.clone();
            record["profile"] = profile.clone();
        });
        assert!(
            detected_row(data, COMMIT).await.unwrap().is_none(),
            "{state} {reason}"
        );
        assert!(ready_commit(data, COMMIT).await.unwrap().is_none());
        assert!(report(pool, data).await.unwrap().is_empty());
    }
    // A record filed under another commit, an unknown field, or garbage.
    tamper(data, COMMIT, |record| {
        *record = good.clone();
        record["commit_rev"] = json!("1".repeat(40));
    });
    assert!(detected_row(data, COMMIT).await.unwrap().is_none());
    tamper(data, COMMIT, |record| {
        *record = good.clone();
        record["admit_everything"] = json!(true);
    });
    assert!(detected_row(data, COMMIT).await.unwrap().is_none());
    std::fs::write(
        detected_dir(data).join(format!("{COMMIT}.json")),
        b"{\"schema\":",
    )
    .unwrap();
    assert!(detected_row(data, COMMIT).await.unwrap().is_none());
    assert!(report(pool, data).await.unwrap().is_empty());
    // Recording the commit again replaces the corrupt record.
    store_detected(
        pool,
        data,
        COMMIT,
        DEFAULT_CHANNEL,
        &metadata(1_793_294_725),
        &ready_outcome(),
    )
    .await
    .unwrap();
    assert!(ready_commit(data, COMMIT).await.unwrap().is_some());
}

#[tokio::test]
async fn detected_records_are_bounded_keeping_ready_commits_in_use() {
    let stores = stores("bounded").await;
    let (pool, data) = (&stores.pool, stores.data.as_path());
    let commit = |index: usize| format!("{index:040x}");
    // The oldest commit is ready and a Blueprint job uses it.
    sqlx::query(
        "INSERT INTO nest_build_jobs (requested_artifact_type, build_spec, status, created_at, updated_at)
         VALUES ('nixos_closure', ?, 'succeeded', '2026-10-31T00:00:00Z', '2026-10-31T00:00:00Z')",
    )
    .bind(json!({"nixpkgs_commit": commit(1)}).to_string())
    .execute(pool)
    .await
    .unwrap();
    store_detected(
        pool,
        data,
        &commit(1),
        DEFAULT_CHANNEL,
        &metadata(1_792_000_000),
        &ready_outcome(),
    )
    .await
    .unwrap();
    for index in 2..=MAX_DETECTED_RECORDS + 5 {
        store_detected(
            pool,
            data,
            &commit(index),
            DEFAULT_CHANNEL,
            &metadata(1_792_000_000 + index as i64),
            &DetectedOutcome::blocked(String::new(), REASON_EVALUATION_FAILED, Vec::new()),
        )
        .await
        .unwrap();
    }
    let rows = detected_rows(data).await.unwrap();
    assert_eq!(rows.len(), MAX_DETECTED_RECORDS);
    assert!(rows.iter().any(|row| row.commit_rev == commit(1)));
    assert!(ready_commit(data, &commit(1)).await.unwrap().is_some());
    // The oldest blocked commits went first.
    assert!(detected_row(data, &commit(2)).await.unwrap().is_none());
    assert!(
        detected_row(data, &commit(MAX_DETECTED_RECORDS + 5))
            .await
            .unwrap()
            .is_some()
    );
    let reported = report(pool, data).await.unwrap();
    assert_eq!(reported.len(), MAX_REPORTED_DETECTED_COMMITS as usize);
    assert_eq!(reported[0].commit, commit(1));
}

#[test]
fn the_check_flake_evaluates_only_the_shipped_tiaris_source_and_nixpkgs() {
    let flake = reference_flake(
        &build::nixpkgs_flake_ref(COMMIT, Some(NAR_HASH)).unwrap(),
        "tarball+file:///usr/share/tiaris-nest/manage-source/0000000000000000000000000000000000000000.tar",
    );
    assert!(flake.contains(&format!(
        "inputs.nixpkgs.url = \"github:NixOS/nixpkgs/{COMMIT}?narHash="
    )));
    // Two inputs only: nixpkgs and the shipped Tiaris source.
    assert_eq!(flake.matches("inputs.").count(), 2);
    assert!(flake.contains("tiaris-workstation-cache-seeds.nix"));
    assert!(flake.contains("tiaris-packages = pkgs.writeText"));
    assert!(flake.contains(&format!("manage + \"/{REFERENCE_BLUEPRINTS_DIR}\"")));
    assert!(flake.contains("referenceBlueprints = referenceNames;"));
    for profile in BUILTIN_BLUEPRINT_PROFILES {
        assert!(flake.contains(&format!("{profile} = blueprint \"{profile}\";")));
    }
    let files = build::blueprint_job_template_files().unwrap();
    assert!(files[0].1.contains("./tiaris-blueprints.nix"));
    assert!(files[0].1.contains("./blueprint.nix"));
    // The reference configuration is the job configuration with the
    // reference's modules in the places of the job's.
    assert!(files[1].1.starts_with("{ desktop, blueprint }:"));
    assert_eq!(
        files[1]
            .1
            .strip_prefix("{ desktop, blueprint }:\n\n")
            .unwrap()
            .replace(
                "    desktop\n    blueprint\n",
                "    ./tiaris-blueprints.nix\n    ./blueprint.nix\n"
            ),
        files[0].1
    );
    for name in ["standard", "taskbar-de", "a1"] {
        assert!(valid_reference_name(name));
    }
    for name in ["", "Standard", "../etc", "1st", &"a".repeat(33)] {
        assert!(!valid_reference_name(name));
    }
}

/// Real evaluation of a channel commit with the local Nix. Not part of CI:
/// it fetches nixpkgs and dry-runs both built-in Blueprints (minutes, a few
/// GiB of narinfo traffic). Set `TIARIS_SOFTWARE_UPDATE_COMMIT`,
/// `TIARIS_SOFTWARE_UPDATE_MANAGE_SOURCE` (a `tarball+file://` Tiaris source)
/// and optionally `TIARIS_SOFTWARE_UPDATE_NIX` (the Nest's Nix; 2.26 cannot
/// read `builtins.path` sources in an isolated dry run).
#[tokio::test]
#[ignore]
async fn real_channel_commit_evaluation() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let commit = std::env::var("TIARIS_SOFTWARE_UPDATE_COMMIT").unwrap();
    let manage = std::env::var("TIARIS_SOFTWARE_UPDATE_MANAGE_SOURCE").unwrap();
    let mut config = AppConfig::default();
    config.build.nix_binary =
        std::env::var("TIARIS_SOFTWARE_UPDATE_NIX").unwrap_or_else(|_| "nix".to_string());
    config.build.work_dir = std::env::temp_dir().join(format!(
        "tiaris-nest-software-update-real-{}",
        std::process::id()
    ));
    let metadata = flake_metadata(&config, &commit, None).await.unwrap();
    eprintln!("metadata: {metadata:?}");
    let work = config.build.work_dir.join("evaluation");
    create_private_dir(&work).unwrap();
    let outcome = evaluate_commit_in(&config, &commit, &metadata, &manage, &work)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&config.build.work_dir);
    eprintln!(
        "state={} reason={:?} kernel={} tiaris_closure={} tiaris_derivations={:#?}\ndetails={:#?}\ncoverage={:#?}\ncounterparts={:#?}\nreviewed fingerprints={} stock commands={} builder files={:?}",
        outcome.state(),
        outcome.reason,
        outcome.kernel_version,
        outcome.tiaris_closure_size,
        outcome.tiaris_derivations,
        outcome.details,
        outcome.coverage,
        outcome.counterparts,
        outcome.reviewed.fingerprints.len(),
        outcome.reviewed.stock_commands.len(),
        outcome.reviewed.builder_files,
    );
}

/// Writes the check flake for manual inspection (`TIARIS_SOFTWARE_UPDATE_FLAKE_DIR`).
#[test]
#[ignore]
fn write_check_flake_for_inspection() {
    let dir = PathBuf::from(std::env::var("TIARIS_SOFTWARE_UPDATE_FLAKE_DIR").unwrap());
    let commit = std::env::var("TIARIS_SOFTWARE_UPDATE_COMMIT").unwrap();
    let nar_hash = std::env::var("TIARIS_SOFTWARE_UPDATE_NAR_HASH").unwrap();
    let manage = std::env::var("TIARIS_SOFTWARE_UPDATE_MANAGE_SOURCE").unwrap();
    create_private_dir(&dir).unwrap();
    write_reference_flake(
        &dir,
        &build::nixpkgs_flake_ref(&commit, Some(&nar_hash)).unwrap(),
        &manage,
    )
    .unwrap();
}

#[tokio::test]
async fn only_shipped_references_are_evaluated_never_organization_jobs() {
    // Organization Blueprint jobs are not an input of the check: whatever
    // the database holds, the dry runs name only the Tiaris packages, the
    // shipped reference Blueprints and the plain profiles.
    let fake = fake_nix(
        "references-only",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV],
    );
    let root = fake.root.clone();
    let outcome = evaluate_with(&fake, true).await.unwrap();
    let calls = std::fs::read_to_string(root.join("calls")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(outcome.state(), "ready");
    let builds = calls
        .lines()
        .filter(|call| call.contains(" build "))
        .collect::<Vec<_>>();
    let installables = builds
        .iter()
        .map(|call| {
            call.split_whitespace()
                .find(|word| word.contains("#packages."))
                .unwrap()
                .rsplit_once("#packages.x86_64-linux.")
                .unwrap()
                .1
        })
        .collect::<Vec<_>>();
    // Tiaris packages once; each reference at the pin and once at the commit.
    assert_eq!(
        installables,
        [
            "tiaris-packages",
            "reference-standard",
            "reference-standard",
            "taskbar",
            "taskbar",
            "dock",
            "dock"
        ]
    );
    assert!(!calls.contains("job-"), "{calls}");
    for call in &builds[1..] {
        assert!(
            call.contains("/pin-flake#") || call.contains("/flake#"),
            "{call}"
        );
    }
}

#[tokio::test]
async fn a_tiaris_source_without_reference_blueprints_blocks() {
    let fake = fake_nix(
        "no-references",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV],
    );
    std::fs::write(fake.root.join("references.json"), "[]").unwrap();
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_REFERENCE_BLUEPRINTS_MISSING));

    let fake = fake_nix(
        "unsafe-references",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV],
    );
    std::fs::write(fake.root.join("references.json"), r#"["../../etc"]"#).unwrap();
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_EVALUATION_FAILED));
}

#[test]
fn provenance_needs_the_branch_to_contain_the_commit_after_the_pin() {
    assert_eq!(
        compare_status(br#"{"status":"ahead","ahead_by":3}"#).unwrap(),
        "ahead"
    );
    assert_eq!(
        compare_status(br#"{"status":"diverged"}"#).unwrap(),
        "diverged"
    );
    assert!(compare_status(br#"{"status":"unknown"}"#).is_err());
    assert!(compare_status(b"not json").is_err());
}

#[test]
fn failed_commits_are_evaluated_again_at_most_daily_and_after_an_update() {
    let now = Utc.with_ymd_and_hms(2026, 10, 31, 12, 0, 0).unwrap();
    let build = "0.2.49 release=0.2.49 source=a tiaris=b";
    let row = |reason: Option<&str>, hours_ago: i64, derived_by: &str| DetectedRow {
        commit_rev: COMMIT.to_string(),
        channel: DEFAULT_CHANNEL.to_string(),
        last_modified: "2026-10-29T17:25:25Z".to_string(),
        nar_hash: NAR_HASH.to_string(),
        kernel_version: String::new(),
        state: if reason.is_some() { "blocked" } else { "ready" }.to_string(),
        reason: reason.map(str::to_string),
        reason_details: "[]".to_string(),
        profile: None,
        tiaris_derivations: "[]".to_string(),
        detected_at: (now - chrono::Duration::hours(hours_ago)).to_rfc3339(),
        derived_by: derived_by.to_string(),
    };
    assert!(needs_evaluation_by(None, now, build));
    for reason in [
        REASON_EVALUATION_FAILED,
        REASON_PROVENANCE_UNVERIFIED,
        REASON_INSUFFICIENT_DISK,
    ] {
        assert!(!needs_evaluation_by(
            Some(&row(Some(reason), 1, build)),
            now,
            build
        ));
        assert!(!needs_evaluation_by(
            Some(&row(Some(reason), 23, build)),
            now,
            build
        ));
        assert!(needs_evaluation_by(
            Some(&row(Some(reason), 24, build)),
            now,
            build
        ));
    }
    for reason in [
        REASON_BUILD_SCRIPT_CHANGED,
        REASON_SOURCE_BUILD_REQUIRED,
        REASON_REFERENCE_BLUEPRINTS_MISSING,
    ] {
        assert!(!needs_evaluation_by(
            Some(&row(Some(reason), 48, build)),
            now,
            build
        ));
        // A Nest update (another build or shipped Tiaris source) may ship
        // the references or reviewed content the commit lacked.
        assert!(needs_evaluation_by(
            Some(&row(
                Some(reason),
                1,
                "0.2.48 release=0.2.48 source=a tiaris=c"
            )),
            now,
            build
        ));
    }
    // Ready commits are derived again through their stale profile instead.
    assert!(!needs_evaluation_by(
        Some(&row(None, 48, "other")),
        now,
        build
    ));
}

#[tokio::test]
async fn a_profile_from_another_nest_build_is_derived_again() {
    let stores = stores("rederive").await;
    let (pool, data) = (&stores.pool, stores.data.as_path());
    store_detected(
        pool,
        data,
        COMMIT,
        DEFAULT_CHANNEL,
        &metadata(1_793_294_725),
        &ready_outcome(),
    )
    .await
    .unwrap();
    assert!(ready_commit(data, COMMIT).await.unwrap().is_some());
    assert!(stale_ready_rows(data).await.unwrap().is_empty());
    assert_eq!(report(pool, data).await.unwrap()[0].state, "ready");
    assert_eq!(ready_commits_in_use(pool, data).await.unwrap(), [COMMIT]);
    for (field, value) in [
        ("schema", json!(PROFILE_SCHEMA - 1)),
        ("nest_build", json!("0.2.47 release=other")),
    ] {
        let mut stored: Value = serde_json::from_str(
            &detected_row(data, COMMIT)
                .await
                .unwrap()
                .unwrap()
                .profile
                .unwrap(),
        )
        .unwrap();
        let current = stored[field].clone();
        stored[field] = value;
        tamper(data, COMMIT, |record| {
            record["profile"] = json!(stored.to_string())
        });
        // Never re-mapped: the commit admits nothing, is not reported or
        // kept as ready, until derived again.
        assert!(ready_commit(data, COMMIT).await.is_err());
        assert_eq!(stale_ready_rows(data).await.unwrap().len(), 1);
        let reported = report(pool, data).await.unwrap();
        assert_eq!(reported[0].state, "blocked");
        assert_eq!(
            reported[0].reason.as_deref(),
            Some(REASON_REDERIVATION_PENDING)
        );
        assert!(ready_commits_in_use(pool, data).await.unwrap().is_empty());
        stored[field] = current;
        tamper(data, COMMIT, |record| {
            record["profile"] = json!(stored.to_string())
        });
    }
    // A profile in the format before this schema is stale too.
    tamper(data, COMMIT, |record| {
        record["profile"] = json!(r#"{"identities":{},"reviewed":{}}"#)
    });
    assert_eq!(stale_ready_rows(data).await.unwrap().len(), 1);
}

/// Provenance of a real commit through the GitHub API. Not part of CI.
/// Set `TIARIS_SOFTWARE_UPDATE_COMMIT` (and optionally `..._CHANNEL`).
#[tokio::test]
#[ignore]
async fn real_commit_provenance() {
    let commit = std::env::var("TIARIS_SOFTWARE_UPDATE_COMMIT").unwrap();
    let channel = std::env::var("TIARIS_SOFTWARE_UPDATE_CHANNEL")
        .unwrap_or_else(|_| DEFAULT_CHANNEL.to_string());
    eprintln!(
        "provenance: {:?}",
        verify_provenance(&channel, &commit).await
    );
}

#[tokio::test]
async fn the_check_keeps_one_isolated_store_at_a_time() {
    let fake = fake_nix(
        "one-store",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV],
    );
    let root = fake.root.clone();
    let outcome = evaluate_with(&fake, true).await.unwrap();
    let stores = std::fs::read_to_string(root.join("stores")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(outcome.state(), "ready");
    // Seven dry runs (Tiaris packages, three references twice) and their
    // derivation queries, each with its store alone.
    assert!(stores.lines().count() >= 7, "{stores}");
    assert!(stores.lines().all(|count| count.trim() == "1"), "{stores}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_cancelled_check_removes_its_work_directory() {
    use std::os::unix::fs::PermissionsExt;
    let root =
        std::env::temp_dir().join(format!("tiaris-nest-check-cancel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("{CHECK_WORK_DIR_PREFIX}{}", "b".repeat(32)));
    let check = {
        let path = path.clone();
        async move {
            let work = CheckWorkDir::create(path).unwrap();
            let read_only = work.path.join("stores/source-policy-store-x/nix/store/y");
            std::fs::create_dir_all(&read_only).unwrap();
            std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o555)).unwrap();
            std::future::pending::<()>().await;
            drop(work);
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(50), check)
            .await
            .is_err()
    );
    assert!(!path.exists(), "a timed-out check left its work directory");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[tokio::test]
async fn startup_removes_interrupted_checks_only() {
    use std::os::unix::fs::PermissionsExt;
    let root =
        std::env::temp_dir().join(format!("tiaris-nest-check-startup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut config = AppConfig::default();
    config.build.work_dir = root.clone();
    let interrupted = root.join(format!("{CHECK_WORK_DIR_PREFIX}{}", "c".repeat(32)));
    let read_only = interrupted.join("stores/s/nix/store/y");
    std::fs::create_dir_all(&read_only).unwrap();
    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o555)).unwrap();
    let job = root.join("job-7-input");
    let other = root.join(format!("{CHECK_WORK_DIR_PREFIX}notes"));
    std::fs::create_dir_all(&job).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    remove_interrupted_checks(&config).await;
    assert!(!interrupted.exists());
    assert!(job.exists() && other.exists());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_check_short_of_disk_space_records_insufficient_disk() {
    let stores = stores("disk").await;
    let (pool, data) = (&stores.pool, stores.data.as_path());
    store_detected(
        pool,
        data,
        COMMIT,
        DEFAULT_CHANNEL,
        &metadata(1_793_294_725),
        &DetectedOutcome::blocked(
            String::new(),
            REASON_INSUFFICIENT_DISK,
            vec!["10 MiB free".to_string()],
        ),
    )
    .await
    .unwrap();
    let reported = report(pool, data).await.unwrap();
    assert_eq!(
        reported[0].reason.as_deref(),
        Some(REASON_INSUFFICIENT_DISK)
    );
    let mut config = AppConfig::default();
    config.build.work_dir = std::env::temp_dir();
    let available = crate::disk::stats(&config.build.work_dir)
        .unwrap()
        .available_bytes;
    assert_eq!(
        enough_disk(&config).is_ok(),
        available >= MIN_CHECK_FREE_BYTES
    );
}
