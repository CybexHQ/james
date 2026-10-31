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

async fn pool() -> SqlitePool {
    let pool = crate::db::connect_with_url("sqlite::memory:")
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
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
    std::fs::write(root.join("blueprint-listing"), listing(blueprint_listing)).unwrap();
    let mut agent = compile(AGENT_DRV);
    agent["inputDrvs"] = agent_inputs
        .iter()
        .map(|path| (path.to_string(), json!(["out"])))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let mut list = compile(WRAPPER_DRV);
    list["inputDrvs"] = json!({ AGENT_DRV: ["out"] });
    let derivations = json!({
        AGENT_DRV: agent,
        WRAPPER_DRV: list,
        VENDOR_DRV: compile(VENDOR_DRV),
        FIREFOX_DRV: compile(FIREFOX_DRV),
        UNITS_DRV: changed_script(),
    });
    std::fs::write(root.join("derivations.json"), derivations.to_string()).unwrap();
    let script = format!(
        r#"#!/bin/sh
set -eu
root='{root}'
printf '%s\n' "$*" >> "$root/calls"
case " $* " in
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
    FakeNix { root, config }
}

async fn evaluate(fake: &FakeNix) -> Result<DetectedOutcome> {
    evaluate_with(fake, &pool().await, false).await
}

async fn evaluate_with(
    fake: &FakeNix,
    db: &SqlitePool,
    keep_root: bool,
) -> Result<DetectedOutcome> {
    let metadata = FlakeMetadata {
        path: "/nix/store/ydk30pf7qngrw0ws113m9p005p681rxy-source".to_string(),
        last_modified: 1_793_294_725,
        nar_hash: NAR_HASH.to_string(),
    };
    let work = fake.root.join("evaluation");
    create_private_dir(&work).unwrap();
    let outcome = evaluate_commit_in(
        &fake.config,
        db,
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
async fn only_the_top_level_tiaris_packages_compile() {
    // The agent's vendored crates are local work too. They are not a Tiaris
    // package: they must be cached or admitted by the ordinary rules.
    let fake = fake_nix_with(
        "tiaris-inputs",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV, VENDOR_DRV],
        &[AGENT_DRV, VENDOR_DRV, WRAPPER_DRV],
        &[VENDOR_DRV],
    );
    let outcome = evaluate(&fake).await.unwrap();
    assert_eq!(outcome.reason, Some(REASON_SOURCE_BUILD_REQUIRED));
    assert_eq!(outcome.details, vec!["cargo-vendor-dir"]);
    assert_eq!(outcome.tiaris_dependencies, vec!["cargo-vendor-dir"]);
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
    assert_eq!(outcome.details, vec!["taskbar"]);
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
    let pool = pool().await;
    apply_managed(&pool, None, None).await.unwrap();
    assert_eq!(check_state(&pool).await.unwrap().channel, None);
    apply_managed(&pool, Some(&json!("nixos-26.05")), None)
        .await
        .unwrap();
    assert_eq!(
        check_state(&pool).await.unwrap().channel.as_deref(),
        Some("nixos-26.05")
    );
    for channel in [
        json!("nixos-26.11"),
        json!("nixos-unstable"),
        json!("nixos-26.05-small"),
        json!(5),
    ] {
        assert!(apply_managed(&pool, Some(&channel), None).await.is_err());
    }
    assert!(
        apply_managed(&pool, None, Some(&json!("yesterday")))
            .await
            .is_err()
    );

    let first = json!("2026-10-31T03:00:00Z");
    apply_managed(&pool, None, Some(&first)).await.unwrap();
    let state = check_state(&pool).await.unwrap();
    assert!(pending_request(&state).is_some());
    // An older request never replaces a newer one.
    apply_managed(&pool, None, Some(&json!("2026-10-30T03:00:00Z")))
        .await
        .unwrap();
    let state = check_state(&pool).await.unwrap();
    assert_eq!(
        parse_timestamp(state.check_requested_at.as_deref()),
        parse_timestamp(first.as_str())
    );
    assert_eq!(checked_at(&pool).await.unwrap(), None);
    // A failed check handles the request but is not a completed check.
    mark_checked(
        &pool,
        state.check_requested_at.as_deref(),
        Some(Err("network".to_string())),
    )
    .await
    .unwrap();
    assert_eq!(checked_at(&pool).await.unwrap(), None);
    mark_checked(&pool, None, Some(Ok(()))).await.unwrap();
    let completed = checked_at(&pool).await.unwrap().unwrap();
    assert!(parse_timestamp(Some(&completed)).is_some() && completed.ends_with('Z'));
    // A deduplicated wake-up records nothing about the last check.
    mark_checked(&pool, None, None).await.unwrap();
    assert_eq!(checked_at(&pool).await.unwrap(), Some(completed));
    assert!(pending_request(&check_state(&pool).await.unwrap()).is_none());
    // A later sync that omits the request keeps it handled.
    apply_managed(&pool, None, None).await.unwrap();
    assert!(pending_request(&check_state(&pool).await.unwrap()).is_none());
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
    let pool = pool().await;
    let blocked = "1111111111111111111111111111111111111111";
    let older_ready = "2222222222222222222222222222222222222222";
    store_detected(
        &pool,
        older_ready,
        DEFAULT_CHANNEL,
        &metadata(1_792_000_000),
        &ready_outcome(),
    )
    .await
    .unwrap();
    store_detected(
        &pool,
        COMMIT,
        DEFAULT_CHANNEL,
        &metadata(1_793_294_725),
        &ready_outcome(),
    )
    .await
    .unwrap();
    store_detected(
        &pool,
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

    let ready = ready_commit(&pool, COMMIT).await.unwrap().unwrap();
    assert_eq!(ready.nar_hash, NAR_HASH);
    assert_eq!(ready.profile.nixpkgs_commit(), COMMIT);
    assert!(ready.profile.admits_tiaris_package(AGENT_DRV));
    assert!(ready_commit(&pool, blocked).await.unwrap().is_none());
    assert!(
        ready_commit(&pool, &"3".repeat(40))
            .await
            .unwrap()
            .is_none()
    );

    let reported = report(&pool).await.unwrap();
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
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        workstation_nixpkgs_commits(&state).await,
        [older_ready, COMMIT, build::BUILTIN_NIXPKGS_COMMIT]
    );
    // The full list goes first with the ready commits still in use.
    assert_eq!(
        report(&pool)
            .await
            .unwrap()
            .iter()
            .map(|commit| commit.commit.as_str())
            .collect::<Vec<_>>(),
        [older_ready, blocked, COMMIT]
    );

    // A tampered profile fails closed.
    sqlx::query("UPDATE detected_nixpkgs_commits SET profile = '{}' WHERE commit_rev = ?")
        .bind(COMMIT)
        .execute(&pool)
        .await
        .unwrap();
    assert!(ready_commit(&pool, COMMIT).await.is_err());
}

#[tokio::test]
async fn the_database_rejects_inconsistent_detected_commits() {
    let pool = pool().await;
    for (state, reason, profile) in [
        ("ready", Some("evaluation_failed"), Some("{}")),
        ("blocked", None, None),
        ("ready", None, None),
        ("blocked", Some("other"), None),
        ("pending", None, Some("{}")),
    ] {
        let result = sqlx::query(
            "INSERT INTO detected_nixpkgs_commits
             (commit_rev, channel, last_modified, nar_hash, state, reason, profile, detected_at)
             VALUES (?, 'nixos-26.05', '2026-10-29T18:45:25Z', ?, ?, ?, ?, '2026-10-31T00:00:00Z')",
        )
        .bind(COMMIT)
        .bind(NAR_HASH)
        .bind(state)
        .bind(reason)
        .bind(profile)
        .execute(&pool)
        .await;
        assert!(result.is_err(), "{state} {reason:?}");
    }
}

#[test]
fn the_check_flake_dry_runs_tiaris_packages_and_every_builtin_blueprint() {
    let flake = builtin_blueprint_flake(
        &build::nixpkgs_flake_ref(COMMIT, Some(NAR_HASH)).unwrap(),
        "tarball+file:///usr/share/tiaris-nest/manage-source/0000000000000000000000000000000000000000.tar",
    );
    assert!(flake.contains(&format!(
        "inputs.nixpkgs.url = \"github:NixOS/nixpkgs/{COMMIT}?narHash="
    )));
    assert!(flake.contains("tiaris-workstation-cache-seeds.nix"));
    assert!(flake.contains("tiaris-packages = pkgs.writeText"));
    for profile in BUILTIN_BLUEPRINT_PROFILES {
        assert!(flake.contains(&format!("{profile} = blueprint \"{profile}\";")));
    }
    let files = build::blueprint_job_template_files();
    assert!(files[0].1.contains("./tiaris-blueprints.nix"));
    assert!(files[0].1.contains("./blueprint.nix"));
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
    let db = pool().await;
    // Optionally a Blueprint job this Nest built at the pin: a directory
    // with Manage's compiler exports `blueprint.nix` and `desktop.nix`.
    if let Ok(job) = std::env::var("TIARIS_SOFTWARE_UPDATE_JOB_DIR") {
        let job = PathBuf::from(job);
        config.build.targets = vec![crate::config::BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: format!("github:NixOS/nixpkgs/{}", build::BUILTIN_NIXPKGS_COMMIT),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        }];
        let spec = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "blueprint",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "nixpkgs_commit": build::BUILTIN_NIXPKGS_COMMIT,
            "source_lock_sha256": "b".repeat(64),
            "build_input": {
                "kind": "blueprint_nixos_module",
                "generated_nix": std::fs::read_to_string(job.join("blueprint.nix")).unwrap(),
                "desktop_module_nix": std::fs::read_to_string(job.join("desktop.nix")).unwrap(),
                "expected_state": serde_json::from_str::<Value>(
                    &std::fs::read_to_string(job.join("expected-state.json")).unwrap()
                ).unwrap(),
                "blueprint_name": "Cache contract",
                "blueprint_revision": 1
            }
        });
        sqlx::query(
            "INSERT INTO nest_build_jobs (requested_artifact_type, build_spec, target, system,
                 input_revision, input_config_hash, status, created_at, updated_at)
             VALUES ('nixos_closure', ?, 'blueprint', 'x86_64-linux', 'rev', ?, 'succeeded',
                 '2026-10-31T00:00:00Z', '2026-10-31T00:00:00Z')",
        )
        .bind(spec.to_string())
        .bind("a".repeat(64))
        .execute(&db)
        .await
        .unwrap();
    }
    let outcome = evaluate_commit_in(&config, &db, &commit, &metadata, &manage, &work)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&config.build.work_dir);
    eprintln!(
        "state={} reason={:?} kernel={} tiaris_derivations={:#?}\ndetails={:#?}\ntiaris_dependencies={:#?}\ncounterparts={:#?}\nreviewed fingerprints={} stock commands={} builder files={:?}",
        outcome.state(),
        outcome.reason,
        outcome.kernel_version,
        outcome.tiaris_derivations,
        outcome.details,
        outcome.tiaris_dependencies,
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
    write_builtin_blueprint_flake(
        &dir,
        &build::nixpkgs_flake_ref(&commit, Some(&nar_hash)).unwrap(),
        &manage,
    )
    .unwrap();
}

#[tokio::test]
async fn the_nests_own_blueprints_are_checked_with_only_nixpkgs_changed() {
    let db = pool().await;
    let pin = build::BUILTIN_NIXPKGS_COMMIT;
    let spec = |name: &str, commit: &str, allow_source_builds: bool| {
        json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "blueprint",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "blueprint_id": "4c20e5ca-a7ae-4b27-8ce6-dff50192ed21",
            "nixpkgs_commit": commit,
            "source_lock_sha256": "b".repeat(64),
            "allow_source_builds": allow_source_builds,
            "build_input": {
                "kind": "blueprint_nixos_module",
                "generated_nix": format!("{{ lib, ... }}: {{ networking.hostName = lib.mkDefault \"{name}\"; }}"),
                "blueprint_name": name,
                "blueprint_revision": 3
            }
        })
    };
    let insert = |value: Value, status: &'static str| {
        let db = db.clone();
        async move {
            sqlx::query(
                "INSERT INTO nest_build_jobs (requested_artifact_type, build_spec, target, system,
                     input_revision, input_config_hash, status, created_at, updated_at)
                 VALUES ('nixos_closure', ?, 'blueprint', 'x86_64-linux', 'rev', ?, ?,
                     '2026-10-31T00:00:00Z', '2026-10-31T00:00:00Z')",
            )
            .bind(value.to_string())
            .bind("a".repeat(64))
            .bind(status)
            .execute(&db)
            .await
            .unwrap()
            .last_insert_rowid()
        }
    };
    insert(spec("older", pin, false), "succeeded").await;
    let newest = insert(spec("newest", pin, false), "succeeded").await;
    insert(spec("failed", pin, false), "failed").await;
    insert(spec("source", pin, true), "succeeded").await;
    insert(spec("other", &"1".repeat(40), false), "succeeded").await;

    let mut fake = fake_nix(
        "retained",
        Some(evaluated_identities("26.05", &[])),
        &[AGENT_DRV],
    );
    fake.config.build.targets = vec![crate::config::BuildTargetConfig {
        artifact_type: "nixos_closure".to_string(),
        target: "blueprint".to_string(),
        system: "x86_64-linux".to_string(),
        flake: format!("github:NixOS/nixpkgs/{pin}"),
        attr: "packages.x86_64-linux.desktop-experience".to_string(),
    }];
    let root = fake.root.clone();
    let outcome = evaluate_with(&fake, &db, true).await;
    let calls = std::fs::read_to_string(root.join("calls")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(outcome.unwrap().state(), "ready");
    let blueprint_runs = calls
        .lines()
        .filter(|call| call.contains(" build ") && !call.contains("tiaris-packages"))
        .collect::<Vec<_>>();
    // The job at the pin, at the commit for its counterparts, and at the
    // commit under the full profile.
    assert_eq!(blueprint_runs.len(), 3, "{calls}");
    let installable = format!("job-{newest}-input#packages.x86_64-linux.desktop-experience");
    assert!(
        blueprint_runs[0].contains(&format!("/pin-jobs/{installable}")),
        "{calls}"
    );
    for run in &blueprint_runs[1..] {
        assert!(run.contains(&format!("/jobs/{installable}")), "{calls}");
    }
}
