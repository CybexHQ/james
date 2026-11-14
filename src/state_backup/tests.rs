//! Round trip: a Nest's STATE is backed up, then restored onto a replacement
//! (data scope) and onto an empty disk (full scope).
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use super::*;
use crate::{db, models::CreateDeviceRequest};

const CACHE_KEY: &[u8] =
    b"-----BEGIN PRIVATE KEY-----\nCACHE-SIGNING-SECRET-7f3a\n-----END PRIVATE KEY-----\n";
const IDENTITY: &[u8] =
    b"{\"device_id\":\"old-nest\",\"private_key\":\"MANAGE-IDENTITY-SECRET-91c2\"}";

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tiaris-state-backup-{label}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn put(root: &Path, relative: &str, body: &[u8], mode: u32) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

async fn database(root: &Path, macs: &[&str], keep_open: bool) {
    fs::create_dir_all(root.join("agent")).unwrap();
    let pool = db::connect_with_url(&format!("sqlite://{}", root.join(DATABASE).display()))
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    for mac in macs {
        db::create_device(
            &pool,
            CreateDeviceRequest {
                mac: (*mac).into(),
                hostname: Some("lab-pc".into()),
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap();
    }
    if keep_open {
        // A running Nest: the backup snapshots a database in use.
        std::mem::forget(pool);
    } else {
        pool.close().await;
    }
}

async fn macs(root: &Path) -> Vec<String> {
    let pool = db::connect_with_url(&format!("sqlite://{}", root.join(DATABASE).display()))
        .await
        .unwrap();
    let mut macs: Vec<String> = db::list_devices(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|device| device.mac)
        .collect();
    pool.close().await;
    macs.sort();
    macs
}

/// An installed Nest's STATE as the appliance lays it out.
async fn old_nest(root: &Path) {
    database(root, &["02:00:00:00:01:01", "02:00:00:00:01:02"], true).await;
    put(root, "agent/cache-private.pem", CACHE_KEY, 0o600);
    put(root, "agent/cache-public.pem", b"cache public key\n", 0o644);
    put(root, "agent/manage-state.json", IDENTITY, 0o600);
    put(
        root,
        "agent/software-cache.netrc",
        b"machine x password NETRC-SECRET\n",
        0o600,
    );
    put(
        root,
        "agent/software-updates/detected/abc.json",
        b"{\"detected\":1}",
        0o600,
    );
    put(root, "agent/vulnix/nvd.json", b"downloaded again", 0o600);
    put(
        root,
        "agent/netboot/staging/runtime.squashfs",
        b"downloaded again",
        0o600,
    );
    put(root, "agent/.cache-egress.json.tmp-0011", b"partial", 0o600);
    put(
        root,
        "control/install-plan.json",
        b"{\"plan\":\"old\"}",
        0o640,
    );
    put(root, "control/config.toml", b"[paths]\n", 0o640);
    put(
        root,
        "status/appliance-update-status.json",
        b"{\"status\":\"idle\"}",
        0o640,
    );
    put(root, "inbox/appliance-update-request.json", b"{}", 0o600);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn a_backup_restores_onto_a_replacement_and_onto_an_empty_disk() {
    let scratch = Scratch::new("round-trip");
    let old = scratch.join("old-state");
    old_nest(&old).await;
    let (private, public) = (scratch.join("backup.key"), scratch.join("backup.pub"));
    let fingerprint = generate_key(&private, &public).unwrap();
    assert_eq!(
        fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let output = scratch.join("nest.backup");
    let summary = backup(&old, &public, &output).await.unwrap();
    assert_eq!(summary.recipient_fingerprint, fingerprint);
    assert_eq!(summary.files, 8, "{summary:?}");

    // Secrets stay protected at rest and are never printed.
    let bytes = fs::read(&output).unwrap();
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for secret in [
        &b"CACHE-SIGNING-SECRET"[..],
        b"MANAGE-IDENTITY-SECRET",
        b"NETRC-SECRET",
        b"02:00:00:00:01:01",
        b"install-plan",
    ] {
        assert!(!contains(&bytes, secret));
    }
    let printed = serde_json::to_string(&summary).unwrap();
    assert!(!printed.contains("SECRET") && !printed.contains("PRIVATE KEY"));
    let receipt = last_receipt(&old).unwrap();
    assert_eq!(receipt["size_bytes"], summary.size_bytes);

    // A replacement Nest, installed and enrolled again under a new identity.
    let replacement = scratch.join("replacement");
    // Restore runs with the replacement's service stopped (database closed).
    database(&replacement, &[], false).await;
    put(
        &replacement,
        "agent/manage-state.json",
        b"{\"device_id\":\"new-nest\"}",
        0o600,
    );
    put(&replacement, "agent/cache-private.pem", b"fresh key", 0o600);
    put(
        &replacement,
        "control/install-plan.json",
        b"{\"plan\":\"new\"}",
        0o640,
    );
    let restored = restore(&output, &private, &replacement, Scope::Data, false)
        .await
        .unwrap();
    assert!(restored.database_restored);
    assert_eq!(restored.backup_device_id.as_deref(), Some("old-nest"));
    assert_eq!(
        macs(&replacement).await,
        ["02:00:00:00:01:01", "02:00:00:00:01:02"]
    );
    assert_eq!(
        fs::read(replacement.join("agent/cache-private.pem")).unwrap(),
        CACHE_KEY
    );
    assert_eq!(
        fs::metadata(replacement.join("agent/cache-private.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::read(replacement.join("agent/software-updates/detected/abc.json")).unwrap(),
        b"{\"detected\":1}"
    );
    // Its own identity, credentials and signed plan stay.
    assert_eq!(
        fs::read(replacement.join("agent/manage-state.json")).unwrap(),
        b"{\"device_id\":\"new-nest\"}"
    );
    assert!(!replacement.join("agent/software-cache.netrc").exists());
    assert_eq!(
        fs::read(replacement.join("control/install-plan.json")).unwrap(),
        b"{\"plan\":\"new\"}"
    );
    assert!(
        restored
            .files_kept
            .contains(&"agent/manage-state.json".to_string())
    );
    assert!(
        restored
            .files_kept
            .contains(&"control/install-plan.json".to_string())
    );
    let leftovers: Vec<_> = fs::read_dir(&replacement)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // The same Nest onto an empty STATE: everything that was backed up.
    let empty = scratch.join("empty");
    fs::create_dir_all(empty.join("lost+found")).unwrap();
    let full = restore(&output, &private, &empty, Scope::Full, false)
        .await
        .unwrap();
    assert!(full.files_kept.is_empty());
    for relative in [
        "agent/cache-private.pem",
        "agent/manage-state.json",
        "agent/software-cache.netrc",
        "control/install-plan.json",
        "control/config.toml",
        "status/appliance-update-status.json",
    ] {
        assert_eq!(
            fs::read(empty.join(relative)).unwrap(),
            fs::read(old.join(relative)).unwrap(),
            "{relative}"
        );
        assert_eq!(
            fs::metadata(empty.join(relative))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            fs::metadata(old.join(relative))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            "{relative}"
        );
    }
    for excluded in [
        "agent/vulnix",
        "agent/netboot",
        "inbox",
        "agent/.cache-egress.json.tmp-0011",
    ] {
        assert!(!empty.join(excluded).exists(), "{excluded}");
    }
    assert_eq!(macs(&empty).await.len(), 2);
    // A full restore never merges into a Nest that already has state.
    let error = restore(&output, &private, &replacement, Scope::Full, true)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("empty state directory"),
        "{error}"
    );
}

#[tokio::test]
async fn a_damaged_truncated_or_foreign_backup_changes_nothing() {
    let scratch = Scratch::new("damage");
    let old = scratch.join("old-state");
    old_nest(&old).await;
    let (private, public) = (scratch.join("backup.key"), scratch.join("backup.pub"));
    generate_key(&private, &public).unwrap();
    let output = scratch.join("nest.backup");
    backup(&old, &public, &output).await.unwrap();
    let bytes = fs::read(&output).unwrap();

    let target = scratch.join("target");
    put(&target, "agent/cache-private.pem", b"untouched", 0o600);
    let untouched = || {
        assert_eq!(
            fs::read(target.join("agent/cache-private.pem")).unwrap(),
            b"untouched"
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
    };
    let mut damaged = bytes.clone();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 0x40;
    let truncated = bytes[..bytes.len() - 7].to_vec();
    let mut extended = bytes.clone();
    extended.push(0);
    for (name, body, expected) in [
        ("damaged", damaged, "authentication"),
        ("truncated", truncated, "truncated"),
        ("extended", extended, "after its end"),
    ] {
        let path = scratch.join(name);
        fs::write(&path, body).unwrap();
        let error = restore(&path, &private, &target, Scope::Data, false)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{name}: {error:#}");
        untouched();
    }
    let (other, other_public) = (scratch.join("other.key"), scratch.join("other.pub"));
    generate_key(&other, &other_public).unwrap();
    let error = restore(&output, &other, &target, Scope::Data, false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("another backup key"), "{error}");
    untouched();
    // The private key must be the owner's only.
    fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
    let error = restore(&output, &private, &target, Scope::Data, false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("chmod 600"), "{error}");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    // A dry run checks everything and writes nothing.
    let dry = restore(&output, &private, &target, Scope::Data, true)
        .await
        .unwrap();
    assert!(dry.dry_run && dry.files_restored > 0);
    untouched();
}

#[tokio::test]
async fn a_failed_backup_never_removes_a_file_it_did_not_create() {
    let scratch = Scratch::new("collision");
    let old = scratch.join("old-state");
    old_nest(&old).await;
    let (private, public) = (scratch.join("backup.key"), scratch.join("backup.pub"));
    generate_key(&private, &public).unwrap();
    // The documented date-named backup, run twice on one day.
    let output = scratch.join("nest-2026-11-14.backup");
    backup(&old, &public, &output).await.unwrap();
    let first = fs::read(&output).unwrap();
    let error = backup(&old, &public, &output).await.unwrap_err();
    assert!(format!("{error:#}").contains("create"), "{error:#}");
    assert_eq!(
        fs::read(&output).unwrap(),
        first,
        "the earlier backup stays"
    );
    // Still a whole backup.
    let target = scratch.join("target");
    fs::create_dir(&target).unwrap();
    restore(&output, &private, &target, Scope::Full, true)
        .await
        .unwrap();

    // A failure before the output is created leaves an existing file alone.
    let broken = scratch.join("broken-state");
    fs::create_dir_all(broken.join(DATABASE)).unwrap();
    let existing = scratch.join("existing.backup");
    fs::write(&existing, b"an earlier backup").unwrap();
    let error = backup(&broken, &public, &existing).await.unwrap_err();
    assert!(error.to_string().contains("not a regular file"), "{error}");
    assert_eq!(fs::read(&existing).unwrap(), b"an earlier backup");
    // A run that fails never leaves a partial output or snapshot.
    let fresh = scratch.join("fresh.backup");
    let error = backup(&old, &scratch.join("no-such.pub"), &fresh)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("no-such.pub"), "{error:#}");
    assert!(!fresh.exists());
    let leftovers: Vec<_> = fs::read_dir(&scratch.0)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().contains(".database-"))
        .collect();
    assert!(leftovers.is_empty(), "no database snapshot is left behind");
}

#[tokio::test]
async fn a_database_this_release_cannot_run_on_is_not_restored() {
    let scratch = Scratch::new("schema");
    let old = scratch.join("old-state");
    old_nest(&old).await;
    let pool = db::connect_with_url(&format!("sqlite://{}", old.join(DATABASE).display()))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (20990101000000, 'undeclared', TRUE, X'00', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    let (private, public) = (scratch.join("backup.key"), scratch.join("backup.pub"));
    generate_key(&private, &public).unwrap();
    let output = scratch.join("nest.backup");
    backup(&old, &public, &output).await.unwrap();
    let target = scratch.join("target");
    fs::create_dir_all(&target).unwrap();
    let error = restore(&output, &private, &target, Scope::Data, false)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains(crate::schema_evolution::INCOMPATIBLE),
        "{error:#}"
    );
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
}

#[test]
fn x25519_matches_the_rfc_7748_vectors() {
    let key = |text: &str| -> [u8; 32] { hex::decode(text).unwrap().try_into().unwrap() };
    let alice = key("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob = key("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    assert_eq!(
        hex::encode(public_of(&alice)),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(
            MontgomeryPoint(public_of(&bob))
                .mul_clamped(alice)
                .to_bytes()
        ),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
}

#[test]
fn only_state_that_cannot_be_downloaded_again_is_included() {
    for path in [
        "agent/cache-private.pem",
        "agent/software-updates/detected/x.json",
        "control/install-plan.json",
        "status/appliance-update-status.json",
    ] {
        assert!(included(path), "{path}");
    }
    for path in [
        "agent/tiaris-nest.sqlite",
        "agent/tiaris-nest.sqlite-wal",
        "agent/tiaris-nest.sqlite-shm",
        "agent/vulnix/x",
        "agent/netboot/sessions/s",
        "inbox/appliance-update-request.json",
        "lost+found/x",
        "control/.install-plan.json.tmp",
    ] {
        assert!(!included(path), "{path}");
    }
    assert!(identity_bound("agent/manage-state.json"));
    assert!(identity_bound("agent/software-cache-uploads/g.grant"));
    assert!(!identity_bound("agent/cache-private.pem"));
}
