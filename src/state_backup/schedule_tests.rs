//! The scheduled backup: the key an operator sets, one backup per run next
//! to its description, retention, leftovers and the disk budget.
use std::{fs, os::unix::fs::PermissionsExt};

use sha2::{Digest, Sha256};

use super::*;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tiaris-state-backup-schedule-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(path.join("state/agent")).unwrap();
        fs::create_dir_all(path.join("state/status")).unwrap();
        fs::write(path.join("state/agent/cache-private.pem"), b"cache key").unwrap();
        fs::write(path.join("state/agent/records.json"), b"{}").unwrap();
        Self(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }

    fn backups(&self) -> PathBuf {
        self.0.join("backups")
    }

    fn keys(&self) -> (PathBuf, PathBuf) {
        let (private, public) = (self.0.join("backup.key"), self.0.join("backup.pub"));
        super::super::generate_key(&private, &public).unwrap();
        (private, public)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Any free space will do in tests; retention as on a Nest.
const ROOMY: Limits = Limits {
    keep: KEEP,
    budget_bytes: BUDGET_BYTES,
    reserve_bytes: 0,
    reserve_divisor: u64::MAX,
};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn the_operator_sets_a_public_key_and_never_the_private_one() {
    let scratch = Scratch::new();
    let (private, public) = scratch.keys();
    assert!(!key_configured(&scratch.state()));
    let refused = set_key(&scratch.state(), &private).unwrap_err().to_string();
    assert!(refused.contains("private key"), "{refused}");
    assert!(!key_configured(&scratch.state()));

    let fingerprint = set_key(&scratch.state(), &public).unwrap();
    assert!(key_configured(&scratch.state()));
    assert_eq!(mode(&key_path(&scratch.state())), 0o644);
    assert_eq!(
        fs::read(key_path(&scratch.state())).unwrap(),
        fs::read(&public).unwrap()
    );
    // Setting it again replaces it in place.
    assert_eq!(set_key(&scratch.state(), &public).unwrap(), fingerprint);
}

#[tokio::test]
async fn without_a_key_a_run_backs_up_nothing() {
    let scratch = Scratch::new();
    let outcome = run_with(&scratch.state(), &scratch.backups(), ROOMY)
        .await
        .unwrap();
    assert_eq!(outcome.outcome, "key_missing");
    assert!(!scratch.backups().exists());
    assert_eq!(
        last_run(&scratch.state()).unwrap()["outcome"],
        "key_missing"
    );
}

#[tokio::test]
async fn each_run_keeps_one_more_backup_up_to_the_newest_three() {
    let scratch = Scratch::new();
    let (private, public) = scratch.keys();
    set_key(&scratch.state(), &public).unwrap();
    let dir = scratch.backups();
    let mut ids = Vec::new();
    for run in 1..=4 {
        let outcome = run_with(&scratch.state(), &dir, ROOMY).await.unwrap();
        assert_eq!(outcome.outcome, "backed_up");
        ids.push(outcome.backup_id.clone().unwrap());
        assert_eq!(outcome.kept, run.min(KEEP));
        assert_eq!(outcome.removed, usize::from(run > KEEP));
        // Distinct creation times order the backups.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(mode(&dir), 0o750);
    let files = list(&dir);
    let kept: Vec<_> = files.iter().map(|file| file.backup_id.clone()).collect();
    assert_eq!(kept, [ids[3].clone(), ids[2].clone(), ids[1].clone()]);
    assert!(!dir.join(format!("{}.backup", ids[0])).exists());
    assert!(!dir.join(format!("{}.json", ids[0])).exists());
    for file in &files {
        let path = file.path(&dir);
        assert_eq!(mode(&path), 0o640);
        assert_eq!(mode(&dir.join(format!("{}.json", file.backup_id))), 0o640);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), file.sha256);
        assert!(!bytes.windows(9).any(|window| window == b"cache key"));
    }
    // The kept backup opens with the private key.
    let restored = scratch.0.join("restored");
    fs::create_dir(&restored).unwrap();
    let summary = super::super::restore(
        &files[0].path(&dir),
        &private,
        &restored,
        super::super::Scope::Full,
        false,
    )
    .await
    .unwrap();
    assert!(summary.files_restored >= 2);
    assert_eq!(
        fs::read(restored.join("agent/cache-private.pem")).unwrap(),
        b"cache key"
    );
    let status = last_run(&scratch.state()).unwrap();
    assert_eq!(status["outcome"], "backed_up");
    assert!(super::super::last_receipt(&scratch.state()).is_some());
}

#[tokio::test]
async fn a_run_removes_what_an_interrupted_run_left() {
    let scratch = Scratch::new();
    let (_, public) = scratch.keys();
    set_key(&scratch.state(), &public).unwrap();
    let dir = scratch.backups();
    fs::create_dir_all(&dir).unwrap();
    let orphan = dir.join(format!("{}.backup", uuid::Uuid::new_v4().hyphenated()));
    let snapshot = dir.join(".x.backup.database-0011");
    fs::write(&orphan, b"half a backup").unwrap();
    fs::write(&snapshot, b"snapshot").unwrap();
    run_with(&scratch.state(), &dir, ROOMY).await.unwrap();
    assert!(!orphan.exists() && !snapshot.exists());
    assert_eq!(list(&dir).len(), 1);
}

#[tokio::test]
async fn a_backup_never_starts_without_room_on_its_disk() {
    let scratch = Scratch::new();
    let (_, public) = scratch.keys();
    set_key(&scratch.state(), &public).unwrap();
    let dir = scratch.backups();
    let full = Limits {
        reserve_bytes: u64::MAX / 2,
        ..ROOMY
    };
    let error = run_with(&scratch.state(), &dir, full)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("not enough free space"), "{error}");
    assert!(list(&dir).is_empty());
    assert_eq!(
        fs::read_dir(&dir).unwrap().flatten().count(),
        1,
        "only the lock"
    );
    assert_eq!(last_run(&scratch.state()).unwrap()["outcome"], "low_disk");
    // The default keeps a tenth of the disk or 4 GiB free.
    let gib = 1024 * 1024 * 1024;
    assert_eq!(Limits::DEFAULT.reserve(16 * gib), 4 * gib);
    assert_eq!(Limits::DEFAULT.reserve(500 * gib), 50 * gib);
}

fn file(created_at: &str, size_bytes: u64) -> BackupFile {
    BackupFile {
        schema: FILE_SCHEMA.into(),
        backup_id: uuid::Uuid::new_v4().hyphenated().to_string(),
        created_at: created_at.into(),
        sha256: "00".repeat(32),
        size_bytes,
        recipient_fingerprint: "11".repeat(32),
    }
}

#[test]
fn retention_keeps_the_newest_within_the_budget_and_always_the_newest() {
    let gib = 1024 * 1024 * 1024;
    let small = [
        file("2026-11-14T03:00:00Z", 10),
        file("2026-11-13T03:00:00Z", 10),
        file("2026-11-12T03:00:00Z", 10),
        file("2026-11-11T03:00:00Z", 10),
        file("2026-11-10T03:00:00Z", 10),
    ];
    let expired_small = expired(&small, 3, BUDGET_BYTES);
    assert_eq!(expired_small, small[3..].to_vec());
    let large = [
        file("2026-11-14T03:00:00Z", 3 * gib / 2),
        file("2026-11-13T03:00:00Z", gib),
        file("2026-11-12T03:00:00Z", gib / 10),
    ];
    assert_eq!(expired(&large, 3, 2 * gib), large[1..].to_vec());
    let huge = [file("2026-11-14T03:00:00Z", 5 * gib)];
    assert!(expired(&huge, 3, 2 * gib).is_empty(), "the newest stays");
}
