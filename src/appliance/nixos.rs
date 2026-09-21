//! NixOS daemon download and independent privileged update admission.
use super::{
    closure,
    release_v3::{self, NixosRelease, ReleaseDescriptor},
};
use anyhow::{Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub const CAPABILITY: &str = "appliance_update_v3";
pub const IDENTITY_PATH: &str = "/usr/share/cybex-james/system-identity.json";
pub const MIGRATIONS_PATH: &str = "/usr/share/cybex-james/sqlite-migrations.json";
const RESERVE: u64 = 23 * 1024 * 1024 * 1024;
// STATE is deliberately only 16 GiB. Bulk bytes belong to the root-backed
// cache; only requests and durable privileged transaction receipts use STATE.
const UPDATE_CACHE_ROOT: &str = "/var/cache/cybex-james/appliance-updates";
const UPDATE_BUNDLE_ROOT: &str = "/var/cache/cybex-james/appliance-updates/inbox";
const UPDATE_PRIVATE_ROOT: &str = "/var/cache/cybex-james/appliance-updates/private";
const DATABASE_BACKUP_RESERVE: u64 = 1024 * 1024 * 1024;
static QUEUE: Mutex<(bool, Option<super::ManagedApplianceUpdate<NixosRelease>>)> =
    Mutex::new((false, None));

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUpdate {
    schema: String,
    attempt_id: Uuid,
    requested_at: DateTime<Utc>,
    release: NixosRelease,
    bundle_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledState {
    pub schema: String,
    pub release: NixosRelease,
    pub system_generation: String,
    pub system_toplevel: String,
    pub system_closure_sha256: String,
    pub base_os: String,
    pub base_os_version: String,
    pub at_rest_protection: String,
}
pub fn is_nixos() -> bool {
    Path::new(IDENTITY_PATH).is_file()
}
pub fn queue(update: super::ManagedApplianceUpdate<ReleaseDescriptor>) -> bool {
    match update.release {
        ReleaseDescriptor::Legacy(release) => {
            super::queue_update_request(super::ManagedApplianceUpdate {
                release,
                attempt_id: update.attempt_id,
                requested_at: update.requested_at,
                qualification_package_transport_url: update.qualification_package_transport_url,
            })
        }
        ReleaseDescriptor::Nixos(release) => {
            let Ok(mut state) = QUEUE.lock() else {
                return false;
            };
            state.1 = Some(super::ManagedApplianceUpdate {
                release,
                attempt_id: update.attempt_id,
                requested_at: update.requested_at,
                qualification_package_transport_url: update.qualification_package_transport_url,
            });
            if state.0 {
                return false;
            }
            state.0 = true;
            drop(state);
            tokio::spawn(async {
                loop {
                    let update = {
                        let Ok(mut s) = QUEUE.lock() else { return };
                        match s.1.take() {
                            Some(v) => v,
                            None => {
                                s.0 = false;
                                return;
                            }
                        }
                    };
                    if let Err(error) = store(update).await {
                        tracing::warn!(error=%error,"NixOS appliance update staging failed");
                    }
                }
            });
            true
        }
    }
}
fn read_installed() -> Result<InstalledState> {
    let bytes = crate::provisioning::read_bounded_nofollow(
        Path::new(super::INSTALLED_STATE_PATH),
        256 * 1024,
        "installed NixOS receipt",
    )?;
    let state: InstalledState = serde_json::from_value(release_v3::strict_json(&bytes)?)?;
    state
        .release
        .verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
    ensure!(
        state.schema == "cybex.james.installed-appliance.v3"
            && state.base_os == "nixos"
            && state.base_os_version == release_v3::NIXOS_VERSION
            && state.at_rest_protection == "none"
            && state.system_toplevel == state.release.system_toplevel
            && state.system_closure_sha256 == state.release.system_closure.sha256,
        "installed NixOS receipt mismatch"
    );
    generation(&state.system_generation)?;
    Ok(state)
}
pub fn generation(v: &str) -> Result<u64> {
    let n: u64 = v.parse()?;
    ensure!(n > 0 && n.to_string() == v, "noncanonical NixOS generation");
    Ok(n)
}
fn newer(release: &NixosRelease, current: &NixosRelease) -> Result<()> {
    ensure!(
        semver::Version::parse(&release.release_id)?
            .cmp_precedence(&semver::Version::parse(&current.release_id)?)
            .is_gt(),
        "appliance update must be strictly newer"
    );
    Ok(())
}
async fn store(update: super::ManagedApplianceUpdate<NixosRelease>) -> Result<()> {
    ensure!(
        is_nixos() && !update.attempt_id.is_nil(),
        "NixOS update requires installed NixOS"
    );
    update
        .release
        .verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
    if let Some(status) =
        super::read_optional_bounded_json::<Value>(Path::new(super::UPDATE_STATUS_PATH), 128 * 1024)
    {
        if status["attempt_id"] == update.attempt_id.to_string()
            && status["target_release"] == update.release.release_id
            && status["system_closure_sha256"] == update.release.system_closure.sha256
            && matches!(
                status["status"].as_str(),
                Some("succeeded" | "failed" | "rolled_back")
            )
        {
            return Ok(());
        }
    }
    let current = read_installed()?;
    newer(&update.release, &current.release)?;
    if let Some(prior) = super::read_optional_bounded_json::<StoredUpdate>(
        Path::new(super::UPDATE_REQUEST_PATH),
        256 * 1024,
    ) {
        if prior.attempt_id == update.attempt_id && prior.release == update.release {
            return Ok(());
        }
        bail!("another appliance update is already staged")
    }
    validate_directory(Path::new(UPDATE_CACHE_ROOT), 0, 0o755)?;
    validate_directory(Path::new(UPDATE_BUNDLE_ROOT), 985, 0o700)?;
    let path = Path::new(UPDATE_BUNDLE_ROOT).join(format!("{}.tar.zst", update.attempt_id));
    let transport = update
        .qualification_package_transport_url
        .as_deref()
        .unwrap_or(&update.release.system_closure.url);
    if transport != update.release.system_closure.url {
        let artifact = super::ApplianceRepositorySnapshot {
            url: update.release.system_closure.url.clone(),
            sha256: update.release.system_closure.sha256.clone(),
            size_bytes: update.release.system_closure.size_bytes,
        };
        super::validate_qualification_package_transport_url(transport, &artifact)?;
    }
    ensure_update_space(
        Path::new(UPDATE_BUNDLE_ROOT),
        Path::new("/nix/store"),
        update.release.system_closure.size_bytes,
        0,
    )?;
    download(
        &update.release,
        transport,
        &path,
        transport != update.release.system_closure.url,
    )
    .await?;
    super::write_atomic_json(
        Path::new(super::UPDATE_REQUEST_PATH),
        &StoredUpdate {
            schema: "cybex.james.appliance-update-request.v3".into(),
            attempt_id: update.attempt_id,
            requested_at: update.requested_at,
            release: update.release,
            bundle_path: path.to_str().ok_or_else(|| anyhow!("archive path"))?.into(),
        },
        0o600,
    )
}

pub async fn download(
    release: &NixosRelease,
    transport: &str,
    path: &Path,
    allow_private: bool,
) -> Result<()> {
    let mut response = crate::release_transport::get(
        transport,
        allow_private,
        false,
        Duration::from_secs(4 * 60 * 60),
        None,
    )
    .await?;
    ensure!(
        response.status() == reqwest::StatusCode::OK
            && response
                .content_length()
                .is_none_or(|n| n == release.system_closure.size_bytes)
            && response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .is_none_or(|v| v == "identity"),
        "invalid closure HTTP response"
    );
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = async {
        let raw = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let mut file = tokio::fs::File::from_std(raw);
        let mut hash = Sha256::new();
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await? {
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow!("closure size overflow"))?;
            ensure!(
                size <= release.system_closure.size_bytes,
                "closure exceeds signed size"
            );
            hash.update(&chunk);
            file.write_all(&chunk).await?;
        }
        ensure!(
            size == release.system_closure.size_bytes
                && hex::encode(hash.finalize()) == release.system_closure.sha256,
            "closure signed size/hash mismatch"
        );
        file.sync_all().await?;
        tokio::fs::rename(&temporary, path).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub fn ensure_space(path: &Path, temporary_and_missing: u64) -> Result<()> {
    let required = temporary_and_missing
        .checked_add(RESERVE)
        .ok_or_else(|| anyhow!("space admission overflow"))?;
    ensure!(
        crate::disk::stats(path)?.available_bytes >= required,
        "insufficient space for closure and 21 GiB workstation reserve plus 2 GiB headroom"
    );
    Ok(())
}

fn validate_directory(path: &Path, owner: u32, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o777 == mode,
        "unsafe appliance update staging directory"
    );
    Ok(())
}

fn admit_update_space(
    same_filesystem: bool,
    staging_free: u64,
    store_free: u64,
    temporary: u64,
    missing: u64,
) -> Result<()> {
    let store_required = missing
        .checked_add(RESERVE)
        .ok_or_else(|| anyhow!("store space overflow"))?;
    let staging_required = if same_filesystem {
        temporary
            .checked_add(store_required)
            .ok_or_else(|| anyhow!("staging space overflow"))?
    } else {
        temporary
            .checked_add(2 * 1024 * 1024 * 1024)
            .ok_or_else(|| anyhow!("staging space overflow"))?
    };
    ensure!(
        staging_free >= staging_required,
        "insufficient appliance cache staging space"
    );
    ensure!(
        store_free >= store_required,
        "insufficient Nix store space and workstation reserve"
    );
    Ok(())
}

fn ensure_update_space(staging: &Path, store: &Path, temporary: u64, missing: u64) -> Result<()> {
    admit_update_space(
        fs::metadata(staging)?.dev() == fs::metadata(store)?.dev(),
        crate::disk::stats(staging)?.available_bytes,
        crate::disk::stats(store)?.available_bytes,
        temporary,
        missing,
    )
}

pub fn verify_update() -> Result<PathBuf> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root verification required"
    );
    let body = crate::provisioning::read_bounded_nofollow(
        Path::new(super::UPDATE_REQUEST_PATH),
        256 * 1024,
        "NixOS update inbox",
    )?;
    let request: StoredUpdate = serde_json::from_value(release_v3::strict_json(&body)?)?;
    ensure!(
        request.schema == "cybex.james.appliance-update-request.v3" && !request.attempt_id.is_nil(),
        "update inbox schema/attempt"
    );
    let key = request
        .release
        .verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
    let verified_result = (|| -> Result<PathBuf> {
        let current = read_installed()?;
        newer(&request.release, &current.release)?;
        ensure!(
            fs::canonicalize("/run/current-system")?.to_str()
                == Some(current.system_toplevel.as_str()),
            "running system differs from source receipt"
        );
        validate_migrations(&current.release, &request.release)?;
        validate_directory(Path::new(UPDATE_CACHE_ROOT), 0, 0o755)?;
        validate_directory(Path::new(UPDATE_BUNDLE_ROOT), 985, 0o700)?;
        validate_directory(Path::new(UPDATE_PRIVATE_ROOT), 0, 0o700)?;
        let canonical =
            Path::new(UPDATE_BUNDLE_ROOT).join(format!("{}.tar.zst", request.attempt_id));
        ensure!(
            Path::new(&request.bundle_path) == canonical,
            "noncanonical update archive path"
        );
        fs::create_dir_all(super::UPDATE_ROOT)?;
        let parent = fs::symlink_metadata(super::UPDATE_ROOT)?;
        ensure!(
            parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o022 == 0,
            "unsafe private updater root"
        );
        for receipt in [
            "pending-system-generation.json",
            "system-prepare-intent.json",
            "system-commit-intent.json",
            "system-rollback-intent.json",
        ] {
            ensure!(
                !Path::new("/var/lib/cybex-james/control")
                    .join(receipt)
                    .exists(),
                "pending update transaction blocks verifier"
            );
        }
        let private = Path::new(UPDATE_PRIVATE_ROOT).join(request.attempt_id.to_string());
        let receipt_directory = Path::new(super::UPDATE_ROOT).join(request.attempt_id.to_string());
        for directory in [&private, &receipt_directory] {
            if fs::symlink_metadata(directory).is_ok() {
                validate_directory(directory, 0, 0o700)?;
                fs::remove_dir_all(directory)?;
            }
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let result = (|| {
            ensure_update_space(
                &private,
                Path::new("/nix/store"),
                request.release.system_closure.size_bytes,
                0,
            )?;
            let archive = private.join("closure.tar.zst");
            super::pin_untrusted_bundle(
                &canonical,
                &archive,
                request.release.system_closure.size_bytes,
                &request.release.system_closure.sha256,
            )?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&archive)?;
            let manifest = closure::verify_archive(&mut file, &request.release, &key, None)?;
            // Conservative accounting never counts protected/shared paths as reclaimable.
            // Missing path accounting avoids charging the imported predecessor twice.
            let mut missing = 0u64;
            for path in &manifest.store_paths {
                if !Path::new(&path.path).exists() {
                    missing = missing
                        .checked_add(path.nar_size)
                        .ok_or_else(|| anyhow!("missing path size overflow"))?;
                }
            }
            ensure_update_space(
                &private,
                Path::new("/nix/store"),
                closure::MAX_EXPANDED
                    .checked_add(DATABASE_BACKUP_RESERVE)
                    .ok_or_else(|| anyhow!("staging size overflow"))?,
                missing,
            )?;
            let database_backup = snapshot_database(&private)?;
            let cache = private.join("cache");
            closure::verify_archive(&mut file, &request.release, &key, Some(&cache))?;
            super::write_atomic_json(
                &receipt_directory.join("verified-update.json"),
                &json!({
                    "schema":"cybex.james.verified-appliance-update.v3","attempt_id":request.attempt_id,"request_sha256":hex::encode(Sha256::digest(&body)),
                    "descriptor_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&super::canonical_json(serde_json::to_value(&request.release)?))?)),
                    "target_release":request.release.release_id,"source_revision":request.release.source_revision,"system_closure_sha256":request.release.system_closure.sha256,
                    "system_closure_size_bytes":request.release.system_closure.size_bytes,"system_toplevel":request.release.system_toplevel,"sqlite_migrations_sha256":request.release.sqlite_migrations_sha256,
                    "total_nar_bytes":manifest.total_nar_bytes,"missing_nar_bytes":missing,"cache_path":cache,"database_backup":database_backup,"release":request.release,"source_system_generation":current.system_generation,"source_system_toplevel":current.system_toplevel,
                }),
                0o600,
            )?;
            Ok(cache)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&private);
            let _ = fs::remove_dir_all(&receipt_directory);
        }
        result
    })();
    if let Err(error) = &verified_result {
        let pending = [
            "pending-system-generation.json",
            "system-prepare-intent.json",
            "system-commit-intent.json",
            "system-rollback-intent.json",
        ]
        .iter()
        .any(|name| {
            Path::new("/var/lib/cybex-james/control")
                .join(name)
                .exists()
        });
        if !pending {
            let reason = if error.to_string().contains("rollback_database_incompatible") {
                "rollback_database_incompatible"
            } else {
                "appliance_update_verification_failed"
            };
            let mut status = json!({"attempt_id":request.attempt_id,"target_release":request.release.release_id,"source_revision":request.release.source_revision,"system_closure_sha256":request.release.system_closure.sha256,"system_toplevel":request.release.system_toplevel,"status":"failed","stage":"verification_failed","rollback_reason":reason,"progress_percent":0,"reported_at":Utc::now()});
            if let Ok(source) = read_installed() {
                status["resulting_system_generation"] = source.system_generation.into();
            }
            match super::write_atomic_json(Path::new(super::UPDATE_STATUS_PATH), &status, 0o640) {
                Err(write_error) => {
                    tracing::error!(%write_error,"could not persist authenticated update verification failure")
                }
                Ok(()) => {
                    let bundle = Path::new(UPDATE_BUNDLE_ROOT)
                        .join(format!("{}.tar.zst", request.attempt_id));
                    if let Err(cleanup_error) = cleanup_failed_request(
                        Path::new(super::UPDATE_REQUEST_PATH),
                        &body,
                        &bundle,
                    ) {
                        tracing::error!(%cleanup_error,"could not clean terminal update request");
                    }
                }
            }
        }
    }
    verified_result
}

fn cleanup_failed_request(request: &Path, original: &[u8], bundle: &Path) -> Result<bool> {
    let current =
        crate::provisioning::read_bounded_nofollow(request, 256 * 1024, "terminal update request")?;
    if current != original {
        return Ok(false);
    }
    // Only the canonical per-attempt basename is removed, never a caller path.
    // Unlink does not follow an untrusted symlink at that basename.
    match fs::remove_file(bundle) {
        Ok(()) => super::sync_directory(bundle.parent().ok_or_else(|| anyhow!("bundle parent"))?)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(request)?;
    super::sync_directory(request.parent().ok_or_else(|| anyhow!("request parent"))?)?;
    Ok(true)
}

fn validate_migrations(source: &NixosRelease, candidate: &NixosRelease) -> Result<()> {
    ensure!(
        source.sqlite_migrations_sha256 == candidate.sqlite_migrations_sha256,
        "rollback_database_incompatible"
    );
    let bytes = crate::provisioning::read_bounded_nofollow(
        Path::new(MIGRATIONS_PATH),
        16 * 1024 * 1024,
        "migration inventory",
    )?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == source.sqlite_migrations_sha256,
        "rollback_database_incompatible: installed inventory digest"
    );
    let inventory = release_v3::strict_json(&bytes)?;
    ensure!(
        inventory["schema"] == "cybex.james.sqlite-migrations.v1",
        "migration inventory schema"
    );
    let output=std::process::Command::new("sqlite3").args(["-readonly","-json","/var/lib/cybex-james/state/agent/cybex-james.sqlite","SELECT version, lower(hex(checksum)) AS sqlx_checksum, success FROM _sqlx_migrations ORDER BY version LIMIT 4097;"]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16 * 1024 * 1024,
        "rollback_database_incompatible: live SQLite inventory"
    );
    let live: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    let expected = inventory["migrations"]
        .as_array()
        .ok_or_else(|| anyhow!("migration inventory missing"))?;
    ensure!(
        live.len() == expected.len(),
        "rollback_database_incompatible: migration count"
    );
    for (row, entry) in live.iter().zip(expected) {
        ensure!(
            row["version"] == entry["version"]
                && row["sqlx_checksum"] == entry["sqlx_checksum"]
                && row["success"] == 1,
            "rollback_database_incompatible: live migration mismatch"
        );
    }
    Ok(())
}

pub async fn report(state: &crate::AppState) -> Result<super::ApplianceReport> {
    let actual = fs::canonicalize("/run/current-system")?;
    let actual_generation = booted_generation(&actual)?;
    let mut installed = read_installed()?;
    if actual.to_str() != Some(installed.system_toplevel.as_str()) {
        let pending_path = Path::new("/var/lib/cybex-james/control/pending-system-generation.json");
        let pending = if pending_path.exists() {
            let bytes = crate::provisioning::read_bounded_nofollow(
                pending_path,
                512 * 1024,
                "pending NixOS generation",
            )?;
            let pending = release_v3::strict_json(&bytes)?;
            ensure!(
                pending["schema"] == "cybex.james.pending-system-generation.v3"
                    && pending["system_toplevel"].as_str() == actual.to_str()
                    && pending["candidate_generation"] == actual_generation,
                "booted candidate differs from protected pending seal"
            );
            pending
        } else {
            // A manual boot of a retained good generation is reported truthfully
            // without reinterpreting an already committed update as rollback.
            let bytes = crate::provisioning::read_bounded_nofollow(
                Path::new("/var/lib/cybex-james/control/known-good-system.json"),
                1024 * 1024,
                "known-good NixOS generations",
            )?;
            let known = release_v3::strict_json(&bytes)?;
            ensure!(
                known["schema"] == "cybex.james.known-good-system.v3",
                "known-good schema"
            );
            known["generations"]
                .as_array()
                .and_then(|rows| {
                    rows.iter().find(|row| {
                        row["system_generation"] == actual_generation
                            && row["system_toplevel"].as_str() == actual.to_str()
                    })
                })
                .cloned()
                .ok_or_else(|| {
                    anyhow!("booted system is neither installed, pending, nor retained known-good")
                })?
        };
        let candidate: NixosRelease = serde_json::from_value(pending["release"].clone())?;
        candidate.verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
        ensure!(
            candidate.system_toplevel == pending["system_toplevel"]
                && candidate.system_closure.sha256 == pending["system_closure_sha256"],
            "candidate release differs from protected seal"
        );
        installed.system_toplevel = candidate.system_toplevel.clone();
        installed.system_closure_sha256 = candidate.system_closure.sha256.clone();
        installed.system_generation = actual_generation.clone();
        installed.release = candidate;
    }
    ensure!(
        installed.system_generation == actual_generation,
        "booted system generation differs from protected receipt"
    );
    let release = &installed.release;
    let identity = release_v3::strict_json(&crate::provisioning::read_bounded_nofollow(
        Path::new(IDENTITY_PATH),
        64 * 1024,
        "booted system identity",
    )?)?;
    for (field, expected) in [
        ("release_id", &release.release_id),
        ("base_os", &release.base_os),
        ("base_os_version", &release.base_os_version),
        ("source_revision", &release.source_revision),
        ("manage_source_revision", &release.manage_source_revision),
        ("nixpkgs_revision", &release.nixpkgs_revision),
    ] {
        ensure!(
            identity[field].as_str() == Some(expected),
            "immutable system identity differs from signed booted release"
        );
    }
    ensure!(
        identity["required_system_versions"]
            == serde_json::to_value(&release.required_system_versions)?
            && identity["manage_origin"] == crate::provisioning::REQUIRED_MANAGE_ORIGIN,
        "immutable system version/origin mismatch"
    );
    let mut fields = BTreeMap::new();
    for (k, v) in [
        ("nixpkgs_revision", json!(release.nixpkgs_revision)),
        ("system_toplevel", json!(installed.system_toplevel)),
        ("system_generation", json!(installed.system_generation)),
        (
            "system_closure_sha256",
            json!(installed.system_closure_sha256),
        ),
        (
            "sqlite_migrations_sha256",
            json!(release.sqlite_migrations_sha256),
        ),
        ("state_schema", json!(3)),
        (
            "systemd_boot_version",
            json!(systemd_version(
                &super::command_text("bootctl", &["--version"]).await
            )?),
        ),
    ] {
        fields.insert(k.to_string(), v);
    }
    let network = json!({"interfaces":super::command_json("ip",&["-j","address","show"]).await,"network_fallback_active":crate::provisioning::network_fallback_active().unwrap_or(true),"network_change":super::read_optional_bounded_json::<Value>(Path::new(super::NETWORK_CHANGE_STATUS_PATH),64*1024).unwrap_or_else(||json!({"status":"idle"}))});
    Ok(super::ApplianceReport {
        base_os: "nixos".into(),
        base_os_version: release.base_os_version.clone(),
        appliance_release: release.release_id.clone(),
        ubuntu_snapshot_id: None,
        root_generation: None,
        kernel_version: super::command_text("uname", &["-r"]).await,
        secure_boot: observed_secure_boot(),
        boot_mode: if Path::new("/sys/firmware/efi").is_dir() {
            "uefi"
        } else {
            "legacy"
        }
        .into(),
        firmware_version: nonempty(super::read_trimmed("/sys/class/dmi/id/bios_version")),
        microcode_version: nonempty(super::microcode_version()),
        nix_version: super::command_text("nix", &["--version"]).await,
        at_rest_protection: "none".into(),
        network,
        package_update: super::read_optional_bounded_json(
            Path::new(super::UPDATE_STATUS_PATH),
            128 * 1024,
        )
        .unwrap_or_else(|| json!({"status":"idle"})),
        local_health: super::local_health(crate::readiness::probe(state).await).await,
        nixos: fields,
    })
}
use std::collections::BTreeMap;
fn systemd_version(output: &str) -> Result<String> {
    let mut words = output.lines().next().unwrap_or_default().split_whitespace();
    ensure!(
        words.next() == Some("systemd"),
        "unknown bootctl version output"
    );
    let major = words
        .next()
        .ok_or_else(|| anyhow!("missing bootctl version"))?;
    let numeric = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    };
    ensure!(numeric(major), "invalid bootctl version");
    if let Some(package) = words
        .next()
        .and_then(|word| word.strip_prefix('('))
        .and_then(|word| word.strip_suffix(')'))
    {
        if numeric(package) {
            return Ok(package.to_owned());
        }
    }
    Ok(major.to_owned())
}
fn nonempty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}
fn observed_secure_boot() -> Option<bool> {
    let path =
        Path::new("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    let bytes = fs::read(path).ok()?;
    if bytes.len() == 5 {
        match bytes[4] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    } else {
        None
    }
}
pub fn record_manage_contact(device_id: &str, fingerprint: &str, origin: &str) -> Result<()> {
    if !is_nixos() {
        return Ok(());
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    super::write_atomic_json(
        Path::new("/var/lib/cybex-james/state/agent/manage-contact.json"),
        &json!({"schema":"cybex.james.manage-contact.v1","device_id":device_id,"public_key_fingerprint":fingerprint,"manage_origin":origin,"reported_at":Utc::now(),"boot_id":boot_id.trim()}),
        0o600,
    )
}

fn booted_generation(actual: &Path) -> Result<String> {
    let body = fs::read(
        "/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f",
    )?;
    ensure!(
        body.len() >= 6 && body.len() <= 1024 && (body.len() - 4) % 2 == 0,
        "invalid selected loader entry variable"
    );
    let utf16: Vec<u16> = body[4..]
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .take_while(|v| *v != 0)
        .collect();
    let entry = String::from_utf16(&utf16)?;
    let value = entry
        .strip_prefix("nixos-generation-")
        .and_then(|s| s.strip_suffix(".conf"))
        .ok_or_else(|| anyhow!("selected loader entry is not an installed generation"))?;
    generation(value)?;
    ensure!(
        fs::canonicalize(format!("/nix/var/nix/profiles/system-{value}-link"))? == actual,
        "selected loader generation differs from booted toplevel"
    );
    Ok(value.to_string())
}

fn snapshot_database(private: &Path) -> Result<PathBuf> {
    let database = "/var/lib/cybex-james/state/agent/cybex-james.sqlite";
    let output = std::process::Command::new("timeout")
        .args([
            "60",
            "sqlite3",
            "-readonly",
            database,
            "PRAGMA page_count; PRAGMA page_size;",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 128,
        "cannot measure consistent database backup"
    );
    let values = String::from_utf8(output.stdout)?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values.len() == 2
            && values[0]
                .checked_mul(values[1])
                .is_some_and(|n| n <= 1024 * 1024 * 1024),
        "database backup exceeds 1 GiB admission bound"
    );
    let backup = private.join("database-compatibility.sqlite");
    let command = format!(".backup {}", backup.display());
    let output = std::process::Command::new("timeout")
        .args(["60", "sqlite3", "-readonly", database, &command])
        .output()?;
    ensure!(output.status.success(), "consistent database backup failed");
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))?;
    let output = std::process::Command::new("timeout")
        .args([
            "60",
            "/run/current-system/sw/bin/cybex-james",
            "verify-appliance-database",
            "--database",
        ])
        .arg(&backup)
        .output()?;
    ensure!(
        output.status.success(),
        "rollback_database_incompatible: predecessor cannot open backup"
    );
    Ok(backup)
}

/// Invoked from both the predecessor and imported candidate binaries on one
/// private SQLite snapshot; never migrates or restores the live appliance DB.
pub async fn verify_database(path: &Path) -> Result<()> {
    use sqlx::{Connection, Row};
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "database compatibility verification requires root"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= 1024 * 1024 * 1024,
        "unsafe database compatibility snapshot"
    );
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .busy_timeout(Duration::from_secs(5));
    let mut connection = sqlx::SqliteConnection::connect_with(&options).await?;
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check(1)")
        .fetch_one(&mut connection)
        .await?;
    ensure!(
        integrity == "ok",
        "rollback_database_incompatible: SQLite integrity failure"
    );
    let migrator = sqlx::migrate!("./migrations");
    let expected: Vec<_> = migrator.iter().collect();
    let rows = sqlx::query(
        "SELECT version,checksum,success FROM _sqlx_migrations ORDER BY version LIMIT 4097",
    )
    .fetch_all(&mut connection)
    .await?;
    ensure!(
        rows.len() == expected.len(),
        "rollback_database_incompatible: migration count"
    );
    for (row, migration) in rows.iter().zip(expected) {
        ensure!(
            row.try_get::<i64, _>("version")? == migration.version
                && row.try_get::<Vec<u8>, _>("checksum")? == migration.checksum.as_ref()
                && row.try_get::<bool, _>("success")?,
            "rollback_database_incompatible: compiled migration history"
        );
    }
    connection.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn bootctl_version_report_is_one_numeric_token() {
        let actual = "systemd 260 (260.2)\n+PAM +AUDIT -SELINUX +APPARMOR +IMA +IPE +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL\n";
        assert_eq!(systemd_version(actual).unwrap(), "260.2");
        assert_eq!(systemd_version("systemd 260\n+PAM").unwrap(), "260");
        assert!(systemd_version("unexpected output\n260").is_err());
        assert!(systemd_version("systemd unknown\n+PAM").is_err());
    }

    #[test]
    fn state_16_gib_does_not_receive_bulk_or_workstation_reserve() {
        assert!(UPDATE_BUNDLE_ROOT.starts_with("/var/cache/cybex-james/"));
        assert!(UPDATE_PRIVATE_ROOT.starts_with("/var/cache/cybex-james/"));
        assert!(super::super::UPDATE_REQUEST_PATH.starts_with("/var/lib/cybex-james/state/"));
        assert!(super::super::UPDATE_ROOT.starts_with("/var/lib/cybex-james/control/"));
        // The installed 16 GiB STATE is absent from bulk admission: ROOT backs
        // both cache and /nix. Existing staging bytes are already in free-space.
        assert!(admit_update_space(true, 64 * GIB, 64 * GIB, 9 * GIB, 4 * GIB).is_ok());
        assert!(admit_update_space(true, 36 * GIB, 36 * GIB, 9 * GIB, 4 * GIB).is_ok());
        assert!(admit_update_space(true, 35 * GIB, 35 * GIB, 9 * GIB, 4 * GIB).is_err());
    }

    #[test]
    fn separate_staging_and_store_are_admitted_independently() {
        assert!(admit_update_space(false, 12 * GIB, 28 * GIB, 9 * GIB, 4 * GIB).is_ok());
        assert!(admit_update_space(false, 64 * GIB, 26 * GIB, 9 * GIB, 4 * GIB).is_err());
        assert!(admit_update_space(false, 10 * GIB, 64 * GIB, 9 * GIB, 4 * GIB).is_err());
        assert!(admit_update_space(true, u64::MAX, u64::MAX, u64::MAX, 0).is_err());
    }

    #[test]
    fn authenticated_failure_allows_a_corrected_attempt_without_erasing_changed_inbox() {
        let directory =
            std::env::temp_dir().join(format!("cybex-update-cleanup-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let request = directory.join("request.json");
        let bundle = directory.join("attempt.tar.zst");
        fs::write(&request, b"old authenticated request").unwrap();
        fs::write(&bundle, b"corrupt bytes").unwrap();
        assert!(cleanup_failed_request(&request, b"old authenticated request", &bundle).unwrap());
        assert!(!request.exists() && !bundle.exists());
        fs::write(&request, b"corrected new request").unwrap();
        fs::write(&bundle, b"new bytes").unwrap();
        assert!(!cleanup_failed_request(&request, b"old authenticated request", &bundle).unwrap());
        assert_eq!(fs::read(&request).unwrap(), b"corrected new request");
        assert_eq!(fs::read(&bundle).unwrap(), b"new bytes");
        fs::remove_dir_all(directory).unwrap();
    }
}
