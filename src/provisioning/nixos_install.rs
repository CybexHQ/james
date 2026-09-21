//! Direct NixOS installation of one fully authenticated offline closure.
use super::{
    DurableProvisioningState, SignedInstallPlan,
    storage::{self, PreparedStorage},
};
use crate::appliance::{
    ApplianceRepositorySnapshot, closure, nixos,
    release_v3::{NixosRelease, SystemClosure},
    validate_qualification_package_transport_url,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::Command,
};
const GIB: u64 = 1024 * 1024 * 1024;
const STAGING: &str = "/run/cybex-appliance-closure";
const ARCHIVE: &str = "/run/cybex-appliance-closure/closure.tar.zst";
const TARGET: &str = "/mnt";

fn release(plan: &SignedInstallPlan) -> Result<&NixosRelease> {
    let release = plan
        .appliance_release
        .as_ref()
        .ok_or_else(|| anyhow!("NixOS plan missing closure"))?
        .nixos()?;
    ensure!(
        release.release_id == plan.release_version,
        "plan release identity mismatch"
    );
    Ok(release)
}

fn validate_closure_transport(transport: &str, artifact: &SystemClosure) -> Result<()> {
    if transport == artifact.url {
        return Ok(());
    }
    // The signed plan may select the same bounded private bridge accepted by
    // Manage qualification and appliance updates. It changes only transport:
    // the independently signed closure identity and NAR checks still apply.
    validate_qualification_package_transport_url(
        transport,
        &ApplianceRepositorySnapshot {
            url: artifact.url.clone(),
            sha256: artifact.sha256.clone(),
            size_bytes: artifact.size_bytes,
        },
    )
}

pub(super) async fn stage_closure(plan: &SignedInstallPlan, key_path: &Path) -> Result<()> {
    let release = release(plan)?;
    let key = release.verify_file(key_path)?;
    let transport = plan
        .package_transport_url
        .as_deref()
        .ok_or_else(|| anyhow!("plan missing transport"))?;
    validate_closure_transport(transport, &release.system_closure)?;
    fs::create_dir_all(STAGING)?;
    let metadata = fs::symlink_metadata(STAGING)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0,
        "unsafe RAM staging directory"
    );
    fs::set_permissions(STAGING, fs::Permissions::from_mode(0o700))?;
    let raw = std::ffi::CString::new(STAGING)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statfs(raw.as_ptr(), &mut stat) } == 0 && stat.f_type == 0x01021994,
        "closure staging must be RAM-backed tmpfs"
    );
    let memory = fs::read_to_string("/proc/meminfo")?;
    let available = memory
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u64>().ok())
        .and_then(|v| v.checked_mul(1024))
        .ok_or_else(|| anyhow!("MemAvailable unavailable"))?;
    let archive = Path::new(ARCHIVE);
    // A previous interrupted download is not a trust receipt. Re-verify the same
    // open file's entire contents before reusing it, while charging resident RAM.
    if let Ok(mut file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(archive)
    {
        if available >= 2 * GIB && closure::verify_archive(&mut file, release, &key, None).is_ok() {
            return Ok(());
        }
        fs::remove_file(archive)?;
    }
    ensure!(
        available
            >= release
                .system_closure
                .size_bytes
                .checked_add(2 * GIB)
                .ok_or_else(|| anyhow!("RAM budget overflow"))?,
        "insufficient available memory for signed closure plus bounded runtime"
    );
    ensure!(
        crate::disk::stats(Path::new(STAGING))?.available_bytes
            >= release.system_closure.size_bytes,
        "insufficient tmpfs capacity"
    );
    nixos::download(
        release,
        transport,
        archive,
        transport != release.system_closure.url,
    )
    .await?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(archive)?;
    closure::verify_archive(&mut file, release, &key, None)?;
    Ok(())
}

pub(super) fn calculate_layout(sector: u64, total: u64) -> Result<([u64; 5], [u64; 5])> {
    ensure!(
        matches!(sector, 512 | 4096) && total % sector == 0 && total >= 160 * GIB,
        "unsupported/insufficient disk geometry"
    );
    let alignment = 1024 * 1024 / sector;
    let mut starts = [0; 5];
    let mut ends = [0; 5];
    let mut cursor = alignment;
    for (i, bytes) in [16 * GIB, GIB, 8 * GIB].into_iter().enumerate() {
        starts[i] = cursor;
        ends[i] = cursor
            .checked_add(bytes / sector)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| anyhow!("partition overflow"))?;
        cursor = ends[i]
            .checked_add(1)
            .ok_or_else(|| anyhow!("partition overflow"))?
            .div_ceil(alignment)
            * alignment;
    }
    starts[3] = cursor;
    ends[3] = (total / sector)
        .checked_sub(alignment + 1)
        .ok_or_else(|| anyhow!("GPT capacity"))?;
    let root = ends[3]
        .checked_sub(starts[3])
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(sector))
        .ok_or_else(|| anyhow!("root capacity overflow"))?;
    ensure!(root >= 134 * GIB, "insufficient root capacity");
    Ok((starts, ends))
}
pub(super) async fn create_remaining(prepared: &PreparedStorage) -> Result<()> {
    let disk = prepared
        .disk_path
        .to_str()
        .ok_or_else(|| anyhow!("disk path"))?;
    for (index, kind, label) in [
        (2u8, "ef00", "CYBEX_EFI"),
        (3, "8200", "CYBEX_SWAP"),
        (4, "8300", "CYBEX_ROOT"),
    ] {
        let slot = usize::from(index - 1);
        let start = prepared.partition_starts[slot];
        let end = prepared.partition_ends[slot];
        match storage::inspect_partition(disk, index).await? {
            Some(p) => p.validate(start, end, kind, label)?,
            None => {
                storage::run_checked(
                    "sgdisk",
                    &[
                        &format!("--new={index}:{start}:{end}"),
                        &format!("--typecode={index}:{kind}"),
                        &format!("--change-name={index}:{label}"),
                        disk,
                    ],
                )
                .await?
            }
        }
    }
    storage::settle_partitions(disk).await?;
    Ok(())
}
async fn format_filesystems(
    prepared: &PreparedStorage,
    state: &DurableProvisioningState,
    root: &Path,
    esp: &Path,
    swap: &Path,
) -> Result<()> {
    let marker = prepared.state_mount.join("filesystems-prepared.json");
    let identity = |path: &Path| -> Result<String> {
        let output = Command::new("blkid")
            .args(["-s", "UUID", "-o", "value"])
            .arg(path)
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 128,
            "target filesystem UUID missing"
        );
        Ok(String::from_utf8(output.stdout)?.trim().into())
    };
    if marker.exists() {
        let body = super::read_bounded_nofollow(&marker, 4096, "prepared target filesystems")?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        ensure!(
            value["schema"] == "cybex.james.prepared-filesystems.v3"
                && value["plan_sha256"] == state.plan.plan_sha256
                && value["root_uuid"] == identity(root)?
                && value["esp_uuid"] == identity(esp)?
                && value["swap_uuid"] == identity(swap)?,
            "prepared filesystem receipt differs from approved attempt"
        );
        return Ok(());
    }
    // The receipt is created before any import. Without it, restarting this exact
    // approved attempt safely repeats formatting, never adopts an old root/cache.
    for (program, args, partition) in [
        ("mkfs.ext4", vec!["-F", "-m", "1", "-L", "CYBEX_ROOT"], root),
        ("mkfs.vfat", vec!["-F", "32", "-n", "CYBEX_EFI"], esp),
        ("mkswap", vec!["-L", "CYBEX_SWAP"], swap),
    ] {
        ensure!(
            tokio::process::Command::new(program)
                .args(args)
                .arg(partition)
                .status()
                .await?
                .success(),
            "format target filesystem failed"
        );
    }
    storage::atomic_write(
        &marker,
        &serde_json::to_vec(
            &json!({"schema":"cybex.james.prepared-filesystems.v3","plan_sha256":state.plan.plan_sha256,"root_uuid":identity(root)?,"esp_uuid":identity(esp)?,"swap_uuid":identity(swap)?}),
        )?,
        0o600,
    )
}
async fn mount(source: &Path, target: &Path, options: &str) -> Result<()> {
    fs::create_dir_all(target)?;
    let output = Command::new("findmnt")
        .args(["-rn", "-M"])
        .arg(target)
        .args(["-o", "SOURCE"])
        .output()?;
    if output.status.success() {
        if options.starts_with("bind") {
            let from = fs::metadata(source)?;
            let to = fs::metadata(target)?;
            ensure!(
                from.dev() == to.dev() && from.ino() == to.ino(),
                "target bind already points at unrelated directory"
            );
        } else {
            let mounted = String::from_utf8(output.stdout)?;
            ensure!(
                fs::canonicalize(mounted.trim())? == fs::canonicalize(source)?,
                "target mount already bound to unrelated device"
            );
        }
        return Ok(());
    }
    ensure!(
        tokio::process::Command::new("mount")
            .args(["-o", options])
            .arg(source)
            .arg(target)
            .status()
            .await?
            .success(),
        "mount target failed"
    );
    Ok(())
}
pub(super) async fn install(prepared: &PreparedStorage, key_path: &Path) -> Result<()> {
    let mut state = storage::load_durable_state(&prepared.state_mount)?;
    ensure!(state.identity_active, "permanent identity not yet active");
    let release = release(&state.plan)?.clone();
    let key = release.verify_file(key_path)?;
    let root = storage::partition_path(&prepared.disk_path, 4)?;
    let esp = storage::partition_path(&prepared.disk_path, 2)?;
    let swap = storage::partition_path(&prepared.disk_path, 3)?;
    format_filesystems(prepared, &state, &root, &esp, &swap).await?;
    let target = Path::new(TARGET);
    mount(&root, target, "defaults").await?;
    mount(&esp, &target.join("boot"), "umask=0077").await?;
    let target_state = target.join("var/lib/cybex-james/state");
    mount(&prepared.state_mount, &target_state, "bind,nodev,nosuid").await?;
    let target_nix = target.join("var/cache/cybex-james/nix");
    fs::create_dir_all(&target_nix)?;
    mount(&target_nix, &target.join("nix"), "bind,nodev,nosuid,exec").await?;
    let mut archive = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ARCHIVE)?;
    let manifest = closure::verify_archive(&mut archive, &release, &key, None)?;
    nixos::ensure_space(
        target,
        manifest
            .total_nar_bytes
            .checked_add(closure::MAX_EXPANDED)
            .ok_or_else(|| anyhow!("install space overflow"))?,
    )?;
    let cache = target.join(format!("var/cache/cybex-james/.install-{}", state.plan.id));
    if cache.exists() {
        let old = fs::symlink_metadata(&cache)?;
        ensure!(
            old.is_dir() && old.uid() == 0,
            "unsafe interrupted installation cache"
        );
        fs::remove_dir_all(&cache)?;
    }
    closure::verify_archive(&mut archive, &release, &key, Some(&cache))?;
    let trust = format!(
        "cybex-james-appliance-1:{}",
        super::protocol::standard_base64(key.as_bytes())
    );
    storage::run_checked(
        "nix",
        &[
            "--extra-experimental-features",
            "nix-command",
            "--option",
            "substituters",
            "",
            "--option",
            "trusted-public-keys",
            &trust,
            "copy",
            "--from",
            &format!("file://{}", cache.display()),
            "--to",
            &format!("local?root={TARGET}"),
            &release.system_toplevel,
        ],
    )
    .await?;
    if state.next_event_sequence == 6 {
        super::report_install_stage(
            &prepared.state_mount,
            "installing_packages",
            "succeeded",
            Some(80),
            "Verified NixOS system closure imported",
        )
        .await?;
        state = storage::load_durable_state(&prepared.state_mount)?;
    }
    // STATE exists before activation and contains all runtime trust/config.
    materialize_state(target, &prepared.state_mount, &state, key_path)?;
    storage::run_checked(
        "nixos-install",
        &[
            "--root",
            TARGET,
            "--system",
            &release.system_toplevel,
            "--no-root-passwd",
            "--no-channel-copy",
            "--option",
            "substituters",
            "",
            "--option",
            "trusted-public-keys",
            &trust,
        ],
    )
    .await?;
    if state.next_event_sequence == 7 {
        super::report_install_stage(
            &prepared.state_mount,
            "installing_bootloader",
            "succeeded",
            Some(95),
            "NixOS systemd-boot installed",
        )
        .await?;
        state = storage::load_durable_state(&prepared.state_mount)?;
    }
    let profile = fs::read_link(target.join("nix/var/nix/profiles/system"))?;
    let generation = profile
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("system-"))
        .and_then(|n| n.strip_suffix("-link"))
        .ok_or_else(|| anyhow!("installed generation unavailable"))?;
    nixos::generation(generation)?;
    let installed = nixos::InstalledState {
        schema: "cybex.james.installed-appliance.v3".into(),
        system_generation: generation.into(),
        system_toplevel: release.system_toplevel.clone(),
        system_closure_sha256: release.system_closure.sha256.clone(),
        base_os: "nixos".into(),
        base_os_version: release.base_os_version.clone(),
        at_rest_protection: "none".into(),
        release,
    };
    let receipt = prepared.state_mount.join("control/appliance-release.json");
    storage::atomic_write(&receipt, &serde_json::to_vec(&installed)?, 0o640)?;
    chown(&receipt, 0, 985)?;
    if state.next_event_sequence == 8 {
        super::report_install_stage(
            &prepared.state_mount,
            "rebooting",
            "succeeded",
            Some(99),
            "Rebooting into the managed NixOS appliance",
        )
        .await?;
        state = storage::load_durable_state(&prepared.state_mount)?;
    }
    state.installation_complete = true;
    storage::save_durable_state(&prepared.state_mount, &state)?;
    fs::remove_dir_all(&cache)?;
    File::open(&prepared.state_mount)?.sync_all()?;
    File::open(target)?.sync_all()?;
    boot_completed(&state, &prepared.state_mount)
}
fn materialize_state(
    target: &Path,
    state_mount: &Path,
    state: &DurableProvisioningState,
    key_path: &Path,
) -> Result<()> {
    for (name, uid, mode) in [
        ("agent", 985, 0o700),
        ("inbox", 985, 0o700),
        ("control", 0, 0o750),
        ("status", 0, 0o750),
    ] {
        let path = state_mount.join(name);
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        chown(&path, uid, 985)?;
    }
    let control = state_mount.join("control");
    let managed = json!({"private_key_b64":state.device_private_key_b64,"public_key_b64":state.device_public_key_b64,"public_key_fingerprint":state.device_public_key_fingerprint,"device_id":state.plan.reserved_device_id,"last_reported_event_id":null});
    let agent = state_mount.join("agent/manage-state.json");
    storage::atomic_write(&agent, &serde_json::to_vec(&managed)?, 0o600)?;
    chown(&agent, 985, 985)?;
    for (name, value) in [
        ("provisioning-state.json", serde_json::to_value(state)?),
        ("install-plan.json", serde_json::to_value(&state.plan)?),
        (
            "netplan-approved.json",
            storage::netplan(&state.plan.network, &state.plan),
        ),
        (
            "netplan-dhcp-fallback.json",
            storage::netplan(
                &super::protocol::JamesProvisioningNetworkPlan {
                    mode: "dhcp".into(),
                    interface_id: state.plan.network.interface_id.clone(),
                    address_cidr: None,
                    gateway: None,
                    dns_servers: Vec::new(),
                },
                &state.plan,
            ),
        ),
    ] {
        let path = control.join(name);
        storage::atomic_write(&path, &serde_json::to_vec(&value)?, 0o640)?;
        chown(&path, 0, 985)?;
    }
    let key_projection = target.join("usr/share/cybex-james/release-public-key");
    fs::create_dir_all(
        key_projection
            .parent()
            .ok_or_else(|| anyhow!("key parent"))?,
    )?;
    storage::atomic_write(&key_projection, &fs::read(key_path)?, 0o644)?;
    let config = storage::james_config(target, state, &storage::public_base_url(&state.plan))?
        .replace("/usr/bin/nix", "/run/current-system/sw/bin/nix")
        .replace(
            "/usr/bin/udp-sender",
            "/run/current-system/sw/bin/udp-sender",
        );
    for (name, body) in [
        ("config.toml", config),
        (
            "ssh-ca.pub",
            format!("{}\n", state.plan.ssh_ca_public_keys.join("\n")),
        ),
        ("principals", format!("{}\n", state.plan.reserved_device_id)),
        (
            "management-cidrs.txt",
            format!("{}\n", state.plan.management_cidrs.join("\n")),
        ),
    ] {
        let path = control.join(name);
        storage::atomic_write(&path, body.as_bytes(), 0o640)?;
        chown(&path, 0, 985)?;
    }
    let flat = state_mount.join("provisioning-state.json");
    if flat.exists() {
        fs::remove_file(flat)?;
    }
    File::open(state_mount)?.sync_all()?;
    Ok(())
}
pub(super) fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0,
        "set persistent state ownership"
    );
    Ok(())
}

pub(super) fn boot_completed(state: &DurableProvisioningState, _state_mount: &Path) -> Result<()> {
    ensure!(
        state.installation_complete && state.identity_active,
        "installation is incomplete"
    );
    let esp = storage::partition_path(Path::new(&state.plan.target_disk.path), 2)?;
    let output = Command::new("blkid")
        .args(["-s", "PARTUUID", "-o", "value"])
        .arg(&esp)
        .output()?;
    ensure!(
        output.status.success(),
        "installed ESP identity unavailable"
    );
    let guid = String::from_utf8(output.stdout)?
        .trim()
        .to_ascii_lowercase();
    let _ = uuid::Uuid::parse_str(&guid)?;
    let output = Command::new("efibootmgr").arg("-v").output()?;
    ensure!(
        output.status.success(),
        "cannot inspect installed UEFI entries"
    );
    let entries = String::from_utf8(output.stdout)?;
    let binding = format!("hd(2,gpt,{guid},");
    let candidates: Vec<_> = entries
        .lines()
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("boot")
                && l.contains(&binding)
                && l.contains("\\efi\\systemd\\systemd-bootx64.efi")
        })
        .collect();
    ensure!(
        candidates.len() == 1,
        "installed UEFI systemd-boot entry is missing or ambiguous"
    );
    let number = candidates[0]
        .get(4..8)
        .ok_or_else(|| anyhow!("UEFI entry number"))?;
    let _ = u16::from_str_radix(number, 16)?;
    ensure!(
        Command::new("efibootmgr")
            .args(["-n", number])
            .status()?
            .success(),
        "set exact installed BootNext failed"
    );
    let verify = Command::new("efibootmgr").output()?;
    ensure!(
        verify.status.success()
            && String::from_utf8(verify.stdout)?
                .lines()
                .any(|l| l.eq_ignore_ascii_case(&format!("BootNext: {number}"))),
        "installed BootNext verification failed"
    );
    ensure!(
        Command::new("sync").status()?.success(),
        "sync installation failed"
    );
    ensure!(
        Command::new("systemctl")
            .args(["reboot", "--no-block"])
            .status()?
            .success(),
        "reboot installed appliance failed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closure_artifact() -> SystemClosure {
        SystemClosure {
            url: "https://releases.example/1.2.3/cybex-james-appliance-closure-1.2.3-x86_64-linux.tar.zst".into(),
            sha256: "a".repeat(64),
            size_bytes: 1024,
        }
    }

    #[test]
    fn closure_transport_accepts_signed_url_or_exact_private_qualification_archive() {
        let artifact = closure_artifact();
        assert!(validate_closure_transport(&artifact.url, &artifact).is_ok());
        let filename = "cybex-james-appliance-closure-1.2.3-x86_64-linux.tar.zst";
        for authority in [
            "10.20.30.40:8080",
            "192.168.50.1:8080",
            "127.0.0.1:8080",
            "[fd00::10]:8080",
            "[::1]:8080",
        ] {
            let transport = format!("http://{authority}/qualification/{filename}");
            assert!(
                validate_closure_transport(&transport, &artifact).is_ok(),
                "authenticated qualification transport was rejected: {transport}"
            );
        }
    }

    #[test]
    fn closure_transport_rejects_unsafe_or_rebound_qualification_urls() {
        let artifact = closure_artifact();
        let filename = "cybex-james-appliance-closure-1.2.3-x86_64-linux.tar.zst";
        for transport in [
            format!("http://bridge.internal:8080/{filename}"),
            format!("http://8.8.8.8:8080/{filename}"),
            format!("http://169.254.169.254:8080/{filename}"),
            format!("http://2130706433:8080/{filename}"),
            format!("https://10.20.30.40:8080/{filename}"),
            format!("https://dev.example.com/qualification/{filename}"),
            format!("http://127.0.0.1/{filename}"),
            format!("http://127.0.0.1:0/{filename}"),
            format!("http://user@10.20.30.40:8080/{filename}"),
            format!("http://user:password@10.20.30.40:8080/{filename}"),
            "http://10.20.30.40:8080/other.tar.zst".into(),
            format!("http://10.20.30.40:8080/{filename}?token=fixture"),
            format!("http://10.20.30.40:8080/{filename}#debug"),
            format!("http://10.20.30.40:8080/path/../{filename}"),
            format!(" http://10.20.30.40:8080/{filename}"),
        ] {
            assert!(
                validate_closure_transport(&transport, &artifact).is_err(),
                "unsafe qualification transport was accepted: {transport}"
            );
        }
    }

    #[test]
    fn geometry_is_byte_correct_for_512_and_4096() {
        for sector in [512, 4096] {
            let (s, e) = calculate_layout(sector, 160 * GIB).unwrap();
            assert_eq!((e[0] - s[0] + 1) * sector, 16 * GIB);
            assert_eq!((e[1] - s[1] + 1) * sector, GIB);
            assert_eq!((e[2] - s[2] + 1) * sector, 8 * GIB);
            assert!((e[3] - s[3] + 1) * sector >= 134 * GIB);
            assert!(e[..3].iter().zip(&s[1..4]).all(|(end, start)| end < start));
        }
    }
    #[test]
    fn undersized_and_invalid_geometry_reject() {
        assert!(calculate_layout(4096, 160 * GIB - 1).is_err());
        assert!(calculate_layout(512, 159 * GIB).is_err());
        assert!(calculate_layout(1024, 160 * GIB).is_err());
    }
}
