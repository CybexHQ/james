use super::*;
use crate::provisioning::protocol;
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;

fn fixture() -> (SignedInstallPlan, NestProvisioningInventory) {
    let (mut plan, envelope, mut inventory, _) = protocol::tests::signed_plan_fixture(
        protocol::INSTALL_PLAN_SCHEMA_V1,
        "TIARIS-NEST-INSTALL-PLAN-V1",
    );
    plan["base_os"] = "nixos".into();
    plan["base_os_version"] = "26.05".into();
    plan["display_name"] = "Acme Nest".into();
    plan["target_disk"]["path"] = "/dev/nvme0n1".into();
    plan["target_disk"]["model"] = "Samsung PM9A3".into();
    plan["target_disk"]["size_bytes"] = 960_197_124_096u64.into();
    plan["network_interface"]["name"] = "eno1".into();
    inventory.ethernet_interfaces[0].name = "eno1".into();
    inventory.ethernet_interfaces[0].addresses = vec!["10.20.0.14/24".into()];
    inventory.disks[0].path = "/dev/nvme0n1".into();
    inventory.disks[0].model = "Samsung PM9A3".into();
    inventory.disks[0].size_bytes = 960_197_124_096;
    inventory.cpu_cores = 8;
    inventory.secure_boot = false;
    assert_eq!(envelope.manage_origin, "https://manage.cybex.net");
    (serde_json::from_value(plan).unwrap(), inventory)
}

fn reporter(dir: &tempdir::TempDir) -> (SetupStatusReporter, PathBuf) {
    let path = dir.path().join("tiaris-nest-setup/status.json");
    (
        SetupStatusReporter::with_boot_mode(Some(path.clone()), Some("uefi")),
        path,
    )
}

fn published(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

mod tempdir {
    //! Minimal self-cleaning temporary directory for writer tests.
    pub struct TempDir(std::path::PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tiaris-nest-setup-status-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn check_values_use_design_units() {
    assert_eq!(format_memory(32 * GIB), "32 GiB");
    assert_eq!(format_memory(32 * GIB - 300 * 1024 * 1024), "32 GiB");
    assert_eq!(format_insufficient_memory(8 * GIB), "8 GiB");
    assert_eq!(
        format_insufficient_memory(15 * GIB + 700 * 1024 * 1024),
        "15.6 GiB"
    );
    assert_eq!(format_disk_size(960_197_124_096), "960 GB");
    assert_eq!(format_disk_size(1_920_383_410_176), "1.9 TB");
    assert_eq!(format_disk_size(4_000_787_030_016), "4 TB");
    assert_eq!(format_link("eno1", Some(1000)), "eno1 · 1 Gb/s");
    assert_eq!(format_link("eno1", Some(2500)), "eno1 · 2.5 Gb/s");
    assert_eq!(format_link("eno1", Some(100)), "eno1 · 100 Mb/s");
    assert_eq!(format_link("eno1", None), "eno1 · link up");
    assert_eq!(measured_percent(42, 100), Some(42));
    assert_eq!(measured_percent(u64::MAX, u64::MAX), Some(100));
    assert_eq!(measured_percent(1, 0), None);
    assert_eq!(measured_percent(2, 1), None);
}

#[test]
fn inventory_rows_follow_admission_minimums() {
    let (_, mut inventory) = fixture();
    let checks = inventory_checks(
        &inventory,
        LinkFacts {
            speed_mbps: Some(1000),
        },
        (CheckState::Active, "Connecting…"),
    );
    let values: Vec<_> = checks
        .iter()
        .map(|check| (check.id, check.state, check.value.as_str()))
        .collect();
    assert_eq!(
        values,
        vec![
            (
                CheckId::Firmware,
                CheckState::Done,
                "x86-64 · UEFI · Secure Boot off"
            ),
            (CheckId::Processor, CheckState::Done, "8 cores"),
            (CheckId::Memory, CheckState::Done, "32 GiB"),
            (CheckId::Ethernet, CheckState::Done, "eno1 · 1 Gb/s"),
            (CheckId::Disk, CheckState::Done, "nvme0n1 · 960 GB"),
            (CheckId::Tiaris, CheckState::Active, "Connecting…"),
        ]
    );
    assert!(hardware_stop(&checks).is_none());

    inventory.memory_bytes = 8 * GIB;
    inventory.cpu_cores = 2;
    let checks = inventory_checks(
        &inventory,
        LinkFacts::default(),
        (CheckState::Queued, "Queued"),
    );
    assert_eq!(checks[1].state, CheckState::Error);
    assert_eq!(checks[1].value, "2 cores · needs 4");
    assert_eq!(checks[2].value, "8 GiB · needs 16 GiB");
    assert_eq!(checks[3].value, "eno1 · link up");
    // The first failing row decides the stop explanation.
    let stop = hardware_stop(&checks).unwrap();
    assert!(stop.disk_untouched);
    assert_eq!(stop.check.unwrap().label, "Processor");
}

#[test]
fn missing_link_and_disk_are_errors_with_recovery_steps() {
    let (_, mut inventory) = fixture();
    inventory.ethernet_interfaces[0].link_up = false;
    inventory.disks[0].eligible = false;
    let checks = inventory_checks(
        &inventory,
        LinkFacts::default(),
        (CheckState::Queued, "Queued"),
    );
    assert_eq!(checks[3].value, "No link on eno1");
    assert_eq!(checks[4].value, "No eligible disk · needs 160 GiB");
    let stop = hardware_stop(&checks).unwrap();
    assert_eq!(
        stop.check,
        Some(CheckRow::new("Wired Ethernet", "No link on eno1"))
    );
    assert_eq!(stop.steps[0], "Connect a network cable to eno1.");

    inventory.ethernet_interfaces.clear();
    let checks = inventory_checks(
        &inventory,
        LinkFacts::default(),
        (CheckState::Queued, "Queued"),
    );
    assert_eq!(checks[3].value, "No wired Ethernet found");

    inventory.boot_mode = "legacy".into();
    let checks = inventory_checks(
        &inventory,
        LinkFacts::default(),
        (CheckState::Queued, "Queued"),
    );
    assert_eq!(checks[0].state, CheckState::Error);
    assert_eq!(checks[0].value, "x86-64 · BIOS · needs UEFI");
}

#[test]
fn secure_boot_is_informational() {
    let (_, mut inventory) = fixture();
    inventory.secure_boot = true;
    let checks = inventory_checks(
        &inventory,
        LinkFacts::default(),
        (CheckState::Done, "Connected"),
    );
    assert_eq!(checks[0].state, CheckState::Done);
    assert_eq!(checks[0].value, "x86-64 · UEFI · Secure Boot on");
}

#[test]
fn awaiting_approval_names_a_disk_only_when_unambiguous() {
    let (_, mut inventory) = fixture();
    assert_eq!(sole_eligible_disk(&inventory).unwrap().path, "/dev/nvme0n1");
    let mut second = inventory.disks[0].clone();
    second.id = "disk-2".into();
    second.path = "/dev/sda".into();
    second.size_bytes = 2_000_000_000_000;
    inventory.disks.push(second.clone());
    assert!(sole_eligible_disk(&inventory).is_none());
    // The hardware row still reports the largest eligible candidate.
    let checks = inventory_checks(
        &inventory,
        LinkFacts::default(),
        (CheckState::Done, "Connected"),
    );
    assert_eq!(checks[4].value, "sda · 2 TB");
    inventory.disks[1].eligible = false;
    assert_eq!(sole_eligible_disk(&inventory).unwrap().path, "/dev/nvme0n1");

    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.media_verified("https://manage.cybex.net");
    status.inventory_collected(&inventory);
    status.session_claimed(&inventory);
    let value = published(&path);
    assert_eq!(value["state"], "awaiting_approval");
    assert_eq!(value["tiaris_host"], "manage.cybex.net");
    assert_eq!(value["boot_mode"], "uefi");
    assert_eq!(
        value["disk"],
        json!({"path": "/dev/nvme0n1", "size_bytes": 960_197_124_096u64, "model": "Samsung PM9A3"})
    );
    assert_eq!(
        value["network"],
        json!({"interface": "eno1", "ipv4": "10.20.0.14"})
    );
    assert_eq!(
        value["checks"][5],
        json!({"id": "tiaris", "state": "done", "value": "Connected"})
    );
    assert!(value.get("stop").is_none());
    assert!(value.get("step").is_none());
}

#[test]
fn pre_destructive_codes_choose_public_steps_and_check_rows() {
    let down = pre_destructive_stop(
        "network_preflight_failed",
        "Nest could not verify the approved wired network before disk preparation.",
        "eno1",
        Some(false),
    );
    assert_eq!(
        down.reason,
        "The wired network link went down during the hardware check. Nothing was written to the disk."
    );
    assert_eq!(
        down.steps,
        vec![
            "Connect a network cable to eno1.",
            "In Tiaris, open Nest and choose Review and try again.",
            "Restart this server from the same ISO.",
        ]
    );
    assert_eq!(
        down.check,
        Some(CheckRow::new("Wired Ethernet", "No link on eno1"))
    );
    assert!(down.disk_untouched);

    for (code, label) in [
        ("network_preflight_failed", Some("Wired Ethernet")),
        ("hardware_revalidation_failed", Some("Hardware")),
        ("installation_media_validation_failed", Some("Setup ISO")),
        ("system_closure_verification_failed", Some("Signed release")),
        ("package_snapshot_download_failed", Some("Signed release")),
        ("unknown_future_code", None),
    ] {
        let stop = pre_destructive_stop(code, "Public message.", "eno1", Some(true));
        assert!(stop.disk_untouched, "{code}");
        assert!(
            !stop.steps.is_empty() && stop.steps.len() <= MAX_STEPS,
            "{code}"
        );
        assert!(stop.reason.starts_with("Public message."), "{code}");
        assert_eq!(stop.check.map(|row| row.label), label.map(str::to_string));
    }
}

#[test]
fn approved_installation_publishes_plan_facts_and_steps() {
    let (plan, inventory) = fixture();
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.begin();
    let first = published(&path);
    assert_eq!(first["schema"], SETUP_STATUS_SCHEMA);
    assert_eq!(first["state"], "checking");
    assert_eq!(first["checks"][0]["state"], "active");
    assert_eq!(first["checks"][5]["state"], "queued");

    status.media_verified("https://manage.cybex.net/");
    status.inventory_collected(&inventory);
    assert_eq!(published(&path)["checks"][5]["state"], "active");
    status.session_claimed(&inventory);
    status.plan_approved(&plan, &inventory);
    let value = published(&path);
    assert_eq!(value["state"], "installing");
    assert_eq!(value["step"], 1);
    assert_eq!(value["organization"], "acme-control");
    assert_eq!(value["name"], "Acme Nest");
    assert_eq!(value["system"], "NixOS 26.05");
    assert_eq!(value["encrypted"], false);
    assert!(value["approved_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(value["network"]["interface"], "eno1");
    assert_eq!(value["network"]["ipv4"], "10.20.0.14");
    assert_eq!(value["disk"]["model"], "Samsung PM9A3");
    assert!(value.get("progress_percent").is_none());

    status.download_progress(10, 100);
    assert_eq!(published(&path)["progress_percent"], 10);
    // Throttled until a second passes, except for completion.
    status.download_progress(11, 100);
    assert_eq!(published(&path)["progress_percent"], 10);
    status.download_progress(100, 100);
    assert_eq!(published(&path)["progress_percent"], 100);
    status.step(InstallStep::VerifyRelease);
    let value = published(&path);
    assert_eq!(value["step"], 2);
    assert!(value.get("progress_percent").is_none());

    status.pre_destructive_stop(
        "hardware_revalidation_failed",
        "Nest could not confirm the approved server hardware before disk preparation.",
    );
    let value = published(&path);
    assert_eq!(value["state"], "stopped");
    assert_eq!(value["stop"]["disk_untouched"], true);
    status.plan_approved(&plan, &inventory);
    assert_eq!(published(&path)["state"], "installing");
    assert!(published(&path).get("stop").is_none());

    status.disk_write_started();
    status.step(InstallStep::InstallSystem);
    status.process_failed();
    let value = published(&path);
    assert_eq!(value["state"], "failed");
    assert_eq!(value["step"], 5);
    assert_eq!(value["stop"]["disk_untouched"], false);
    assert_eq!(
        value["stop"]["steps"][0],
        "In Tiaris, open Nest to see installation details."
    );
}

#[test]
fn process_errors_before_disk_writes_are_untouched_stops() {
    let (plan, inventory) = fixture();
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.begin();
    status.process_failed();
    assert_eq!(published(&path)["stop"]["check"]["label"], "Setup ISO");

    // Each run is independent: no preserved screen from the previous one.
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.media_verified("https://manage.cybex.net");
    status.inventory_collected(&inventory);
    status.process_failed();
    let value = published(&path);
    assert_eq!(value["state"], "stopped");
    assert_eq!(value["stop"]["disk_untouched"], true);
    assert_eq!(value["stop"]["check"]["label"], "Tiaris");
    assert!(
        value["stop"]["reason"]
            .as_str()
            .unwrap()
            .contains("manage.cybex.net")
    );

    // A recorded hardware stop is kept rather than replaced by a generic one.
    let mut blocked = inventory.clone();
    blocked.memory_bytes = 8 * GIB;
    // Each run is independent: no preserved screen from the previous one.
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.inventory_collected(&blocked);
    status.session_claimed(&blocked);
    assert_eq!(published(&path)["state"], "stopped");
    status.process_failed();
    assert_eq!(published(&path)["stop"]["check"]["label"], "Memory");

    // A resumed installation can never claim the disk is untouched.
    // Each run is independent: no preserved screen from the previous one.
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.resumed(&plan, &inventory);
    status.process_failed();
    let value = published(&path);
    assert_eq!(value["state"], "failed");
    assert_eq!(value["step"], 1);
    assert_eq!(value["stop"]["disk_untouched"], false);

    // Each run is independent: no preserved screen from the previous one.
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.resumed(&plan, &inventory);
    status.rebooting();
    let value = published(&path);
    assert_eq!(value["state"], "rebooting");
    assert_eq!(value["step"], 6);
}

#[test]
fn published_status_never_contains_secret_or_transport_material() {
    let (plan, inventory) = fixture();
    let (raw_plan, envelope, _, _) = protocol::tests::signed_plan_fixture(
        protocol::INSTALL_PLAN_SCHEMA_V2,
        "TIARIS-NEST-INSTALL-PLAN-V2",
    );
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.begin();
    status.media_verified("https://user:password@manage.cybex.net/private/path?token=abc");
    status.inventory_collected(&inventory);
    status.session_claimed(&inventory);
    status.plan_approved(&plan, &inventory);
    status.pre_destructive_stop("network_preflight_failed", "Public message.");
    status.process_failed();
    let body = fs::read_to_string(&path).unwrap();
    for secret in [
        envelope.media_secret.as_str(),
        plan.signature.as_str(),
        plan.plan_sha256.as_str(),
        plan.hardware_digest.as_str(),
        plan.reserved_device_id.as_str(),
        plan.target_disk.serial.as_str(),
        inventory.serial_number.as_str(),
        plan.network_interface.mac.as_str(),
        raw_plan["package_transport_url"].as_str().unwrap(),
        "password",
        "token",
        "/private/path",
        "ssh-ed25519",
    ] {
        assert!(!body.contains(secret), "status leaked {secret}");
    }
    assert!(body.contains("\"tiaris_host\":\"manage.cybex.net\""));
    assert!(body.len() <= MAX_STATUS_BYTES);
}

#[test]
fn text_fields_are_single_line_and_bounded() {
    let (mut plan, inventory) = fixture();
    plan.display_name = format!("Evil\u{1b}[2J\n{}", "x".repeat(400));
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.plan_approved(&plan, &inventory);
    let name = published(&path)["name"].as_str().unwrap().to_string();
    assert!(name.chars().count() <= MAX_VALUE_CHARS);
    assert!(!name.chars().any(char::is_control));
}

#[test]
fn writer_is_atomic_world_readable_and_bounded() {
    let dir = tempdir::TempDir::new();
    let path = dir.path().join("fresh/status.json");
    let mut status = SetupStatus::initial(Some("uefi"));
    let previous = unsafe { libc::umask(0o077) };
    let result = write_status(&path, &status);
    unsafe { libc::umask(previous) };
    result.unwrap();
    let file = fs::metadata(&path).unwrap();
    assert_eq!(file.mode() & 0o7777, 0o644);
    assert_eq!(
        fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o7777,
        0o755
    );
    status.state = SetupState::Rebooting;
    write_status(&path, &status).unwrap();
    assert_eq!(published(&path)["state"], "rebooting");
    // No temporary files remain beside the published document.
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);

    status.checks = (0..400)
        .map(|_| Check::new(CheckId::Disk, CheckState::Done, "x".repeat(80)))
        .collect();
    assert!(write_status(&path, &status).is_err());
    assert_eq!(published(&path)["state"], "rebooting");

    let file_parent = dir.path().join("not-a-directory");
    fs::write(&file_parent, b"").unwrap();
    assert!(
        write_status(
            &file_parent.join("status.json"),
            &SetupStatus::initial(None)
        )
        .is_err()
    );
}

#[test]
fn writer_failures_never_escape_the_reporter() {
    let dir = tempdir::TempDir::new();
    let blocker = dir.path().join("blocked");
    fs::write(&blocker, b"").unwrap();
    let status = SetupStatusReporter::with_boot_mode(Some(blocker.join("status.json")), None);
    status.begin();
    status.process_failed();
    assert_eq!(status.snapshot().state, SetupState::Stopped);
}

#[test]
fn omitted_fields_are_not_serialized_as_null() {
    let value = serde_json::to_value(SetupStatus::initial(None)).unwrap();
    let object = value.as_object().unwrap();
    assert!(object.values().all(|value| !value.is_null()));
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["checks", "schema", "state", "updated_at"]
    );
}

/// Run one bootstrap attempt that stops, then restart on the same status file.
fn restarted_after(
    first_run: impl FnOnce(&SetupStatusReporter),
) -> (tempdir::TempDir, PathBuf, Value) {
    let dir = tempdir::TempDir::new();
    let (status, path) = reporter(&dir);
    status.begin();
    first_run(&status);
    let preserved = published(&path);
    assert!(matches!(
        preserved["state"].as_str(),
        Some("stopped" | "failed")
    ));
    (dir, path, preserved)
}

fn without_timestamp(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("updated_at");
    value
}

#[test]
fn restarted_run_keeps_a_session_stop_until_the_claim_succeeds() {
    let (_, inventory) = fixture();
    let (dir, path, preserved) = restarted_after(|status| {
        status.media_verified("https://manage.cybex.net");
        status.inventory_collected(&inventory);
        status.process_failed();
    });
    assert_eq!(preserved["stop"]["check"]["label"], "Tiaris");

    let (status, _) = reporter(&dir);
    assert!(status.holding());
    status.begin();
    status.media_verified("https://manage.cybex.net");
    status.inventory_collected(&inventory);
    let shown = published(&path);
    assert_eq!(
        without_timestamp(shown.clone()),
        without_timestamp(preserved.clone())
    );
    assert!(shown["updated_at"].as_str().unwrap() >= preserved["updated_at"].as_str().unwrap());
    // Failing again at the same point keeps the same screen: no flicker.
    status.process_failed();
    assert_eq!(
        without_timestamp(published(&path)),
        without_timestamp(preserved.clone())
    );

    let (status, _) = reporter(&dir);
    status.begin();
    status.media_verified("https://manage.cybex.net");
    status.inventory_collected(&inventory);
    status.session_claimed(&inventory);
    assert!(!status.holding());
    assert_eq!(published(&path)["state"], "awaiting_approval");
}

#[test]
fn restarted_run_keeps_a_media_stop_until_media_verifies() {
    let (dir, path, preserved) = restarted_after(|status| status.process_failed());
    assert_eq!(preserved["stop"]["check"]["label"], "Setup ISO");
    let (status, _) = reporter(&dir);
    status.begin();
    assert_eq!(published(&path)["state"], "stopped");
    status.process_failed();
    assert_eq!(published(&path)["stop"]["check"]["label"], "Setup ISO");

    let (status, _) = reporter(&dir);
    status.begin();
    status.media_verified("https://manage.cybex.net");
    let shown = published(&path);
    assert_eq!(shown["state"], "checking");
    assert_eq!(shown["tiaris_host"], "manage.cybex.net");
}

#[test]
fn restarted_run_keeps_a_plan_stop_until_a_new_plan_is_approved() {
    let (plan, inventory) = fixture();
    let (dir, path, preserved) = restarted_after(|status| {
        status.media_verified("https://manage.cybex.net");
        status.inventory_collected(&inventory);
        status.session_claimed(&inventory);
        status.plan_approved(&plan, &inventory);
        status.pre_destructive_stop(
            "hardware_revalidation_failed",
            "Nest could not confirm the approved server hardware before disk preparation.",
        );
        status.process_failed();
    });
    assert_eq!(preserved["stop"]["check"]["label"], "Hardware");

    let (status, _) = reporter(&dir);
    status.begin();
    status.media_verified("https://manage.cybex.net");
    status.inventory_collected(&inventory);
    status.session_claimed(&inventory);
    assert_eq!(published(&path)["stop"]["check"]["label"], "Hardware");
    status.process_failed();
    assert_eq!(published(&path)["stop"]["check"]["label"], "Hardware");

    // A run that fails earlier than the preserved stop shows its own reason.
    let (status, _) = reporter(&dir);
    status.begin();
    status.process_failed();
    assert_eq!(published(&path)["stop"]["check"]["label"], "Setup ISO");

    let (dir, path, _) = restarted_after(|status| {
        status.media_verified("https://manage.cybex.net");
        status.inventory_collected(&inventory);
        status.session_claimed(&inventory);
        status.plan_approved(&plan, &inventory);
        status.pre_destructive_stop("network_preflight_failed", "Public message.");
    });
    let (status, _) = reporter(&dir);
    status.begin();
    status.media_verified("https://manage.cybex.net");
    status.inventory_collected(&inventory);
    status.session_claimed(&inventory);
    assert_eq!(published(&path)["state"], "stopped");
    status.plan_approved(&plan, &inventory);
    assert_eq!(published(&path)["state"], "installing");
}

#[test]
fn restarted_run_never_replaces_failed_with_checking_or_an_untouched_stop() {
    let (plan, inventory) = fixture();
    let (dir, path, preserved) = restarted_after(|status| {
        status.media_verified("https://manage.cybex.net");
        status.inventory_collected(&inventory);
        status.session_claimed(&inventory);
        status.plan_approved(&plan, &inventory);
        status.disk_write_started();
        status.process_failed();
    });
    assert_eq!(preserved["stop"]["disk_untouched"], false);

    for failure_point in 0..4 {
        let (status, _) = reporter(&dir);
        status.begin();
        if failure_point > 0 {
            status.media_verified("https://manage.cybex.net");
        }
        if failure_point > 1 {
            status.inventory_collected(&inventory);
        }
        if failure_point > 2 {
            status.session_claimed(&inventory);
        }
        assert_eq!(published(&path)["state"], "failed", "point {failure_point}");
        status.process_failed();
        let shown = published(&path);
        assert_eq!(shown["state"], "failed", "point {failure_point}");
        assert_eq!(shown["stop"]["disk_untouched"], false);
    }

    // Only resumed installation progress replaces it.
    let (status, _) = reporter(&dir);
    status.begin();
    status.media_verified("https://manage.cybex.net");
    status.inventory_collected(&inventory);
    status.resumed(&plan, &inventory);
    let shown = published(&path);
    assert_eq!(shown["state"], "installing");
    assert_eq!(shown["step"], 1);
}

#[test]
fn restarted_run_rechecks_a_hardware_stop_with_fresh_inventory() {
    let (_, inventory) = fixture();
    let mut blocked = inventory.clone();
    blocked.memory_bytes = 8 * GIB;
    let (dir, path, _) = restarted_after(|status| {
        status.media_verified("https://manage.cybex.net");
        status.inventory_collected(&blocked);
        status.process_failed();
    });
    let (status, _) = reporter(&dir);
    status.begin();
    status.media_verified("https://manage.cybex.net");
    assert_eq!(published(&path)["stop"]["check"]["label"], "Memory");
    status.inventory_collected(&inventory);
    assert_eq!(published(&path)["state"], "checking");
}

#[test]
fn only_valid_stopped_or_failed_screens_are_preserved() {
    let checking = serde_json::to_vec(&SetupStatus::initial(Some("uefi"))).unwrap();
    assert!(held_screen(&checking).is_none());
    assert!(held_screen(b"not json").is_none());
    assert!(held_screen(br#"{"schema":"other","state":"stopped","stop":{}}"#).is_none());
    assert!(
        held_screen(br#"{"schema":"tiaris.nest-setup-status.v1","state":"stopped"}"#).is_none()
    );
    assert!(
        held_screen(br#"{"schema":"tiaris.nest-setup-status.v1","state":"rebooting","stop":{}}"#)
            .is_none()
    );
    let held =
        held_screen(br#"{"schema":"tiaris.nest-setup-status.v1","state":"failed","stop":{}}"#)
            .unwrap();
    assert!(held.failed);
    assert_eq!(held.release, Milestone::PlanAccepted);

    let dir = tempdir::TempDir::new();
    let path = dir.path().join("tiaris-nest-setup/status.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = dir.path().join("elsewhere.json");
    fs::write(
        &target,
        br#"{"schema":"tiaris.nest-setup-status.v1","state":"failed","stop":{}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(!SetupStatusReporter::with_boot_mode(Some(path.clone()), None).holding());
    fs::remove_file(&path).unwrap();
    fs::write(&path, vec![b' '; MAX_STATUS_BYTES + 1]).unwrap();
    assert!(!SetupStatusReporter::with_boot_mode(Some(path), None).holding());
}
