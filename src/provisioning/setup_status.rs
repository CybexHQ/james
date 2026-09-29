//! Public, bounded projection of Nest setup progress for the tty1 kiosk.
//!
//! `tiaris-installer-kiosk --nest-setup` renders this file. It is presentation
//! only: provisioning never reads it back, and a failed write is logged and
//! ignored. The projection carries fixed public sentences and hardware
//! summaries; it never carries envelope or media secrets, keys, tokens,
//! serial numbers, transport URLs or raw error text.
use super::{
    NestProvisioningInventory, SignedInstallPlan,
    inventory::{MIN_DISK_BYTES, NestProvisioningDisk, NestProvisioningEthernetInterface},
};
use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use tracing::warn;

pub const SETUP_STATUS_PATH: &str = "/run/tiaris-nest-setup/status.json";
pub const SETUP_STATUS_SCHEMA: &str = "tiaris.nest-setup-status.v1";
const MAX_STATUS_BYTES: usize = 16 * 1024;
// Keep these synchronized with Tiaris's Nest provisioning admission.
const MIN_CPU_CORES: u32 = 4;
const MIN_MEMORY_BYTES: u64 = 16 * GIB;
const GIB: u64 = 1024 * 1024 * 1024;
const PROGRESS_PUBLISH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_VALUE_CHARS: usize = 80;
const MAX_LABEL_CHARS: usize = 40;
const MAX_REASON_CHARS: usize = 240;
const MAX_STEP_CHARS: usize = 160;
const MAX_STEPS: usize = 3;
const REVIEW_AND_RETRY: &str = "In Tiaris, open Nest and choose Review and try again.";
const RESTART_SAME_ISO: &str = "Restart this server from the same ISO.";
const UNTOUCHED: &str = "Nothing was written to the disk.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupState {
    Checking,
    AwaitingApproval,
    Installing,
    Stopped,
    Failed,
    Rebooting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    Firmware,
    Processor,
    Memory,
    Ethernet,
    Disk,
    Tiaris,
}

impl CheckId {
    fn label(self) -> &'static str {
        match self {
            Self::Firmware => "Firmware",
            Self::Processor => "Processor",
            Self::Memory => "Memory",
            Self::Ethernet => "Wired Ethernet",
            Self::Disk => "Disk",
            Self::Tiaris => "Tiaris",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Done,
    Active,
    Queued,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: CheckId,
    pub state: CheckState,
    pub value: String,
}

impl Check {
    fn new(id: CheckId, state: CheckState, value: impl AsRef<str>) -> Self {
        Self {
            id,
            state,
            value: bounded(value.as_ref(), MAX_VALUE_CHARS),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiskSummary {
    pub path: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetworkSummary {
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckRow {
    pub label: String,
    pub value: String,
}

impl CheckRow {
    fn new(label: &str, value: impl AsRef<str>) -> Self {
        Self {
            label: bounded(label, MAX_LABEL_CHARS),
            value: bounded(value.as_ref(), MAX_VALUE_CHARS),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StopDetail {
    pub reason: String,
    pub disk_untouched: bool,
    pub steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<CheckRow>,
}

impl StopDetail {
    fn new(
        reason: impl AsRef<str>,
        disk_untouched: bool,
        steps: &[String],
        check: Option<CheckRow>,
    ) -> Self {
        Self {
            reason: bounded(reason.as_ref(), MAX_REASON_CHARS),
            disk_untouched,
            steps: steps
                .iter()
                .take(MAX_STEPS)
                .map(|step| bounded(step, MAX_STEP_CHARS))
                .collect(),
            check,
        }
    }
}

/// The eight installation steps drawn by the kiosk. Steps 6-8 run on the
/// installed appliance and are reported by its console status instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InstallStep {
    StageRelease = 1,
    VerifyRelease = 2,
    RecheckHardware = 3,
    PrepareDisk = 4,
    InstallSystem = 5,
    FirstBoot = 6,
}

impl InstallStep {
    fn number(self) -> u8 {
        self as u8
    }

    fn title(self) -> &'static str {
        match self {
            Self::StageRelease => "Stage the signed release",
            Self::VerifyRelease => "Verify signatures and system",
            Self::RecheckHardware => "Recheck disk, memory and link",
            Self::PrepareDisk => "Partition and format",
            Self::InstallSystem => "Install the system",
            Self::FirstBoot => "First boot",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SetupStatus {
    pub schema: &'static str,
    pub state: SetupState,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tiaris_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<DiskSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopDetail>,
}

impl SetupStatus {
    fn initial(boot_mode: Option<&'static str>) -> Self {
        Self {
            schema: SETUP_STATUS_SCHEMA,
            state: SetupState::Checking,
            updated_at: timestamp(Utc::now()),
            boot_mode,
            checks: initial_checks(),
            tiaris_host: None,
            organization: None,
            name: None,
            disk: None,
            network: None,
            system: None,
            encrypted: None,
            approved_at: None,
            step: None,
            progress_percent: None,
            stop: None,
        }
    }
}

/// Live facts the pure builders cannot read themselves.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct LinkFacts {
    /// Negotiated speed in Mb/s, when the driver reports one.
    pub speed_mbps: Option<u32>,
}

fn initial_checks() -> Vec<Check> {
    [
        CheckId::Firmware,
        CheckId::Processor,
        CheckId::Memory,
        CheckId::Ethernet,
        CheckId::Disk,
        CheckId::Tiaris,
    ]
    .into_iter()
    .map(|id| {
        if id == CheckId::Firmware {
            Check::new(id, CheckState::Active, "Checking…")
        } else {
            Check::new(id, CheckState::Queued, "Queued")
        }
    })
    .collect()
}

/// Hardware rows for a collected inventory plus the Tiaris row. A row that
/// fails Tiaris's admission minimum is an error.
pub(super) fn inventory_checks(
    inventory: &NestProvisioningInventory,
    link: LinkFacts,
    tiaris: (CheckState, &str),
) -> Vec<Check> {
    let mut checks = vec![firmware_check(inventory)];
    checks.push(if inventory.cpu_cores >= MIN_CPU_CORES {
        Check::new(
            CheckId::Processor,
            CheckState::Done,
            cores(inventory.cpu_cores),
        )
    } else {
        Check::new(
            CheckId::Processor,
            CheckState::Error,
            format!("{} · needs {MIN_CPU_CORES}", cores(inventory.cpu_cores)),
        )
    });
    checks.push(if inventory.memory_bytes >= MIN_MEMORY_BYTES {
        Check::new(
            CheckId::Memory,
            CheckState::Done,
            format_memory(inventory.memory_bytes),
        )
    } else {
        Check::new(
            CheckId::Memory,
            CheckState::Error,
            format!(
                "{} · needs {}",
                format_insufficient_memory(inventory.memory_bytes),
                format_memory(MIN_MEMORY_BYTES)
            ),
        )
    });
    checks.push(match linked_interface(inventory) {
        Some(interface) => Check::new(
            CheckId::Ethernet,
            CheckState::Done,
            format_link(&interface.name, link.speed_mbps),
        ),
        None => Check::new(
            CheckId::Ethernet,
            CheckState::Error,
            no_link_value(inventory),
        ),
    });
    checks.push(match largest_eligible_disk(inventory) {
        Some(disk) => Check::new(CheckId::Disk, CheckState::Done, disk_value(disk)),
        None => Check::new(
            CheckId::Disk,
            CheckState::Error,
            format!("No eligible disk · needs {}", format_memory(MIN_DISK_BYTES)),
        ),
    });
    checks.push(Check::new(CheckId::Tiaris, tiaris.0, tiaris.1));
    checks
}

fn firmware_check(inventory: &NestProvisioningInventory) -> Check {
    let architecture = architecture();
    if inventory.boot_mode == "uefi" {
        // Secure Boot is informational: Tiaris Nest does not require it.
        let secure_boot = if inventory.secure_boot { "on" } else { "off" };
        Check::new(
            CheckId::Firmware,
            CheckState::Done,
            format!("{architecture} · UEFI · Secure Boot {secure_boot}"),
        )
    } else {
        Check::new(
            CheckId::Firmware,
            CheckState::Error,
            format!("{architecture} · BIOS · needs UEFI"),
        )
    }
}

fn architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86-64",
        "aarch64" => "ARM64",
        other => other,
    }
}

fn cores(count: u32) -> String {
    if count == 1 {
        "1 core".to_string()
    } else {
        format!("{count} cores")
    }
}

/// Memory uses binary GiB, rounded to the nearest whole GiB.
pub(super) fn format_memory(bytes: u64) -> String {
    format!("{} GiB", (bytes + GIB / 2) / GIB)
}

/// Below the floor, rounding up could print the minimum itself. Show a
/// truncated tenth instead so "15.6 GiB · needs 16 GiB" stays truthful.
fn format_insufficient_memory(bytes: u64) -> String {
    let rounded = (bytes + GIB / 2) / GIB;
    if rounded * GIB < MIN_MEMORY_BYTES {
        return format!("{rounded} GiB");
    }
    let tenths = bytes * 10 / GIB;
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

/// Disks use decimal units, as printed on drive labels.
pub(super) fn format_disk_size(bytes: u64) -> String {
    const GB: u64 = 1_000_000_000;
    const TB: u64 = 1_000 * GB;
    if bytes >= TB {
        let tenths = (bytes + TB / 20) / (TB / 10);
        if tenths % 10 == 0 {
            format!("{} TB", tenths / 10)
        } else {
            format!("{}.{} TB", tenths / 10, tenths % 10)
        }
    } else {
        format!("{} GB", (bytes + GB / 2) / GB)
    }
}

pub(super) fn format_link(interface: &str, speed_mbps: Option<u32>) -> String {
    match speed_mbps {
        Some(speed) if speed >= 1000 && speed % 1000 == 0 => {
            format!("{interface} · {} Gb/s", speed / 1000)
        }
        Some(speed) if speed >= 1000 => {
            format!("{interface} · {}.{} Gb/s", speed / 1000, speed % 1000 / 100)
        }
        Some(speed) if speed > 0 => format!("{interface} · {speed} Mb/s"),
        _ => format!("{interface} · link up"),
    }
}

fn disk_value(disk: &NestProvisioningDisk) -> String {
    format!(
        "{} · {}",
        device_name(&disk.path),
        format_disk_size(disk.size_bytes)
    )
}

fn device_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn no_link_value(inventory: &NestProvisioningInventory) -> String {
    match inventory.ethernet_interfaces.first() {
        Some(interface) => format!("No link on {}", interface.name),
        None => "No wired Ethernet found".to_string(),
    }
}

fn linked_interface(
    inventory: &NestProvisioningInventory,
) -> Option<&NestProvisioningEthernetInterface> {
    inventory
        .ethernet_interfaces
        .iter()
        .find(|interface| interface.link_up)
}

fn largest_eligible_disk(inventory: &NestProvisioningInventory) -> Option<&NestProvisioningDisk> {
    inventory
        .disks
        .iter()
        .filter(|disk| disk.eligible)
        .max_by_key(|disk| disk.size_bytes)
}

/// The awaiting-approval screen names a target disk only when the choice is
/// unambiguous; with several candidates the administrator picks in Tiaris.
pub(super) fn sole_eligible_disk(
    inventory: &NestProvisioningInventory,
) -> Option<&NestProvisioningDisk> {
    let mut eligible = inventory.disks.iter().filter(|disk| disk.eligible);
    let first = eligible.next()?;
    eligible.next().is_none().then_some(first)
}

fn disk_summary(disk: &NestProvisioningDisk) -> DiskSummary {
    let model = bounded(&disk.model, MAX_VALUE_CHARS);
    DiskSummary {
        path: bounded(&disk.path, MAX_VALUE_CHARS),
        size_bytes: disk.size_bytes,
        model: (!model.is_empty()).then_some(model),
    }
}

fn first_ipv4(addresses: &[String]) -> Option<String> {
    addresses.iter().find_map(|address| {
        let host = address.split_once('/').map_or(address.as_str(), |v| v.0);
        host.parse::<Ipv4Addr>().ok().map(|ip| ip.to_string())
    })
}

fn interface_summary(interface: &NestProvisioningEthernetInterface) -> NetworkSummary {
    NetworkSummary {
        interface: bounded(&interface.name, MAX_VALUE_CHARS),
        ipv4: first_ipv4(&interface.addresses),
    }
}

fn plan_network(plan: &SignedInstallPlan, inventory: &NestProvisioningInventory) -> NetworkSummary {
    let live = inventory
        .ethernet_interfaces
        .iter()
        .find(|interface| interface.id == plan.network.interface_id);
    let ipv4 = plan
        .network
        .address_cidr
        .as_ref()
        .and_then(|cidr| first_ipv4(std::slice::from_ref(cidr)))
        .or_else(|| live.and_then(|interface| first_ipv4(&interface.addresses)));
    NetworkSummary {
        interface: bounded(&plan.network_interface.name, MAX_VALUE_CHARS),
        ipv4,
    }
}

fn plan_system(plan: &SignedInstallPlan) -> Option<String> {
    let name = match plan.base_os.as_str() {
        "nixos" => "NixOS",
        "ubuntu" => "Ubuntu",
        _ => return None,
    };
    let version = plan.base_os_version.trim();
    let version_is_public = !version.is_empty()
        && version.len() <= 16
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    Some(if version_is_public {
        format!("{name} {version}")
    } else {
        name.to_string()
    })
}

/// Encryption is shown only when the signed plan clearly asks for it.
fn plan_encrypted(plan: &SignedInstallPlan) -> bool {
    let protection = plan.at_rest_protection.to_ascii_lowercase();
    protection != "none" && (protection.contains("luks") || protection.contains("encrypt"))
}

/// Host of the Management origin, without scheme, path or credentials.
pub(super) fn origin_host(origin: &str) -> Option<String> {
    let url = reqwest::Url::parse(origin).ok()?;
    let host = url.host_str()?;
    Some(bounded(host, MAX_VALUE_CHARS))
}

/// Public detail for a hardware minimum that fails before approval.
pub(super) fn hardware_stop(checks: &[Check]) -> Option<StopDetail> {
    let failing = checks
        .iter()
        .find(|check| check.state == CheckState::Error && check.id != CheckId::Tiaris)?;
    let row = Some(CheckRow::new(failing.id.label(), &failing.value));
    let interface = failing
        .value
        .strip_prefix("No link on ")
        .map(str::to_string);
    let (reason, steps): (&str, Vec<String>) = match failing.id {
        CheckId::Firmware => (
            "Tiaris Nest needs UEFI boot.",
            vec![
                "Switch this server's firmware to UEFI boot.".into(),
                RESTART_SAME_ISO.into(),
            ],
        ),
        CheckId::Processor => (
            "Tiaris Nest needs at least 4 processor cores.",
            vec![
                "Use a server with at least 4 processor cores.".into(),
                "In Tiaris, open Nest to review the hardware check.".into(),
            ],
        ),
        CheckId::Memory => (
            "Tiaris Nest needs at least 16 GiB of memory.",
            vec![
                "Add memory so this server has at least 16 GiB.".into(),
                RESTART_SAME_ISO.into(),
            ],
        ),
        CheckId::Ethernet => (
            "Tiaris Nest needs a connected wired Ethernet link.",
            vec![
                match interface {
                    Some(name) => format!("Connect a network cable to {name}."),
                    None => "Connect this server to a wired network.".to_string(),
                },
                "Setup continues automatically once the link is up.".into(),
            ],
        ),
        CheckId::Disk => (
            "Tiaris Nest needs an internal disk of at least 160 GiB that is not in use.",
            vec![
                "Connect an internal disk of at least 160 GiB.".into(),
                RESTART_SAME_ISO.into(),
            ],
        ),
        CheckId::Tiaris => return None,
    };
    Some(StopDetail::new(
        format!("{reason} {UNTOUCHED}"),
        true,
        &steps,
        row,
    ))
}

/// Public detail for a `PreDestructiveFailure`, keyed by its stable code.
/// `link_up` is the live carrier of the approved interface, if known.
pub(super) fn pre_destructive_stop(
    code: &str,
    public_message: &str,
    interface: &str,
    link_up: Option<bool>,
) -> StopDetail {
    let (reason, check, steps): (String, Option<CheckRow>, Vec<String>) = match code {
        "network_preflight_failed" if link_up == Some(false) => (
            format!("The wired network link went down during the hardware check. {UNTOUCHED}"),
            Some(CheckRow::new(
                "Wired Ethernet",
                format!("No link on {interface}"),
            )),
            vec![
                format!("Connect a network cable to {interface}."),
                REVIEW_AND_RETRY.into(),
                RESTART_SAME_ISO.into(),
            ],
        ),
        "network_preflight_failed" => (
            format!("{public_message} {UNTOUCHED}"),
            Some(CheckRow::new(
                "Wired Ethernet",
                format!("{interface} · not verified"),
            )),
            vec![
                format!("Check the cable and network settings for {interface}."),
                REVIEW_AND_RETRY.into(),
                RESTART_SAME_ISO.into(),
            ],
        ),
        "hardware_revalidation_failed" => (
            format!("{public_message} {UNTOUCHED}"),
            Some(CheckRow::new("Hardware", "Changed since approval")),
            vec![
                "Reconnect the approved disk and network cable.".into(),
                REVIEW_AND_RETRY.into(),
            ],
        ),
        "installation_media_validation_failed" => (
            format!("{public_message} {UNTOUCHED}"),
            Some(CheckRow::new(
                "Setup ISO",
                "Does not match the approved plan",
            )),
            vec![
                "In Tiaris, open Nest and download a new setup ISO.".into(),
                "Restart this server from the new ISO.".into(),
            ],
        ),
        "system_closure_verification_failed" | "package_snapshot_download_failed" => (
            format!("{public_message} {UNTOUCHED}"),
            Some(CheckRow::new(
                "Signed release",
                "Download or verification failed",
            )),
            vec![
                format!("Check that {interface} can reach the internet."),
                REVIEW_AND_RETRY.into(),
            ],
        ),
        _ => (
            format!("{public_message} {UNTOUCHED}"),
            None,
            vec![REVIEW_AND_RETRY.into()],
        ),
    };
    StopDetail::new(reason, true, &steps, check)
}

/// Public detail for an error after the disk may have been changed.
pub(super) fn post_destructive_failure(step: InstallStep) -> StopDetail {
    StopDetail::new(
        format!(
            "Installation stopped at step {}, {}. The disk may already have been changed.",
            step.number(),
            step.title().to_lowercase()
        ),
        false,
        &[
            "In Tiaris, open Nest to see installation details.".to_string(),
            "Keep this server on the same ISO; setup retries automatically.".to_string(),
        ],
        None,
    )
}

/// Where the setup flow was when an error ended the bootstrap process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Media,
    Inventory,
    Connecting,
    AwaitingApproval,
    Preparing,
}

fn phase_stop(phase: Phase, host: Option<&str>) -> StopDetail {
    let tiaris = host.unwrap_or("Tiaris");
    let (reason, check, steps): (String, Option<CheckRow>, Vec<String>) = match phase {
        Phase::Media => (
            format!("This setup ISO cannot start an installation. {UNTOUCHED}"),
            Some(CheckRow::new("Setup ISO", "Expired or not valid")),
            vec![
                "In Tiaris, open Nest and download a new setup ISO.".into(),
                "Restart this server from the new ISO.".into(),
            ],
        ),
        Phase::Inventory => (
            format!("Nest could not read this server's hardware. {UNTOUCHED}"),
            Some(CheckRow::new("Hardware", "Could not be read")),
            vec!["Setup retries automatically in a few seconds.".into()],
        ),
        Phase::Connecting => (
            format!("Nest could not start setup with {tiaris}. {UNTOUCHED}"),
            Some(CheckRow::new("Tiaris", "Not connected")),
            vec![
                format!("Check that this server's wired network can reach {tiaris}."),
                "In Tiaris, open Nest to check this setup.".into(),
                "Setup retries automatically in a few seconds.".into(),
            ],
        ),
        Phase::AwaitingApproval => (
            format!("Setup stopped while waiting for approval in Tiaris. {UNTOUCHED}"),
            None,
            vec![
                "In Tiaris, open Nest to check this setup.".into(),
                "Setup retries automatically in a few seconds.".into(),
            ],
        ),
        Phase::Preparing => (
            format!("Setup stopped before disk preparation. {UNTOUCHED}"),
            None,
            vec![
                "In Tiaris, open Nest to see installation details.".into(),
                "Setup retries automatically in a few seconds.".into(),
            ],
        ),
    };
    StopDetail::new(reason, true, &steps, check)
}

/// Milestones of one bootstrap run, in the order the flow reaches them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Milestone {
    Started,
    MediaVerified,
    InventoryCollected,
    SessionClaimed,
    PlanAccepted,
}

impl Milestone {
    fn previous(self) -> Self {
        match self {
            Self::Started | Self::MediaVerified => Self::Started,
            Self::InventoryCollected => Self::MediaVerified,
            Self::SessionClaimed => Self::InventoryCollected,
            Self::PlanAccepted => Self::SessionClaimed,
        }
    }
}

/// A `stopped` or `failed` screen preserved from an earlier run of the
/// restarting bootstrap. It stays on screen until this run passes `release`.
#[derive(Clone, Debug)]
struct HeldScreen {
    document: serde_json::Map<String, serde_json::Value>,
    release: Milestone,
    failed: bool,
}

/// Classify a preserved status. Anything other than a well-formed
/// `stopped`/`failed` document of this schema is ignored.
fn held_screen(body: &[u8]) -> Option<HeldScreen> {
    let serde_json::Value::Object(document) = serde_json::from_slice(body).ok()? else {
        return None;
    };
    if document.get("schema")?.as_str()? != SETUP_STATUS_SCHEMA {
        return None;
    }
    let state = document.get("state")?.as_str()?;
    if !document
        .get("stop")
        .is_some_and(serde_json::Value::is_object)
    {
        return None;
    }
    let checks = document
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let check_state = |id: &str| {
        checks
            .iter()
            .find(|check| check.get("id").and_then(serde_json::Value::as_str) == Some(id))
            .and_then(|check| check.get("state").and_then(serde_json::Value::as_str))
    };
    let release = match state {
        // After a disk write only resumed installation progress may replace it.
        "failed" => Milestone::PlanAccepted,
        "stopped" if document.contains_key("approved_at") => Milestone::PlanAccepted,
        "stopped"
            if ["firmware", "processor", "memory", "ethernet", "disk"]
                .iter()
                .any(|id| check_state(id) == Some("error")) =>
        {
            Milestone::InventoryCollected
        }
        "stopped" if !document.contains_key("tiaris_host") => Milestone::MediaVerified,
        "stopped" if matches!(check_state("processor"), None | Some("queued")) => {
            Milestone::InventoryCollected
        }
        "stopped" => Milestone::SessionClaimed,
        _ => return None,
    };
    let failed = state == "failed";
    Some(HeldScreen {
        document,
        release,
        failed,
    })
}

fn preserved_screen(path: Option<&Path>) -> Option<HeldScreen> {
    let path = path?;
    let body =
        super::read_bounded_nofollow(path, MAX_STATUS_BYTES as u64, "preserved setup status")
            .ok()?;
    held_screen(&body)
}

/// What one update publishes: this run's status or the preserved screen.
#[derive(Serialize)]
#[serde(untagged)]
enum Snapshot {
    Current(Box<SetupStatus>),
    Held(serde_json::Map<String, serde_json::Value>),
}

struct ReporterState {
    status: SetupStatus,
    /// Preserved screen still shown instead of `status`, if any.
    held: Option<HeldScreen>,
    reached: Milestone,
    phase: Phase,
    /// True once any target write may have happened, including every resume
    /// of an interrupted installation.
    disk_may_be_changed: bool,
    /// A hardware minimum failed before approval; the screen stays stopped
    /// until an approved plan arrives.
    hardware_blocked: bool,
    current_step: Option<InstallStep>,
    last_progress: Option<(u8, Instant)>,
}

/// Best-effort publisher. Every method updates the in-memory projection and
/// rewrites the file; failures are logged and never change provisioning.
pub(super) struct SetupStatusReporter {
    path: Option<PathBuf>,
    state: Mutex<ReporterState>,
}

impl SetupStatusReporter {
    pub(super) fn new(path: Option<PathBuf>) -> Self {
        let boot_mode = if Path::new("/sys/firmware/efi").is_dir() {
            "uefi"
        } else {
            "bios"
        };
        Self::with_boot_mode(path, Some(boot_mode))
    }

    /// A restarted bootstrap keeps showing a preserved `stopped` or `failed`
    /// screen instead of flashing `checking` while it retries.
    fn with_boot_mode(path: Option<PathBuf>, boot_mode: Option<&'static str>) -> Self {
        let held = preserved_screen(path.as_deref());
        Self {
            path,
            state: Mutex::new(ReporterState {
                status: SetupStatus::initial(boot_mode),
                held,
                reached: Milestone::Started,
                phase: Phase::Media,
                disk_may_be_changed: false,
                hardware_blocked: false,
                current_step: None,
                last_progress: None,
            }),
        }
    }

    fn update(&self, milestone: Milestone, change: impl FnOnce(&mut ReporterState)) {
        let snapshot = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            change(&mut state);
            state.reached = state.reached.max(milestone);
            let now = timestamp(Utc::now());
            state.status.updated_at = now.clone();
            let reached = state.reached;
            if state
                .held
                .as_ref()
                .is_some_and(|held| reached >= held.release)
            {
                state.held = None;
            }
            match state.held.as_mut() {
                Some(held) => {
                    held.document
                        .insert("updated_at".to_string(), serde_json::Value::String(now));
                    Snapshot::Held(held.document.clone())
                }
                None => Snapshot::Current(Box::new(state.status.clone())),
            }
        };
        let Some(path) = self.path.as_deref() else {
            return;
        };
        if let Err(error) = write_status(path, &snapshot) {
            warn!(error = %error, path = %path.display(), "could not publish Nest setup status");
        }
    }

    #[cfg(test)]
    fn holding(&self) -> bool {
        self.state.lock().unwrap().held.is_some()
    }

    #[cfg(test)]
    fn snapshot(&self) -> SetupStatus {
        self.state.lock().unwrap().status.clone()
    }

    /// Firmware is being checked; every other row is queued.
    pub(super) fn begin(&self) {
        self.update(Milestone::Started, |_| {});
    }

    pub(super) fn media_verified(&self, manage_origin: &str) {
        self.update(Milestone::MediaVerified, |state| {
            state.phase = Phase::Inventory;
            state.status.tiaris_host = origin_host(manage_origin);
        });
    }

    pub(super) fn inventory_collected(&self, inventory: &NestProvisioningInventory) {
        let link = LinkFacts {
            speed_mbps: linked_interface(inventory).and_then(|i| link_speed_mbps(&i.name)),
        };
        self.update(Milestone::InventoryCollected, |state| {
            state.phase = Phase::Connecting;
            let checks = inventory_checks(inventory, link, (CheckState::Active, "Connecting…"));
            state.status.boot_mode = Some(boot_mode_label(inventory));
            match hardware_stop(&checks) {
                Some(stop) => {
                    state.hardware_blocked = true;
                    state.status.state = SetupState::Stopped;
                    state.status.stop = Some(stop);
                }
                None => state.status.state = SetupState::Checking,
            }
            state.status.checks = checks;
        });
    }

    /// The session claim or recovery poll succeeded.
    pub(super) fn session_claimed(&self, inventory: &NestProvisioningInventory) {
        let link = LinkFacts {
            speed_mbps: linked_interface(inventory).and_then(|i| link_speed_mbps(&i.name)),
        };
        self.update(Milestone::SessionClaimed, |state| {
            state.phase = Phase::AwaitingApproval;
            state.status.checks =
                inventory_checks(inventory, link, (CheckState::Done, "Connected"));
            state.status.boot_mode = Some(boot_mode_label(inventory));
            state.status.disk = sole_eligible_disk(inventory).map(disk_summary);
            state.status.network = linked_interface(inventory).map(interface_summary);
            if !state.hardware_blocked {
                state.status.state = SetupState::AwaitingApproval;
                state.status.stop = None;
            }
        });
    }

    /// An approved plan (first or retry) was verified by this process.
    pub(super) fn plan_approved(
        &self,
        plan: &SignedInstallPlan,
        inventory: &NestProvisioningInventory,
    ) {
        self.update(Milestone::PlanAccepted, |state| {
            state.phase = Phase::Preparing;
            state.hardware_blocked = false;
            apply_plan(&mut state.status, plan, inventory);
            state.status.state = SetupState::Installing;
            state.status.approved_at = Some(timestamp(Utc::now()));
            state.status.stop = None;
            set_step(state, InstallStep::StageRelease);
        });
    }

    /// Resuming an interrupted installation: the disk may already be changed.
    pub(super) fn resumed(&self, plan: &SignedInstallPlan, inventory: &NestProvisioningInventory) {
        self.update(Milestone::PlanAccepted, |state| {
            state.phase = Phase::Preparing;
            state.disk_may_be_changed = true;
            state.hardware_blocked = false;
            apply_plan(&mut state.status, plan, inventory);
            state.status.state = SetupState::Installing;
            state.status.approved_at = Some(timestamp(Utc::now()));
            state.status.stop = None;
            set_step(state, InstallStep::StageRelease);
        });
    }

    pub(super) fn step(&self, step: InstallStep) {
        self.update(Milestone::PlanAccepted, |state| set_step(state, step));
    }

    /// Mark the point after which a failure can no longer be "untouched".
    pub(super) fn disk_write_started(&self) {
        self.update(Milestone::PlanAccepted, |state| {
            state.disk_may_be_changed = true;
            set_step(state, InstallStep::PrepareDisk);
        });
    }

    /// Measured release download progress. Publishes at most once a second
    /// and only when the whole percentage changes.
    pub(super) fn download_progress(&self, received: u64, total: u64) {
        let Some(percent) = measured_percent(received, total) else {
            return;
        };
        let publish = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let due = match state.last_progress {
                Some((last, at)) => {
                    percent != last && (percent == 100 || at.elapsed() >= PROGRESS_PUBLISH_INTERVAL)
                }
                None => true,
            };
            if due {
                state.last_progress = Some((percent, Instant::now()));
            }
            due
        };
        if publish {
            self.update(Milestone::PlanAccepted, |state| {
                state.status.progress_percent = Some(percent)
            });
        }
    }

    pub(super) fn pre_destructive_stop(&self, code: &str, public_message: &str) {
        self.update(Milestone::PlanAccepted, |state| {
            let interface = state
                .status
                .network
                .as_ref()
                .map(|network| network.interface.clone())
                .unwrap_or_else(|| "the wired interface".to_string());
            let link_up = state
                .status
                .network
                .as_ref()
                .and_then(|network| carrier(&network.interface));
            state.status.state = SetupState::Stopped;
            state.status.progress_percent = None;
            state.status.stop = Some(pre_destructive_stop(
                code,
                public_message,
                &interface,
                link_up,
            ));
        });
    }

    pub(super) fn rebooting(&self) {
        self.update(Milestone::PlanAccepted, |state| {
            set_step(state, InstallStep::FirstBoot);
            state.status.state = SetupState::Rebooting;
            state.status.stop = None;
        });
    }

    /// The bootstrap process is about to exit with an error. Publish a public
    /// explanation chosen from the recorded phase, never the error text.
    ///
    /// A preserved screen stays if this run failed at or after the point
    /// where the earlier run stopped: it is still the first obstacle. A run
    /// that failed earlier replaces a preserved `stopped` screen with its own,
    /// but a preserved `failed` screen is never replaced by an untouched stop.
    pub(super) fn process_failed(&self) {
        self.update(Milestone::Started, |state| {
            let reached = state.reached;
            if state.held.as_ref().is_some_and(|held| {
                (held.failed && !state.disk_may_be_changed) || reached >= held.release.previous()
            }) {
                return;
            }
            state.held = None;
            state.status.progress_percent = None;
            if state.disk_may_be_changed {
                let step = state.current_step.unwrap_or(InstallStep::PrepareDisk);
                state.status.state = SetupState::Failed;
                state.status.step = Some(step.number());
                state.status.stop = Some(post_destructive_failure(step));
                return;
            }
            if state.status.state == SetupState::Stopped && state.status.stop.is_some() {
                return;
            }
            let stop = phase_stop(state.phase, state.status.tiaris_host.as_deref());
            state.status.state = SetupState::Stopped;
            state.status.stop = Some(stop);
        });
    }
}

fn set_step(state: &mut ReporterState, step: InstallStep) {
    state.current_step = Some(step);
    state.status.step = Some(step.number());
    state.status.progress_percent = None;
    state.last_progress = None;
}

fn apply_plan(
    status: &mut SetupStatus,
    plan: &SignedInstallPlan,
    inventory: &NestProvisioningInventory,
) {
    status.organization = plan
        .organization_slug
        .as_deref()
        .map(|slug| bounded(slug, MAX_VALUE_CHARS))
        .filter(|slug| !slug.is_empty());
    let name = bounded(&plan.display_name, MAX_VALUE_CHARS);
    status.name = (!name.is_empty()).then_some(name);
    status.disk = Some(disk_summary(&plan.target_disk));
    status.network = Some(plan_network(plan, inventory));
    status.system = plan_system(plan);
    status.encrypted = Some(plan_encrypted(plan));
    status.boot_mode = Some(boot_mode_label(inventory));
    for check in &mut status.checks {
        if check.state == CheckState::Active {
            check.state = CheckState::Done;
        }
    }
}

fn boot_mode_label(inventory: &NestProvisioningInventory) -> &'static str {
    if inventory.boot_mode == "uefi" {
        "uefi"
    } else {
        "bios"
    }
}

pub(super) fn measured_percent(received: u64, total: u64) -> Option<u8> {
    if total == 0 || received > total {
        return None;
    }
    u8::try_from(u128::from(received) * 100 / u128::from(total)).ok()
}

fn safe_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn link_speed_mbps(interface: &str) -> Option<u32> {
    if !safe_interface_name(interface) {
        return None;
    }
    let body = fs::read_to_string(format!("/sys/class/net/{interface}/speed")).ok()?;
    body.trim().parse::<u32>().ok().filter(|speed| *speed > 0)
}

fn carrier(interface: &str) -> Option<bool> {
    if !safe_interface_name(interface) {
        return None;
    }
    match fs::read_to_string(format!("/sys/class/net/{interface}/carrier"))
        .ok()?
        .trim()
    {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

fn timestamp(value: chrono::DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Single-line public text: control characters removed, bounded in chars.
fn bounded(value: &str, maximum: usize) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(maximum)
        .collect()
}

/// Atomically replace `path` with a world-readable status document.
pub(super) fn write_status(path: &Path, status: &impl Serialize) -> Result<()> {
    let body = serde_json::to_vec(status).context("serialize Nest setup status")?;
    crate::public_status::write_public_json(path, &body, MAX_STATUS_BYTES)
}

#[cfg(test)]
mod tests;
