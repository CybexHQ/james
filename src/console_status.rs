//! Public appliance status for the tty1 console kiosk.
//!
//! `tiaris-installer-kiosk --appliance` renders `/run/tiaris-nest/console-status.json`.
//! The daemon rewrites it every 15 seconds and promptly after Tiaris contact.
//! Readiness follows the retired `tiaris-nest-console` script: a failed unit
//! needs attention, a Nest that stays not ready for six consecutive checks
//! needs attention, and otherwise it is starting or healthy. The daemon cannot
//! observe its own unit stopping; the kiosk treats a stale file as attention.
use crate::AppState;
use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::OnceLock,
    time::Duration,
};
use tokio::{process::Command, sync::Notify};
use tracing::{debug, warn};

pub const CONSOLE_STATUS_PATH: &str = "/run/tiaris-nest/console-status.json";
pub const CONSOLE_STATUS_SCHEMA: &str = "tiaris.nest-console-status.v1";
const REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const ATTENTION_AFTER_CHECKS: u32 = 6;
/// Tiaris normally hears from Nest every sync interval (at most an hour, 30 s
/// by default). Ten silent minutes means the link, not the schedule, failed.
const TIARIS_UNREACHABLE_AFTER_SECONDS: i64 = 10 * 60;
const MAX_STATUS_BYTES: usize = 16 * 1024;
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(5);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(20);
const INSTALL_PLAN_PATH: &str = "/var/lib/tiaris-nest/control/install-plan.json";
const MANAGE_CONTACT_PATH: &str = "/var/lib/tiaris-nest/state/agent/manage-contact.json";
const SYSTEM_IDENTITY_PATH: &str = "/usr/share/tiaris-nest/system-identity.json";
const SERVICE_GID: u32 = 985;

/// Units whose failure needs attention, in the retired console's order.
const WATCHED_UNITS: [(&str, &str); 8] = [
    ("tiaris-nest-first-boot.service", "First boot"),
    ("tiaris-nest-network-runtime.service", "Network runtime"),
    ("tiaris-nest-firewall.service", "Firewall"),
    ("tiaris-nest.service", "Tiaris Nest service"),
    ("nginx.service", "Web server"),
    ("tftpd-hpa.service", "TFTP boot server"),
    ("nix-daemon.service", "Nix daemon"),
    ("ssh.service", "Remote support (SSH)"),
];
/// Units that must be active before Nest can be healthy.
const REQUIRED_ACTIVE: [&str; 6] = [
    "tiaris-nest.service",
    "tiaris-nest-firewall.service",
    "nginx.service",
    "tftpd-hpa.service",
    "nix-daemon.service",
    "ssh.service",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleState {
    Starting,
    Healthy,
    Attention,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    FirstBoot,
    Enrolling,
    Services,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pxe {
    Active,
    Standby,
    External,
    Unavailable,
}

impl Pxe {
    fn parse(status: &str) -> Option<Self> {
        match status {
            "active" => Some(Self::Active),
            "standby" => Some(Self::Standby),
            "external" => Some(Self::External),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionCode {
    ServiceFailed,
    TiarisUnreachable,
    NotReady,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckRow {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Attention {
    pub code: AttentionCode,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<CheckRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConsoleStatus {
    pub schema: &'static str,
    pub state: ConsoleState,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<Stage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tiaris_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pxe: Option<Pxe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_installs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_contact_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub booted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attention: Option<Attention>,
}

/// Public identity facts; each is independently optional.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub tiaris_host: Option<String>,
    pub address: Option<String>,
    pub interface: Option<String>,
    pub system: Option<String>,
    pub booted_at: Option<DateTime<Utc>>,
}

/// Unit states observed through systemd. `None` means systemd could not be
/// queried, which is never reported as a failed unit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitStates {
    pub failed: Vec<&'static str>,
    pub inactive_required: Vec<&'static str>,
    pub first_boot_active: bool,
}

/// One observation of the appliance; the pure evaluator maps it to a status.
#[derive(Clone, Debug)]
pub struct Observation {
    pub now: DateTime<Utc>,
    /// When this daemon began observing; bounds the unreachable window so a
    /// Nest powered off for a day is not "unreachable" the moment it boots.
    pub observing_since: DateTime<Utc>,
    pub units: Option<UnitStates>,
    pub health_ready: bool,
    pub last_contact: Option<DateTime<Utc>>,
    /// Tiaris accepted a signed report from this boot's identity.
    pub contacted_this_boot: bool,
    pub identity: Identity,
    pub pxe: Option<Pxe>,
    pub active_installs: Option<u32>,
}

/// Consecutive-check memory ported from the retired console script.
#[derive(Debug, Default)]
pub struct ReadinessTracker {
    non_ready_checks: u32,
    non_ready_since: Option<DateTime<Utc>>,
    attention: Option<(AttentionCode, String, DateTime<Utc>)>,
}

impl ReadinessTracker {
    /// Precedence: attention > starting > healthy.
    pub fn evaluate(&mut self, observation: &Observation) -> ConsoleStatus {
        let name = observation
            .identity
            .name
            .clone()
            .unwrap_or_else(|| "This Nest".to_string());
        let units = observation.units.clone().unwrap_or(UnitStates {
            failed: Vec::new(),
            inactive_required: Vec::new(),
            first_boot_active: true,
        });
        let mut status = base_status(observation);

        if let Some(unit) = units.failed.first() {
            let label = unit_label(unit);
            let since = self.attention_since(AttentionCode::ServiceFailed, unit, observation.now);
            status.state = ConsoleState::Attention;
            status.attention = Some(Attention {
                code: AttentionCode::ServiceFailed,
                title: bounded(&format!("{name} needs attention"), 80),
                detail: bounded(
                    &format!(
                        "{label} stopped unexpectedly. Check Tiaris for status and next steps."
                    ),
                    240,
                ),
                since: Some(timestamp(since)),
                check: Some(CheckRow {
                    label: bounded(label, 40),
                    value: "Failed".to_string(),
                }),
            });
            return status;
        }

        if !units.first_boot_active {
            self.reset();
            status.state = ConsoleState::Starting;
            status.stage = Some(Stage::FirstBoot);
            return status;
        }

        let reference = observation
            .last_contact
            .map_or(observation.observing_since, |contact| {
                contact.max(observation.observing_since)
            });
        let silent_seconds = (observation.now - reference).num_seconds();
        if silent_seconds > TIARIS_UNREACHABLE_AFTER_SECONDS {
            self.reset();
            status.state = ConsoleState::Attention;
            status.attention = Some(unreachable_attention(observation, &name));
            return status;
        }

        let services_ready = observation.units.is_some()
            && units.inactive_required.is_empty()
            && observation.health_ready;
        if services_ready {
            self.reset();
            if observation.contacted_this_boot {
                status.state = ConsoleState::Healthy;
            } else {
                status.state = ConsoleState::Starting;
                status.stage = Some(Stage::Enrolling);
            }
            return status;
        }

        // PXE readiness depends on Tiaris-provided discovery. Until this boot
        // has reached Tiaris, missing health alone is enrollment progress;
        // the unreachable rule above bounds that wait.
        if !observation.contacted_this_boot
            && observation.units.is_some()
            && units.inactive_required.is_empty()
        {
            self.reset();
            status.state = ConsoleState::Starting;
            status.stage = Some(Stage::Enrolling);
            return status;
        }

        // Prompt refreshes must not shorten the retired console's window, so
        // attention also needs the checks to span five refresh intervals.
        self.non_ready_checks = self.non_ready_checks.saturating_add(1);
        let since = *self.non_ready_since.get_or_insert(observation.now);
        let window = chrono::Duration::from_std(REFRESH_INTERVAL * (ATTENTION_AFTER_CHECKS - 1))
            .unwrap_or_else(|_| chrono::Duration::zero());
        if self.non_ready_checks < ATTENTION_AFTER_CHECKS || observation.now - since < window {
            status.state = ConsoleState::Starting;
            status.stage = Some(if observation.contacted_this_boot {
                Stage::Services
            } else {
                Stage::Enrolling
            });
            return status;
        }
        let (label, value) = match units.inactive_required.first() {
            Some(unit) => (unit_label(unit), "Not running"),
            None if observation.units.is_none() => ("Service status", "Unavailable"),
            None => ("Boot services", "Not ready"),
        };
        let since = self.attention_since(AttentionCode::NotReady, label, observation.now);
        status.state = ConsoleState::Attention;
        status.attention = Some(Attention {
            code: AttentionCode::NotReady,
            title: bounded(&format!("{name} is not ready"), 80),
            detail: "Nest services have not become ready. Check Tiaris for status and next steps."
                .to_string(),
            since: Some(timestamp(since)),
            check: Some(CheckRow {
                label: label.to_string(),
                value: value.to_string(),
            }),
        });
        status
    }

    fn reset(&mut self) {
        self.non_ready_checks = 0;
        self.non_ready_since = None;
        self.attention = None;
    }

    fn attention_since(
        &mut self,
        code: AttentionCode,
        subject: &str,
        now: DateTime<Utc>,
    ) -> DateTime<Utc> {
        match &self.attention {
            Some((current, current_subject, since))
                if *current == code && current_subject == subject =>
            {
                *since
            }
            _ => {
                self.attention = Some((code, subject.to_string(), now));
                now
            }
        }
    }
}

fn base_status(observation: &Observation) -> ConsoleStatus {
    let identity = &observation.identity;
    ConsoleStatus {
        schema: CONSOLE_STATUS_SCHEMA,
        state: ConsoleState::Starting,
        updated_at: timestamp(observation.now),
        stage: None,
        name: identity.name.clone(),
        organization: identity.organization.clone(),
        tiaris_host: identity.tiaris_host.clone(),
        address: identity.address.clone(),
        interface: identity.interface.clone(),
        pxe: observation.pxe,
        active_installs: observation.active_installs,
        last_contact_at: observation.last_contact.map(timestamp),
        booted_at: identity.booted_at.map(timestamp),
        system: identity.system.clone(),
        attention: None,
    }
}

fn unreachable_attention(observation: &Observation, name: &str) -> Attention {
    let interface = observation
        .identity
        .interface
        .as_deref()
        .unwrap_or("its wired interface");
    let (detail, value) = match observation.last_contact {
        Some(contact) => {
            let minutes = (observation.now - contact).num_minutes().max(0);
            (
                format!(
                    "Last contact was at {} UTC. Check the network connection on {interface}.",
                    contact.format("%H:%M")
                ),
                format!("Unreachable · {}", format_minutes(minutes)),
            )
        }
        None => (
            format!(
                "Nest has not reached Tiaris yet. Check the network connection on {interface}."
            ),
            "Unreachable".to_string(),
        ),
    };
    Attention {
        code: AttentionCode::TiarisUnreachable,
        title: bounded(&format!("{name} can't reach Tiaris"), 80),
        detail: bounded(&detail, 240),
        since: observation.last_contact.map(timestamp),
        check: Some(CheckRow {
            label: "Connection to Tiaris".to_string(),
            value,
        }),
    }
}

fn format_minutes(minutes: i64) -> String {
    if minutes < 120 {
        format!("{minutes} min")
    } else if minutes < 48 * 60 {
        format!("{} h", minutes / 60)
    } else {
        format!("{} days", minutes / (24 * 60))
    }
}

fn unit_label(unit: &str) -> &'static str {
    WATCHED_UNITS
        .iter()
        .find(|(name, _)| *name == unit)
        .map_or("A Nest service", |(_, label)| label)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn bounded(value: &str, maximum: usize) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(maximum)
        .collect()
}

/// Parse `systemctl show --property=Id --property=ActiveState` output for
/// the queried units, which systemd prints in argument order.
pub fn parse_unit_states(output: &str, queried: &[&'static str]) -> Option<UnitStates> {
    let blocks: Vec<_> = output
        .split("\n\n")
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .collect();
    if blocks.len() != queried.len() {
        return None;
    }
    let mut states = UnitStates::default();
    for (unit, block) in queried.iter().zip(blocks) {
        let active_state = block
            .lines()
            .find_map(|line| line.strip_prefix("ActiveState="))?;
        match active_state {
            "failed" => states.failed.push(unit),
            "active" | "reloading" => {
                if *unit == "tiaris-nest-first-boot.service" {
                    states.first_boot_active = true;
                }
            }
            _ => {
                if REQUIRED_ACTIVE.contains(unit) {
                    states.inactive_required.push(unit);
                }
            }
        }
    }
    Some(states)
}

async fn observe_units() -> Option<UnitStates> {
    let queried: Vec<&'static str> = WATCHED_UNITS.iter().map(|(unit, _)| *unit).collect();
    let mut command = Command::new("systemctl");
    command
        .arg("show")
        .arg("--property=Id")
        .arg("--property=ActiveState")
        .arg("--")
        .args(&queried)
        .kill_on_drop(true);
    let output = tokio::time::timeout(SYSTEMCTL_TIMEOUT, command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return None;
    }
    parse_unit_states(&String::from_utf8_lossy(&output.stdout), &queried)
}

/// Same readiness as `/healthz?tiaris_fresh=1`, which the console used.
async fn observe_health(state: &AppState) -> bool {
    let readiness = tokio::time::timeout(HEALTH_TIMEOUT, crate::readiness::probe_fresh(state))
        .await
        .map(|readiness| readiness.ready)
        .unwrap_or(false);
    readiness
        && matches!(
            crate::pxe_discovery::status()
                .get("status")
                .and_then(Value::as_str),
            Some("active" | "standby" | "external")
        )
}

/// Last accepted Tiaris report, and whether it came from this boot.
pub fn parse_manage_contact(body: &[u8], boot_id: &str) -> Option<(DateTime<Utc>, bool)> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if value.get("schema")?.as_str()? != "tiaris.nest.manage-contact.v1" {
        return None;
    }
    let reported_at = value
        .get("reported_at")?
        .as_str()?
        .parse::<DateTime<Utc>>()
        .ok()?;
    let same_boot = value.get("boot_id").and_then(Value::as_str) == Some(boot_id.trim());
    Some((reported_at, same_boot))
}

fn observe_manage_contact() -> (Option<DateTime<Utc>>, bool) {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    crate::provisioning::read_bounded_nofollow(
        Path::new(MANAGE_CONTACT_PATH),
        4096,
        "Tiaris contact receipt",
    )
    .ok()
    .and_then(|body| parse_manage_contact(&body, &boot_id))
    .map_or((None, false), |(at, same_boot)| (Some(at), same_boot))
}

/// Name, organization and interface from the sealed install plan. Like the
/// retired console, trust only the root:tiaris-nest 0640 copy that first
/// boot authenticated, and only names matching the public character set.
pub fn plan_identity(plan: &Value) -> (Option<String>, Option<String>, Option<String>) {
    let text = |value: Option<&Value>, valid: fn(&str) -> bool| {
        value
            .and_then(Value::as_str)
            .filter(|text| valid(text))
            .map(str::to_string)
    };
    (
        text(plan.get("display_name"), safe_display_name),
        text(plan.get("organization_slug"), safe_slug),
        text(
            plan.get("network_interface")
                .and_then(|interface| interface.get("name")),
            safe_interface_name,
        ),
    )
}

fn safe_display_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b" ._()-".contains(byte))
}

fn safe_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn safe_interface_name(value: &str) -> bool {
    (1..=15).contains(&value.len())
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn read_sealed_plan() -> Option<Value> {
    let path = Path::new(INSTALL_PLAN_PATH);
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != SERVICE_GID
        || metadata.permissions().mode() & 0o7777 != 0o640
    {
        return None;
    }
    let body = crate::provisioning::read_bounded_nofollow(path, 1024 * 1024, "sealed install plan")
        .ok()?;
    serde_json::from_slice(&body).ok()
}

/// "NixOS 26.05" from the immutable system identity.
pub fn system_label(identity: &Value) -> Option<String> {
    let name = match identity.get("base_os")?.as_str()? {
        "nixos" => "NixOS",
        _ => return None,
    };
    let version = identity.get("base_os_version")?.as_str()?;
    let valid = (1..=16).contains(&version.len())
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    Some(if valid {
        format!("{name} {version}")
    } else {
        name.to_string()
    })
}

/// Boot time from the `btime` line of /proc/stat.
pub fn parse_boot_time(proc_stat: &str) -> Option<DateTime<Utc>> {
    let seconds = proc_stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse::<i64>()
        .ok()?;
    Utc.timestamp_opt(seconds, 0).single()
}

fn observe_identity(state: &AppState) -> Identity {
    let (name, organization, interface) = read_sealed_plan()
        .as_ref()
        .map(plan_identity)
        .unwrap_or_default();
    let system = crate::provisioning::read_bounded_nofollow(
        Path::new(SYSTEM_IDENTITY_PATH),
        64 * 1024,
        "system identity",
    )
    .ok()
    .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
    .as_ref()
    .and_then(system_label);
    Identity {
        name,
        organization,
        tiaris_host: url_host(&state.config.manage.api_url),
        address: runtime_ipv4(&state.runtime_settings().public_base_url),
        interface,
        system,
        booted_at: fs::read_to_string("/proc/stat")
            .ok()
            .as_deref()
            .and_then(parse_boot_time),
    }
}

fn url_host(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    url.host_str().map(|host| bounded(host, 80))
}

/// The network runtime keeps the advertised boot URL on the live wired IPv4.
fn runtime_ipv4(public_base_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(public_base_url).ok()?;
    let address: std::net::Ipv4Addr = url.host_str()?.parse().ok()?;
    Some(address.to_string())
}

/// Computers currently being served an installation: distinct workstations
/// holding an unexpired Nest boot grant. Nest issues one grant per PXE boot
/// of the workstation installer runtime and it expires after ten minutes.
pub async fn count_active_installs(db: &sqlx::SqlitePool, now: DateTime<Utc>) -> Result<u32> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT normalized_mac) FROM nest_boot_sessions WHERE expires_at > ?",
    )
    .bind(now.timestamp())
    .fetch_one(db)
    .await
    .context("count active workstation boot grants")?;
    u32::try_from(count).context("active install count is out of range")
}

fn change_signal() -> &'static Notify {
    static CHANGED: OnceLock<Notify> = OnceLock::new();
    CHANGED.get_or_init(Notify::new)
}

/// Ask the console writer to refresh now (for example after Tiaris contact).
pub fn notify_changed() {
    change_signal().notify_one();
}

pub(crate) fn write_status(path: &Path, status: &ConsoleStatus) -> Result<()> {
    let body = serde_json::to_vec(status).context("serialize Nest console status")?;
    crate::public_status::write_public_json(path, &body, MAX_STATUS_BYTES)
}

/// Keep the console projection current. Only the managed NixOS appliance
/// has a console kiosk; elsewhere this does nothing.
pub fn spawn(state: AppState) {
    if !crate::appliance::is_managed_appliance() {
        return;
    }
    tokio::spawn(async move {
        let observing_since = Utc::now();
        let mut tracker = ReadinessTracker::default();
        let path = Path::new(CONSOLE_STATUS_PATH);
        loop {
            let now = Utc::now();
            let (units, health_ready) = tokio::join!(observe_units(), observe_health(&state));
            let (last_contact, contacted_this_boot) = observe_manage_contact();
            let active_installs = match count_active_installs(&state.db, now).await {
                Ok(count) => Some(count),
                Err(error) => {
                    debug!(error = %error, "active install count is unavailable");
                    None
                }
            };
            let observation = Observation {
                now,
                observing_since,
                units,
                health_ready,
                last_contact,
                contacted_this_boot,
                identity: observe_identity(&state),
                pxe: crate::pxe_discovery::status()
                    .get("status")
                    .and_then(Value::as_str)
                    .and_then(Pxe::parse),
                active_installs,
            };
            let status = tracker.evaluate(&observation);
            if let Err(error) = write_status(path, &status) {
                warn!(error = %error, "could not publish Nest console status");
            }
            let _ = tokio::time::timeout(REFRESH_INTERVAL, change_signal().notified()).await;
        }
    });
}

#[cfg(test)]
mod tests;
