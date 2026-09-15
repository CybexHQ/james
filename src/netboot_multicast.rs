use std::{
    collections::{BTreeMap, HashMap},
    ffi::CStr,
    fs::{self, OpenOptions},
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::{Mutex, Notify, watch},
    time::sleep,
};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{AppState, config::AppConfig, netboot::WorkstationNetbootDescriptor};

pub const CAPABILITY: &str = "workstation_rootfs_multicast_v1";
pub const JOIN_SCHEMA: &str = "cybex.james.squashfs-multicast-join.v1";
pub const OFFER_SCHEMA: &str = "cybex.james.squashfs-multicast-offer.v1";
pub const RESULT_SCHEMA: &str = "cybex.james.squashfs-multicast-result.v1";
pub const POLICY_SCHEMA: &str = "cybex.manage.workstation-multicast-policy.v1";
pub const REPORT_SCHEMA: &str = "cybex.manage.workstation-multicast-report.v1";
pub const TRANSPORT: &str = "udpcast-v1";
pub const MINIMUM_ROOTFS_MULTICAST_RUNTIME_VERSION: &str = "1.0.56";

const MAX_REQUEST_BYTES: usize = 1024;
const MAX_PENDING_SESSIONS: usize = 64;
const MAX_REPORT_EVENTS: usize = 256;
const MAX_REPORT_EVENT_BYTES: usize = 1024 * 1024;
const MAX_LATE_RECEIPTS: i64 = 1_000_000_000;
const RECEIPT_COLLECTION_SECONDS: i64 = 30;
const FAILURE_COOLDOWN_SECONDS: u64 = 15;
const FINALIZED_TRANSFER_RETENTION_DAYS: i64 = 7;
const CHILD_OUTPUT_CAPTURE_BYTES: usize = 16 * 1024;
const NETWORK_PLAN_PATH: &str = "/var/lib/cybex-james/control/netplan-approved.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkstationMulticastMode {
    Automatic,
    HttpOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationMulticastReportContract {
    pub schema: String,
    pub maximum_events_per_page: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationMulticastPolicy {
    pub schema: String,
    pub generation: i64,
    pub mode: WorkstationMulticastMode,
    pub multicast_domain_id: Uuid,
    pub qualification_revision: i64,
    pub rendezvous_address: Ipv4Addr,
    pub data_address: Ipv4Addr,
    pub port_base: u16,
    pub minimum_receivers: u16,
    pub join_window_seconds: u16,
    pub max_bitrate_bps: u64,
    pub absolute_timeout_seconds: u16,
    pub report_contract: WorkstationMulticastReportContract,
}

impl WorkstationMulticastPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.schema != POLICY_SCHEMA
            || self.generation < 0
            || self.qualification_revision <= 0
            || self.report_contract.schema != REPORT_SCHEMA
            || !(1..=64).contains(&self.report_contract.maximum_events_per_page)
            || !(2..=30).contains(&self.minimum_receivers)
            || !(1..=15).contains(&self.join_window_seconds)
            || !(1_000_000..=1_000_000_000).contains(&self.max_bitrate_bps)
            || !(15..=120).contains(&self.absolute_timeout_seconds)
            || !(9000..=9998).contains(&self.port_base)
            || self.port_base % 2 != 0
            || !organization_local_multicast(self.rendezvous_address)
            || !organization_local_multicast(self.data_address)
            || u32::from(self.rendezvous_address)
                .checked_add(1)
                .map(Ipv4Addr::from)
                != Some(self.data_address)
        {
            bail!("workstation multicast policy is invalid");
        }
        Ok(())
    }

    fn sha256(&self) -> Result<String> {
        Ok(sha256_hex(serde_json::to_vec(self)?))
    }

    fn start_timeout_seconds(&self) -> u16 {
        self.join_window_seconds.saturating_add(5).min(15)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinRequest {
    schema: String,
    join_token: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultRequest {
    schema: String,
    join_token: String,
    multicast_outcome: MulticastOutcome,
    fallback_outcome: FallbackOutcome,
}

impl ResultRequest {
    fn has_consistent_outcomes(&self) -> bool {
        matches!(
            (self.multicast_outcome, self.fallback_outcome),
            (MulticastOutcome::Verified, FallbackOutcome::NotNeeded)
                | (
                    MulticastOutcome::NotAttempted
                        | MulticastOutcome::OfferUnavailable
                        | MulticastOutcome::OfferInvalid
                        | MulticastOutcome::InterfaceUnavailable
                        | MulticastOutcome::JoinTimeout
                        | MulticastOutcome::SenderUnavailable
                        | MulticastOutcome::ReceiveTimeout
                        | MulticastOutcome::ReceiverFailed
                        | MulticastOutcome::SizeMismatch
                        | MulticastOutcome::DigestMismatch,
                    FallbackOutcome::HttpVerified | FallbackOutcome::HttpFailed
                )
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MulticastOutcome {
    NotAttempted,
    Verified,
    OfferUnavailable,
    OfferInvalid,
    InterfaceUnavailable,
    JoinTimeout,
    SenderUnavailable,
    ReceiveTimeout,
    ReceiverFailed,
    SizeMismatch,
    DigestMismatch,
}

impl MulticastOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Verified => "verified",
            Self::OfferUnavailable => "offer_unavailable",
            Self::OfferInvalid => "offer_invalid",
            Self::InterfaceUnavailable => "interface_unavailable",
            Self::JoinTimeout => "join_timeout",
            Self::SenderUnavailable => "sender_unavailable",
            Self::ReceiveTimeout => "receive_timeout",
            Self::ReceiverFailed => "receiver_failed",
            Self::SizeMismatch => "size_mismatch",
            Self::DigestMismatch => "digest_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FallbackOutcome {
    NotNeeded,
    HttpVerified,
    HttpFailed,
}

impl FallbackOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotNeeded => "not_needed",
            Self::HttpVerified => "http_verified",
            Self::HttpFailed => "http_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MulticastOffer {
    schema: &'static str,
    transport: &'static str,
    component_sha256: String,
    size_bytes: u64,
    rendezvous_address: Ipv4Addr,
    port_base: u16,
    start_timeout_seconds: u16,
    receive_timeout_seconds: u16,
    absolute_timeout_seconds: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TransferKey {
    component_sha256: String,
    size_bytes: u64,
    interface_fingerprint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchPhase {
    Gathering,
    SenderStarting,
    Sending,
}

#[derive(Clone, Debug)]
struct Registration {
    discovery_deadline: Instant,
}

#[derive(Clone, Debug)]
struct Batch {
    transfer_id: String,
    bundle_sha256: String,
    key: TransferKey,
    interface_name: String,
    artifact_path: PathBuf,
    offer: MulticastOffer,
    policy: WorkstationMulticastPolicy,
    phase: BatchPhase,
    gathering_deadline: Instant,
    registrations: HashMap<String, Registration>,
    cancel: watch::Sender<bool>,
}

fn batch_accepts_registration(
    batch: &Batch,
    key: &TransferKey,
    policy_generation: i64,
    session_id: &str,
) -> bool {
    batch.phase == BatchPhase::Gathering
        && batch.key == *key
        && batch.policy.generation == policy_generation
        && batch.registrations.len() < MAX_PENDING_SESSIONS
        && !batch.registrations.contains_key(session_id)
}

fn request_batch_cancellation(batch: &Batch) {
    // `send_replace` retains the value when sender startup has not subscribed
    // yet; `send(true)` would lose this fail-closed cancellation in that race.
    batch.cancel.send_replace(true);
}

#[derive(Default)]
struct CoordinatorState {
    policy: Option<WorkstationMulticastPolicy>,
    policy_hash: String,
    lane_authorized: bool,
    batch: Option<Batch>,
    cooldown_until: Option<Instant>,
}

struct SharedCoordinator {
    state: Mutex<CoordinatorState>,
    changed: Notify,
    shutting_down: AtomicBool,
}

#[derive(Clone)]
pub struct NetbootMulticast {
    shared: Arc<SharedCoordinator>,
}

impl Default for NetbootMulticast {
    fn default() -> Self {
        Self::new()
    }
}

impl NetbootMulticast {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(SharedCoordinator {
                state: Mutex::new(CoordinatorState::default()),
                changed: Notify::new(),
                shutting_down: AtomicBool::new(false),
            }),
        }
    }

    async fn policy(&self) -> Option<(WorkstationMulticastPolicy, String, bool)> {
        let state = self.shared.state.lock().await;
        state
            .policy
            .clone()
            .map(|policy| (policy, state.policy_hash.clone(), state.lane_authorized))
    }

    async fn remove_live_registration(&self, transfer_id: &str, session_id: &str) {
        let mut state = self.shared.state.lock().await;
        let Some(batch) = state.batch.as_mut() else {
            return;
        };
        if batch.transfer_id == transfer_id && batch.phase == BatchPhase::Gathering {
            batch.registrations.remove(session_id);
        }
    }

    async fn cancel_active(&self) -> Option<String> {
        let mut state = self.shared.state.lock().await;
        let gathering = state
            .batch
            .as_ref()
            .is_some_and(|batch| batch.phase == BatchPhase::Gathering);
        let removed = if gathering {
            state.batch.take().map(|batch| batch.transfer_id)
        } else {
            if let Some(batch) = state.batch.as_ref() {
                request_batch_cancellation(batch);
            }
            None
        };
        self.shared.changed.notify_waiters();
        removed
    }

    pub async fn shutdown(&self, pool: &sqlx::SqlitePool) {
        self.shared.shutting_down.store(true, Ordering::SeqCst);
        if let Some(transfer_id) = self.cancel_active().await {
            let timestamp = now_text();
            let _ = sqlx::query(
                "UPDATE workstation_multicast_transfers
                 SET state = 'interrupted', sender_outcome = 'service_shutdown',
                     sender_finished_at = ?, receipt_deadline = ?, updated_at = ?
                 WHERE transfer_id = ? AND finalized_at IS NULL",
            )
            .bind(&timestamp)
            .bind(Utc::now().timestamp() + RECEIPT_COLLECTION_SECONDS)
            .bind(&timestamp)
            .bind(transfer_id)
            .execute(pool)
            .await;
        }
        for _ in 0..50 {
            if self.shared.state.lock().await.batch.is_none() {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}

struct LiveRegistrationGuard {
    coordinator: NetbootMulticast,
    transfer_id: String,
    session_id: String,
    armed: bool,
}

impl Drop for LiveRegistrationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let coordinator = self.coordinator.clone();
        let transfer_id = self.transfer_id.clone();
        let session_id = self.session_id.clone();
        tokio::spawn(async move {
            coordinator
                .remove_live_registration(&transfer_id, &session_id)
                .await;
        });
    }
}

#[derive(Debug, FromRow)]
struct EligibleSessionRow {
    session_id: String,
    expires_at: i64,
    cleanup_after: i64,
    runtime_version: String,
    descriptor_json: String,
    root_path: String,
}

#[derive(Clone, Debug)]
struct EligibleSession {
    session_id: String,
    bundle_sha256: String,
    component_sha256: String,
    size_bytes: u64,
    root_path: PathBuf,
}

#[derive(Clone, Debug)]
struct NetworkSelection {
    source_matches_public_base: bool,
    interface_name: String,
    interface_fingerprint: String,
    network_plan_fingerprint: String,
}

pub async fn initialize(state: &AppState) -> Result<()> {
    ensure_report_instance(&state.db).await?;
    let now = now_text();
    let receipt_deadline = Utc::now().timestamp() + RECEIPT_COLLECTION_SECONDS;
    sqlx::query(
        "UPDATE workstation_multicast_transfers
         SET state = 'interrupted', sender_outcome = 'service_restart',
             sender_finished_at = COALESCE(sender_finished_at, ?),
             receipt_deadline = COALESCE(receipt_deadline, ?), updated_at = ?
         WHERE state IN ('gathering', 'sender_starting', 'sending')",
    )
    .bind(&now)
    .bind(receipt_deadline)
    .bind(&now)
    .execute(&state.db)
    .await?;

    // A process exit drops Tokio timers. Re-arm every unfinalized terminal
    // transfer so restart/shutdown cannot strand an event forever.
    let pending: Vec<(String, Option<i64>)> = sqlx::query_as(
        "SELECT transfer_id, receipt_deadline
         FROM workstation_multicast_transfers
         WHERE finalized_at IS NULL
           AND state IN ('completed', 'failed', 'interrupted')",
    )
    .fetch_all(&state.db)
    .await?;
    let now_epoch = Utc::now().timestamp();
    for (transfer_id, deadline) in pending {
        let delay = deadline
            .unwrap_or(now_epoch)
            .saturating_sub(now_epoch)
            .max(0) as u64;
        schedule_finalization_after(state.clone(), transfer_id, delay);
    }

    let row: (i64, String, Option<String>, i64) = sqlx::query_as(
        "SELECT generation, policy_sha256, policy_json, lane_authorized
         FROM workstation_multicast_policy WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    if row.3 != 0 {
        if let Some(raw) = row.2 {
            if let Ok(policy) = serde_json::from_str::<WorkstationMulticastPolicy>(&raw) {
                if policy.validate().is_ok()
                    && policy.generation == row.0
                    && policy.sha256()? == row.1
                {
                    let mut coordinator = state.netboot_multicast.shared.state.lock().await;
                    coordinator.policy = Some(policy);
                    coordinator.policy_hash = row.1;
                    coordinator.lane_authorized = true;
                }
            }
        }
    }
    Ok(())
}

pub async fn apply_desired_policy(state: &AppState, desired: Option<Value>) -> Result<()> {
    let Some(value) = desired else {
        sqlx::query(
            "UPDATE workstation_multicast_policy
             SET lane_authorized = 0, updated_at = ? WHERE singleton_id = 1",
        )
        .bind(now_text())
        .execute(&state.db)
        .await?;
        {
            let mut coordinator = state.netboot_multicast.shared.state.lock().await;
            coordinator.lane_authorized = false;
            if let Some(policy) = coordinator.policy.as_mut() {
                policy.mode = WorkstationMulticastMode::HttpOnly;
            }
        }
        if let Some(transfer_id) = state.netboot_multicast.cancel_active().await {
            finish_transfer_row(state, &transfer_id, "interrupted", "policy_disabled").await?;
            schedule_finalization(state.clone(), transfer_id);
        }
        return Ok(());
    };

    let policy: WorkstationMulticastPolicy =
        serde_json::from_value(value).context("decode workstation multicast policy")?;
    policy.validate()?;
    let policy_hash = policy.sha256()?;
    let current: (i64, String) = sqlx::query_as(
        "SELECT generation, policy_sha256 FROM workstation_multicast_policy WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    if policy.generation < current.0 {
        return Ok(());
    }
    if policy.generation == current.0 && !current.1.is_empty() && current.1 != policy_hash {
        bail!("workstation multicast policy changed at an existing generation");
    }
    let replacing_policy = !current.1.is_empty() && current.1 != policy_hash;
    let policy_json = serde_json::to_string(&policy)?;
    sqlx::query(
        "UPDATE workstation_multicast_policy
         SET generation = ?, policy_sha256 = ?, policy_json = ?, lane_authorized = 1,
             updated_at = ? WHERE singleton_id = 1",
    )
    .bind(policy.generation)
    .bind(&policy_hash)
    .bind(policy_json)
    .bind(now_text())
    .execute(&state.db)
    .await?;
    let disabling = policy.mode == WorkstationMulticastMode::HttpOnly;
    {
        let mut coordinator = state.netboot_multicast.shared.state.lock().await;
        coordinator.policy = Some(policy);
        coordinator.policy_hash = policy_hash;
        coordinator.lane_authorized = true;
    }
    if disabling || replacing_policy {
        if let Some(transfer_id) = state.netboot_multicast.cancel_active().await {
            let outcome = if disabling {
                "policy_disabled"
            } else {
                "policy_changed"
            };
            finish_transfer_row(state, &transfer_id, "interrupted", outcome).await?;
            schedule_finalization(state.clone(), transfer_id);
        }
    }
    state.netboot_multicast.shared.changed.notify_waiters();
    Ok(())
}

pub fn binary_available(config: &AppConfig) -> bool {
    let path = Path::new(&config.workstation_netboot.udp_sender_path);
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.permissions().mode() & 0o111 != 0
}

pub fn join_token_from_nonce(nonce: &str) -> String {
    sha256_hex(format!("{JOIN_SCHEMA}\n{nonce}"))
}

pub fn stored_join_token_hash(nonce: &str) -> String {
    sha256_hex(join_token_from_nonce(nonce))
}

pub async fn discover(
    State(state): State<AppState>,
    AxumPath(bundle_sha256): AxumPath<String>,
    body: Bytes,
) -> Response {
    let result = discover_inner(&state, &bundle_sha256, &body).await;
    match result {
        Ok(Some(offer)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            Json(offer),
        )
            .into_response(),
        Ok(None) => no_offer_response(),
        Err(error) => {
            debug!(reason = %safe_reason(&error), "multicast discovery fell back to HTTP");
            no_offer_response()
        }
    }
}

async fn discover_inner(
    state: &AppState,
    bundle_sha256: &str,
    body: &[u8],
) -> Result<Option<MulticastOffer>> {
    validate_sha256(bundle_sha256)?;
    if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
        return Ok(None);
    }
    let request: JoinRequest = serde_json::from_slice(body)?;
    if request.schema != JOIN_SCHEMA || !is_sha256(&request.join_token) {
        return Ok(None);
    }
    if state
        .netboot_multicast
        .shared
        .shutting_down
        .load(Ordering::SeqCst)
        || state
            .config
            .workstation_netboot
            .multicast_emergency_disabled
        || !binary_available(&state.config)
    {
        return Ok(None);
    }
    let Some((policy, _, lane_authorized)) = state.netboot_multicast.policy().await else {
        return Ok(None);
    };
    if !lane_authorized || policy.mode != WorkstationMulticastMode::Automatic {
        return Ok(None);
    }
    let network = match select_network(&state.config) {
        Ok(network) => network,
        Err(_) => return Ok(None),
    };
    let token_hash = sha256_hex(&request.join_token);
    let now = Utc::now().timestamp();
    let row = sqlx::query_as::<_, EligibleSessionRow>(
        "SELECT session.session_id, session.expires_at, session.cleanup_after,
                bundle.runtime_version, bundle.descriptor_json, bundle.root_path
         FROM james_boot_sessions session
         JOIN workstation_netboot_bundles bundle
           ON bundle.bundle_sha256 = session.bundle_sha256
         WHERE session.multicast_join_token_sha256 = ?
           AND session.bundle_sha256 = ?
           AND session.expires_at >= ?
           AND session.multicast_finalized_at IS NULL
           AND bundle.retention_state = 'verified'",
    )
    .bind(token_hash)
    .bind(bundle_sha256)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let reserve =
        i64::from(policy.join_window_seconds) + i64::from(policy.absolute_timeout_seconds) + 120;
    if row.expires_at.saturating_sub(now) < reserve || row.cleanup_after < row.expires_at {
        return Ok(None);
    }
    let runtime = Version::parse(&row.runtime_version)?;
    if runtime < Version::parse(MINIMUM_ROOTFS_MULTICAST_RUNTIME_VERSION)? {
        return Ok(None);
    }
    let descriptor: WorkstationNetbootDescriptor = serde_json::from_str(&row.descriptor_json)?;
    let component = descriptor.components.nix_store_squashfs;
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(bundle_sha256);
    if Path::new(&row.root_path) != expected_root {
        return Ok(None);
    }
    let eligible = EligibleSession {
        session_id: row.session_id,
        bundle_sha256: bundle_sha256.to_string(),
        component_sha256: component.sha256,
        size_bytes: component.size_bytes,
        root_path: expected_root,
    };
    join_cohort(state, policy, network, eligible).await
}

async fn join_cohort(
    state: &AppState,
    policy: WorkstationMulticastPolicy,
    network: NetworkSelection,
    session: EligibleSession,
) -> Result<Option<MulticastOffer>> {
    let now = Instant::now();
    let mut deadline = now + Duration::from_secs(u64::from(policy.join_window_seconds));
    let gathering_deadline = deadline - Duration::from_millis(500);
    let key = TransferKey {
        component_sha256: session.component_sha256.clone(),
        size_bytes: session.size_bytes,
        interface_fingerprint: network.interface_fingerprint.clone(),
    };
    let transfer_id;
    let offer;
    let created;
    {
        let mut coordinator = state.netboot_multicast.shared.state.lock().await;
        if coordinator
            .cooldown_until
            .is_some_and(|cooldown| cooldown > now)
        {
            return Ok(None);
        }
        if coordinator.cooldown_until.is_some() {
            coordinator.cooldown_until = None;
        }
        if let Some(batch) = coordinator.batch.as_mut() {
            if !batch_accepts_registration(batch, &key, policy.generation, &session.session_id) {
                return Ok(None);
            }
            batch
                .registrations
                .retain(|_, registration| registration.discovery_deadline > now);
            if batch.registrations.len() >= MAX_PENDING_SESSIONS {
                return Ok(None);
            }
            deadline = batch.gathering_deadline + Duration::from_millis(500);
            batch.registrations.insert(
                session.session_id.clone(),
                Registration {
                    discovery_deadline: deadline,
                },
            );
            transfer_id = batch.transfer_id.clone();
            offer = batch.offer.clone();
            created = false;
        } else {
            let id = Uuid::new_v4().to_string();
            let (cancel, _) = watch::channel(false);
            offer = MulticastOffer {
                schema: OFFER_SCHEMA,
                transport: TRANSPORT,
                component_sha256: session.component_sha256.clone(),
                size_bytes: session.size_bytes,
                rendezvous_address: policy.rendezvous_address,
                port_base: policy.port_base,
                start_timeout_seconds: policy.start_timeout_seconds(),
                receive_timeout_seconds: 30.min(policy.absolute_timeout_seconds),
                absolute_timeout_seconds: policy.absolute_timeout_seconds,
            };
            let mut registrations = HashMap::new();
            registrations.insert(
                session.session_id.clone(),
                Registration {
                    discovery_deadline: deadline,
                },
            );
            coordinator.batch = Some(Batch {
                transfer_id: id.clone(),
                bundle_sha256: session.bundle_sha256.clone(),
                key,
                interface_name: network.interface_name,
                artifact_path: session.root_path.join("nix-store.squashfs"),
                offer: offer.clone(),
                policy: policy.clone(),
                phase: BatchPhase::Gathering,
                gathering_deadline,
                registrations,
                cancel,
            });
            transfer_id = id;
            created = true;
        }
    }

    let persistence = async {
        let mut transaction = state.db.begin().await?;
        if created {
            sqlx::query(
                "INSERT INTO workstation_multicast_transfers
             (transfer_id, bundle_sha256, component_sha256, size_bytes,
              interface_fingerprint, policy_generation, state, registered_sessions)
             VALUES (?, ?, ?, ?, ?, ?, 'gathering', 1)",
            )
            .bind(&transfer_id)
            .bind(&session.bundle_sha256)
            .bind(&session.component_sha256)
            .bind(i64::try_from(session.size_bytes)?)
            .bind(&network.interface_fingerprint)
            .bind(policy.generation)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO workstation_multicast_registrations(transfer_id, session_id)
             VALUES (?, ?)",
        )
        .bind(&transfer_id)
        .bind(&session.session_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE workstation_multicast_transfers
             SET registered_sessions = (
               SELECT COUNT(*) FROM workstation_multicast_registrations WHERE transfer_id = ?
             ), updated_at = ? WHERE transfer_id = ?",
        )
        .bind(&transfer_id)
        .bind(now_text())
        .bind(&transfer_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = persistence {
        let mut coordinator = state.netboot_multicast.shared.state.lock().await;
        if coordinator
            .batch
            .as_ref()
            .is_some_and(|batch| batch.transfer_id == transfer_id)
        {
            if created {
                coordinator.batch = None;
            } else if let Some(batch) = coordinator.batch.as_mut() {
                batch.registrations.remove(&session.session_id);
            }
        }
        drop(coordinator);
        state.netboot_multicast.shared.changed.notify_waiters();
        return Err(error);
    }

    if created {
        let state_for_deadline = state.clone();
        let transfer_for_deadline = transfer_id.clone();
        tokio::spawn(async move {
            sleep(gathering_deadline.saturating_duration_since(Instant::now())).await;
            if let Err(error) = expire_gathering(&state_for_deadline, &transfer_for_deadline).await
            {
                warn!(reason = %safe_reason(&error), "multicast gathering expiry failed");
            }
        });
    }
    let mut guard = LiveRegistrationGuard {
        coordinator: state.netboot_multicast.clone(),
        transfer_id: transfer_id.clone(),
        session_id: session.session_id,
        armed: true,
    };
    loop {
        let notified = state.netboot_multicast.shared.changed.notified();
        {
            let coordinator = state.netboot_multicast.shared.state.lock().await;
            match coordinator.batch.as_ref() {
                Some(batch)
                    if batch.transfer_id == transfer_id
                        && matches!(
                            batch.phase,
                            BatchPhase::SenderStarting | BatchPhase::Sending
                        ) =>
                {
                    guard.armed = false;
                    return Ok(Some(offer));
                }
                Some(batch) if batch.transfer_id == transfer_id => {}
                _ => return Ok(None),
            }
        }
        tokio::select! {
            _ = notified => {},
            _ = sleep(deadline.saturating_duration_since(Instant::now())) => {
                return Ok(None);
            }
        }
    }
}

async fn expire_gathering(state: &AppState, transfer_id: &str) -> Result<()> {
    enum Decision {
        Start,
        Fail,
        Ignore,
    }
    let decision = {
        let mut coordinator = state.netboot_multicast.shared.state.lock().await;
        match coordinator.batch.as_mut() {
            Some(batch)
                if batch.transfer_id == transfer_id && batch.phase == BatchPhase::Gathering =>
            {
                if batch.registrations.len() >= usize::from(batch.policy.minimum_receivers) {
                    batch.phase = BatchPhase::SenderStarting;
                    Decision::Start
                } else {
                    coordinator.batch = None;
                    Decision::Fail
                }
            }
            _ => Decision::Ignore,
        }
    };
    match decision {
        Decision::Start => {
            let persisted = sqlx::query(
                "UPDATE workstation_multicast_transfers
                 SET state = 'sender_starting', updated_at = ?
                 WHERE transfer_id = ? AND state = 'gathering'",
            )
            .bind(now_text())
            .bind(transfer_id)
            .execute(&state.db)
            .await;
            match persisted {
                Ok(result) if result.rows_affected() == 1 => {
                    state.netboot_multicast.shared.changed.notify_waiters();
                    spawn_sender(state.clone(), transfer_id.to_string());
                    Ok(())
                }
                Ok(_) => {
                    let mut coordinator = state.netboot_multicast.shared.state.lock().await;
                    if coordinator
                        .batch
                        .as_ref()
                        .is_some_and(|batch| batch.transfer_id == transfer_id)
                    {
                        coordinator.batch = None;
                    }
                    drop(coordinator);
                    state.netboot_multicast.shared.changed.notify_waiters();
                    Ok(())
                }
                Err(error) => {
                    let mut coordinator = state.netboot_multicast.shared.state.lock().await;
                    if coordinator
                        .batch
                        .as_ref()
                        .is_some_and(|batch| batch.transfer_id == transfer_id)
                    {
                        coordinator.batch = None;
                    }
                    drop(coordinator);
                    state.netboot_multicast.shared.changed.notify_waiters();
                    if finish_transfer_row(state, transfer_id, "failed", "storage_unavailable")
                        .await
                        .is_ok()
                    {
                        schedule_finalization(state.clone(), transfer_id.to_string());
                    }
                    Err(error.into())
                }
            }
        }
        Decision::Fail => {
            state.netboot_multicast.shared.changed.notify_waiters();
            finish_transfer_row(state, transfer_id, "failed", "http_quorum_unavailable").await?;
            schedule_finalization(state.clone(), transfer_id.to_string());
            Ok(())
        }
        Decision::Ignore => Ok(()),
    }
}

fn spawn_sender(state: AppState, transfer_id: String) {
    tokio::spawn(async move {
        let outcome = run_sender(&state, &transfer_id).await;
        let (row_state, sender_outcome, cooldown) = match outcome {
            Ok(true) => ("completed", "completed", false),
            Ok(false) => ("interrupted", "cancelled", true),
            Err(error) => {
                warn!(reason = %safe_reason(&error), "multicast sender failed");
                ("failed", "sender_failed", true)
            }
        };
        if let Err(error) =
            finish_transfer_row(&state, &transfer_id, row_state, sender_outcome).await
        {
            warn!(reason = %safe_reason(&error), "multicast transfer final state could not be persisted");
        }
        {
            let mut coordinator = state.netboot_multicast.shared.state.lock().await;
            if coordinator
                .batch
                .as_ref()
                .is_some_and(|batch| batch.transfer_id == transfer_id)
            {
                coordinator.batch = None;
            }
            if cooldown {
                coordinator.cooldown_until =
                    Some(Instant::now() + Duration::from_secs(FAILURE_COOLDOWN_SECONDS));
            }
        }
        state.netboot_multicast.shared.changed.notify_waiters();
        schedule_finalization(state, transfer_id);
    });
}

async fn run_sender(state: &AppState, transfer_id: &str) -> Result<bool> {
    let (batch, mut cancellation) = {
        let mut coordinator = state.netboot_multicast.shared.state.lock().await;
        let batch = coordinator
            .batch
            .as_mut()
            .filter(|batch| batch.transfer_id == transfer_id)
            .ok_or_else(|| anyhow!("multicast batch disappeared before sender start"))?;
        let cancellation = batch.cancel.subscribe();
        (batch.clone(), cancellation)
    };
    let file = open_pinned_artifact(&batch.artifact_path, batch.key.size_bytes)?;
    let mut command = Command::new(&state.config.workstation_netboot.udp_sender_path);
    command
        .env_clear()
        .arg("--interface")
        .arg(&batch.interface_name)
        .arg("--mcast-rdv-address")
        .arg(batch.policy.rendezvous_address.to_string())
        .arg("--mcast-data-address")
        .arg(batch.policy.data_address.to_string())
        .arg("--portbase")
        .arg(batch.policy.port_base.to_string())
        .arg("--ttl")
        .arg("1")
        .arg("--max-bitrate")
        .arg(batch.policy.max_bitrate_bps.to_string())
        .arg("--min-receivers")
        .arg(batch.policy.minimum_receivers.to_string())
        .arg("--min-wait")
        .arg(batch.policy.join_window_seconds.to_string())
        .arg("--start-timeout")
        .arg(batch.policy.start_timeout_seconds().to_string())
        .arg("--retries-until-drop")
        .arg("5")
        .arg("--blocksize")
        .arg("1456")
        .arg("--full-duplex")
        .arg("--nopointopoint")
        .arg("--nokbd")
        .arg("--no-progress")
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().context("spawn pinned udp-sender")?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_task = tokio::spawn(drain_bounded(stdout));
    let stderr_task = tokio::spawn(drain_bounded(stderr));
    {
        let mut coordinator = state.netboot_multicast.shared.state.lock().await;
        if let Some(batch) = coordinator
            .batch
            .as_mut()
            .filter(|batch| batch.transfer_id == transfer_id)
        {
            batch.phase = BatchPhase::Sending;
        }
    }
    let timestamp = now_text();
    let persisted_start = sqlx::query(
        "UPDATE workstation_multicast_transfers
         SET state = 'sending', started_at = ?, updated_at = ? WHERE transfer_id = ?",
    )
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(transfer_id)
    .execute(&state.db)
    .await;
    match persisted_start {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            terminate_child(&mut child).await;
            let _ = tokio::join!(stdout_task, stderr_task);
            bail!("multicast transfer was cancelled before sender persistence");
        }
        Err(error) => {
            terminate_child(&mut child).await;
            let _ = tokio::join!(stdout_task, stderr_task);
            return Err(error.into());
        }
    }
    state.netboot_multicast.shared.changed.notify_waiters();

    let deadline =
        Instant::now() + Duration::from_secs(u64::from(batch.policy.absolute_timeout_seconds));
    let status: Result<Option<std::process::ExitStatus>> = loop {
        if *cancellation.borrow()
            || state
                .netboot_multicast
                .shared
                .shutting_down
                .load(Ordering::SeqCst)
        {
            terminate_child(&mut child).await;
            break Ok(None);
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                terminate_child(&mut child).await;
                break Err(error.into());
            }
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child).await;
            break Err(anyhow!("udp-sender exceeded its absolute timeout"));
        }
        tokio::select! {
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    terminate_child(&mut child).await;
                    break Ok(None);
                }
            },
            _ = sleep(Duration::from_millis(100)) => {},
        }
    };
    let _ = tokio::join!(stdout_task, stderr_task);
    let status = status?;
    sqlx::query(
        "UPDATE workstation_netboot_bundles SET last_served_at = ?, updated_at = ?
         WHERE bundle_sha256 = ?",
    )
    .bind(now_text())
    .bind(now_text())
    .bind(&batch.bundle_sha256)
    .execute(&state.db)
    .await?;
    match status {
        Some(status) if status.success() => Ok(true),
        Some(_) => bail!("udp-sender exited unsuccessfully"),
        None => Ok(false),
    }
}

async fn terminate_child(child: &mut Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

async fn drain_bounded<T>(stream: Option<T>)
where
    T: tokio::io::AsyncRead + Unpin,
{
    let Some(mut stream) = stream else {
        return;
    };
    let mut buffer = [0_u8; 4096];
    let mut retained = 0_usize;
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                retained = retained
                    .saturating_add(read)
                    .min(CHILD_OUTPUT_CAPTURE_BYTES)
            }
        }
    }
    let _ = retained;
}

fn open_pinned_artifact(path: &Path, expected_size: u64) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("open canonical multicast artifact")?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || !path_metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != expected_size
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
        || metadata.dev()
            != fs::metadata(path.parent().context("artifact parent is missing")?)?.dev()
    {
        bail!("canonical multicast artifact identity is invalid");
    }
    Ok(file)
}

async fn finish_transfer_row(
    state: &AppState,
    transfer_id: &str,
    row_state: &str,
    sender_outcome: &str,
) -> Result<()> {
    let finished = now_text();
    let deadline = Utc::now().timestamp() + RECEIPT_COLLECTION_SECONDS;
    sqlx::query(
        "UPDATE workstation_multicast_transfers
         SET state = ?, sender_outcome = ?, sender_finished_at = ?, receipt_deadline = ?,
             updated_at = ? WHERE transfer_id = ? AND finalized_at IS NULL",
    )
    .bind(row_state)
    .bind(sender_outcome)
    .bind(&finished)
    .bind(deadline)
    .bind(&finished)
    .bind(transfer_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

fn schedule_finalization(state: AppState, transfer_id: String) {
    schedule_finalization_after(state, transfer_id, RECEIPT_COLLECTION_SECONDS as u64);
}

fn schedule_finalization_after(state: AppState, transfer_id: String, delay_seconds: u64) {
    tokio::spawn(async move {
        sleep(Duration::from_secs(delay_seconds)).await;
        if let Err(error) = finalize_transfer_event(&state, &transfer_id).await {
            warn!(reason = %safe_reason(&error), "multicast report event finalization failed");
        }
    });
}

pub async fn record_result(
    State(state): State<AppState>,
    AxumPath(bundle_sha256): AxumPath<String>,
    body: Bytes,
) -> Response {
    if let Err(error) = record_result_inner(&state, &bundle_sha256, &body).await {
        debug!(reason = %safe_reason(&error), "multicast result receipt ignored");
    }
    (
        StatusCode::NO_CONTENT,
        [(header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}

async fn record_result_inner(state: &AppState, bundle_sha256: &str, body: &[u8]) -> Result<()> {
    validate_sha256(bundle_sha256)?;
    if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
        return Ok(());
    }
    let request: ResultRequest = serde_json::from_slice(body)?;
    if request.schema != RESULT_SCHEMA
        || !is_sha256(&request.join_token)
        || !request.has_consistent_outcomes()
    {
        return Ok(());
    }
    let token_hash = sha256_hex(&request.join_token);
    let now = Utc::now().timestamp();
    let session: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT session_id, multicast_finalized_at FROM james_boot_sessions
         WHERE multicast_join_token_sha256 = ?
           AND bundle_sha256 = ? AND cleanup_after >= ?",
    )
    .bind(token_hash)
    .bind(bundle_sha256)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    let Some((session_id, finalized_at)) = session else {
        return Ok(());
    };
    if finalized_at.is_some() {
        sqlx::query(
            "UPDATE workstation_multicast_report_state
             SET late_receipts = MIN(late_receipts + 1, ?), updated_at = ?
             WHERE singleton_id = 1",
        )
        .bind(MAX_LATE_RECEIPTS)
        .bind(now_text())
        .execute(&state.db)
        .await?;
        return Ok(());
    }
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT transfer.transfer_id, registration.multicast_outcome,
                registration.fallback_outcome
         FROM workstation_multicast_registrations registration
         JOIN workstation_multicast_transfers transfer
           ON transfer.transfer_id = registration.transfer_id
         WHERE registration.session_id = ? AND transfer.finalized_at IS NULL",
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((transfer_id, existing_multicast, existing_fallback)) = row else {
        return Ok(());
    };
    let multicast = request.multicast_outcome.as_str();
    let fallback = request.fallback_outcome.as_str();
    if let (Some(existing_multicast), Some(existing_fallback)) =
        (existing_multicast, existing_fallback)
    {
        if existing_multicast == multicast && existing_fallback == fallback {
            return Ok(());
        }
        return Ok(());
    }
    sqlx::query(
        "UPDATE workstation_multicast_registrations
         SET multicast_outcome = ?, fallback_outcome = ?, receipt_recorded_at = ?
         WHERE transfer_id = ? AND session_id = ?
           AND multicast_outcome IS NULL AND fallback_outcome IS NULL",
    )
    .bind(multicast)
    .bind(fallback)
    .bind(now_text())
    .bind(&transfer_id)
    .bind(session_id)
    .execute(&state.db)
    .await?;
    maybe_finalize_complete_receipts(state, &transfer_id).await
}

async fn maybe_finalize_complete_receipts(state: &AppState, transfer_id: &str) -> Result<()> {
    let counts: (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(multicast_outcome), transfer.receipt_deadline
         FROM workstation_multicast_registrations registration
         JOIN workstation_multicast_transfers transfer ON transfer.transfer_id = registration.transfer_id
         WHERE registration.transfer_id = ?",
    )
    .bind(transfer_id)
    .fetch_one(&state.db)
    .await?;
    if counts.2.is_some() && counts.0 > 0 && counts.0 == counts.1 {
        finalize_transfer_event(state, transfer_id).await?;
    }
    Ok(())
}

#[derive(Debug, FromRow)]
struct FinalizeTransferRow {
    component_sha256: String,
    size_bytes: i64,
    registered_sessions: i64,
    started_at: Option<String>,
    sender_finished_at: Option<String>,
    finalized_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationMulticastTransferEvent {
    pub event_id: i64,
    pub component_sha256: String,
    pub registered_session_count: u16,
    pub multicast_verified_receipt_count: u16,
    pub missing_receipt_count: u16,
    pub fallback_counts: BTreeMap<String, u16>,
    pub payload_bytes: u64,
    pub estimated_unicast_bytes_avoided: u64,
    pub duration_milliseconds: u64,
}

async fn finalize_transfer_event(state: &AppState, transfer_id: &str) -> Result<()> {
    let mut transaction = state.db.begin().await?;
    let transfer = sqlx::query_as::<_, FinalizeTransferRow>(
        "SELECT component_sha256, size_bytes, registered_sessions, started_at,
                sender_finished_at, finalized_at
         FROM workstation_multicast_transfers WHERE transfer_id = ?",
    )
    .bind(transfer_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(transfer) = transfer else {
        transaction.rollback().await?;
        return Ok(());
    };
    if transfer.finalized_at.is_some() {
        transaction.rollback().await?;
        return Ok(());
    }
    let receipts: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT multicast_outcome, fallback_outcome
         FROM workstation_multicast_registrations WHERE transfer_id = ?",
    )
    .bind(transfer_id)
    .fetch_all(&mut *transaction)
    .await?;
    let verified = receipts
        .iter()
        .filter(|(multicast, _)| multicast.as_deref() == Some("verified"))
        .count();
    let mut fallback_counts = BTreeMap::<String, u16>::new();
    for (multicast, fallback) in &receipts {
        if matches!(fallback.as_deref(), Some("http_verified" | "http_failed")) {
            let reason = multicast
                .as_deref()
                .unwrap_or("missing_receipt")
                .to_string();
            let count = fallback_counts.entry(reason).or_default();
            *count = count.saturating_add(1);
        }
    }
    // `registered_sessions` is frozen before the sender starts. Session
    // retention cleanup can remove a registration row after a long outage,
    // so derive missing receipts from that frozen cardinality rather than
    // silently shrinking the immutable cohort.
    let fallback_receipts = fallback_counts
        .values()
        .map(|count| usize::from(*count))
        .sum::<usize>();
    let missing = usize::try_from(transfer.registered_sessions)?
        .saturating_sub(verified.saturating_add(fallback_receipts));
    let (instance_id, next_event_id, acknowledged_through, events_omitted): (
        String,
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT report_instance_id, next_event_id, acknowledged_through, events_omitted
             FROM workstation_multicast_report_state WHERE singleton_id = 1",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let queue: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(event_size_bytes), 0)
         FROM workstation_multicast_report_events WHERE event_id > ?",
    )
    .bind(acknowledged_through)
    .fetch_one(&mut *transaction)
    .await?;
    let started = transfer
        .started_at
        .as_deref()
        .and_then(parse_timestamp_millis);
    let finished = transfer
        .sender_finished_at
        .as_deref()
        .and_then(parse_timestamp_millis);
    let duration_milliseconds = match (started, finished) {
        (Some(started), Some(finished)) => finished.saturating_sub(started),
        _ => 0,
    };
    let payload_bytes = u64::try_from(transfer.size_bytes)?;
    let avoided = payload_bytes.saturating_mul(u64::try_from(verified.saturating_sub(1))?);
    let event = WorkstationMulticastTransferEvent {
        event_id: next_event_id,
        component_sha256: transfer.component_sha256,
        registered_session_count: u16::try_from(transfer.registered_sessions.min(64))?,
        multicast_verified_receipt_count: u16::try_from(verified.min(64))?,
        missing_receipt_count: u16::try_from(missing.min(64))?,
        fallback_counts,
        payload_bytes,
        estimated_unicast_bytes_avoided: avoided,
        duration_milliseconds,
    };
    let event_json = serde_json::to_string(&event)?;
    let event_size = event_json.len();
    if usize::try_from(queue.0)? >= MAX_REPORT_EVENTS
        || usize::try_from(queue.1)?.saturating_add(event_size) > MAX_REPORT_EVENT_BYTES
    {
        sqlx::query(
            "UPDATE workstation_multicast_report_state
             SET events_omitted = ?, updated_at = ? WHERE singleton_id = 1",
        )
        .bind(events_omitted.saturating_add(1))
        .bind(now_text())
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO workstation_multicast_report_events(event_id, event_json, event_size_bytes)
             VALUES (?, ?, ?)",
        )
        .bind(next_event_id)
        .bind(event_json)
        .bind(i64::try_from(event_size)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE workstation_multicast_report_state
             SET next_event_id = next_event_id + 1, updated_at = ? WHERE singleton_id = 1",
        )
        .bind(now_text())
        .execute(&mut *transaction)
        .await?;
    }
    let finalized_at = now_text();
    sqlx::query(
        "UPDATE james_boot_sessions SET multicast_finalized_at = ?
         WHERE session_id IN (
           SELECT session_id FROM workstation_multicast_registrations WHERE transfer_id = ?
         ) AND multicast_finalized_at IS NULL",
    )
    .bind(&finalized_at)
    .bind(transfer_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE workstation_multicast_transfers SET finalized_at = ?, updated_at = ?
         WHERE transfer_id = ? AND finalized_at IS NULL",
    )
    .bind(&finalized_at)
    .bind(&finalized_at)
    .bind(transfer_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM workstation_multicast_registrations WHERE transfer_id = ?")
        .bind(transfer_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    let _ = instance_id;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationMulticastNodeSnapshot {
    pub state: String,
    pub reason: String,
    pub applied_policy_generation: i64,
    pub applied_policy_sha256: String,
    pub active_transfer_count: u16,
    pub report_time: String,
    pub source_matches_public_base: bool,
    pub interface_kind: String,
    pub multicast_capable: bool,
    pub network_plan_fingerprint: String,
    pub events_omitted: u64,
    pub evidence_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationMulticastReport {
    pub schema: &'static str,
    pub report_instance_id: String,
    pub snapshot: WorkstationMulticastNodeSnapshot,
    pub events: Vec<WorkstationMulticastTransferEvent>,
}

pub async fn report_page(state: &AppState) -> Result<Option<WorkstationMulticastReport>> {
    let Some((policy, policy_hash, lane_authorized)) = state.netboot_multicast.policy().await
    else {
        return Ok(None);
    };
    if !lane_authorized {
        return Ok(None);
    }
    let report_state: (String, i64, i64) = sqlx::query_as(
        "SELECT report_instance_id, acknowledged_through, events_omitted
         FROM workstation_multicast_report_state WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    let limit = i64::from(policy.report_contract.maximum_events_per_page.min(64));
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT event_json FROM workstation_multicast_report_events
         WHERE event_id > ? ORDER BY event_id ASC LIMIT ?",
    )
    .bind(report_state.1)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let mut events = Vec::with_capacity(rows.len());
    for (raw,) in rows {
        events.push(serde_json::from_str::<WorkstationMulticastTransferEvent>(
            &raw,
        )?);
    }
    let active: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM workstation_multicast_transfers
         WHERE state IN ('gathering', 'sender_starting', 'sending')",
    )
    .fetch_one(&state.db)
    .await?;
    let cooldown_active = {
        let mut coordinator = state.netboot_multicast.shared.state.lock().await;
        match coordinator.cooldown_until {
            Some(deadline) if deadline > Instant::now() => true,
            Some(_) => {
                coordinator.cooldown_until = None;
                false
            }
            None => false,
        }
    };
    let network = select_network(&state.config);
    let binary = binary_available(&state.config);
    let (snapshot_state, reason) = if state
        .config
        .workstation_netboot
        .multicast_emergency_disabled
    {
        ("disabled", "emergency_disabled")
    } else if policy.mode == WorkstationMulticastMode::HttpOnly {
        ("disabled", "http_only")
    } else if !binary || cooldown_active {
        ("degraded", "sender_unavailable")
    } else if network.is_err() {
        ("degraded", "network_unqualified")
    } else {
        ("ready", "ready")
    };
    let network = network.ok();
    Ok(Some(WorkstationMulticastReport {
        schema: REPORT_SCHEMA,
        report_instance_id: report_state.0,
        snapshot: WorkstationMulticastNodeSnapshot {
            state: snapshot_state.to_string(),
            reason: reason.to_string(),
            applied_policy_generation: policy.generation,
            applied_policy_sha256: policy_hash,
            active_transfer_count: u16::try_from(active.0.min(1))?,
            report_time: now_text(),
            source_matches_public_base: network
                .as_ref()
                .is_some_and(|network| network.source_matches_public_base),
            interface_kind: if network.is_some() {
                "wired"
            } else {
                "unknown"
            }
            .to_string(),
            multicast_capable: network.is_some(),
            network_plan_fingerprint: network
                .map(|network| network.network_plan_fingerprint)
                .unwrap_or_default(),
            events_omitted: u64::try_from(report_state.2)?,
            evidence_complete: report_state.2 == 0,
        },
        events,
    }))
}

pub async fn acknowledge_report(
    state: &AppState,
    report_instance_id: &str,
    acknowledged_through: i64,
) -> Result<bool> {
    if Uuid::parse_str(report_instance_id).is_err() || acknowledged_through < 0 {
        return Ok(false);
    }
    let current: (String, i64, i64) = sqlx::query_as(
        "SELECT report_instance_id, acknowledged_through, next_event_id
         FROM workstation_multicast_report_state WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    if current.0 != report_instance_id
        || acknowledged_through < current.1
        || acknowledged_through >= current.2
    {
        return Ok(false);
    }
    let mut transaction = state.db.begin().await?;
    sqlx::query(
        "UPDATE workstation_multicast_report_state
         SET acknowledged_through = ?, updated_at = ? WHERE singleton_id = 1
           AND report_instance_id = ? AND acknowledged_through <= ?",
    )
    .bind(acknowledged_through)
    .bind(now_text())
    .bind(report_instance_id)
    .bind(acknowledged_through)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM workstation_multicast_report_events WHERE event_id <= ?")
        .bind(acknowledged_through)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn cancel_for_bundle(state: &AppState, bundle_sha256: &str) -> Result<()> {
    let should_cancel = {
        let coordinator = state.netboot_multicast.shared.state.lock().await;
        coordinator
            .batch
            .as_ref()
            .is_some_and(|batch| batch.bundle_sha256 == bundle_sha256)
    };
    if should_cancel {
        if let Some(transfer_id) = state.netboot_multicast.cancel_active().await {
            let _ =
                finish_transfer_row(state, &transfer_id, "interrupted", "artifact_cancelled").await;
            schedule_finalization(state.clone(), transfer_id);
        }
        for _ in 0..50 {
            let active = {
                let coordinator = state.netboot_multicast.shared.state.lock().await;
                coordinator
                    .batch
                    .as_ref()
                    .is_some_and(|batch| batch.bundle_sha256 == bundle_sha256)
            };
            if !active {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        let still_active = {
            let coordinator = state.netboot_multicast.shared.state.lock().await;
            coordinator
                .batch
                .as_ref()
                .is_some_and(|batch| batch.bundle_sha256 == bundle_sha256)
        };
        if still_active {
            bail!("multicast sender did not release the canonical artifact");
        }
    }
    Ok(())
}

pub async fn cleanup_retained_transfers(state: &AppState) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM workstation_multicast_transfers
         WHERE transfer_id IN (
           SELECT transfer_id FROM workstation_multicast_transfers
           WHERE finalized_at IS NOT NULL
             AND datetime(finalized_at) < datetime('now', ?)
           ORDER BY finalized_at ASC LIMIT 256
         )",
    )
    .bind(format!("-{FINALIZED_TRANSFER_RETENTION_DAYS} days"))
    .execute(&state.db)
    .await?;
    Ok(result.rows_affected())
}

async fn ensure_report_instance(pool: &sqlx::SqlitePool) -> Result<()> {
    let current: (String,) = sqlx::query_as(
        "SELECT report_instance_id FROM workstation_multicast_report_state WHERE singleton_id = 1",
    )
    .fetch_one(pool)
    .await?;
    if current.0.is_empty() {
        sqlx::query(
            "UPDATE workstation_multicast_report_state
             SET report_instance_id = ?, updated_at = ?
             WHERE singleton_id = 1 AND report_instance_id = ''",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(now_text())
        .execute(pool)
        .await?;
    }
    Ok(())
}

fn select_network(config: &AppConfig) -> Result<NetworkSelection> {
    let url = reqwest::Url::parse(config.public_base_url())?;
    if url.scheme() != "http" || url.username() != "" || url.password().is_some() {
        bail!("public base URL is not a production numeric HTTP origin");
    }
    let target: Ipv4Addr = url
        .host_str()
        .context("public base URL omitted its host")?
        .parse()
        .context("public base URL host is not numeric IPv4")?;
    let interfaces = ipv4_interfaces()?;
    let mut matching = interfaces
        .into_iter()
        .filter(|interface| interface.address == target && interface.up && interface.multicast)
        .filter(|interface| {
            !Path::new("/sys/class/net")
                .join(&interface.name)
                .join("wireless")
                .exists()
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        bail!("public base IPv4 did not select exactly one wired multicast interface");
    }
    let interface = matching.remove(0);
    let network_plan_fingerprint = fs::read(NETWORK_PLAN_PATH)
        .ok()
        .filter(|bytes| bytes.len() <= 64 * 1024)
        .map(sha256_hex)
        .unwrap_or_default();
    if network_plan_fingerprint.is_empty() {
        bail!("approved appliance network plan fingerprint is unavailable");
    }
    let interface_fingerprint = sha256_hex(format!(
        "wired\n{}\n{}\n{}",
        interface.name, target, network_plan_fingerprint
    ));
    Ok(NetworkSelection {
        source_matches_public_base: true,
        interface_name: interface.name,
        interface_fingerprint,
        network_plan_fingerprint,
    })
}

struct Ipv4Interface {
    name: String,
    address: Ipv4Addr,
    up: bool,
    multicast: bool,
}

fn ipv4_interfaces() -> Result<Vec<Ipv4Interface>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes `head` on success and freeifaddrs accepts
    // exactly that allocation. Every pointer is checked before dereference.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: pointer came from a successful getifaddrs call.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Guard(head);
    let mut interfaces = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: the linked list remains alive through `_guard`.
        let item = unsafe { &*current };
        if !item.ifa_addr.is_null()
            // SAFETY: `ifa_addr` is non-null and points to a sockaddr.
            && unsafe { (*item.ifa_addr).sa_family as i32 } == libc::AF_INET
            && !item.ifa_name.is_null()
        {
            // SAFETY: AF_INET guarantees sockaddr_in layout.
            let address = unsafe { *(item.ifa_addr as *const libc::sockaddr_in) };
            let address = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            // SAFETY: ifaddrs names are NUL-terminated for the list lifetime.
            let name = unsafe { CStr::from_ptr(item.ifa_name) }
                .to_str()?
                .to_string();
            interfaces.push(Ipv4Interface {
                name,
                address,
                up: item.ifa_flags & u32::try_from(libc::IFF_UP)? != 0,
                multicast: item.ifa_flags & u32::try_from(libc::IFF_MULTICAST)? != 0,
            });
        }
        current = item.ifa_next;
    }
    Ok(interfaces)
}

fn organization_local_multicast(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 239 && (192..=195).contains(&octets[1])
}

fn no_offer_response() -> Response {
    (
        StatusCode::NO_CONTENT,
        [(header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}

fn validate_sha256(value: &str) -> Result<()> {
    if !is_sha256(value) {
        bail!("multicast component identity is invalid");
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(value: impl AsRef<[u8]>) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_ref());
    hex::encode(digest.finalize())
}

fn now_text() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn parse_timestamp_millis(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|value| u64::try_from(value.timestamp_millis()).ok())
}

fn safe_reason(error: &anyhow::Error) -> &'static str {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("policy") {
        "policy_invalid"
    } else if message.contains("network") || message.contains("interface") {
        "network_unavailable"
    } else if message.contains("artifact") {
        "artifact_unavailable"
    } else if message.contains("sender") {
        "sender_failed"
    } else if message.contains("database") || message.contains("sqlite") {
        "storage_unavailable"
    } else {
        "unavailable"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> WorkstationMulticastPolicy {
        WorkstationMulticastPolicy {
            schema: POLICY_SCHEMA.to_string(),
            generation: 7,
            mode: WorkstationMulticastMode::Automatic,
            multicast_domain_id: Uuid::nil(),
            qualification_revision: 3,
            rendezvous_address: "239.192.0.10".parse().unwrap(),
            data_address: "239.192.0.11".parse().unwrap(),
            port_base: 9000,
            minimum_receivers: 2,
            join_window_seconds: 10,
            max_bitrate_bps: 800_000_000,
            absolute_timeout_seconds: 120,
            report_contract: WorkstationMulticastReportContract {
                schema: REPORT_SCHEMA.to_string(),
                maximum_events_per_page: 64,
            },
        }
    }

    #[test]
    fn canonical_join_token_vector_matches_the_runtime() {
        let nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            join_token_from_nonce(nonce),
            "cc1f6776d65be2867765fa4b9ef8731128f2820171764185aac7bfd47b2056f0"
        );
        assert_eq!(
            stored_join_token_hash(nonce),
            "86a6a5fbf524ff2ae56014382de39ca74d53a5b8a4152c14b8455c21b9511234"
        );
    }

    #[test]
    fn policy_has_closed_modes_and_bounded_network_values() {
        let valid = policy();
        valid.validate().unwrap();

        let mut invalid = valid.clone();
        invalid.port_base = 9001;
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.rendezvous_address = "224.0.0.1".parse().unwrap();
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.data_address = "239.192.0.12".parse().unwrap();
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.minimum_receivers = 1;
        assert!(invalid.validate().is_err());
        assert!(serde_json::from_str::<WorkstationMulticastMode>("\"multicast_only\"").is_err());
    }

    #[test]
    fn offer_and_receipt_contracts_reject_unknown_fields() {
        let join = serde_json::from_str::<JoinRequest>(&format!(
            "{{\"schema\":\"{JOIN_SCHEMA}\",\"join_token\":\"{}\",\"extra\":true}}",
            "a".repeat(64)
        ));
        assert!(join.is_err());
        let result = serde_json::from_str::<ResultRequest>(&format!(
            "{{\"schema\":\"{RESULT_SCHEMA}\",\"join_token\":\"{}\",\"multicast_outcome\":\"verified\",\"fallback_outcome\":\"not_needed\",\"extra\":true}}",
            "a".repeat(64)
        ));
        assert!(result.is_err());

        let inconsistent = ResultRequest {
            schema: RESULT_SCHEMA.to_string(),
            join_token: "b".repeat(64),
            multicast_outcome: MulticastOutcome::Verified,
            fallback_outcome: FallbackOutcome::HttpVerified,
        };
        assert!(!inconsistent.has_consistent_outcomes());
        let fallback = ResultRequest {
            schema: RESULT_SCHEMA.to_string(),
            join_token: "b".repeat(64),
            multicast_outcome: MulticastOutcome::ReceiveTimeout,
            fallback_outcome: FallbackOutcome::HttpVerified,
        };
        assert!(fallback.has_consistent_outcomes());
    }

    #[test]
    fn sender_flags_keep_multicast_local_bounded_and_above_udp_quorum() {
        let source = include_str!("netboot_multicast.rs");
        for required in [
            "--min-receivers",
            "--nopointopoint",
            "--min-wait",
            "--start-timeout",
            "--ttl",
            "--max-bitrate",
            "--retries-until-drop",
            "--no-progress",
        ] {
            assert!(source.contains(required));
        }
        assert!(!source.contains(".arg(\"--max-wait\")"));
        assert!(!source.contains(".arg(\"--streaming\")"));
        assert!(!source.contains(".arg(\"--file\")"));
    }

    #[test]
    fn cancellation_is_retained_before_sender_startup_subscribes() {
        let (cancel, receiver) = watch::channel(false);
        drop(receiver);
        let mut batch = test_batch(cancel);
        batch.phase = BatchPhase::SenderStarting;

        request_batch_cancellation(&batch);

        let receiver = batch.cancel.subscribe();
        assert!(*receiver.borrow());
    }

    #[test]
    fn gathering_accepts_only_the_same_component_interface_and_policy() {
        let (cancel, _) = watch::channel(false);
        let mut batch = test_batch(cancel);
        let policy = batch.policy.clone();
        let key = batch.key.clone();
        assert!(batch_accepts_registration(
            &batch,
            &key,
            policy.generation,
            "new-session"
        ));

        let mut other = key.clone();
        other.component_sha256 = "c".repeat(64);
        assert!(!batch_accepts_registration(
            &batch,
            &other,
            policy.generation,
            "new-session"
        ));
        assert!(!batch_accepts_registration(
            &batch,
            &key,
            policy.generation + 1,
            "new-session"
        ));
        batch.registrations.insert(
            "duplicate".to_string(),
            Registration {
                discovery_deadline: Instant::now() + Duration::from_secs(1),
            },
        );
        assert!(!batch_accepts_registration(
            &batch,
            &key,
            policy.generation,
            "duplicate"
        ));
        batch.phase = BatchPhase::Sending;
        assert!(!batch_accepts_registration(
            &batch,
            &key,
            policy.generation,
            "late-session"
        ));
    }

    fn test_batch(cancel: watch::Sender<bool>) -> Batch {
        let policy = policy();
        let key = TransferKey {
            component_sha256: "a".repeat(64),
            size_bytes: 1024,
            interface_fingerprint: "wired-plan".to_string(),
        };
        Batch {
            transfer_id: Uuid::nil().to_string(),
            bundle_sha256: "b".repeat(64),
            key: key.clone(),
            interface_name: "eth0".to_string(),
            artifact_path: PathBuf::from("/canonical/nix-store.squashfs"),
            offer: MulticastOffer {
                schema: OFFER_SCHEMA,
                transport: TRANSPORT,
                component_sha256: key.component_sha256.clone(),
                size_bytes: key.size_bytes,
                rendezvous_address: policy.rendezvous_address,
                port_base: policy.port_base,
                start_timeout_seconds: policy.start_timeout_seconds(),
                receive_timeout_seconds: 30,
                absolute_timeout_seconds: policy.absolute_timeout_seconds,
            },
            policy: policy.clone(),
            phase: BatchPhase::Gathering,
            gathering_deadline: Instant::now() + Duration::from_secs(1),
            registrations: HashMap::new(),
            cancel,
        }
    }
}
