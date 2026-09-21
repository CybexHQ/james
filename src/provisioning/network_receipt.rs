//! Authenticated, durable network commits survive expiry and installer-plan age.
use super::{DurableProvisioningState, protocol, storage};
use crate::appliance::{self, SignedApplianceNetworkAcknowledgement, SignedApplianceNetworkChange};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, os::unix::fs::MetadataExt, path::Path};
use uuid::Uuid;

const CONTROL: &str = "/var/lib/cybex-james/control";
const SCHEMA: &str = "cybex.james.network-committed.v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    change: SignedApplianceNetworkChange,
    acknowledgement: SignedApplianceNetworkAcknowledgement,
    candidate: String,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let body = super::read_bounded_nofollow(path, 256 * 1024, "network transaction evidence")?;
    serde_json::from_value(crate::appliance::release_v3::strict_json(&body)?)
        .context("parse network transaction evidence")
}

fn protected(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!("network commit is not protected root-owned state")
    }
    Ok(())
}

fn installed_state(control: &Path) -> Result<DurableProvisioningState> {
    protected(&control.join("provisioning-state.json"))?;
    let state: DurableProvisioningState = read_json(&control.join("provisioning-state.json"))?;
    if !state.identity_active
        || !state.installation_complete
        || state.plan.schema != protocol::INSTALL_PLAN_SCHEMA_V3
    {
        bail!("network commits require a completed NixOS installed identity")
    }
    Ok(state)
}

fn validate(
    receipt: &Receipt,
    state: &DurableProvisioningState,
    interface: &(String, String),
    committed: bool,
) -> Result<String> {
    let change = &receipt.change;
    let ack = &receipt.acknowledgement;
    if receipt.schema != SCHEMA
        || change.schema != "cybex.james.network-change.v1"
        || change.id.is_nil()
        || change.device_incarnation_id.is_nil()
        || change.revision <= 0
        || change.device_id != state.plan.reserved_device_id
        || ack.device_id != change.device_id
        || ack.schema != "cybex.james.network-ack.v1"
        || ack.change_id != change.id
        || change.expires_at <= change.issued_at
        || change.expires_at - change.issued_at > chrono::Duration::minutes(5)
        || ack.expires_at <= ack.issued_at
        || ack.expires_at - ack.issued_at > chrono::Duration::minutes(2)
        || ack.issued_at < change.issued_at
        || ack.issued_at > change.expires_at
        || (!committed && (change.expires_at <= Utc::now() || ack.expires_at <= Utc::now()))
    {
        bail!("network commit does not match its signed installed-device authority")
    }
    appliance::validate_network_input(&change.network)?;
    let network = serde_json::to_value(&change.network)?;
    if protocol::sha256_hex(serde_json::to_vec(&network)?) != change.config_sha256 {
        bail!("network commit configuration digest differs from signed input")
    }
    appliance::verify_management_signature(
        change,
        "signature",
        &change.signature,
        "CYBEX-JAMES-NETWORK-CHANGE-V1",
        &state.management_signing_public_key_b64,
    )?;
    appliance::verify_management_signature(
        ack,
        "signature",
        &ack.signature,
        "CYBEX-JAMES-NETWORK-ACK-V1",
        &state.management_signing_public_key_b64,
    )?;
    let hash = protocol::sha256_hex(receipt.candidate.as_bytes());
    if hash != ack.candidate_sha256 {
        bail!("network commit candidate differs from signed acknowledgement")
    }
    let mut bound_plan = state.plan.clone();
    bound_plan.network_interface.name = interface.0.clone();
    bound_plan.network_interface.mac = interface.1.clone();
    let network = protocol::JamesProvisioningNetworkPlan {
        mode: change.network.mode.clone(),
        interface_id: change.network.interface_id.clone(),
        address_cidr: change.network.address_cidr.clone(),
        gateway: change.network.gateway.clone(),
        dns_servers: change.network.dns_servers.clone(),
    };
    let candidate: Value = crate::appliance::release_v3::strict_json(receipt.candidate.as_bytes())?;
    if candidate != storage::netplan(&network, &bound_plan) {
        bail!("network commit candidate is not derived from the signed change and wired interface")
    }
    Ok(hash)
}

fn write_control(path: &Path, body: &[u8]) -> Result<()> {
    storage::atomic_write(path, body, 0o640)?;
    super::nixos_install::chown(path, 0, 985)
}

pub fn commit_network_change(candidate: &Path) -> Result<String> {
    let control = Path::new(CONTROL);
    let state = installed_state(control)?;
    let request =
        Path::new("/var/lib/cybex-james/state/inbox/appliance-network-change-request.json");
    let acknowledgement =
        Path::new("/var/lib/cybex-james/state/inbox/netplan-acknowledgement.json");
    protected(candidate)?;
    let receipt = Receipt {
        schema: SCHEMA.to_owned(),
        change: read_json(request)?,
        acknowledgement: read_json(acknowledgement)?,
        candidate: String::from_utf8(super::read_bounded_nofollow(
            candidate,
            128 * 1024,
            "network candidate",
        )?)?,
    };
    if candidate
        != Path::new("/run/cybex-james-network-change").join(format!("{}.yaml", receipt.change.id))
    {
        bail!("network candidate path differs from the signed transaction")
    }
    let interface = appliance::resolve_wired_interface(&receipt.change.network.interface_id)?;
    let hash = validate(&receipt, &state, &interface, false)?;
    let pending = control.join("netplan-pending.sha256");
    protected(&pending)?;
    if super::read_bounded_nofollow(&pending, 128, "pending network digest")?
        != format!("{hash}\n").as_bytes()
    {
        bail!("network commit is not the active pending transaction")
    }
    // The atomic receipt is the commit point. The approved profile is derived;
    // recurring boot verification repairs it after interruption at this boundary.
    write_control(
        &control.join("network-committed.json"),
        &serde_json::to_vec(&receipt)?,
    )?;
    restore_derived_profiles(control, &receipt, &state, &interface)?;
    Ok(hash)
}

pub fn verify_committed_network_change(change_id: Uuid, repair: bool) -> Result<String> {
    let control = Path::new(CONTROL);
    let state = installed_state(control)?;
    if repair {
        return restore_approved(control, &state, Some(change_id));
    }
    let receipt = committed_receipt(control, Some(change_id))?;
    let interface = appliance::resolve_wired_interface(&receipt.change.network.interface_id)?;
    validate(&receipt, &state, &interface, true)
}

fn committed_receipt(control: &Path, change_id: Option<Uuid>) -> Result<Receipt> {
    let path = control.join("network-committed.json");
    protected(&path)?;
    let receipt: Receipt = read_json(&path)?;
    if change_id.is_some_and(|id| id != receipt.change.id) {
        bail!("another network transaction was committed")
    }
    Ok(receipt)
}

pub(super) fn restore_approved(
    control: &Path,
    state: &DurableProvisioningState,
    change_id: Option<Uuid>,
) -> Result<String> {
    let receipt = committed_receipt(control, change_id)?;
    let interface = appliance::resolve_wired_interface(&receipt.change.network.interface_id)?;
    let hash = validate(&receipt, state, &interface, true)?;
    restore_derived_profiles(control, &receipt, state, &interface)?;
    Ok(hash)
}

fn restore_derived_profiles(
    control: &Path,
    receipt: &Receipt,
    state: &DurableProvisioningState,
    interface: &(String, String),
) -> Result<()> {
    let mut bound_plan = state.plan.clone();
    bound_plan.network_interface.name = interface.0.clone();
    bound_plan.network_interface.mac = interface.1.clone();
    let fallback = protocol::JamesProvisioningNetworkPlan {
        mode: "dhcp".into(),
        interface_id: receipt.change.network.interface_id.clone(),
        address_cidr: None,
        gateway: None,
        dns_servers: Vec::new(),
    };
    let fallback = serde_json::to_vec(&storage::netplan(&fallback, &bound_plan))?;
    restore_profile(
        &control.join("netplan-approved.json"),
        receipt.candidate.as_bytes(),
        write_control,
    )?;
    restore_profile(
        &control.join("netplan-dhcp-fallback.json"),
        &fallback,
        write_control,
    )
}

fn restore_profile(
    path: &Path,
    expected: &[u8],
    write: impl FnOnce(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    if super::read_bounded_nofollow(path, 128 * 1024, "derived network profile")
        .ok()
        .as_deref()
        != Some(expected)
    {
        write(path, expected)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
