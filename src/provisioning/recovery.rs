//! Server-authorized recovery before a random permanent identity is durable.
use super::{JamesProvisioningInventory, SignedInstallPlan, inventory, protocol};
use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;

/// Completed installations need only authenticated local boot evidence. This
/// path performs no contact, closure import, or installation authorization.
pub(super) fn durable_plan(
    durable: &super::DurableProvisioningState,
    verified: &protocol::VerifiedEnvelope,
    inventory: &JamesProvisioningInventory,
) -> Result<SignedInstallPlan> {
    if durable.session_id != verified.envelope.session_id
        || durable.manage_origin != verified.envelope.manage_origin
        || durable.management_signing_public_key_b64
            != protocol::standard_base64(verified.signing_key.to_bytes())
        || durable.next_event_sequence < 3
        || durable.next_event_sequence
            > if durable.installation_complete
                || durable.plan.schema == protocol::INSTALL_PLAN_SCHEMA_V3
            {
                9
            } else {
                6
            }
        || (durable.installation_complete && !durable.identity_active)
    {
        bail!("durable appliance recovery state does not match this signed media")
    }
    if !durable.installation_complete {
        protocol::require_current_envelope(verified)?;
    }
    let key = durable.signing_key()?;
    if durable.device_public_key_b64 != protocol::standard_base64(key.verifying_key().to_bytes())
        || durable.device_public_key_fingerprint
            != protocol::sha256_hex(key.verifying_key().to_bytes())
    {
        bail!("durable appliance device identity is inconsistent")
    }
    let plan = protocol::verify_durable_install_plan(
        serde_json::to_value(&durable.plan)?,
        &verified.signing_key,
        &verified.envelope,
        inventory,
    )?;
    inventory::revalidate_durable_plan_hardware(&plan, inventory)?;
    Ok(plan)
}

pub(super) async fn initial_session(
    client: &protocol::ProvisioningClient,
    verified: &protocol::VerifiedEnvelope,
    key: &SigningKey,
    inventory: &JamesProvisioningInventory,
    hardware_digest: &str,
) -> Result<(protocol::AgentSessionResponse, bool)> {
    match client.poll_plan(key).await {
        Ok(session) => match session.state.as_str() {
            "approved" | "installing" => return Ok((session, true)),
            "created" | "awaiting_approval" => {}
            _ => bail!("this provisioning session requires managed recovery or fresh approval"),
        },
        Err(error) if protocol::unclaimed_session(&error) => {}
        Err(error) => {
            return Err(error).context("could not authenticate interrupted-install recovery");
        }
    }
    // Never claim after a retired-key, transport or server error. An unclaimed
    // session still requires its media secret and explicit Console approval.
    let session = client
        .claim(
            &verified.envelope.media_secret,
            key,
            inventory,
            hardware_digest,
        )
        .await?;
    Ok((session, false))
}

pub(super) fn active_plan(
    session: &protocol::AgentSessionResponse,
    verified: &protocol::VerifiedEnvelope,
    inventory: &JamesProvisioningInventory,
) -> Result<SignedInstallPlan> {
    if session.session_id != verified.envelope.session_id
        || !matches!(session.state.as_str(), "approved" | "installing")
    {
        bail!("interrupted-install authority is not this active session")
    }
    let value = session
        .plan
        .clone()
        .context("active recovery session omitted its signed plan")?;
    // Expiry may pass after acknowledgement. Manage's exact seq1/seq2 replay
    // fences below still reject expired unacknowledged or superseded authority.
    let plan = protocol::verify_durable_install_plan(
        value,
        &verified.signing_key,
        &verified.envelope,
        inventory,
    )?;
    if plan.schema != protocol::INSTALL_PLAN_SCHEMA_V3 {
        bail!("missing-state recovery requires an exact NixOS V3 plan")
    }
    inventory::revalidate_plan_hardware(&plan, inventory)?;
    Ok(plan)
}

#[cfg(test)]
mod tests;
