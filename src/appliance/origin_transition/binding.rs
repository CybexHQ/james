use super::*;
use ed25519_dalek::SigningKey;
/// Caller must source these inputs from protected installed state, not the
/// daemon or reservation history. The plan is independently authenticated.
pub struct InstalledContext<'a> {
    pub original_plan: &'a [u8],
    pub trusted_provisioning_keys: &'a [VerifyingKey],
    pub original_signer: &'a VerifyingKey,
    pub permanent_key: &'a SigningKey,
    pub organization_id: &'a str,
    pub device_id: &'a str,
    pub session_id: &'a str,
    pub original_origin: &'a str,
    pub existing_binding: Option<&'a [u8]>,
    pub signed_schedule: Option<&'a [u8]>,
}
#[derive(Debug)]
pub struct VerifiedBinding {
    pub(super) value: wire::InstalledOriginBinding,
    pub(super) digest: String,
    pub(super) signer: VerifyingKey,
}
impl VerifiedBinding {
    pub fn claims(&self) -> &wire::InstalledOriginBinding {
        &self.value
    }
    pub fn sha256(&self) -> &str {
        &self.digest
    }
}
pub fn verify_binding(bytes: &[u8], context: &InstalledContext<'_>) -> Result<VerifiedBinding> {
    ensure!(
        context.original_plan.len() <= 256 * 1024,
        "original plan bound"
    );
    let plan_value = release_v3::strict_json(context.original_plan)?;
    let (plan, signer) = crate::provisioning::protocol::verify_promoted_install_plan(
        plan_value.clone(),
        context.trusted_provisioning_keys,
    )?;
    ensure!(
        signer == *context.original_signer && !signer.is_weak(),
        "original plan signer changed"
    );
    ensure!(
        plan.schema == "tiaris.nest.install-plan.v3" && plan.base_os == "nixos",
        "origin binding requires a provisioned NixOS plan"
    );
    let value = verify_signed(bytes, &signer)?;
    wire::validate("InstalledOriginBinding", &value)?;
    let binding: wire::InstalledOriginBinding = serde_json::from_value(value)?;
    ensure!(
        binding.organization_id == context.organization_id
            && binding.organization_id == plan.organization_id.to_string()
            && binding.device_id == context.device_id
            && binding.device_id == plan.reserved_device_id
            && binding.provisioning_session_id == context.session_id
            && binding.provisioning_session_id == plan.session_id.to_string()
            && binding.source_origin == context.original_origin
            && binding.base_plan_sha256 == plan.plan_sha256
            && binding.base_signed_plan_sha256 == object_digest(&plan_value)?
            && binding.management_signing_key_sha256 == digest(signer.as_bytes())
            && binding.device_public_key_sha256
                == digest(context.permanent_key.verifying_key().as_bytes()),
        "binding differs from protected installed identity"
    );
    if let Some(previous) = context.existing_binding {
        // Write-once means the ENTIRE signed binding, not just its incarnation.
        let previous = verify_signed(previous, &signer)?;
        ensure!(
            object_digest(&previous)? == digest(bytes),
            "existing binding is immutable"
        );
    }
    if let Some(schedule) = context.signed_schedule {
        ensure!(schedule.len() <= 64 * 1024, "schedule bound");
        let v = release_v3::strict_json(schedule)?;
        let policy: super::super::schedule::SignedPolicy = serde_json::from_value(v.clone())?;
        let mut message = b"TIARIS-NEST-UPDATE-SCHEDULE-V1\n".to_vec();
        message.extend(canonical(&unsigned(&v)?)?);
        signer.verify_strict(
            &message,
            &Signature::from_slice(&wire::url_bytes(&policy.signature, 64)?)?,
        )?;
        ensure!(
            policy.schema == "tiaris.nest.update-schedule.v1"
                && policy.revision > 0
                && policy.device_incarnation_id.to_string() == binding.device_incarnation_id
                && policy.device_id == binding.device_id
                && policy.provisioning_session_id.to_string() == binding.provisioning_session_id,
            "binding differs from protected signed schedule"
        );
    }
    Ok(VerifiedBinding {
        value: binding,
        digest: digest(bytes),
        signer,
    })
}
