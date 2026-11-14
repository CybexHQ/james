use super::*;
/// All local inputs must be read under the maintenance lock from protected
/// installed/boot state and the independently verified update request.
pub struct TransitionContext<'a> {
    pub installed: InstalledContext<'a>,
    pub release_key: &'a VerifyingKey,
    pub source_release: &'a release_v3::NixosRelease,
    pub target_release: &'a release_v3::NixosRelease,
    pub source_generation: &'a str,
    pub booted_source_toplevel: &'a str,
    pub expected_target_origin: &'a str,
    pub expected_attempt_id: &'a str,
    pub now: u64,
}
/// Cryptographically verified authority, NOT a durable admission capability.
/// No Deserialize/From<DTO> constructor exists. The future root transaction
/// must seal its watermark before PREPARE and recheck expiry at that boundary.
#[derive(Debug)]
pub struct VerifiedTransition {
    pub(super) binding: VerifiedBinding,
    pub(super) claims: wire::DeviceOriginTransition,
    pub(super) evidence: VerifiedEvidence,
    pub(super) snapshot: Vec<u8>,
    pub(super) digest: String,
}
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
impl VerifiedTransition {
    pub fn binding(&self) -> &VerifiedBinding {
        &self.binding
    }
    pub fn claims(&self) -> &wire::DeviceOriginTransition {
        &self.claims
    }
    pub fn evidence(&self) -> &VerifiedEvidence {
        &self.evidence
    }
    pub fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }
    pub fn sha256(&self) -> &str {
        &self.digest
    }
}
/// Explicit capable-path verifier. Existing update readers and limits are not
/// changed. Operates only on the supplied snapshot; never reopens a pathname.
pub fn verify_bundle(bytes: &[u8], context: &TransitionContext<'_>) -> Result<VerifiedTransition> {
    ensure!(
        bytes.len() <= MAX_BUNDLE_BYTES,
        "origin bundle exceeds 8 MiB"
    );
    let value = release_v3::strict_json(bytes)?;
    ensure!(canonical(&value)? == bytes, "bundle is not exact C JSON");
    let bundle: wire::OriginTransitionBundle = serde_json::from_value(value.clone())?;
    let binding = verify_binding(&canonical(&value["binding"])?, &context.installed)?;
    let transition_value = verify_signed(&canonical(&value["transition"])?, &binding.signer)?;
    wire::validate("DeviceOriginTransition", &transition_value)?;
    for field in [
        "organization_id",
        "device_id",
        "device_incarnation_id",
        "device_public_key_sha256",
        "provisioning_session_id",
        "base_plan_sha256",
        "base_signed_plan_sha256",
        "source_origin",
    ] {
        ensure!(
            transition_value[field] == value["binding"][field],
            "transition/binding identity mismatch"
        );
    }
    let claims = bundle.transition;
    ensure!(
        claims.binding_sha256 == binding.digest
            && claims.attempt_id == context.expected_attempt_id
            && claims.target_origin == context.expected_target_origin
            && claims.source_system_generation == context.source_generation
            && claims.source.system_toplevel == context.booted_source_toplevel,
        "transition differs from local update/boot context"
    );
    valid_time(
        claims.issued_at,
        claims.expires_at,
        context.now,
        86400,
        false,
    )?;
    let evidence = verify_evidence(
        &bundle.evidence,
        &claims.source,
        &claims.target,
        &claims.pair_authorization_sha256,
        &claims.source_origin,
        &claims.target_origin,
        context.release_key,
    )?;
    ensure!(
        evidence.source == *context.source_release && evidence.target == *context.target_release,
        "evidence differs from protected source or update descriptor"
    );
    Ok(VerifiedTransition {
        binding,
        claims,
        evidence,
        snapshot: bytes.to_vec(),
        digest: object_digest(&transition_value)?,
    })
}
/// A verified signed response, never proof of a target TLS connection. The root
/// caller must receive these bytes directly over its pinned-origin TLS client.
#[derive(Debug)]
pub struct VerifiedAcknowledgement {
    claims: wire::OriginContactAcknowledgement,
    digest: String,
}
impl VerifiedAcknowledgement {
    pub fn claims(&self) -> &wire::OriginContactAcknowledgement {
        &self.claims
    }
    pub fn sha256(&self) -> &str {
        &self.digest
    }
}
pub fn verify_acknowledgement(
    bytes: &[u8],
    request: &[u8],
    authority: &VerifiedTransition,
    now: u64,
) -> Result<VerifiedAcknowledgement> {
    ensure!(
        bytes.len() <= 16384 && request.len() <= 16384,
        "contact bound"
    );
    let req = release_v3::strict_json(request)?;
    wire::validate("OriginContactRequest", &req)?;
    ensure!(canonical(&req)? == request, "request is not exact C JSON");
    let ack = verify_signed(bytes, &authority.binding.signer)?;
    wire::validate("OriginContactAcknowledgement", &ack)?;
    for (field, value) in req.as_object().unwrap() {
        if field != "schema" {
            ensure!(ack[field] == *value, "ack differs from exact root request");
        }
    }
    let t = serde_json::to_value(&authority.claims)?;
    for field in [
        "transition_id",
        "attempt_id",
        "revision",
        "organization_id",
        "device_id",
        "device_incarnation_id",
        "target_origin",
    ] {
        ensure!(req[field] == t[field], "request differs from transition");
    }
    ensure!(
        req["transition_sha256"] == authority.digest
            && req["binding_sha256"] == authority.binding.digest
            && req["target_system_closure_sha256"] == authority.claims.target.system_closure_sha256
            && req["target_system_toplevel"] == authority.claims.target.system_toplevel
            && ack["request_sha256"] == digest(request),
        "contact authority mismatch"
    );
    let claims: wire::OriginContactAcknowledgement = serde_json::from_value(ack)?;
    valid_time(claims.issued_at, claims.expires_at, now, 300, true)?;
    Ok(VerifiedAcknowledgement {
        claims,
        digest: digest(bytes),
    })
}
fn valid_time(issued: u64, expires: u64, now: u64, life: u64, exact: bool) -> Result<()> {
    let duration = expires
        .checked_sub(issued)
        .ok_or_else(|| anyhow!("inverted expiry"))?;
    ensure!(
        duration > 0
            && duration <= life
            && (!exact || duration == life)
            && issued <= now.saturating_add(60)
            && now < expires,
        "signed object outside admission time"
    );
    Ok(())
}
