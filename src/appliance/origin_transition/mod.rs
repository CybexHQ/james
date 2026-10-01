//! Verification foundation only: no lifecycle admission or origin projection.
use super::release_v3;
use anyhow::{Result, anyhow, bail, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
mod binding;
mod transition;
pub mod wire;
pub use transition::{
    MAX_BUNDLE_BYTES, TransitionContext, VerifiedAcknowledgement, VerifiedTransition,
    verify_acknowledgement, verify_bundle,
};
mod evidence;
pub use binding::{InstalledContext, VerifiedBinding, verify_binding};
pub use evidence::{VerifiedEvidence, verify_evidence};

fn canonical(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&super::canonical_json(value.clone()))?)
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn object_digest(value: &Value) -> Result<String> {
    Ok(digest(&canonical(value)?))
}
fn unsigned(value: &Value) -> Result<Value> {
    let mut v = value.clone();
    v.as_object_mut()
        .ok_or_else(|| anyhow!("expected object"))?
        .remove("signature");
    Ok(v)
}
fn domain(value: &Value) -> Result<&'static [u8]> {
    match value["schema"].as_str() {
        Some("tiaris.nest.installed-origin-binding.v1") => {
            Ok(b"TIARIS-NEST-INSTALLED-ORIGIN-BINDING-V1\n")
        }
        Some("tiaris.nest.device-origin-transition.v1") => {
            Ok(b"TIARIS-NEST-DEVICE-ORIGIN-TRANSITION-V1\n")
        }
        Some("tiaris.nest.origin-contact-ack.v1") => Ok(b"TIARIS-NEST-ORIGIN-CONTACT-ACK-V1\n"),
        _ => bail!("unsupported origin object"),
    }
}
fn verify_signed(bytes: &[u8], key: &VerifyingKey) -> Result<Value> {
    ensure!(bytes.len() <= 32768, "signed object too large");
    let value = release_v3::strict_json(bytes)?;
    ensure!(
        canonical(&value)? == bytes,
        "signed object is not exact C JSON"
    );
    let (kind, maximum) = match value["schema"].as_str() {
        Some("tiaris.nest.installed-origin-binding.v1") => ("InstalledOriginBinding", 16384),
        Some("tiaris.nest.device-origin-transition.v1") => ("DeviceOriginTransition", 32768),
        Some("tiaris.nest.origin-contact-ack.v1") => ("OriginContactAcknowledgement", 16384),
        _ => bail!("unknown signed type"),
    };
    ensure!(bytes.len() <= maximum, "signed object bound");
    wire::validate(kind, &value)?;
    let mut message = domain(&value)?.to_vec();
    message.extend(canonical(&unsigned(&value)?)?);
    let text = value["signature"]
        .as_str()
        .ok_or_else(|| anyhow!("missing signature"))?;
    ensure!(text.len() == 86, "signature length");
    let signature = URL_SAFE_NO_PAD.decode(text)?;
    ensure!(
        signature.len() == 64 && URL_SAFE_NO_PAD.encode(&signature) == text,
        "noncanonical signature"
    );
    ensure!(!key.is_weak(), "weak management key");
    key.verify_strict(&message, &Signature::from_slice(&signature)?)?;
    Ok(value)
}
#[cfg(test)]
mod negative_tests;
#[cfg(test)]
mod release_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transition_tests;
