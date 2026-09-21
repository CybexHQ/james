//! Signed maintenance schedules cross the untrusted inbox through this verifier.
use anyhow::{Result, anyhow, bail, ensure};
use chrono::NaiveTime;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
const INBOX: &str = "/var/lib/cybex-james/state/inbox/update-schedule.json";
const CONTROL: &str = "/var/lib/cybex-james/control/update-schedule.json";
pub const CAPABILITY: &str = "appliance_update_schedule_v1";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub timezone: String,
    pub weekdays: Vec<u8>,
    pub start: String,
    pub duration_minutes: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunNow {
    pub attempt_id: Uuid,
    pub release_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_snapshot_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_closure_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    pub schema: String,
    pub device_id: String,
    pub device_incarnation_id: Uuid,
    pub provisioning_session_id: Uuid,
    pub revision: i64,
    pub schedule: Schedule,
    pub run_now: Option<RunNow>,
    pub signature: String,
}
impl SignedPolicy {
    fn verify(&self, state: &crate::provisioning::DurableProvisioningState) -> Result<()> {
        ensure!(
            self.schema == "cybex.james.update-schedule.v1"
                && self.device_id == state.plan.reserved_device_id
                && self.provisioning_session_id == state.session_id
                && !self.device_incarnation_id.is_nil()
                && self.revision > 0,
            "schedule identity mismatch"
        );
        let schedule = &self.schedule;
        ensure!(
            !schedule.weekdays.is_empty()
                && schedule.weekdays.len() <= 7
                && schedule.weekdays.iter().all(|d| *d <= 6)
                && schedule.weekdays.windows(2).all(|p| p[0] < p[1])
                && (15..=1440).contains(&schedule.duration_minutes),
            "invalid maintenance schedule"
        );
        ensure!(
            schedule.start.len() == 5
                && NaiveTime::parse_from_str(&schedule.start, "%H:%M").is_ok(),
            "invalid maintenance time"
        );
        ensure!(
            !schedule.timezone.is_empty()
                && schedule.timezone.len() <= 128
                && !schedule.timezone.starts_with('/')
                && !schedule
                    .timezone
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == "..")
                && schedule
                    .timezone
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b)),
            "invalid maintenance timezone"
        );
        ensure!(
            Path::new("/usr/share/zoneinfo")
                .join(&schedule.timezone)
                .is_file(),
            "unknown maintenance timezone"
        );
        if let Some(now) = &self.run_now {
            ensure!(
                !now.attempt_id.is_nil() && now.package_snapshot_sha256.is_none(),
                "NixOS immediate update requires closure identity"
            );
            super::release_v3::require_hex(
                now.system_closure_sha256
                    .as_deref()
                    .ok_or_else(|| anyhow!("immediate closure digest missing"))?,
                64,
            )?;
            let version = semver::Version::parse(&now.release_id)?;
            ensure!(
                version.to_string() == now.release_id,
                "immediate release ID"
            );
        }
        super::verify_management_signature(
            self,
            "signature",
            &self.signature,
            "CYBEX-JAMES-UPDATE-SCHEDULE-V1",
            &state.management_signing_public_key_b64,
        )
    }
}
pub fn store(policy: Option<SignedPolicy>, supported: bool) -> Result<()> {
    if !super::nixos::is_nixos() {
        return Ok(());
    }
    if let Some(policy) = policy {
        ensure!(supported, "server supplied unsupported schedule");
        super::write_atomic_json(Path::new(INBOX), &policy, 0o600)?;
    }
    Ok(())
}
pub fn verify_stored() -> Result<PathBuf> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "schedule verification requires root"
    );
    let state = super::load_provisioning_state()?;
    let read = |path: &Path| -> Result<SignedPolicy> {
        let bytes = crate::provisioning::read_bounded_nofollow(path, 64 * 1024, "signed schedule")?;
        Ok(serde_json::from_value(super::release_v3::strict_json(
            &bytes,
        )?)?)
    };
    let previous = if Path::new(CONTROL).exists() {
        let previous = read(Path::new(CONTROL))?;
        previous.verify(&state)?;
        Some(previous)
    } else {
        None
    };
    let incoming = if Path::new(INBOX).exists() {
        read(Path::new(INBOX))?
    } else if let Some(previous) = previous {
        return Ok({
            previous.verify(&state)?;
            PathBuf::from(CONTROL)
        });
    } else {
        bail!("no authenticated maintenance schedule received")
    };
    incoming.verify(&state)?;
    if let Some(previous) = previous {
        validate_transition(&previous, &incoming)?;
    }
    super::write_atomic_json(Path::new(CONTROL), &incoming, 0o640)?;
    Ok(PathBuf::from(CONTROL))
}

fn validate_transition(previous: &SignedPolicy, incoming: &SignedPolicy) -> Result<()> {
    ensure!(
        incoming.device_incarnation_id == previous.device_incarnation_id
            && incoming.revision >= previous.revision,
        "schedule incarnation changed or revision replayed"
    );
    ensure!(
        incoming.revision != previous.revision || incoming == previous,
        "same schedule revision has different signed bytes"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::Signer;
    #[test]
    fn signed_schedule_binds_session_incarnation_revision_and_closure() {
        let (value, envelope, _, key) = crate::provisioning::protocol::tests::signed_plan_fixture(
            "cybex.james.install-plan.v1",
            "CYBEX-JAMES-INSTALL-PLAN-V1",
        );
        let state = crate::provisioning::DurableProvisioningState {
            schema: "cybex.james.provisioning-state.v1".into(),
            session_id: envelope.session_id,
            plan: serde_json::from_value(value).unwrap(),
            manage_origin: envelope.manage_origin,
            management_signing_public_key_b64: crate::provisioning::protocol::standard_base64(
                key.verifying_key().as_bytes(),
            ),
            device_private_key_b64: String::new(),
            device_public_key_b64: String::new(),
            device_public_key_fingerprint: String::new(),
            next_event_sequence: 6,
            identity_active: true,
            installation_complete: true,
            updated_at: chrono::Utc::now(),
        };
        let mut policy = SignedPolicy {
            schema: "cybex.james.update-schedule.v1".into(),
            device_id: state.plan.reserved_device_id.clone(),
            device_incarnation_id: Uuid::from_bytes([8; 16]),
            provisioning_session_id: state.session_id,
            revision: 1,
            schedule: Schedule {
                timezone: "UTC".into(),
                weekdays: vec![0, 2, 6],
                start: "03:00".into(),
                duration_minutes: 60,
            },
            run_now: Some(RunNow {
                attempt_id: Uuid::from_bytes([9; 16]),
                release_id: "1.2.3".into(),
                package_snapshot_sha256: None,
                system_closure_sha256: Some("a".repeat(64)),
            }),
            signature: String::new(),
        };
        let mut value = serde_json::to_value(&policy).unwrap();
        value.as_object_mut().unwrap().remove("signature");
        let mut bytes = b"CYBEX-JAMES-UPDATE-SCHEDULE-V1\n".to_vec();
        bytes.extend(serde_json::to_vec(&crate::appliance::canonical_json(value)).unwrap());
        policy.signature = URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes());
        policy.verify(&state).unwrap();
        let mut changed = policy.clone();
        changed.run_now.as_mut().unwrap().system_closure_sha256 = Some("b".repeat(64));
        assert!(changed.verify(&state).is_err());
        let mut changed = policy.clone();
        changed.provisioning_session_id = Uuid::new_v4();
        assert!(changed.verify(&state).is_err());
        let mut changed = policy.clone();
        changed.revision = 0;
        assert!(validate_transition(&policy, &changed).is_err());
        let mut changed = policy.clone();
        changed.schedule.start = "04:00".into();
        assert!(validate_transition(&policy, &changed).is_err());
        let mut changed = policy.clone();
        changed.device_incarnation_id = Uuid::new_v4();
        assert!(validate_transition(&policy, &changed).is_err());
        assert!(validate_transition(&policy, &policy).is_ok());
    }
}
