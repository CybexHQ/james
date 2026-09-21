//! Root-verified maintenance policy, independent of the immutable install plan.
use super::*;
use chrono::{Datelike, Timelike};

pub const CAPABILITY: &str = "appliance_update_schedule_v1";
const DOMAIN: &str = "CYBEX-JAMES-UPDATE-SCHEDULE-V1";
const INBOX: &str = "/var/lib/cybex-james/state/inbox/update-schedule.json";
const CONTROL: &str = "/var/lib/cybex-james/control/update-schedule.json";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub timezone: String,
    pub weekdays: Vec<u8>,
    pub start: String,
    pub duration_minutes: u16,
}

impl Schedule {
    fn validate(&self) -> Result<()> {
        self.timezone
            .parse::<chrono_tz::Tz>()
            .context("invalid maintenance timezone")?;
        if self.weekdays.is_empty()
            || self.weekdays.len() > 7
            || self.weekdays.iter().any(|day| *day > 6)
            || self.weekdays.windows(2).any(|days| days[0] >= days[1])
            || !(15..=1440).contains(&self.duration_minutes)
            || self.start.len() != 5
            || chrono::NaiveTime::parse_from_str(&self.start, "%H:%M").is_err()
        {
            bail!("invalid maintenance schedule");
        }
        Ok(())
    }

    fn includes(&self, now: DateTime<Utc>) -> Result<bool> {
        self.validate()?;
        let local = now.with_timezone(&self.timezone.parse::<chrono_tz::Tz>()?);
        let start = chrono::NaiveTime::parse_from_str(&self.start, "%H:%M")?;
        let current =
            local.weekday().num_days_from_sunday() * 1440 + local.hour() * 60 + local.minute();
        Ok(self.weekdays.iter().any(|day| {
            let beginning = u32::from(*day) * 1440 + start.hour() * 60 + start.minute();
            (current + 10080 - beginning) % 10080 < u32::from(self.duration_minutes)
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImmediateUpdate {
    pub attempt_id: uuid::Uuid,
    pub release_id: String,
    pub package_snapshot_sha256: String,
}

impl ImmediateUpdate {
    fn matches(&self, attempt: uuid::Uuid, release: &str, snapshot: &str) -> bool {
        self.attempt_id == attempt
            && self.release_id == release
            && self.package_snapshot_sha256 == snapshot
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    pub schema: String,
    pub device_id: String,
    pub device_incarnation_id: uuid::Uuid,
    pub provisioning_session_id: uuid::Uuid,
    pub revision: i64,
    pub schedule: Schedule,
    pub run_now: Option<ImmediateUpdate>,
    pub signature: String,
}

fn validate(
    policy: &SignedPolicy,
    device: &str,
    session: uuid::Uuid,
    public_key: &str,
) -> Result<()> {
    policy.schedule.validate()?;
    if policy.schema != "cybex.james.update-schedule.v1"
        || policy.device_id != device
        || policy.provisioning_session_id != session
        || policy.device_incarnation_id.is_nil()
        || policy.revision < 1
        || policy.run_now.as_ref().is_some_and(|now| {
            now.attempt_id.is_nil()
                || now.release_id.is_empty()
                || now.package_snapshot_sha256.len() != 64
                || !now
                    .package_snapshot_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
        })
    {
        bail!("maintenance policy does not match this appliance installation");
    }
    verify_management_signature(policy, "signature", &policy.signature, DOMAIN, public_key)
}

fn validate_for_installation(policy: &SignedPolicy) -> Result<()> {
    let state = load_provisioning_state()?;
    validate(
        policy,
        &state.plan.reserved_device_id,
        state.session_id,
        &state.management_signing_public_key_b64,
    )
}

fn check_revision(previous: &SignedPolicy, next: &SignedPolicy) -> Result<()> {
    if next.provisioning_session_id != previous.provisioning_session_id
        || next.device_incarnation_id != previous.device_incarnation_id
        || next.revision < previous.revision
        || (next.revision == previous.revision && next != previous)
    {
        bail!("maintenance policy replay or conflicting revision");
    }
    Ok(())
}

/// Unprivileged delivery does not confer root authority. Root verifies again.
pub fn store(policy: Option<SignedPolicy>) -> Result<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    validate_for_installation(&policy)?;
    if let Some(previous) = read_optional_bounded_json::<SignedPolicy>(Path::new(INBOX), 65536) {
        check_revision(&previous, &policy)?;
        if previous == policy {
            return Ok(());
        }
    }
    write_atomic_json(Path::new(INBOX), &policy, 0o600)
}

fn read_control() -> Result<Option<SignedPolicy>> {
    let path = Path::new(CONTROL);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!("unsafe root maintenance policy");
    }
    let policy = read_bounded_json(path, 65536)?;
    validate_for_installation(&policy)?;
    Ok(Some(policy))
}

/// Called by a root oneshot without opening the agent's live database.
pub fn apply() -> Result<()> {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/lock/cybex-james/update-schedule.lock")?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        bail!("unsafe maintenance policy lock");
    }
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if !Path::new(INBOX).try_exists()? {
        return Ok(());
    }
    let policy: SignedPolicy = read_bounded_json(Path::new(INBOX), 65536)?;
    validate_for_installation(&policy)?;
    if let Some(previous) = read_control()? {
        check_revision(&previous, &policy)?;
        if previous == policy {
            return Ok(());
        }
    }
    // This file contains public signed policy only; the agent must report its
    // applied revision. Root ownership prevents the agent forging acceptance.
    write_atomic_json(Path::new(CONTROL), &policy, 0o644)
}

pub fn report() -> Value {
    match read_control() {
        Ok(Some(policy)) => {
            json!({"revision":policy.revision,"schedule":policy.schedule,"run_now_attempt_id":policy.run_now.map(|now| now.attempt_id)})
        }
        Ok(None) => json!({"revision":0}),
        Err(_) => json!({"error":"invalid_applied_schedule"}),
    }
}

/// The manual exception matches one immutable attempt, never all future updates.
pub fn readiness(now: DateTime<Utc>) -> Result<&'static str> {
    let Some(policy) = read_control()? else {
        return Ok("legacy");
    };
    let request: StoredApplianceUpdate = read_bounded_json(Path::new(UPDATE_REQUEST_PATH), 65536)?;
    let immediate = policy.run_now.as_ref().is_some_and(|allow| {
        allow.matches(
            request.attempt_id,
            &request.release.release_id,
            &request.release.cybex_repository_snapshot.sha256,
        )
    });
    if immediate || policy.schedule.includes(now)? {
        Ok("ready")
    } else {
        Ok("waiting")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn schedule() -> Schedule {
        Schedule {
            timezone: "Europe/Amsterdam".into(),
            weekdays: (0..7).collect(),
            start: "02:00".into(),
            duration_minutes: 120,
        }
    }
    fn instant(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }

    #[test]
    fn nightly_policy_handles_boundaries_dst_and_cross_midnight() {
        let s = schedule();
        assert!(s.includes(instant("2026-09-22T00:00:00Z")).unwrap());
        assert!(!s.includes(instant("2026-09-22T02:00:00Z")).unwrap());
        assert!(s.includes(instant("2026-10-25T00:30:00Z")).unwrap());
        assert!(s.includes(instant("2026-10-25T01:30:00Z")).unwrap());
        let overnight = Schedule {
            weekdays: vec![0],
            start: "23:30".into(),
            ..s
        };
        assert!(overnight.includes(instant("2026-09-20T23:00:00Z")).unwrap());
        assert!(!overnight.includes(instant("2026-09-21T23:00:00Z")).unwrap());
    }

    #[test]
    fn a_manual_exception_cannot_authorize_another_release_or_attempt() {
        let attempt = uuid::Uuid::new_v4();
        let permission = ImmediateUpdate {
            attempt_id: attempt,
            release_id: "0.2.9".into(),
            package_snapshot_sha256: "a".repeat(64),
        };
        assert!(permission.matches(attempt, "0.2.9", &"a".repeat(64)));
        assert!(!permission.matches(uuid::Uuid::new_v4(), "0.2.9", &"a".repeat(64)));
        assert!(!permission.matches(attempt, "0.2.10", &"a".repeat(64)));
        assert!(!permission.matches(attempt, "0.2.9", &"b".repeat(64)));
    }

    #[test]
    fn signatures_bind_schedule_manual_attempt_and_installation() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let session = uuid::Uuid::new_v4();
        let mut policy = SignedPolicy {
            schema: "cybex.james.update-schedule.v1".into(),
            device_id: "dev_example".into(),
            device_incarnation_id: uuid::Uuid::new_v4(),
            provisioning_session_id: session,
            revision: 1,
            schedule: schedule(),
            run_now: Some(ImmediateUpdate {
                attempt_id: uuid::Uuid::new_v4(),
                release_id: "0.2.9".into(),
                package_snapshot_sha256: "a".repeat(64),
            }),
            signature: String::new(),
        };
        let mut value = serde_json::to_value(&policy).unwrap();
        value.as_object_mut().unwrap().remove("signature");
        let mut payload = DOMAIN.as_bytes().to_vec();
        payload.push(b'\n');
        payload.extend(serde_json::to_vec(&canonical_json(value)).unwrap());
        policy.signature = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
        let public = STANDARD.encode(key.verifying_key().to_bytes());
        assert!(validate(&policy, "dev_example", session, &public).is_ok());
        assert!(validate(&policy, "dev_other", session, &public).is_err());
        assert!(validate(&policy, "dev_example", uuid::Uuid::new_v4(), &public).is_err());
        let mut tampered = policy.clone();
        tampered.run_now.as_mut().unwrap().attempt_id = uuid::Uuid::new_v4();
        assert!(validate(&tampered, "dev_example", session, &public).is_err());
        assert!(check_revision(&policy, &tampered).is_err());
        tampered.revision = 0;
        assert!(check_revision(&policy, &tampered).is_err());
        assert!(check_revision(&policy, &policy).is_ok());
    }
}
