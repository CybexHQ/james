//! Narrow handoff between signed Management configuration and the privileged
//! appliance PXE supervisor. The main service never gains network privileges.
use crate::AppState;
use anyhow::{Result, bail};
use axum::{Json, extract::State};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub const CAPABILITY: &str = "pxe_proxy_v1";
const STATUS_PATH: &str = "/run/cybex-james-pxe/status.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Desired {
    pub schema: String,
    pub server_device_id: String,
    pub complete: bool,
    pub peers: Vec<Peer>,
    pub clients: Vec<Client>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub server_device_id: String,
    pub address: String,
    pub mac: String,
    pub bootloader_filename: String,
    pub proxy_capable: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub mac: String,
    pub server_device_id: Option<String>,
}

pub fn persist(state: &AppState, desired: Option<&Desired>) -> Result<()> {
    if !crate::appliance::is_managed_appliance() {
        return Ok(());
    }
    persist_at(&state.config.manage.state_path, desired)
}

fn persist_at(state_path: &Path, desired: Option<&Desired>) -> Result<()> {
    let parent = state_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("PXE state directory missing"))?;
    let path = parent.join("pxe-discovery.json");
    let value = json!({"received_at":Utc::now().timestamp(), "desired":desired});
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() > 2 * 1024 * 1024 {
        bail!("PXE discovery inventory exceeds bound");
    }
    let temporary = parent.join(format!(".pxe-discovery-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn status() -> Value {
    read_status(Path::new(STATUS_PATH), Utc::now().timestamp())
        .unwrap_or_else(|| json!({"status":"unavailable","reason":"supervisor_unavailable","operational":false,"eligible":false}))
}

fn read_status(path: &Path, now: i64) -> Option<Value> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    if value.get("schema")?.as_str()? != "cybex.james.pxe-status.v1" {
        return None;
    }
    let age = now.checked_sub(value.get("checked_at")?.as_i64()?)?;
    if !(0..=45).contains(&age) {
        return None;
    }
    let status = value.get("status")?.as_str()?;
    if !matches!(
        status,
        "active" | "standby" | "external" | "starting" | "unavailable"
    ) {
        return None;
    }
    let reason = value.get("reason")?.as_str()?;
    if reason.len() > 80 || !reason.bytes().all(|c| c.is_ascii_lowercase() || c == b'_') {
        return None;
    }
    Some(json!({"status":status,"reason":reason,
        "identity": value.get("identity").and_then(Value::as_str).filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
        "operational":matches!(status,"active"|"standby"),
        "eligible":value.get("eligible").and_then(Value::as_bool).unwrap_or(false)}))
}

/// Public, credential-free liveness used only after matching the peer's MAC
/// on the managed interface. Never exposes tenant or boot-client inventories.
pub async fn candidate(State(state): State<AppState>) -> Json<Value> {
    let status = status();
    let ready = crate::readiness::probe(&state).await.ready;
    Json(
        json!({"schema":"cybex.james.pxe-candidate.v1", "ready":ready, "identity":status.get("identity"),
        "eligible":ready && status.get("eligible").and_then(Value::as_bool) == Some(true)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn inventory_is_atomic_private_and_revoked_when_removed_from_manage() {
        let directory =
            std::env::temp_dir().join(format!("pxe-inventory-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let state = directory.join("manage-state.json");
        let desired = Desired {
            schema: "cybex.james.pxe-discovery.v1".into(),
            server_device_id: "qualification".into(),
            complete: true,
            peers: Vec::new(),
            clients: Vec::new(),
        };
        persist_at(&state, Some(&desired)).unwrap();
        let path = directory.join("pxe-discovery.json");
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["desired"]["server_device_id"], "qualification");
        assert!(value["received_at"].as_i64().unwrap() <= Utc::now().timestamp());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        persist_at(&state, None).unwrap();
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(value["desired"].is_null());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn expired_or_future_supervisor_evidence_cannot_claim_availability() {
        let path = std::env::temp_dir().join(format!("pxe-status-{}", uuid::Uuid::new_v4()));
        fs::write(
            &path,
            json!({"schema":"cybex.james.pxe-status.v1","checked_at":100,
            "status":"active","reason":"proxy_ready","eligible":true})
            .to_string(),
        )
        .unwrap();
        assert_eq!(read_status(&path, 110).unwrap()["operational"], true);
        assert!(read_status(&path, 146).is_none());
        assert!(read_status(&path, 99).is_none());
        fs::remove_file(path).unwrap();
    }
}
