//! Untrusted wire values. Constructing a DTO never creates verified authority.
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledOriginBinding {
    pub schema: String,
    pub binding_id: String,
    pub organization_id: String,
    pub device_id: String,
    pub device_incarnation_id: String,
    pub device_public_key_sha256: String,
    pub provisioning_session_id: String,
    pub base_plan_sha256: String,
    pub base_signed_plan_sha256: String,
    pub source_origin: String,
    pub management_signing_key_sha256: String,
    pub issued_at: u64,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub release_version: String,
    pub compatibility_sha256: String,
    pub manifest_sha256: String,
    pub descriptor_sha256: String,
    pub system_closure_sha256: String,
    pub system_toplevel: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceOriginTransition {
    pub schema: String,
    pub transition_id: String,
    pub revision: u64,
    pub attempt_id: String,
    pub binding_sha256: String,
    pub organization_id: String,
    pub device_id: String,
    pub device_incarnation_id: String,
    pub device_public_key_sha256: String,
    pub provisioning_session_id: String,
    pub base_plan_sha256: String,
    pub base_signed_plan_sha256: String,
    pub source_origin: String,
    pub target_origin: String,
    pub source_system_generation: String,
    pub source: ReleaseIdentity,
    pub target: ReleaseIdentity,
    pub pair_authorization_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginContactRequest {
    pub schema: String,
    pub transition_id: String,
    pub transition_sha256: String,
    pub binding_sha256: String,
    pub attempt_id: String,
    pub revision: u64,
    pub organization_id: String,
    pub device_id: String,
    pub device_incarnation_id: String,
    pub target_origin: String,
    pub target_system_closure_sha256: String,
    pub target_system_generation: String,
    pub target_system_toplevel: String,
    pub boot_id: String,
    pub boot_nonce: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginContactAcknowledgement {
    pub schema: String,
    pub request_sha256: String,
    pub transition_id: String,
    pub transition_sha256: String,
    pub binding_sha256: String,
    pub attempt_id: String,
    pub revision: u64,
    pub organization_id: String,
    pub device_id: String,
    pub device_incarnation_id: String,
    pub target_origin: String,
    pub target_system_closure_sha256: String,
    pub target_system_generation: String,
    pub target_system_toplevel: String,
    pub boot_id: String,
    pub boot_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginEvidence {
    pub pair_authorization: String,
    pub source_compatibility: String,
    pub target_compatibility: String,
    pub source_manifest: String,
    pub target_manifest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginTransitionBundle {
    pub binding: InstalledOriginBinding,
    pub transition: DeviceOriginTransition,
    pub evidence: OriginEvidence,
}
pub(super) fn validate(kind: &str, v: &Value) -> Result<()> {
    let fields: &[(&str, &str)] = match kind {
        "InstalledOriginBinding" => &[
            ("schema", "literal:tiaris.nest.installed-origin-binding.v1"),
            ("binding_id", "Uuid"),
            ("organization_id", "Uuid"),
            ("device_id", "DeviceId"),
            ("device_incarnation_id", "Uuid"),
            ("device_public_key_sha256", "Sha256"),
            ("provisioning_session_id", "Uuid"),
            ("base_plan_sha256", "Sha256"),
            ("base_signed_plan_sha256", "Sha256"),
            ("source_origin", "Origin"),
            ("management_signing_key_sha256", "Sha256"),
            ("issued_at", "UnixSeconds"),
            ("signature", "Signature"),
        ],
        "ReleaseIdentity" => &[
            ("release_version", "Semver"),
            ("compatibility_sha256", "Sha256"),
            ("manifest_sha256", "Sha256"),
            ("descriptor_sha256", "Sha256"),
            ("system_closure_sha256", "Sha256"),
            ("system_toplevel", "StoreToplevel"),
        ],
        "DeviceOriginTransition" => &[
            ("schema", "literal:tiaris.nest.device-origin-transition.v1"),
            ("transition_id", "Uuid"),
            ("revision", "Revision"),
            ("attempt_id", "Uuid"),
            ("binding_sha256", "Sha256"),
            ("organization_id", "Uuid"),
            ("device_id", "DeviceId"),
            ("device_incarnation_id", "Uuid"),
            ("device_public_key_sha256", "Sha256"),
            ("provisioning_session_id", "Uuid"),
            ("base_plan_sha256", "Sha256"),
            ("base_signed_plan_sha256", "Sha256"),
            ("source_origin", "Origin"),
            ("target_origin", "Origin"),
            ("source_system_generation", "Generation"),
            ("source", "ReleaseIdentity"),
            ("target", "ReleaseIdentity"),
            ("pair_authorization_sha256", "Sha256"),
            ("issued_at", "UnixSeconds"),
            ("expires_at", "UnixSeconds"),
            ("signature", "Signature"),
        ],
        "OriginContactRequest" => &[
            ("schema", "literal:tiaris.nest.origin-contact.v1"),
            ("transition_id", "Uuid"),
            ("transition_sha256", "Sha256"),
            ("binding_sha256", "Sha256"),
            ("attempt_id", "Uuid"),
            ("revision", "Revision"),
            ("organization_id", "Uuid"),
            ("device_id", "DeviceId"),
            ("device_incarnation_id", "Uuid"),
            ("target_origin", "Origin"),
            ("target_system_closure_sha256", "Sha256"),
            ("target_system_generation", "Generation"),
            ("target_system_toplevel", "StoreToplevel"),
            ("boot_id", "Uuid"),
            ("boot_nonce", "Nonce"),
        ],
        "OriginContactAcknowledgement" => &[
            ("schema", "literal:tiaris.nest.origin-contact-ack.v1"),
            ("request_sha256", "Sha256"),
            ("transition_id", "Uuid"),
            ("transition_sha256", "Sha256"),
            ("binding_sha256", "Sha256"),
            ("attempt_id", "Uuid"),
            ("revision", "Revision"),
            ("organization_id", "Uuid"),
            ("device_id", "DeviceId"),
            ("device_incarnation_id", "Uuid"),
            ("target_origin", "Origin"),
            ("target_system_closure_sha256", "Sha256"),
            ("target_system_generation", "Generation"),
            ("target_system_toplevel", "StoreToplevel"),
            ("boot_id", "Uuid"),
            ("boot_nonce", "Nonce"),
            ("issued_at", "UnixSeconds"),
            ("expires_at", "UnixSeconds"),
            ("signature", "Signature"),
        ],
        _ => bail!("unknown wire type"),
    };
    let object = v.as_object().ok_or_else(|| anyhow!("expected object"))?;
    ensure!(
        object.len() == fields.len() && fields.iter().all(|(f, _)| object.contains_key(*f)),
        "unknown or missing wire field"
    );
    for (field, kind) in fields {
        let value = &v[field];
        if *kind == "ReleaseIdentity" {
            validate(kind, value)?;
            continue;
        }
        if matches!(*kind, "Revision" | "UnixSeconds") {
            ensure!(
                value
                    .as_u64()
                    .is_some_and(|n| (1..=9_007_199_254_740_991).contains(&n)),
                "integer outside bound"
            );
            continue;
        }
        let s = value.as_str().ok_or_else(|| anyhow!("expected string"))?;
        ensure!(
            s.is_ascii() && !s.bytes().any(|b| b.is_ascii_control()),
            "non-ASCII/control wire string"
        );
        match *kind {
            "Uuid" => {
                let id = uuid::Uuid::parse_str(s)?;
                ensure!(!id.is_nil() && id.to_string() == s, "noncanonical UUID");
            }
            "Sha256" => release_v3::require_hex(s, 64)?,
            "DeviceId" => {
                release_v3::require_hex(
                    s.strip_prefix("dev_")
                        .ok_or_else(|| anyhow!("device prefix"))?,
                    32,
                )?;
            }
            "Origin" => origin(s)?,
            "Generation" => {
                let n: u64 = s.parse()?;
                ensure!(n > 0 && n.to_string() == s, "noncanonical generation");
            }
            "Semver" => {
                version(s)?;
            }
            "StoreToplevel" => {
                ensure!(s.len() <= 4096, "toplevel bound");
                release_v3::store_path(s)?;
            }
            "Signature" => {
                url_bytes(s, 64)?;
            }
            "Nonce" => {
                url_bytes(s, 32)?;
            }
            literal if literal.starts_with("literal:") => {
                ensure!(s == &literal[8..], "wrong schema")
            }
            _ => bail!("unsupported wire primitive"),
        }
    }
    Ok(())
}
pub(super) fn url_bytes(s: &str, length: usize) -> Result<Vec<u8>> {
    ensure!(s.len() == (length * 8).div_ceil(6), "base64url bound");
    let bytes = URL_SAFE_NO_PAD.decode(s)?;
    ensure!(
        bytes.len() == length && URL_SAFE_NO_PAD.encode(&bytes) == s,
        "noncanonical base64url"
    );
    Ok(bytes)
}
pub(super) fn version(s: &str) -> Result<semver::Version> {
    ensure!(s.len() <= 128, "version bound");
    let v = semver::Version::parse(s)?;
    ensure!(v.to_string() == s, "noncanonical version");
    Ok(v)
}
// Match the release-tool origin grammar without URL parser normalization of
// IPv4 shorthand, explicit default ports, empty paths or DNS labels.
pub(super) fn origin(s: &str) -> Result<()> {
    ensure!(s.len() <= 2048 && s.is_ascii(), "origin bound");
    let authority = s
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("HTTPS origin required"))?;
    let (host, port) = if authority.starts_with('[') {
        let (h, p) = authority
            .split_once(']')
            .ok_or_else(|| anyhow!("IPv6 origin"))?;
        let ip: std::net::Ipv6Addr = h[1..].parse()?;
        // Python ipaddress.compressed (the normative release tool) uses hex
        // for mapped IPv4 addresses; Rust Display uses dotted decimal there.
        let host = if ip.to_ipv4_mapped().is_some() {
            let segments = ip.segments();
            format!("::ffff:{:x}:{:x}", segments[6], segments[7])
        } else {
            ip.to_string()
        };
        ensure!(format!("[{host}") == h, "noncanonical IPv6");
        (format!("{h}]"), p)
    } else if let Some((h, _)) = authority.split_once(':') {
        (h.to_owned(), &authority[h.len()..])
    } else {
        (authority.to_owned(), "")
    };
    if !port.is_empty() {
        let raw = port
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("origin port"))?;
        let n: u16 = raw.parse()?;
        ensure!(
            n != 0 && n != 443 && n.to_string() == raw,
            "noncanonical origin port"
        );
    }
    if !host.starts_with('[') {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            ensure!(ip.to_string() == host, "IPv4 origin");
        } else {
            ensure!(
                host.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')),
                "noncanonical origin host"
            );
        }
    }
    Ok(())
}
