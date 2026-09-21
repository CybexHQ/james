//! Unsigned fixture transport never replaces the signed runtime identity.
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, bail};
use reqwest::{Client, Url, header};

use super::{
    DesiredWorkstationNetboot, WorkstationNetbootDescriptor, sha256_bytes,
    validate_descriptor_with_policy,
};

pub(super) fn validate_desired(
    desired: &DesiredWorkstationNetboot,
    key: &str,
    allow_private: bool,
) -> Result<()> {
    // The historical development flag skips signatures. It must never grant
    // authority to the separate unsigned qualification transport.
    validate_descriptor_with_policy(
        &desired.descriptor,
        key,
        allow_private && desired.bundle_transport_url.is_none(),
    )?;
    if let Some(value) = desired.bundle_transport_url.as_deref() {
        validate_url(value, &desired.descriptor)?;
    }
    Ok(())
}

pub(super) fn validate_url(value: &str, descriptor: &WorkstationNetbootDescriptor) -> Result<()> {
    let invalid = || anyhow::anyhow!("workstation netboot descriptor transport URL is invalid");
    if value.len() > 4096 {
        return Err(invalid());
    }
    let url = Url::parse(value).map_err(|_| invalid())?;
    let ip = url
        .host_str()
        .and_then(|host| host.parse::<Ipv4Addr>().ok())
        .ok_or_else(invalid)?;
    let filename = Url::parse(&descriptor.url)
        .map_err(|_| invalid())?
        .path_segments()
        .and_then(|mut parts| parts.next_back().map(str::to_owned))
        .ok_or_else(invalid)?;
    let authority = value
        .strip_prefix("http://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(host, _)| host)
        .ok_or_else(invalid)?;
    let port = authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(invalid)?;
    // Raw reconstruction also rejects URL-parser normalization: encoded path,
    // dot segments, alternate IPv4 spellings, whitespace, credentials, default
    // port omission and padded ports. Explicit :80 is valid despite Url's
    // normalized serialization dropping that default port.
    if !ip.is_private()
        || filename.is_empty()
        || filename
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)))
        || value != format!("http://{ip}:{port}/{filename}")
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn attempt_identity(descriptor_sha256: &str, transport: Option<&str>) -> String {
    match transport {
        None => descriptor_sha256.to_owned(),
        Some(value) => sha256_bytes(
            format!(
                "CYBEX-WORKSTATION-TRANSPORT-V1\n{descriptor_sha256}\n{}\n",
                sha256_bytes(value.as_bytes())
            )
            .as_bytes(),
        ),
    }
}

pub(super) fn raw_attempt_identity(
    descriptor_sha256: &str,
    transport: Option<&serde_json::Value>,
) -> String {
    match transport {
        None | Some(serde_json::Value::Null) => attempt_identity(descriptor_sha256, None),
        Some(serde_json::Value::String(value)) => attempt_identity(descriptor_sha256, Some(value)),
        Some(value) => sha256_bytes(
            format!("CYBEX-WORKSTATION-MALFORMED-TRANSPORT-V1\n{descriptor_sha256}\n{value}\n")
                .as_bytes(),
        ),
    }
}

pub(super) fn partial_path(
    staging: &Path,
    descriptor: &WorkstationNetbootDescriptor,
    transport: Option<&str>,
) -> Result<PathBuf> {
    let descriptor_sha256 = sha256_bytes(&serde_json::to_vec(descriptor)?);
    let identity = attempt_identity(&descriptor_sha256, transport);
    Ok(staging.join(format!("{}.{identity}.tar.zst.part", descriptor.sha256)))
}

/// Remove only this bundle's superseded partial downloads, including the legacy
/// unbound filename. Never reuse bytes from another descriptor/transport pair.
pub(super) async fn discard_other_partials(
    staging: &Path,
    descriptor: &WorkstationNetbootDescriptor,
    current: &Path,
) -> Result<()> {
    let prefix = format!("{}.", descriptor.sha256);
    let mut entries = tokio::fs::read_dir(staging).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.path() == current {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let owned = name == format!("{}.tar.zst.part", descriptor.sha256)
            || name
                .strip_prefix(&prefix)
                .and_then(|tail| tail.strip_suffix(".tar.zst.part"))
                .is_some_and(|identity| {
                    identity.len() == 64
                        && identity
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                });
        if owned {
            if !entry.file_type().await?.is_file() {
                bail!("workstation netboot partial path is not a regular file");
            }
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

pub(super) fn client() -> Result<Client> {
    Ok(Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(90))
        .timeout(Duration::from_secs(30 * 60))
        .build()?)
}

pub(super) async fn get(
    value: &str,
    descriptor: &WorkstationNetbootDescriptor,
    offset: u64,
) -> Result<reqwest::Response> {
    validate_url(value, descriptor)?;
    let mut request = client()?
        .get(value)
        .header(header::ACCEPT_ENCODING, "identity");
    if offset > 0 {
        request = request.header(header::RANGE, format!("bytes={offset}-"));
    }
    request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("download workstation netboot fixture transport failed"))
}
