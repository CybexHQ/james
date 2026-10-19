//! Signed appliance outputs available to an otherwise isolated source preflight.
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;

use crate::{cache, nix_command, subprocess::run_bounded_command};

pub(crate) async fn authenticated_outputs(
    program: &str,
    paths: &BTreeSet<String>,
    release_key: &str,
) -> Result<HashSet<String>> {
    let mut authenticated = HashSet::new();
    if release_key.is_empty() || paths.is_empty() {
        return Ok(authenticated);
    }
    let key = format!("tiaris-nest-appliance-1:{release_key}");
    cache::parse_cache_public_key(&key)?;
    let paths = paths.iter().collect::<Vec<_>>();
    for chunk in paths.chunks(100) {
        let mut command = nix_command::tokio_command(program);
        command
            .args(["--store", "daemon", "path-info", "--json"])
            .args(chunk)
            .env("LC_ALL", "C")
            .env("LANG", "C");
        let output = run_bounded_command(
            command,
            Duration::from_secs(120),
            4 * 1024 * 1024,
            64 * 1024,
            "query signed appliance seed metadata",
        )
        .await?;
        // Missing paths can produce a nonzero exit with partial JSON. Only
        // complete, independently authenticated records grant any authority.
        let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
            continue;
        };
        for path in chunk {
            let info = match &value {
                Value::Object(entries) => entries.get(path.as_str()),
                Value::Array(entries) => entries
                    .iter()
                    .find(|entry| entry.get("path").and_then(Value::as_str) == Some(path.as_str())),
                _ => None,
            };
            if info
                .is_some_and(|info| cache::verify_signed_store_path_info(path, info, &key).is_ok())
            {
                authenticated.insert((*path).clone());
            }
        }
    }
    Ok(authenticated)
}
