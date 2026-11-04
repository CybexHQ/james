//! Workstation cache seeds: the custom workstation outputs that
//! cache.nixos.org cannot serve (every output of the Tiaris agent and the
//! Blueprint-selected packages). The appliance carries them in its signed
//! system closure and lists them in [`MANIFEST_PATH`]. Workstations ask this
//! Nest's cache first, so each seed must also be published there, signed with
//! the Nest cache key; otherwise a runtime rollout, which asks Nest to build
//! nothing, leaves workstations compiling the agent themselves.
//!
//! Publication needs no build job. It runs when the daemon starts, is retried
//! while a seed fails, and runs again when the manifest changes and once a day
//! to repair members a scrub withdrew. Only seeds that are valid in the local
//! store and carry the appliance release signature are copied, through the
//! same `nix copy` and signed closure verification as a build export; a seed
//! whose verified closure is already in the cache is left alone.
//!
//! Seeds are not inventory rows: Tiaris never sees them as artifacts and
//! retention never evicts them. The cache sweep keeps the closures of the
//! seeds the current manifest lists; seeds of an earlier release are no
//! longer listed and are swept like any other unreferenced member.
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::task;
use tracing::{debug, info, warn};

use crate::{AppState, config::AppConfig};

/// Installed by the appliance activation script from `nixos-appliance/module.nix`.
pub const MANIFEST_PATH: &str = "/usr/share/tiaris-nest/workstation-cache-seeds.json";
const MANIFEST_SCHEMA: &str = "tiaris.nest.workstation-cache-seeds.v1";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SEEDS: usize = 1024;
/// How often the background task looks at the manifest; also the retry delay
/// after a pass in which a seed failed.
const POLL_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// A seed the local store could not authenticate is looked at again after
/// this long: the daemon query may have failed transiently.
const UNAUTHENTICATED_RECHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// A complete pass is verified again after this long, so members a scrub
/// quarantined are published again.
const REVERIFY_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const CLOSURE_SIZE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    store_paths: Vec<String>,
}

/// What one publication pass did with the listed seeds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Publication {
    pub listed: usize,
    pub published: usize,
    pub already_published: usize,
    /// Not valid in the local store, or not signed by the appliance release key.
    pub unauthenticated: usize,
    pub failed: usize,
}

/// The last pass that needs no retry: the manifest it read, when it ran, and
/// how long its result stands.
struct Settled {
    digest: Option<[u8; 32]>,
    at: Instant,
    recheck_after: Duration,
}

/// Publish the seeds on start and keep them published. Never fatal: failures
/// are logged and retried on the next poll.
pub fn spawn(state: AppState) {
    if !state.config.cache.enabled {
        return;
    }
    tokio::spawn(async move {
        let mut settled: Option<Settled> = None;
        loop {
            let digest = manifest_digest(&state.config.cache.seed_manifest_path).await;
            if pass_due(settled.as_ref(), digest, Instant::now()) {
                let outcome = publish(&state.config).await;
                settled = recheck_after(&outcome).map(|recheck_after| Settled {
                    digest,
                    at: Instant::now(),
                    recheck_after,
                });
                match outcome {
                    Ok(publication) if publication.failed == 0 => {
                        if publication.published + publication.unauthenticated > 0 {
                            info!(
                                listed = publication.listed,
                                published = publication.published,
                                already_published = publication.already_published,
                                unauthenticated = publication.unauthenticated,
                                "workstation cache seeds checked"
                            );
                        } else {
                            debug!(
                                listed = publication.listed,
                                "workstation cache seeds are published"
                            );
                        }
                    }
                    Ok(publication) => warn!(
                        listed = publication.listed,
                        published = publication.published,
                        failed = publication.failed,
                        retry_seconds = POLL_INTERVAL.as_secs(),
                        "some workstation cache seeds could not be published; retrying"
                    ),
                    Err(error) => warn!(
                        error = %safe_error(&error),
                        retry_seconds = POLL_INTERVAL.as_secs(),
                        "workstation cache seed publication failed; retrying"
                    ),
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
}

/// How long a pass's result stands; `None` retries on the next poll.
fn recheck_after(outcome: &Result<Publication>) -> Option<Duration> {
    match outcome {
        Ok(publication) if publication.failed == 0 && publication.unauthenticated == 0 => {
            Some(REVERIFY_INTERVAL)
        }
        Ok(publication) if publication.failed == 0 => Some(UNAUTHENTICATED_RECHECK_INTERVAL),
        _ => None,
    }
}

/// A pass is due until one settles, then again when the manifest changes (a
/// new generation) or the settled result is due for a recheck.
fn pass_due(settled: Option<&Settled>, digest: Option<[u8; 32]>, now: Instant) -> bool {
    settled.is_none_or(|settled| {
        settled.digest != digest
            || now.saturating_duration_since(settled.at) >= settled.recheck_after
    })
}

async fn manifest_digest(path: &Path) -> Option<[u8; 32]> {
    let path = path.to_path_buf();
    task::spawn_blocking(move || read_manifest_bytes(&path))
        .await
        .ok()?
        .ok()?
        .map(|raw| Sha256::digest(raw).into())
}

/// Publish every listed seed that is authentic and not yet in the cache.
pub async fn publish(config: &AppConfig) -> Result<Publication> {
    let mut publication = Publication::default();
    if !config.cache.enabled {
        return Ok(publication);
    }
    let manifest_path = config.cache.seed_manifest_path.clone();
    let Some(seeds) = task::spawn_blocking(move || read_manifest(&manifest_path))
        .await
        .context("join workstation cache seed manifest task")??
    else {
        debug!("no workstation cache seed manifest; nothing to publish");
        return Ok(publication);
    };
    publication.listed = seeds.len();
    if seeds.is_empty() {
        return Ok(publication);
    }
    if config.update.trusted_public_key.is_empty() {
        warn!(
            "no appliance release key is configured; workstation cache seeds cannot be authenticated"
        );
        publication.unauthenticated = seeds.len();
        return Ok(publication);
    }
    let authenticated = crate::build_signed_seeds::authenticated_outputs(
        &config.build.nix_binary,
        &seeds,
        &config.update.trusted_public_key,
    )
    .await
    .context("authenticate workstation cache seeds")?;
    let mut candidates = Vec::new();
    for seed in seeds {
        if authenticated.contains(&seed) {
            candidates.push(seed);
        } else {
            publication.unauthenticated += 1;
            info!(
                store_path = %seed,
                "not publishing workstation cache seed: it is not valid in the local store or lacks the appliance release signature"
            );
        }
    }
    if candidates.is_empty() {
        return Ok(publication);
    }

    let public_key = super::ensure_signing_key(config).await?;
    let missing = unpublished(config, candidates.clone(), &public_key).await?;
    publication.already_published = candidates.len() - missing.len();
    if missing.is_empty() {
        return Ok(publication);
    }
    let closure_sizes = closure_sizes(&config.build.nix_binary, &missing).await;
    for seed in missing {
        let closure_size_bytes = closure_sizes.get(&seed).copied().unwrap_or(0);
        match export(config, &seed, &public_key, closure_size_bytes).await {
            Ok(()) => {
                publication.published += 1;
                info!(store_path = %seed, "published workstation cache seed to the Nest cache");
            }
            Err(error) => {
                publication.failed += 1;
                warn!(
                    store_path = %seed,
                    error = %safe_error(&error),
                    "could not publish workstation cache seed to the Nest cache"
                );
            }
        }
    }
    Ok(publication)
}

/// The listed seeds, or `None` when this system ships no manifest.
fn read_manifest(path: &Path) -> Result<Option<BTreeSet<String>>> {
    read_manifest_bytes(path)?
        .map(|raw| parse_manifest(&raw))
        .transpose()
}

/// Store paths whose cached closures the sweep keeps. An unreadable manifest
/// must not stop retention, so it protects nothing; publication reports it.
pub(super) fn sweep_roots(path: &Path) -> Vec<String> {
    match read_manifest(path) {
        Ok(seeds) => seeds.unwrap_or_default().into_iter().collect(),
        Err(error) => {
            warn!(
                error = %safe_error(&error),
                "workstation cache seed manifest is unreadable; the cache sweep keeps no seeds"
            );
            Vec::new()
        }
    }
}

fn read_manifest_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("open workstation cache seed manifest {}", path.display())
            });
        }
    };
    let metadata = file
        .metadata()
        .context("inspect workstation cache seed manifest")?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        bail!("workstation cache seed manifest is not a bounded regular file");
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut raw)
        .context("read workstation cache seed manifest")?;
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("workstation cache seed manifest exceeded its size limit");
    }
    Ok(Some(raw))
}

fn parse_manifest(raw: &[u8]) -> Result<BTreeSet<String>> {
    let manifest: Manifest =
        serde_json::from_slice(raw).context("parse workstation cache seed manifest")?;
    if manifest.schema != MANIFEST_SCHEMA {
        bail!("unsupported workstation cache seed manifest schema");
    }
    if manifest.store_paths.len() > MAX_SEEDS {
        bail!("workstation cache seed manifest lists more than {MAX_SEEDS} store paths");
    }
    let mut seeds = BTreeSet::new();
    for store_path in manifest.store_paths {
        super::validate_store_path(&store_path)
            .context("validate workstation cache seed store path")?;
        seeds.insert(store_path);
    }
    Ok(seeds)
}

/// The seeds whose signed closure is not already complete in the cache.
async fn unpublished(
    config: &AppConfig,
    seeds: Vec<String>,
    public_key: &str,
) -> Result<Vec<String>> {
    let _mutation_lock = super::acquire_cache_mutation_lock(config).await?;
    let cache_root = config.cache.root_dir.clone();
    let public_key = public_key.to_string();
    task::spawn_blocking(move || {
        seeds
            .into_iter()
            .filter(|seed| {
                super::build_closure_manifest(&cache_root, seed, None, &public_key, &mut Vec::new())
                    .is_err()
            })
            .collect()
    })
    .await
    .context("join workstation cache seed check task")
}

/// Copy one seed's closure into the cache and verify it like a build export.
/// A closure that fails verification is quarantined and retried later.
async fn export(
    config: &AppConfig,
    store_path: &str,
    public_key: &str,
    closure_size_bytes: u64,
) -> Result<()> {
    let _mutation_lock = super::acquire_cache_mutation_lock(config).await?;
    crate::disk::ensure_headroom(
        &config.cache.root_dir,
        closure_size_bytes,
        "Nest cache seed export",
    )?;
    let cache_dir = config.cache.root_dir.clone();
    let quarantine_dir = config.paths.data_dir.join("cache-quarantine");
    let private_key_path = config.cache.private_key_path.clone();
    let nix_binary = config.build.nix_binary.clone();
    let export_timeout = Duration::from_secs(config.build.timeout_seconds);
    let store_path = store_path.to_string();
    let public_key = public_key.to_string();
    task::spawn_blocking(move || {
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create cache directory {}", cache_dir.display()))?;
        super::prepare_quarantine_root(&cache_dir, &quarantine_dir)?;
        super::copy_store_path_to_cache_controlled(
            &nix_binary,
            &super::export_destination(&cache_dir, &private_key_path),
            &cache_dir,
            &quarantine_dir,
            &private_key_path,
            &store_path,
            export_timeout,
            &Default::default(),
        )?;
        super::build_or_quarantine_closure_manifest(
            &cache_dir,
            &quarantine_dir,
            &store_path,
            None,
            &public_key,
        )?;
        Ok(())
    })
    .await
    .context("join workstation cache seed export task")?
}

/// Closure NAR sizes for the disk preflight. Best effort: an unknown size
/// still requires the standard headroom.
async fn closure_sizes(nix_binary: &str, store_paths: &[String]) -> HashMap<String, u64> {
    let mut command = crate::nix_command::tokio_command(nix_binary);
    command
        .args(["--store", "daemon", "path-info", "--closure-size", "--json"])
        .args(store_paths)
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = match crate::subprocess::run_bounded_command(
        command,
        CLOSURE_SIZE_TIMEOUT,
        4 * 1024 * 1024,
        64 * 1024,
        "query workstation cache seed closure sizes",
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            debug!(error = %safe_error(&error), "could not query workstation cache seed closure sizes");
            return HashMap::new();
        }
    };
    let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
        return HashMap::new();
    };
    store_paths
        .iter()
        .filter_map(|store_path| {
            let info = match &value {
                Value::Object(entries) => entries.get(store_path.as_str()),
                Value::Array(entries) => entries.iter().find(|entry| {
                    entry.get("path").and_then(Value::as_str) == Some(store_path.as_str())
                }),
                _ => None,
            }?;
            let size = info.get("closureSize").and_then(Value::as_u64)?;
            Some((store_path.clone(), size))
        })
        .collect()
}

fn safe_error(error: &anyhow::Error) -> String {
    crate::redact::redact_sensitive_key_values(&format!("{error:#}"))
        .chars()
        .take(1024)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;
    use crate::{
        cache::{
            encode_nix_base32_sha256, narinfo_filename_for_store_path, remove_artifacts_by_key,
            tests::{test_public_key, test_store_path, test_temp_dir, write_manifest_cache_member},
        },
        db,
    };

    fn release_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    /// A Nest with a fake `nix`: `path-info` prints the local store's signed
    /// records, and `copy` publishes the staged cache members.
    struct Fixture {
        root: PathBuf,
        config: AppConfig,
        staging: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = test_temp_dir(label);
            let staging = root.join("staging");
            fs::create_dir_all(staging.join("nar")).unwrap();
            let mut config = AppConfig::default();
            config.paths.data_dir = root.join("data");
            config.cache.root_dir = root.join("cache");
            config.cache.seed_manifest_path = root.join("workstation-cache-seeds.json");
            config.cache.private_key_path = root.join("keys/cache-private.pem");
            config.cache.public_key_path = root.join("keys/cache-public.pem");
            config.update.trusted_public_key =
                BASE64_STANDARD.encode(release_key().verifying_key().as_bytes());
            fs::create_dir_all(root.join("keys")).unwrap();
            fs::create_dir_all(&config.cache.root_dir).unwrap();
            fs::write(
                &config.cache.private_key_path,
                "test-cache:not-used-by-fake-nix",
            )
            .unwrap();
            fs::write(&config.cache.public_key_path, test_public_key()).unwrap();
            let nix = root.join("fake-nix");
            fs::write(
                &nix,
                format!(
                    "#!/bin/sh\n\
                     set -eu\n\
                     case \" $* \" in\n\
                       *' copy '*)\n\
                         for last; do :; done\n\
                         printf '%s\\n' \"$last\" >> '{root}/copies'\n\
                         cp -R '{staging}/.' '{cache}/'\n\
                         ;;\n\
                       *' --closure-size '*) printf '{{}}' ;;\n\
                       *' path-info '*) cat '{root}/path-info.json' ;;\n\
                       *) exit 2 ;;\n\
                     esac\n",
                    root = root.display(),
                    staging = staging.display(),
                    cache = config.cache.root_dir.display(),
                ),
            )
            .unwrap();
            fs::set_permissions(&nix, fs::Permissions::from_mode(0o755)).unwrap();
            config.build.nix_binary = nix.display().to_string();
            Self {
                root,
                config,
                staging,
            }
        }

        fn write_manifest(&self, store_paths: &[&String]) {
            fs::write(
                &self.config.cache.seed_manifest_path,
                serde_json::to_vec(&json!({"schema": MANIFEST_SCHEMA, "store_paths": store_paths}))
                    .unwrap(),
            )
            .unwrap();
        }

        /// Local store records of `store_paths`, each signed by `key` under
        /// the appliance key name.
        fn write_path_info(&self, store_paths: &[(&String, &SigningKey)]) {
            let mut records = serde_json::Map::new();
            for (store_path, key) in store_paths {
                let fingerprint = format!(
                    "1;{store_path};sha256:{};42;",
                    encode_nix_base32_sha256(&[9; 32])
                );
                let signature = format!(
                    "tiaris-nest-appliance-1:{}",
                    BASE64_STANDARD.encode(key.sign(fingerprint.as_bytes()).to_bytes())
                );
                records.insert(
                    store_path.to_string(),
                    json!({"narHash": format!("sha256-{}", BASE64_STANDARD.encode([9; 32])),
                        "narSize": 42, "references": [], "signatures": [signature]}),
                );
            }
            fs::write(
                self.root.join("path-info.json"),
                serde_json::to_vec(&records).unwrap(),
            )
            .unwrap();
        }

        fn copies(&self) -> Vec<String> {
            fs::read_to_string(self.root.join("copies"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn published(&self, store_path: &str) -> bool {
            super::super::build_closure_manifest(
                &self.config.cache.root_dir,
                store_path,
                None,
                &test_public_key(),
                &mut Vec::new(),
            )
            .is_ok()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).ok();
        }
    }

    #[tokio::test]
    async fn publishes_only_authentic_unpublished_seeds_and_is_idempotent() {
        let fixture = Fixture::new("seed-publish");
        let agent = test_store_path('a', "tiaris-agent-0.1.0");
        let debug = test_store_path('b', "tiaris-agent-0.1.0-debug");
        let dependency = test_store_path('c', "glibc");
        let foreign = test_store_path('d', "foreign-signed");
        let absent = test_store_path('f', "not-in-store");
        write_manifest_cache_member(&fixture.staging, &dependency, b"dependency", &[]);
        write_manifest_cache_member(
            &fixture.staging,
            &agent,
            b"agent",
            std::slice::from_ref(&dependency),
        );
        write_manifest_cache_member(&fixture.config.cache.root_dir, &debug, b"debug", &[]);
        fixture.write_manifest(&[&agent, &debug, &foreign, &absent]);
        let other_key = SigningKey::from_bytes(&[8; 32]);
        fixture.write_path_info(&[
            (&agent, &release_key()),
            (&debug, &release_key()),
            (&foreign, &other_key),
        ]);

        let publication = publish(&fixture.config).await.unwrap();

        assert_eq!(
            publication,
            Publication {
                listed: 4,
                published: 1,
                already_published: 1,
                unauthenticated: 2,
                failed: 0,
            }
        );
        assert_eq!(fixture.copies(), vec![agent.clone()]);
        assert!(fixture.published(&agent));
        assert!(fixture.published(&debug));

        let again = publish(&fixture.config).await.unwrap();
        assert_eq!(again.published, 0);
        assert_eq!(again.already_published, 2);
        assert_eq!(fixture.copies(), vec![agent]);
    }

    #[tokio::test]
    async fn a_seed_that_fails_verification_is_quarantined_and_reported() {
        let fixture = Fixture::new("seed-quarantine");
        let agent = test_store_path('a', "tiaris-agent-0.1.0");
        let (_, nar) = write_manifest_cache_member(&fixture.staging, &agent, b"agent", &[]);
        fs::write(nar, b"tampered").unwrap();
        fixture.write_manifest(&[&agent]);
        fixture.write_path_info(&[(&agent, &release_key())]);

        let publication = publish(&fixture.config).await.unwrap();

        assert_eq!(publication.failed, 1);
        assert_eq!(publication.published, 0);
        assert_eq!(fixture.copies(), vec![agent.clone()]);
        let narinfo = narinfo_filename_for_store_path(&agent).unwrap();
        assert!(!fixture.config.cache.root_dir.join(&narinfo).exists());

        // The withdrawn record is copied again on the next pass.
        assert_eq!(publish(&fixture.config).await.unwrap().failed, 1);
        assert_eq!(fixture.copies().len(), 2);
    }

    #[tokio::test]
    async fn without_a_manifest_or_release_key_nothing_is_run() {
        let fixture = Fixture::new("seed-absent");
        let mut config = fixture.config.clone();
        config.build.nix_binary = fixture.root.join("missing-nix").display().to_string();
        assert_eq!(publish(&config).await.unwrap(), Publication::default());

        let agent = test_store_path('a', "tiaris-agent-0.1.0");
        fixture.write_manifest(&[&agent]);
        config.update.trusted_public_key.clear();
        let publication = publish(&config).await.unwrap();
        assert_eq!(publication.listed, 1);
        assert_eq!(publication.unauthenticated, 1);
        assert!(fixture.copies().is_empty());
    }

    #[test]
    fn manifest_requires_its_schema_and_canonical_store_paths() {
        let root = test_temp_dir("seed-manifest");
        let path = root.join("seeds.json");
        assert!(read_manifest(&path).unwrap().is_none());
        let agent = test_store_path('a', "tiaris-agent-0.1.0");
        fs::write(
            &path,
            json!({"schema": MANIFEST_SCHEMA, "store_paths": [agent, agent]}).to_string(),
        )
        .unwrap();
        assert_eq!(
            read_manifest(&path).unwrap().unwrap(),
            BTreeSet::from([agent.clone()])
        );
        for invalid in [
            json!({"schema": "other", "store_paths": [agent]}),
            json!({"schema": MANIFEST_SCHEMA, "store_paths": ["/tmp/agent"]}),
            json!({"schema": MANIFEST_SCHEMA, "store_paths": [format!("{agent}/bin")]}),
            json!({"schema": MANIFEST_SCHEMA, "store_paths": [agent], "extra": true}),
            json!({"schema": MANIFEST_SCHEMA}),
        ] {
            fs::write(&path, invalid.to_string()).unwrap();
            assert!(read_manifest(&path).is_err(), "accepted {invalid}");
        }
        assert!(sweep_roots(&path).is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn passes_repeat_on_failure_manifest_change_and_recheck() {
        let complete = Publication {
            listed: 2,
            already_published: 2,
            ..Default::default()
        };
        let unauthenticated = Publication {
            listed: 2,
            already_published: 1,
            unauthenticated: 1,
            ..Default::default()
        };
        let failed = Publication {
            listed: 2,
            failed: 1,
            ..Default::default()
        };
        assert_eq!(recheck_after(&Ok(complete)), Some(REVERIFY_INTERVAL));
        assert_eq!(
            recheck_after(&Ok(unauthenticated)),
            Some(UNAUTHENTICATED_RECHECK_INTERVAL)
        );
        assert_eq!(recheck_after(&Ok(failed)), None);
        assert_eq!(
            recheck_after(&Err(anyhow::anyhow!("nix copy failed"))),
            None
        );

        let now = Instant::now();
        let digest = Some([1; 32]);
        assert!(pass_due(None, digest, now));
        let settled = Settled {
            digest,
            at: now,
            recheck_after: REVERIFY_INTERVAL,
        };
        assert!(!pass_due(Some(&settled), digest, now + POLL_INTERVAL));
        assert!(pass_due(Some(&settled), Some([2; 32]), now));
        assert!(pass_due(Some(&settled), None, now));
        assert!(pass_due(Some(&settled), digest, now + REVERIFY_INTERVAL));
    }

    #[tokio::test]
    async fn cache_sweep_keeps_current_seed_closures_and_drops_earlier_seeds() {
        let pool = db::connect_with_url("sqlite::memory:").await.unwrap();
        db::migrate(&pool).await.unwrap();
        let root = test_temp_dir("seed-sweep");
        let cache_root = root.join("cache");
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = cache_root.clone();
        config.cache.seed_manifest_path = root.join("seeds.json");

        // Nix writes reference basenames; the sweep follows them.
        let members = [
            ('a', "tiaris-agent", Some(('c', "glibc"))),
            ('c', "glibc", None),
            ('d', "old-agent", Some(('e', "old-glibc"))),
            ('e', "old-glibc", None),
            ('f', "artifact", Some(('c', "glibc"))),
        ];
        for (hash, name, reference) in members {
            let hash = hash.to_string().repeat(32);
            let references = reference
                .map(|(hash, name)| format!("{}-{name}", hash.to_string().repeat(32)))
                .unwrap_or_default();
            fs::write(
                cache_root.join(format!("{hash}.narinfo")),
                format!(
                    "StorePath: /nix/store/{hash}-{name}\nURL: nar/{name}.nar.zst\nReferences: {references}\n"
                ),
            )
            .unwrap();
            fs::write(cache_root.join(format!("nar/{name}.nar.zst")), b"nar").unwrap();
        }
        let current = test_store_path('a', "tiaris-agent");
        fs::write(
            &config.cache.seed_manifest_path,
            json!({"schema": MANIFEST_SCHEMA, "store_paths": [current]}).to_string(),
        )
        .unwrap();
        let artifact_hash = "f".repeat(64);
        db::create_cache_artifact(
            &pool,
            crate::models::CreateCacheArtifactRequest {
                artifact_type: "nixos_closure".to_string(),
                hash: artifact_hash.clone(),
                size_bytes: 3,
                path: cache_root
                    .join("nar/artifact.nar.zst")
                    .display()
                    .to_string(),
                store_path: Some(test_store_path('f', "artifact")),
                narinfo_path: Some(
                    cache_root
                        .join(format!("{}.narinfo", "f".repeat(32)))
                        .display()
                        .to_string(),
                ),
                nar_url: Some("nar/artifact.nar.zst".to_string()),
                file_hash: Some("sha256:artifact".to_string()),
                nar_hash: Some("sha256:artifactnar".to_string()),
                nar_size_bytes: Some(3),
                closure_size_bytes: Some(6),
                closure_file_size_bytes: None,
                compression: Some("zstd".to_string()),
                references: Some(json!([])),
                serving_url: Some("http://nest.example/cache/nar/artifact.nar.zst".to_string()),
                source_build_job_id: None,
                cache_metadata: None,
            },
        )
        .await
        .unwrap();

        remove_artifacts_by_key(
            &pool,
            &config,
            &[("nixos_closure".to_string(), artifact_hash)],
        )
        .await
        .unwrap();

        let present = |hash: char, name: &str| {
            cache_root
                .join(format!("{}.narinfo", hash.to_string().repeat(32)))
                .exists()
                && cache_root.join(format!("nar/{name}.nar.zst")).exists()
        };
        assert!(present('a', "tiaris-agent"));
        assert!(present('c', "glibc"));
        assert!(!present('d', "old-agent"));
        assert!(!present('e', "old-glibc"));
        assert!(!present('f', "artifact"));
        assert!(db::list_cache_artifacts(&pool).await.unwrap().is_empty());
        fs::remove_dir_all(root).ok();
    }
}
