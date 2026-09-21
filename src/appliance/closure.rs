//! Bounded offline closure verification. No extraction, import, or disk mutation
//! is needed to authenticate the full archive and every inner NAR.
use super::release_v3::{NixosRelease, canonical_base64, store_path, strict_json};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub const MAX_EXPANDED: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_NAR_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_MEMBERS: usize = 65536;
const MAX_MANIFEST: u64 = 16 * 1024 * 1024;
const MAX_NARINFO: u64 = 1024 * 1024;
const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorePath {
    pub path: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub narinfo: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManageSource {
    pub revision: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub store_path: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureManifest {
    pub schema: String,
    pub release_id: String,
    pub base_os: String,
    pub base_os_version: String,
    pub source_revision: String,
    pub manage_source_revision: String,
    pub nixpkgs_revision: String,
    pub system_toplevel: String,
    pub required_system_versions: BTreeMap<String, String>,
    pub sqlite_migrations_sha256: String,
    pub nix_signing_public_key: String,
    pub manage_source: ManageSource,
    pub microcode_versions: BTreeMap<String, String>,
    pub store_paths: Vec<StorePath>,
    pub total_nar_bytes: u64,
}
impl ClosureManifest {
    fn validate(&self, release: &NixosRelease, key: &VerifyingKey) -> Result<()> {
        ensure!(
            self.schema == "cybex.james.system-closure.v1",
            "closure manifest schema"
        );
        ensure!(
            self.release_id == release.release_id
                && self.base_os == release.base_os
                && self.base_os_version == release.base_os_version
                && self.source_revision == release.source_revision
                && self.manage_source_revision == release.manage_source_revision
                && self.nixpkgs_revision == release.nixpkgs_revision
                && self.system_toplevel == release.system_toplevel
                && self.required_system_versions == release.required_system_versions
                && self.sqlite_migrations_sha256 == release.sqlite_migrations_sha256,
            "closure manifest does not match signed descriptor"
        );
        ensure!(
            self.nix_signing_public_key
                == format!(
                    "cybex-james-appliance-1:{}",
                    STANDARD.encode(key.as_bytes())
                ),
            "archive Nix key differs from independently trusted key"
        );
        ensure!(
            self.manage_source.revision == release.manage_source_revision
                && self.manage_source.size_bytes > 0,
            "Manage source identity mismatch"
        );
        super::release_v3::require_hex(&self.manage_source.sha256, 64)?;
        let (source_root, _) = source_location(&self.manage_source)?;
        ensure!(
            self.microcode_versions
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                == ["amd", "intel"]
                && self
                    .microcode_versions
                    .values()
                    .all(|v| super::release_v3::safe_token(v, 256)),
            "microcode package identities"
        );
        ensure!(
            !self.store_paths.is_empty() && self.store_paths.len() < MAX_MEMBERS / 2,
            "invalid store path count"
        );
        let mut previous = "";
        let mut total = 0u64;
        let mut all = BTreeSet::new();
        for path in &self.store_paths {
            let name = store_path(&path.path)?;
            ensure!(
                path.path.as_str() > previous,
                "store paths must be unique and sorted"
            );
            previous = &path.path;
            ensure!(
                path.narinfo == format!("{}.narinfo", &name[..32]),
                "NARInfo basename mismatch"
            );
            require_nix_hash(&path.nar_hash)?;
            ensure!(path.nar_size > 0, "zero NAR size");
            total = total
                .checked_add(path.nar_size)
                .ok_or_else(|| anyhow!("NAR size overflow"))?;
            ensure!(total <= MAX_NAR_BYTES, "closure NAR size limit");
            let mut prev = "";
            for reference in &path.references {
                store_path(reference)?;
                ensure!(
                    reference.as_str() > prev,
                    "references must be sorted and unique"
                );
                prev = reference;
            }
            all.insert(path.path.as_str());
        }
        ensure!(total == self.total_nar_bytes, "total NAR size mismatch");
        ensure!(
            all.contains(self.system_toplevel.as_str()) && all.contains(source_root),
            "closure missing toplevel/source"
        );
        let paths: BTreeMap<_, _> = self
            .store_paths
            .iter()
            .map(|p| (p.path.as_str(), p))
            .collect();
        let mut reachable = BTreeSet::new();
        let mut pending = vec![self.system_toplevel.as_str()];
        while let Some(path) = pending.pop() {
            if !reachable.insert(path) {
                continue;
            }
            let entry = paths
                .get(path)
                .ok_or_else(|| anyhow!("incomplete closure reference graph"))?;
            pending.extend(entry.references.iter().map(String::as_str));
        }
        ensure!(
            reachable == all,
            "closure contains paths outside exact toplevel graph"
        );
        Ok(())
    }
}

fn source_location(source: &ManageSource) -> Result<(&str, &str)> {
    store_path(&source.store_path)?;
    Ok((&source.store_path, ""))
}

struct NarInfo {
    entry: StorePath,
    file_hash: String,
    file_size: u64,
}
fn narinfo(body: &[u8], entry: &StorePath, key: &VerifyingKey) -> Result<(String, NarInfo)> {
    let text = std::str::from_utf8(body)?;
    ensure!(
        text.ends_with('\n') && !text.contains('\r'),
        "NARInfo line encoding"
    );
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed NARInfo field"))?;
        let value = value
            .strip_prefix(' ')
            .ok_or_else(|| anyhow!("NARInfo separator"))?;
        ensure!(
            matches!(
                name,
                "StorePath"
                    | "URL"
                    | "Compression"
                    | "FileHash"
                    | "FileSize"
                    | "NarHash"
                    | "NarSize"
                    | "References"
                    | "Sig"
                    | "Deriver"
            ),
            "unknown NARInfo field"
        );
        ensure!(
            fields.insert(name, value).is_none(),
            "duplicate NARInfo field"
        );
    }
    let field = |name| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("missing NARInfo {name}"))
    };
    ensure!(
        field("StorePath")? == entry.path
            && field("NarHash")? == entry.nar_hash
            && field("Compression")? == "zstd",
        "NARInfo identity mismatch"
    );
    ensure!(
        decimal(field("NarSize")?)? == entry.nar_size,
        "NARInfo NAR size mismatch"
    );
    let references = entry
        .references
        .iter()
        .map(|v| store_path(v))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    ensure!(
        field("References")? == references,
        "NARInfo references mismatch"
    );
    let url = field("URL")?;
    ensure!(valid_nar_name(url), "unsafe NAR payload URL");
    let file_hash = field("FileHash")?.to_string();
    require_nix_hash(&file_hash)?;
    let file_size = decimal(field("FileSize")?)?;
    ensure!(
        file_size > 0 && file_size <= super::release_v3::MAX_ARCHIVE_BYTES,
        "compressed NAR size limit"
    );
    let sig = field("Sig")?
        .strip_prefix("cybex-james-appliance-1:")
        .ok_or_else(|| anyhow!("NARInfo signer is untrusted"))?;
    let sig: [u8; 64] = canonical_base64(sig, 64)?
        .try_into()
        .map_err(|_| anyhow!("NARInfo signature length"))?;
    let fingerprint = format!(
        "1;{};{};{};{}",
        entry.path,
        entry.nar_hash,
        entry.nar_size,
        entry.references.join(",")
    );
    key.verify_strict(fingerprint.as_bytes(), &Signature::from_bytes(&sig))
        .context("untrusted NARInfo signature")?;
    Ok((
        url.to_owned(),
        NarInfo {
            entry: entry.clone(),
            file_hash,
            file_size,
        },
    ))
}
fn decimal(text: &str) -> Result<u64> {
    let v: u64 = text.parse()?;
    ensure!(v.to_string() == text, "noncanonical decimal");
    Ok(v)
}
fn valid_nar_name(name: &str) -> bool {
    name.strip_prefix("nar/").is_some_and(|n| {
        n.ends_with(".nar.zst") && super::release_v3::safe_token(n, 255) && !n.starts_with('.')
    })
}
fn require_nix_hash(hash: &str) -> Result<()> {
    let h = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("unsupported Nix hash"))?;
    ensure!(
        h.len() == 52 && h.bytes().all(|b| NIX32.contains(&b)) && h.as_bytes()[0] <= b'1',
        "noncanonical Nix SHA-256"
    );
    Ok(())
}
pub fn nix_hash(bytes: &[u8]) -> String {
    let mut out = String::from("sha256:");
    for n in (0..bytes.len().saturating_mul(8).div_ceil(5)).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let j = bit % 8;
        let mut v = (bytes[i] as u16) >> j;
        if i + 1 < bytes.len() {
            v |= (bytes[i + 1] as u16) << (8 - j)
        }
        out.push(NIX32[(v & 31) as usize] as char);
    }
    out
}

struct Counting<R> {
    inner: R,
    bytes: u64,
    limit: u64,
    hash: Sha256,
}
impl<R: Read> Read for Counting<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(out)?;
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("stream size overflow"))?;
        if self.bytes > self.limit {
            return Err(io::Error::other("stream exceeded verified limit"));
        }
        self.hash.update(&out[..n]);
        Ok(n)
    }
}
impl<R> Counting<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            bytes: 0,
            limit,
            hash: Sha256::new(),
        }
    }
}

/// The same file descriptor stays open throughout byte, tar and NAR validation.
/// Optional extraction targets only a new private root-owned cache directory.
pub fn verify_archive(
    file: &mut File,
    release: &NixosRelease,
    key: &VerifyingKey,
    output: Option<&Path>,
) -> Result<ClosureManifest> {
    release.verify(key)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.len() == release.system_closure.size_bytes,
        "archive is not the exact ordinary signed file"
    );
    file.rewind()?;
    let mut hash = Sha256::new();
    let mut block = [0u8; 64 * 1024];
    let mut size = 0;
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        ensure!(size <= release.system_closure.size_bytes, "archive grew");
        hash.update(&block[..n]);
    }
    ensure!(
        size == release.system_closure.size_bytes
            && hex::encode(hash.finalize()) == release.system_closure.sha256,
        "archive signed size/hash mismatch"
    );
    if let Some(root) = output {
        fs::create_dir(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    file.rewind()?;
    let mut decoder = zstd::stream::read::Decoder::new(&mut *file)?.single_frame();
    decoder.window_log_max(27)?;
    let mut tar = Counting::new(decoder, MAX_EXPANDED);
    let mut manifest: Option<ClosureManifest> = None;
    let mut paths = BTreeMap::new();
    let mut infos = BTreeMap::new();
    let mut members = BTreeSet::new();
    let mut payloads = BTreeSet::new();
    let mut saw_cache = false;
    let mut payload_started = false;
    let mut timestamp = None;
    loop {
        let mut raw = [0u8; 512];
        tar.read_exact(&mut raw)
            .context("incomplete USTAR header")?;
        if raw == [0; 512] {
            let mut second = [0u8; 512];
            tar.read_exact(&mut second)?;
            ensure!(second == [0; 512], "USTAR requires two end blocks");
            let mut trailing = 0u64;
            loop {
                let n = tar.read(&mut block)?;
                if n == 0 {
                    break;
                }
                trailing += n as u64;
                ensure!(
                    trailing <= 10240 && block[..n].iter().all(|b| *b == 0),
                    "unexpected trailing tar data"
                );
            }
            ensure!(trailing % 512 == 0, "unaligned trailing tar data");
            break;
        }
        ensure!(members.len() < MAX_MEMBERS, "too many archive members");
        let (name, length, directory, mtime) = header(&raw)?;
        ensure!(
            timestamp.is_none_or(|t| t == mtime),
            "unstable archive timestamps"
        );
        timestamp = Some(mtime);
        ensure!(members.insert(name.clone()), "duplicate archive member");
        let allowed = name == "manifest.json"
            || name == "nix-cache-info"
            || name == "nar/"
            || paths.contains_key(&name)
            || valid_nar_name(&name);
        ensure!(allowed, "unexpected archive member");
        ensure!(length <= MAX_EXPANDED, "archive entry size limit");
        if directory {
            ensure!(
                name == "nar/" && length == 0,
                "unexpected archive directory"
            );
            if let Some(root) = output {
                fs::create_dir(root.join("nar"))?;
            }
            continue;
        }
        let mut entry = (&mut tar).take(length);
        if name == "manifest.json" {
            ensure!(
                members.len() == 1 && length <= MAX_MANIFEST,
                "manifest must be first and bounded"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let value = strict_json(&bytes)?;
            let mut canonical = serde_json::to_vec(&super::canonical_json(value.clone()))?;
            canonical.push(b'\n');
            ensure!(
                bytes == canonical,
                "closure manifest must be canonical JSON plus LF"
            );
            let m: ClosureManifest = serde_json::from_value(value)?;
            m.validate(release, key)?;
            for p in &m.store_paths {
                paths.insert(p.narinfo.clone(), p.clone());
            }
            if let Some(root) = output {
                write_new(&root.join(&name), &bytes)?;
            }
            manifest = Some(m);
        } else if name == "nix-cache-info" {
            ensure!(
                !payload_started && length <= 1024,
                "cache metadata ordering/size"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let text = std::str::from_utf8(&bytes)?;
            ensure!(
                text == "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
                    || text == "StoreDir: /nix/store\n",
                "unexpected Nix cache metadata"
            );
            if let Some(root) = output {
                write_new(&root.join(&name), &bytes)?;
            }
            saw_cache = true;
        } else if let Some(path) = paths.get(&name) {
            ensure!(
                !payload_started && length <= MAX_NARINFO,
                "NARInfos must precede payloads and be bounded"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let (url, info) = narinfo(&bytes, path, key)?;
            ensure!(
                infos.insert(url, info).is_none(),
                "duplicate NAR payload identity"
            );
            if let Some(root) = output {
                write_new(&root.join(&name), &bytes)?;
            }
        } else {
            payload_started = true;
            ensure!(
                infos.len() == paths.len() && saw_cache,
                "payload before complete metadata"
            );
            let info = infos
                .get(&name)
                .ok_or_else(|| anyhow!("unreferenced NAR payload"))?;
            ensure!(length == info.file_size, "compressed NAR size mismatch");
            let destination = output.map(|root| root.join(&name));
            let target = destination
                .as_ref()
                .map(|path| {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(path)
                })
                .transpose()?;
            ensure!(
                members.contains("nar/"),
                "NAR directory must precede payloads"
            );
            let source = manifest
                .as_ref()
                .map(|m| &m.manage_source)
                .ok_or_else(|| anyhow!("manifest missing"))?;
            let (source_root, source_relative) = source_location(source)?;
            verify_nar(
                &mut entry,
                info,
                target,
                if info.entry.path == source_root {
                    Some((source_relative, source))
                } else {
                    None
                },
            )?;
            payloads.insert(name);
        }
        ensure!(entry.limit() == 0, "short archive member");
        let pad = (512 - length % 512) % 512;
        let mut padding = [0u8; 512];
        tar.read_exact(&mut padding[..pad as usize])?;
        ensure!(
            padding[..pad as usize].iter().all(|b| *b == 0),
            "nonzero USTAR padding"
        );
    }
    ensure!(
        payloads.len() == paths.len() && infos.len() == paths.len() && saw_cache,
        "incomplete closure archive"
    );
    let mut compressed = tar.inner.finish();
    ensure!(
        compressed.fill_buf()?.is_empty(),
        "concatenated zstd frame or trailing compressed garbage"
    );
    let after = file.metadata()?;
    ensure!(
        after.len() == meta.len()
            && after.mtime() == meta.mtime()
            && after.mtime_nsec() == meta.mtime_nsec(),
        "archive changed during verification"
    );
    manifest.ok_or_else(|| anyhow!("missing closure manifest"))
}

struct Tee<R> {
    reader: R,
    output: Option<File>,
}
impl<R: Read> Read for Tee<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(b)?;
        if let Some(out) = &mut self.output {
            out.write_all(&b[..n])?;
        }
        Ok(n)
    }
}
fn verify_nar(
    reader: impl Read,
    info: &NarInfo,
    output: Option<File>,
    source: Option<(&str, &ManageSource)>,
) -> Result<()> {
    let compressed = Counting::new(Tee { reader, output }, info.file_size);
    let mut decoder = zstd::stream::read::Decoder::new(compressed)?.single_frame();
    decoder.window_log_max(27)?;
    let mut nar = Counting::new(decoder, info.entry.nar_size);
    ensure!(
        nar_string(&mut nar, 64)? == b"nix-archive-1",
        "invalid NAR header"
    );
    let components = source
        .map(|(path, _)| {
            path.split('/')
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut found_source = false;
    nar_node(
        &mut nar,
        0,
        source.map(|(_, source)| (components.as_slice(), source)),
        &mut found_source,
    )?;
    ensure!(
        source.is_none() || found_source,
        "embedded Manage source file is absent from its NAR"
    );
    let mut one = [0];
    ensure!(nar.read(&mut one)? == 0, "trailing NAR bytes");
    ensure!(
        nar.bytes == info.entry.nar_size && nix_hash(&nar.hash.finalize()) == info.entry.nar_hash,
        "NAR size/hash mismatch"
    );
    let mut buffered = nar.inner.finish();
    ensure!(
        buffered.fill_buf()?.is_empty(),
        "trailing or concatenated NAR frame"
    );
    let compressed = buffered.into_inner();
    ensure!(
        compressed.bytes == info.file_size
            && nix_hash(&compressed.hash.finalize()) == info.file_hash,
        "compressed NAR hash/size mismatch"
    );
    if let Some(file) = compressed.inner.output {
        file.sync_all()?;
    }
    Ok(())
}
fn nar_string(reader: &mut impl Read, max: u64) -> Result<Vec<u8>> {
    let mut len = [0u8; 8];
    reader.read_exact(&mut len)?;
    let len = u64::from_le_bytes(len);
    ensure!(len <= max, "NAR token size limit");
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes)?;
    nar_padding(reader, len)?;
    Ok(bytes)
}
fn nar_padding(reader: &mut impl Read, len: u64) -> Result<()> {
    let mut pad = [0u8; 8];
    let n = ((8 - len % 8) % 8) as usize;
    reader.read_exact(&mut pad[..n])?;
    ensure!(pad[..n].iter().all(|b| *b == 0), "invalid NAR padding");
    Ok(())
}
fn nar_expect(reader: &mut impl Read, value: &[u8]) -> Result<()> {
    ensure!(nar_string(reader, 256)? == value, "invalid NAR structure");
    Ok(())
}
fn nar_node(
    reader: &mut impl Read,
    depth: usize,
    source: Option<(&[&str], &ManageSource)>,
    found_source: &mut bool,
) -> Result<()> {
    ensure!(depth <= 256, "NAR recursion limit");
    nar_expect(reader, b"(")?;
    nar_expect(reader, b"type")?;
    match nar_string(reader, 32)?.as_slice() {
        b"regular" => {
            let mut token = nar_string(reader, 32)?;
            if token == b"executable" {
                nar_expect(reader, b"")?;
                token = nar_string(reader, 32)?;
            }
            ensure!(token == b"contents", "invalid regular NAR");
            let mut len = [0u8; 8];
            reader.read_exact(&mut len)?;
            let len = u64::from_le_bytes(len);
            ensure!(len <= MAX_NAR_BYTES, "NAR contents limit");
            let mut contents = reader.take(len);
            let mut hash = Sha256::new();
            let mut copied = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let n = contents.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                copied += n as u64;
                if source.is_some() {
                    hash.update(&buffer[..n]);
                }
            }
            ensure!(copied == len, "truncated NAR file");
            if let Some((remaining, metadata)) = source {
                ensure!(
                    remaining.is_empty()
                        && len == metadata.size_bytes
                        && hex::encode(hash.finalize()) == metadata.sha256,
                    "embedded Manage source bytes do not match manifest"
                );
                *found_source = true;
            }
            nar_padding(reader, len)?;
            nar_expect(reader, b")")?;
        }
        b"directory" => {
            let mut previous = Vec::new();
            loop {
                let token = nar_string(reader, 32)?;
                if token == b")" {
                    break;
                }
                ensure!(token == b"entry", "invalid NAR directory");
                nar_expect(reader, b"(")?;
                nar_expect(reader, b"name")?;
                let name = nar_string(reader, 255)?;
                ensure!(
                    !name.is_empty()
                        && name != b"."
                        && name != b".."
                        && !name.contains(&b'/')
                        && !name.contains(&0)
                        && name > previous,
                    "invalid or unordered NAR entry name"
                );
                let child_source = source.and_then(|(remaining, metadata)| {
                    remaining.split_first().and_then(|(first, tail)| {
                        if first.as_bytes() == name {
                            Some((tail, metadata))
                        } else {
                            None
                        }
                    })
                });
                previous = name;
                nar_expect(reader, b"node")?;
                nar_node(reader, depth + 1, child_source, found_source)?;
                nar_expect(reader, b")")?;
            }
        }
        b"symlink" => {
            ensure!(
                source.is_none(),
                "embedded Manage source cannot be a symlink"
            );
            nar_expect(reader, b"target")?;
            let target = nar_string(reader, 4096)?;
            ensure!(!target.contains(&0), "NAR symlink NUL");
            nar_expect(reader, b")")?;
        }
        _ => bail!("unsupported NAR node"),
    }
    Ok(())
}
fn header(raw: &[u8; 512]) -> Result<(String, u64, bool, u64)> {
    ensure!(
        &raw[257..263] == b"ustar\0" && &raw[263..265] == b"00",
        "archive is not canonical USTAR"
    );
    let recorded = octal(&raw[148..156])?;
    let sum: u64 = raw
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                *b as u64
            }
        })
        .sum();
    ensure!(recorded == sum, "USTAR checksum mismatch");
    ensure!(
        octal(&raw[108..116])? == 0 && octal(&raw[116..124])? == 0,
        "archive ownership must be root"
    );
    ensure!(
        raw[157..257].iter().all(|b| *b == 0) && raw[345..512].iter().all(|b| *b == 0),
        "links, prefixes and extensions forbidden"
    );
    let name_end = raw[..100].iter().position(|b| *b == 0).unwrap_or(100);
    ensure!(
        raw[name_end..100].iter().all(|b| *b == 0),
        "noncanonical USTAR filename"
    );
    let name = std::str::from_utf8(&raw[..name_end])?.to_string();
    ensure!(
        name.len() <= 100
            && !name.starts_with('/')
            && !name.contains("..")
            && !name.bytes().any(|b| b.is_ascii_control()),
        "unsafe archive name"
    );
    let directory = raw[156] == b'5';
    ensure!(
        directory || raw[156] == b'0',
        "only ordinary files and nar directory are permitted"
    );
    ensure!(
        octal(&raw[100..108])? == if directory { 0o755 } else { 0o644 },
        "noncanonical archive mode"
    );
    Ok((
        name,
        octal(&raw[124..136])?,
        directory,
        octal(&raw[136..148])?,
    ))
}
fn octal(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes)?.trim_matches(['\0', ' ']);
    ensure!(
        !text.is_empty() && text.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        "noncanonical tar numeric field"
    );
    Ok(u64::from_str_radix(text, 8)?)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nix_base32_matches_known_sha256() {
        assert_eq!(nix_hash(&[0; 32]), format!("sha256:{}", "0".repeat(52)));
        assert_eq!(nix_hash(&[255; 32]), format!("sha256:1{}", "z".repeat(51)));
    }
    #[test]
    fn archive_header_rejects_links_and_traversal() {
        for name in ["../secret", "/etc/shadow"] {
            let mut h = tar::Header::new_ustar();
            h.set_path("manifest.json").unwrap();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            h.set_entry_type(tar::EntryType::Regular);
            h.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            assert!(header(h.as_bytes()).is_err());
        }
        let mut h = tar::Header::new_ustar();
        h.set_path("nar/test.nar.zst").unwrap();
        h.set_size(0);
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_cksum();
        assert!(header(h.as_bytes()).is_err());
    }
    #[test]
    fn nar_rejects_oversized_tokens_without_allocating() {
        let mut b = &u64::MAX.to_le_bytes()[..];
        assert!(nar_string(&mut b, 256).is_err());
    }
}

#[cfg(test)]
#[path = "closure_tests.rs"]
mod full_archive_tests;
