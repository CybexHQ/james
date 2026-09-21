//! Strict NixOS release identity. Legacy descriptors keep their original type
//! and serialization so inspecting history never silently changes signed bytes.
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

pub const SCHEMA: &str = "cybex.james.appliance-release.v3";
pub const DOMAIN: &str = "CYBEX-JAMES-APPLIANCE-RELEASE-V3";
pub const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub fn pinned_nixpkgs_revision() -> &'static str {
    include_str!("../../release/nixpkgs.nix")
        .split_once("revision = \"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(revision, _)| revision)
        .expect("shared Nix pin has a revision")
}
pub const NIXOS_VERSION: &str = "26.05";
const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemClosure {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixosRelease {
    pub schema: String,
    pub release_id: String,
    pub source_revision: String,
    pub base_os: String,
    pub base_os_version: String,
    pub nixpkgs_revision: String,
    pub manage_source_revision: String,
    pub system_toplevel: String,
    pub system_closure: SystemClosure,
    pub required_system_versions: BTreeMap<String, String>,
    pub sqlite_migrations_sha256: String,
    pub minimum_protocol: u32,
    pub minimum_state_schema: u32,
    pub rollback_compatible: bool,
    pub release_notes: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ReleaseDescriptor {
    Nixos(NixosRelease),
    Legacy(super::SignedApplianceRelease),
}

impl ReleaseDescriptor {
    pub fn nixos(&self) -> Result<&NixosRelease> {
        match self {
            Self::Nixos(value) => Ok(value),
            Self::Legacy(_) => bail!("NixOS media requires install-plan.v3 and a NixOS closure"),
        }
    }
    pub fn legacy(&self) -> Result<&super::SignedApplianceRelease> {
        match self {
            Self::Legacy(value) => Ok(value),
            Self::Nixos(_) => bail!("Ubuntu installation cannot consume a NixOS closure"),
        }
    }
}

impl NixosRelease {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA
            || self.base_os != "nixos"
            || self.base_os_version != NIXOS_VERSION
            || self.nixpkgs_revision != pinned_nixpkgs_revision()
            || self.minimum_protocol != 4
            || self.minimum_state_schema != 3
            || !self.rollback_compatible
        {
            bail!("NixOS appliance release contract is incompatible")
        }
        let version = semver::Version::parse(&self.release_id)?;
        if version.to_string() != self.release_id {
            bail!("release ID is not canonical SemVer")
        }
        require_hex(&self.source_revision, 40)?;
        require_hex(&self.manage_source_revision, 40)?;
        require_hex(&self.sqlite_migrations_sha256, 64)?;
        require_hex(&self.system_closure.sha256, 64)?;
        store_path(&self.system_toplevel)?;
        if self.system_closure.size_bytes == 0 || self.system_closure.size_bytes > MAX_ARCHIVE_BYTES
        {
            bail!("closure size is outside the signed archive limit")
        }
        let expected = format!(
            "cybex-james-appliance-closure-{}-x86_64-linux.tar.zst",
            self.release_id
        );
        let url = canonical_https(&self.system_closure.url)?;
        if url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            != Some(expected.as_str())
        {
            bail!("closure URL has an unexpected artifact basename")
        }
        canonical_https(&self.release_notes)?;
        let keys: Vec<_> = self
            .required_system_versions
            .keys()
            .map(String::as_str)
            .collect();
        if keys
            != [
                "cybex-james",
                "kernel",
                "linux-firmware",
                "nix",
                "systemd-boot",
            ]
            || self.required_system_versions["cybex-james"] != self.release_id
            || self
                .required_system_versions
                .values()
                .any(|v| !safe_token(v, 256))
        {
            bail!("NixOS release requires exactly five valid system anchors")
        }
        Ok(())
    }

    pub fn signature_message(&self) -> Result<Vec<u8>> {
        let mut unsigned = serde_json::to_value(self)?;
        unsigned
            .as_object_mut()
            .ok_or_else(|| anyhow!("release is not an object"))?
            .remove("signature");
        let mut message = format!("{DOMAIN}\n").into_bytes();
        message.extend(serde_json::to_vec(&super::canonical_json(unsigned))?);
        Ok(message)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        self.validate()?;
        if key.is_weak() {
            bail!("release public key is weak")
        }
        let signature: [u8; 64] = canonical_base64(&self.signature, 64)?
            .try_into()
            .map_err(|_| anyhow!("signature length"))?;
        key.verify_strict(
            &self.signature_message()?,
            &Signature::from_bytes(&signature),
        )
        .context("NixOS release signature is not trusted")
    }

    pub fn verify_file(&self, path: &Path) -> Result<VerifyingKey> {
        let key = load_public_key(path)?;
        self.verify(&key)?;
        Ok(key)
    }
}

pub fn load_public_key(path: &Path) -> Result<VerifyingKey> {
    let bytes = crate::provisioning::read_bounded_nofollow(path, 128, "release public key")?;
    let body = std::str::from_utf8(&bytes)?;
    let text = body
        .strip_suffix('\n')
        .ok_or_else(|| anyhow!("public key requires final LF"))?;
    let key: [u8; 32] = canonical_base64(text, 32)?
        .try_into()
        .map_err(|_| anyhow!("public key length"))?;
    let key = VerifyingKey::from_bytes(&key)?;
    if key.is_weak() {
        bail!("release public key is weak")
    }
    Ok(key)
}

pub fn canonical_base64(value: &str, length: usize) -> Result<Vec<u8>> {
    let decoded = STANDARD.decode(value)?;
    if decoded.len() != length || STANDARD.encode(&decoded) != value {
        bail!("noncanonical base64")
    }
    Ok(decoded)
}

pub fn require_hex(value: &str, length: usize) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("noncanonical hexadecimal identity")
    }
    Ok(())
}

pub fn safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+._?=-".contains(&b))
}

pub fn store_path(value: &str) -> Result<&str> {
    let name = value
        .strip_prefix("/nix/store/")
        .ok_or_else(|| anyhow!("not a Nix store path"))?;
    if name.len() < 34
        || name.as_bytes()[32] != b'-'
        || !name.as_bytes()[..32].iter().all(|b| NIX32.contains(b))
        || !safe_token(&name[33..], 211)
    {
        bail!("noncanonical Nix store path")
    }
    Ok(name)
}

pub fn canonical_https(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
        || value.bytes().any(|b| b.is_ascii_control())
        || url.path().contains('%')
    {
        bail!("URL is not immutable canonical HTTPS")
    }
    Ok(url)
}

/// Reject duplicate keys recursively before converting wire JSON to a typed
/// descriptor; serde_json::Value otherwise keeps only the last occurrence.
pub struct Strict(pub Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("integer-only JSON without duplicate keys")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut m: M,
            ) -> std::result::Result<Strict, M::Error> {
                let mut object = serde_json::Map::new();
                while let Some((key, Strict(value))) = m.next_entry::<String, Strict>()? {
                    if object.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(Strict(Value::Object(object)))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut s: S,
            ) -> std::result::Result<Strict, S::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = s.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
        }
        d.deserialize_any(Visitor)
    }
}

pub fn strict_json(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice::<Strict>(bytes)?.0)
}

impl<'de> Deserialize<'de> for ReleaseDescriptor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let Strict(value) = Strict::deserialize(deserializer)?;
        match value.get("schema").and_then(Value::as_str) {
            Some(SCHEMA) => serde_json::from_value(value)
                .map(Self::Nixos)
                .map_err(serde::de::Error::custom),
            Some("cybex.james.appliance-release.v1" | "cybex.james.appliance-release.v2") => {
                serde_json::from_value(value)
                    .map(Self::Legacy)
                    .map_err(serde::de::Error::custom)
            }
            _ => Err(serde::de::Error::custom(
                "unsupported appliance descriptor schema",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_golden_descriptor_verifies_exact_bytes_and_rejects_mutations() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../protocol/fixtures/james-appliance-v3.json"
        ))
        .unwrap();
        let release: NixosRelease =
            serde_json::from_value(fixture["appliance_release"].clone()).unwrap();
        let key: [u8; 32] = canonical_base64(fixture["public_key"].as_str().unwrap(), 32)
            .unwrap()
            .try_into()
            .unwrap();
        let key = VerifyingKey::from_bytes(&key).unwrap();
        release.verify(&key).unwrap();
        assert_eq!(
            STANDARD.encode(release.signature_message().unwrap()),
            fixture["appliance_release_message_base64"]
        );
        for field in [
            "source_revision",
            "manage_source_revision",
            "nixpkgs_revision",
            "system_toplevel",
            "release_id",
            "release_notes",
        ] {
            let mut value = fixture["appliance_release"].clone();
            value[field] = "changed".into();
            assert!(
                serde_json::from_value::<NixosRelease>(value)
                    .unwrap()
                    .verify(&key)
                    .is_err(),
                "{field}"
            );
        }
        let mut value = fixture["appliance_release"].clone();
        value["expected_kernel"] = "legacy".into();
        assert!(serde_json::from_value::<ReleaseDescriptor>(value).is_err());
    }
    #[test]
    fn strict_json_rejects_ambiguous_signatures() {
        assert!(strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json(br#"{"nested":{"x":1,"x":2}}"#).is_err());
        assert!(strict_json(br#"{"a":1.5}"#).is_err());
        assert!(store_path("/nix/store/00000000000000000000000000000000-a/../../etc").is_err());
    }
}
