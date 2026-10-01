//! Existing release formats, never a second origin-pair protocol.
use super::*;
use serde_json::json;
use wire::{OriginEvidence, ReleaseIdentity};

#[derive(Debug)]
pub struct VerifiedEvidence {
    pub(super) source: release_v3::NixosRelease,
    pub(super) target: release_v3::NixosRelease,
}
impl VerifiedEvidence {
    pub fn source(&self) -> &release_v3::NixosRelease {
        &self.source
    }
    pub fn target(&self) -> &release_v3::NixosRelease {
        &self.target
    }
}
fn r(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = canonical(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn artifact(text: &str, max: usize) -> Result<Vec<u8>> {
    // Check the encoded bound BEFORE allocating the decoded buffer.
    ensure!(text.len() <= max.div_ceil(3) * 4, "encoded artifact bound");
    let bytes = STANDARD.decode(text)?;
    ensure!(
        bytes.len() <= max && STANDARD.encode(&bytes) == text,
        "noncanonical/oversize artifact"
    );
    Ok(bytes)
}
fn exact(v: &Value, fields: &[&str]) -> Result<()> {
    let o = v
        .as_object()
        .ok_or_else(|| anyhow!("expected release object"))?;
    ensure!(
        o.len() == fields.len() && fields.iter().all(|f| o.contains_key(*f)),
        "unknown/missing release fields"
    );
    Ok(())
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field]
        .as_str()
        .ok_or_else(|| anyhow!("missing release string"))
}
fn number(v: &Value, field: &str, min: u64, max: u64) -> Result<u64> {
    let n = v[field]
        .as_u64()
        .ok_or_else(|| anyhow!("release integer required"))?;
    ensure!((min..=max).contains(&n), "release integer bound");
    Ok(n)
}
fn signature(key: &VerifyingKey, text: &str, message: &[u8]) -> Result<()> {
    ensure!(
        !key.is_weak() && text.len() == 88,
        "release key/signature bound"
    );
    key.verify_strict(
        message,
        &Signature::from_slice(&release_v3::canonical_base64(text, 64)?)?,
    )?;
    Ok(())
}
fn signed_r(v: &Value, bytes: &[u8], domain: &[u8], key: &VerifyingKey) -> Result<()> {
    ensure!(
        r(v)? == bytes,
        "release artifact is not exact R JSON (one LF required)"
    );
    ensure!(
        text(v, "public_key")? == STANDARD.encode(key.as_bytes()),
        "embedded key is not retained key"
    );
    let mut message = domain.to_vec();
    message.extend(r(&unsigned(v)?)?);
    signature(key, text(v, "signature")?, &message)
}
fn url(v: &Value, field: &str, basename: Option<&str>) -> Result<()> {
    let s = text(v, field)?;
    ensure!(s.len() <= 2048, "URL bound");
    let u = release_v3::canonical_https(s)?;
    if let Some(name) = basename {
        ensure!(
            u.path_segments().and_then(|mut p| p.next_back()) == Some(name),
            "artifact basename mismatch"
        );
    }
    Ok(())
}
fn compatibility_contract(v: &Value) -> Result<()> {
    exact(
        v,
        &[
            "schema",
            "protocol_version",
            "manage",
            "nest",
            "workstation_runtime",
        ],
    )?;
    ensure!(
        v["schema"] == "tiaris.component-compatibility.v1",
        "compatibility schema"
    );
    number(v, "protocol_version", 1, i32::MAX as u64)?;
    for (side, lo, hi) in [
        ("manage", "minimum_nest_protocol", "maximum_nest_protocol"),
        ("nest", "minimum_manage_protocol", "maximum_manage_protocol"),
    ] {
        exact(&v[side], &[lo, hi])?;
        ensure!(
            number(&v[side], lo, 1, i32::MAX as u64)? <= number(&v[side], hi, 1, i32::MAX as u64)?,
            "protocol range inverted"
        );
    }
    let runtime = &v["workstation_runtime"];
    let expected: Value =
        serde_json::from_str(include_str!("../../../protocol/compatibility.json"))?;
    let fields: Vec<_> = expected["workstation_runtime"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    exact(runtime, &fields)?;
    number(runtime, "compatibility_epoch", 1, i32::MAX as u64)?;
    for field in [
        "descriptor_schema",
        "manifest_schema",
        "architecture",
        "format",
        "required_nest_protocol",
    ] {
        ensure!(
            runtime[field] == expected["workstation_runtime"][field],
            "unsupported runtime contract"
        );
    }
    for field in [
        "import_states",
        "import_error_codes",
        "resolution_states",
        "resolution_error_codes",
        "report_receipt_states",
        "report_receipt_error_codes",
    ] {
        let entries = runtime[field]
            .as_array()
            .ok_or_else(|| anyhow!("runtime vocabulary"))?;
        ensure!(
            !entries.is_empty() && entries.len() <= 64,
            "vocabulary bound"
        );
        let mut seen = std::collections::BTreeSet::new();
        for entry in entries {
            let s = entry.as_str().ok_or_else(|| anyhow!("vocabulary string"))?;
            // Match nest-release.py: [a-z][a-z0-9_]{0,63}, unique but not sorted.
            ensure!(
                s.len() <= 64
                    && s.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    && seen.insert(s),
                "invalid/duplicate vocabulary"
            );
        }
    }
    Ok(())
}
fn manifest(
    v: &Value,
    key: &VerifyingKey,
    origin: &str,
) -> Result<(release_v3::NixosRelease, Value)> {
    exact(
        v,
        &[
            "schema",
            "version",
            "release_url",
            "notes_url",
            "published_at",
            "artifact",
            "signature",
            "installer_iso_template_v3",
            "appliance_release_v1",
            "workstation_netboot",
        ],
    )?;
    ensure!(v["schema"] == "tiaris.nest.release.v1", "manifest schema");
    let version = text(v, "version")?;
    wire::version(version)?;
    url(v, "release_url", None)?;
    url(v, "notes_url", None)?;
    let published = text(v, "published_at")?;
    let time = chrono::DateTime::parse_from_rfc3339(published)?;
    ensure!(
        time.format("%Y-%m-%dT%H:%M:%SZ").to_string() == published,
        "manifest timestamp"
    );
    let binary = &v["artifact"];
    exact(binary, &["url", "sha256"])?;
    url(binary, "url", Some("tiaris-nest-x86_64-linux"))?;
    release_v3::require_hex(text(binary, "sha256")?, 64)?;
    signature(
        key,
        text(v, "signature")?,
        format!(
            "{version}\n{}\n{}\n",
            text(binary, "sha256")?,
            text(binary, "url")?
        )
        .as_bytes(),
    )?;
    let iso = &v["installer_iso_template_v3"];
    let order = [
        "version",
        "architecture",
        "base_os",
        "base_os_version",
        "url",
        "size_bytes",
        "template_sha256",
        "personalization_offset",
        "personalization_size",
        "placeholder_sha256",
        "provisioning_public_keys",
        "package_delivery",
        "manage_origin",
    ];
    let mut fields = order.to_vec();
    fields.push("signature");
    exact(iso, &fields)?;
    ensure!(
        iso["version"] == version
            && iso["architecture"] == "x86_64-linux"
            && iso["base_os"] == "nixos"
            && iso["base_os_version"] == release_v3::NIXOS_VERSION
            && iso["package_delivery"] == "system-closure-v1"
            && iso["manage_origin"] == origin,
        "ISO contract/origin mismatch"
    );
    wire::origin(origin)?;
    url(
        iso,
        "url",
        Some(&format!(
            "tiaris-nest-appliance-template-{version}-x86_64-linux.iso"
        )),
    )?;
    let size = number(iso, "size_bytes", 8192, 16 * 1024 * 1024 * 1024)?;
    number(iso, "personalization_offset", 0, size - 8192)?;
    number(iso, "personalization_size", 8192, 8192)?;
    release_v3::require_hex(text(iso, "template_sha256")?, 64)?;
    ensure!(
        iso["placeholder_sha256"] == digest(&[0; 8192]),
        "ISO placeholder mismatch"
    );
    let keys = iso["provisioning_public_keys"]
        .as_array()
        .ok_or_else(|| anyhow!("ISO keys"))?;
    ensure!((1..=8).contains(&keys.len()), "ISO key count");
    let mut key_texts = Vec::new();
    for k in keys {
        let k = k.as_str().ok_or_else(|| anyhow!("ISO key text"))?;
        release_v3::canonical_base64(k, 32)?;
        key_texts.push(k);
    }
    ensure!(
        key_texts.windows(2).all(|p| p[0] < p[1]),
        "ISO keys unsorted/duplicate"
    );
    let mut message = String::from("TIARIS-NEST-INSTALLER-ISO-TEMPLATE-V3\n");
    for field in order {
        if field == "provisioning_public_keys" {
            message.push_str(&key_texts.join(","));
        } else if let Some(s) = iso[field].as_str() {
            ensure!(!s.chars().any(char::is_control), "ISO control string");
            message.push_str(s);
        } else {
            message.push_str(&iso[field].to_string());
        }
        message.push('\n');
    }
    signature(key, text(iso, "signature")?, message.as_bytes())?;
    let release: release_v3::NixosRelease =
        serde_json::from_value(v["appliance_release_v1"].clone())?;
    release.verify(key)?;
    ensure!(
        release.release_id == version
            && release.release_notes == text(v, "notes_url")?
            && release.base_os_version == text(iso, "base_os_version")?,
        "manifest/descriptor mismatch"
    );
    let runtime: crate::netboot::WorkstationNetbootDescriptor =
        serde_json::from_value(v["workstation_netboot"].clone())?;
    crate::netboot::validate_descriptor(&runtime, &STANDARD.encode(key.as_bytes()))?;
    signature(
        key,
        &runtime.signature,
        crate::netboot::signature_message(&runtime).as_bytes(),
    )?;
    url(&v["workstation_netboot"], "url", None)?;
    wire::version(&runtime.runtime_version)?;
    ensure!(
        runtime.nixpkgs_revision == release.nixpkgs_revision
            && runtime.manage_source_revision == release.manage_source_revision,
        "runtime/source pins differ"
    );
    // Reject unknown/null optional fields which would disappear in typed projection.
    ensure!(
        serde_json::to_value(&runtime)? == v["workstation_netboot"],
        "runtime projection changed fields"
    );
    let identities = json!({"nest_binary":binary,
        "appliance_iso_template":{"url":iso["url"],"sha256":iso["template_sha256"],"size_bytes":iso["size_bytes"],"manage_origin":origin},
        "appliance_package_snapshot":{"url":release.system_closure.url,"sha256":release.system_closure.sha256,"size_bytes":release.system_closure.size_bytes,"minimum_state_schema":release.minimum_state_schema},
        "workstation_runtime":unsigned(&v["workstation_netboot"])?});
    Ok((release, identities))
}
fn release(
    compatibility: &[u8],
    manifest_bytes: &[u8],
    identity: &ReleaseIdentity,
    origin: &str,
    key: &VerifyingKey,
) -> Result<(release_v3::NixosRelease, Value)> {
    wire::validate("ReleaseIdentity", &serde_json::to_value(identity)?)?;
    ensure!(
        digest(compatibility) == identity.compatibility_sha256
            && digest(manifest_bytes) == identity.manifest_sha256,
        "release raw hash mismatch"
    );
    let c = release_v3::strict_json(compatibility)?;
    exact(
        &c,
        &[
            "schema",
            "nest_release_version",
            "release_manifest",
            "compatibility",
            "compatibility_sha256",
            "artifacts",
            "public_key",
            "signature",
        ],
    )?;
    signed_r(
        &c,
        compatibility,
        b"TIARIS-NEST-RELEASE-COMPATIBILITY-V1\n",
        key,
    )?;
    ensure!(
        c["schema"] == "tiaris.nest.release-compatibility.v1"
            && c["nest_release_version"] == identity.release_version,
        "compatibility release mismatch"
    );
    exact(&c["release_manifest"], &["url", "sha256"])?;
    url(
        &c["release_manifest"],
        "url",
        Some("tiaris-nest-release.json"),
    )?;
    ensure!(
        c["release_manifest"]["sha256"] == identity.manifest_sha256,
        "manifest raw hash mismatch"
    );
    compatibility_contract(&c["compatibility"])?;
    ensure!(
        c["compatibility_sha256"] == digest(&r(&c["compatibility"])?),
        "compatibility contract hash mismatch"
    );
    let m = release_v3::strict_json(manifest_bytes)?;
    let (descriptor, artifacts) = manifest(&m, key, origin)?;
    ensure!(
        c["artifacts"] == artifacts,
        "compatibility artifacts do not equal signed manifest projection"
    );
    ensure!(
        descriptor.release_id == identity.release_version
            && descriptor.system_toplevel == identity.system_toplevel
            && descriptor.system_closure.sha256 == identity.system_closure_sha256
            && object_digest(&m["appliance_release_v1"])? == identity.descriptor_sha256,
        "release identity differs from signed descriptor"
    );
    Ok((descriptor, c))
}
/// Cryptographic evidence only. No closure import, admission or mutation occurs.
pub fn verify_evidence(
    e: &OriginEvidence,
    source: &ReleaseIdentity,
    target: &ReleaseIdentity,
    pair_sha256: &str,
    source_origin: &str,
    target_origin: &str,
    key: &VerifyingKey,
) -> Result<VerifiedEvidence> {
    wire::origin(source_origin)?;
    wire::origin(target_origin)?;
    ensure!(
        source_origin != target_origin,
        "pair requires distinct origins"
    );
    let pair_bytes = artifact(&e.pair_authorization, 16384)?;
    let sc = artifact(&e.source_compatibility, 1048576)?;
    let tc = artifact(&e.target_compatibility, 1048576)?;
    let sm = artifact(&e.source_manifest, 524288)?;
    let tm = artifact(&e.target_manifest, 524288)?;
    ensure!(
        digest(&pair_bytes) == pair_sha256,
        "pair raw digest mismatch"
    );
    let pair = release_v3::strict_json(&pair_bytes)?;
    signed_r(
        &pair,
        &pair_bytes,
        b"TIARIS-NEST-ORIGIN-TRANSITION-V1\n",
        key,
    )?;
    let reason = text(&pair, "reason")?;
    ensure!(
        !reason.is_empty()
            && reason.chars().count() <= 255
            && reason.trim() == reason
            && reason.chars().all(|c| c as u32 >= 32),
        "pair reason"
    );
    let (source_descriptor, before) = release(&sc, &sm, source, source_origin, key)?;
    let (target_descriptor, after) = release(&tc, &tm, target, target_origin, key)?;
    ensure!(
        wire::version(&target.release_version)?
            .cmp_precedence(&wire::version(&source.release_version)?)
            .is_gt(),
        "target version must advance"
    );
    let old = &before["artifacts"]["workstation_runtime"];
    let new = &after["artifacts"]["workstation_runtime"];
    let old_epoch = number(
        &before["compatibility"]["workstation_runtime"],
        "compatibility_epoch",
        1,
        i32::MAX as u64,
    )?;
    let new_epoch = number(
        &after["compatibility"]["workstation_runtime"],
        "compatibility_epoch",
        1,
        i32::MAX as u64,
    )?;
    let order = wire::version(text(new, "runtime_version")?)?
        .cmp_precedence(&wire::version(text(old, "runtime_version")?)?);
    ensure!(
        new_epoch >= old_epoch && !order.is_lt(),
        "runtime floor decreased"
    );
    ensure!(
        !order.is_eq() || old == new,
        "runtime changed at equal precedence"
    );
    ensure!(
        !(order.is_gt() || new_epoch != old_epoch) || old["sha256"] != new["sha256"],
        "runtime advanced without new bytes"
    );
    ensure!(
        target_descriptor.minimum_state_schema >= source_descriptor.minimum_state_schema,
        "state schema floor decreased"
    );
    let expected = json!({"schema":"tiaris.nest.origin-transition.v1","public_key":STANDARD.encode(key.as_bytes()),"reason":reason,
        "source":{"compatibility_sha256":source.compatibility_sha256,"release_version":source.release_version,"manifest":before["release_manifest"],"manage_origin":source_origin},
        "target":{"compatibility_sha256":target.compatibility_sha256,"release_version":target.release_version,"manifest":after["release_manifest"],"manage_origin":target_origin}});
    ensure!(
        unsigned(&pair)? == expected,
        "pair does not bind exact releases/origins"
    );
    Ok(VerifiedEvidence {
        source: source_descriptor,
        target: target_descriptor,
    })
}
