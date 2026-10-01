use super::tests::{
    check_evidence, evidence_fixture, release_fixture, release_identity, release_key,
};
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
fn signer(f: &Value) -> SigningKey {
    SigningKey::from_bytes(
        &hex::decode(f["release_seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
fn r(v: &Value) -> Vec<u8> {
    let mut b = canonical(v).unwrap();
    b.push(b'\n');
    b
}
fn seal_r(v: &mut Value, domain: &[u8], key: &SigningKey) {
    let mut message = domain.to_vec();
    message.extend(r(&unsigned(v).unwrap()));
    v["signature"] = STANDARD.encode(key.sign(&message).to_bytes()).into();
}
// Re-sign the containing compatibility and pair so negative tests cannot pass
// merely by detecting a stale outer hash. Leaf signatures remain independent.
fn rebind(f: &mut Value) {
    let key = signer(f);
    for side in ["source", "target"] {
        let m = f[side]["manifest"].clone();
        let mb = r(&m);
        f[side]["manifest_bytes"] = STANDARD.encode(&mb).into();
        let c = &mut f[side]["compatibility"];
        c["nest_release_version"] = m["version"].clone();
        c["release_manifest"]["sha256"] = digest(&mb).into();
        c["artifacts"]["workstation_runtime"] = unsigned(&m["workstation_netboot"]).unwrap();
        c["artifacts"]["appliance_package_snapshot"] =
            m["appliance_release_v1"]["system_closure"].clone();
        c["artifacts"]["appliance_package_snapshot"]["minimum_state_schema"] =
            m["appliance_release_v1"]["minimum_state_schema"].clone();
        c["compatibility_sha256"] = digest(&r(&c["compatibility"])).into();
        seal_r(c, b"TIARIS-NEST-RELEASE-COMPATIBILITY-V1\n", &key);
        let cb = r(c);
        f[side]["compatibility_bytes"] = STANDARD.encode(&cb).into();
        f["pair"][side]["release_version"] = m["version"].clone();
        f["pair"][side]["compatibility_sha256"] = digest(&cb).into();
        f["pair"][side]["manifest"] = f[side]["compatibility"]["release_manifest"].clone();
    }
    seal_r(&mut f["pair"], b"TIARIS-NEST-ORIGIN-TRANSITION-V1\n", &key);
    f["pair_bytes"] = STANDARD.encode(r(&f["pair"])).into();
}
fn check(f: &Value) -> Result<VerifiedEvidence> {
    check_evidence(
        &evidence_fixture(f),
        &release_identity(f, "source"),
        &release_identity(f, "target"),
        &release_key(f),
    )
}
// Exercise all six vocabularies in both signed releases, not just a token helper.
fn check_vocabularies(values: &[Value], accepted: bool) {
    let mut failures = Vec::new();
    for side in ["source", "target"] {
        for field in [
            "import_states",
            "import_error_codes",
            "resolution_states",
            "resolution_error_codes",
            "report_receipt_states",
            "report_receipt_error_codes",
        ] {
            for value in values {
                let mut f = release_fixture();
                f[side]["compatibility"]["compatibility"]["workstation_runtime"][field] =
                    value.clone();
                rebind(&mut f);
                match check(&f) {
                    Ok(_) if accepted => {}
                    Err(error) if !accepted && error.to_string().contains("vocabulary") => {}
                    Ok(_) => failures.push(format!("accepted {side}/{field}: {value}")),
                    Err(error) => failures.push(format!("{side}/{field} {value}: {error}")),
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn fully_signed_vocabulary_rejects_uppercase() {
    check_vocabularies(&[json!(["Ready"]), json!(["rEady"])], false);
}

#[test]
fn fully_signed_vocabulary_rejects_punctuation() {
    let values: Vec<_> = ['+', '.', '?', '=', '-']
        .into_iter()
        .map(|c| json!([format!("ready{c}state")]))
        .collect();
    check_vocabularies(&values, false);
}

#[test]
fn fully_signed_vocabulary_rejects_65_character_identifier() {
    check_vocabularies(&[json!(["a".repeat(65)])], false);
}

#[test]
fn fully_signed_vocabulary_rejects_65_entries() {
    let entries: Vec<_> = (0..65).map(|i| format!("state_{i}")).collect();
    check_vocabularies(&[json!(entries)], false);
}

#[test]
fn fully_signed_vocabulary_requires_initial_lowercase_letter() {
    check_vocabularies(&[json!(["0ready"]), json!(["_ready"])], false);
}

#[test]
fn fully_signed_vocabulary_preserves_shape_and_uniqueness_rules() {
    check_vocabularies(
        &[
            json!([]),
            json!([""]),
            json!(["ready", "ready"]),
            json!("ready"),
            json!([1]),
            json!([null]),
            json!(["réady"]),
            json!(["ready\n"]),
        ],
        false,
    );
}

#[test]
fn fully_signed_vocabulary_accepts_release_boundaries_without_sorting() {
    let entries: Vec<_> = (0..64).rev().map(|i| format!("state_{i}")).collect();
    check_vocabularies(
        &[
            json!(["a"]),
            json!(["a".repeat(64)]),
            json!(["z_09", "a"]),
            json!(entries),
        ],
        true,
    );
}

#[test]
fn authentic_outer_artifacts_cannot_hide_invalid_leaf_signatures() {
    for side in ["source", "target"] {
        for leaf in [
            "appliance_release_v1",
            "installer_iso_template_v3",
            "workstation_netboot",
            "binary",
        ] {
            let mut f = release_fixture();
            let object = if leaf == "binary" {
                &mut f[side]["manifest"]
            } else {
                &mut f[side]["manifest"][leaf]
            };
            object["signature"] = STANDARD.encode([0; 64]).into();
            rebind(&mut f);
            let error = check(&f).unwrap_err().to_string();
            assert!(
                !error.contains("raw hash mismatch"),
                "outer hash concealed {side}/{leaf}"
            );
        }
    }
}
#[test]
fn fully_signed_runtime_identity_and_epoch_floors_are_enforced() {
    for case in [
        "equal_changed",
        "version_decreased",
        "epoch_decreased",
        "epoch_advanced_same_bytes",
    ] {
        let mut f = release_fixture();
        let key = signer(&f);
        match case {
            "equal_changed" => {
                f["target"]["manifest"]["workstation_netboot"]["sha256"] = "f".repeat(64).into()
            }
            "version_decreased" => {
                f["target"]["manifest"]["workstation_netboot"]["runtime_version"] = "0.9.0".into();
                f["target"]["manifest"]["workstation_netboot"]["url"]="https://releases.example.test/tiaris-workstation-netboot-0.9.0-bbbbbbbbbbbb-x86_64-linux.tar.zst".into();
            }
            "epoch_decreased" => {
                f["source"]["compatibility"]["compatibility"]["workstation_runtime"]["compatibility_epoch"] =
                    2.into()
            }
            _ => {
                f["target"]["compatibility"]["compatibility"]["workstation_runtime"]["compatibility_epoch"] =
                    2.into()
            }
        }
        let d: crate::netboot::WorkstationNetbootDescriptor =
            serde_json::from_value(f["target"]["manifest"]["workstation_netboot"].clone()).unwrap();
        f["target"]["manifest"]["workstation_netboot"]["signature"] = STANDARD
            .encode(
                key.sign(crate::netboot::signature_message(&d).as_bytes())
                    .to_bytes(),
            )
            .into();
        rebind(&mut f);
        assert!(
            check(&f).unwrap_err().to_string().contains("runtime"),
            "wrong failure {case}"
        );
    }
}
#[test]
fn compatibility_signatures_are_not_replaced_by_a_valid_pair_hash() {
    for side in ["source", "target"] {
        let mut f = release_fixture();
        f[side]["compatibility"]["signature"] = STANDARD.encode([0; 64]).into();
        let cb = r(&f[side]["compatibility"]);
        f[side]["compatibility_bytes"] = STANDARD.encode(&cb).into();
        f["pair"][side]["compatibility_sha256"] = digest(&cb).into();
        let key = signer(&f);
        seal_r(&mut f["pair"], b"TIARIS-NEST-ORIGIN-TRANSITION-V1\n", &key);
        f["pair_bytes"] = STANDARD.encode(r(&f["pair"])).into();
        assert!(check(&f).is_err());
    }
}
#[test]
fn nested_manifest_unknown_fields_and_state_schema_changes_fail() {
    for pointer in [
        "/target/manifest/unknown",
        "/source/manifest/installer_iso_template_v3/unknown",
        "/target/manifest/appliance_release_v1/system_closure/unknown",
        "/source/manifest/workstation_netboot/components/bzImage/unknown",
    ] {
        let mut f = release_fixture();
        let (base, field) = pointer.rsplit_once('/').unwrap();
        f.pointer_mut(base).unwrap()[field] = true.into();
        rebind(&mut f);
        assert!(check(&f).is_err(), "accepted {pointer}");
    }
    let mut f = release_fixture();
    f["target"]["manifest"]["appliance_release_v1"]["minimum_state_schema"] = 2.into();
    let key = signer(&f);
    let d: release_v3::NixosRelease =
        serde_json::from_value(f["target"]["manifest"]["appliance_release_v1"].clone()).unwrap();
    f["target"]["manifest"]["appliance_release_v1"]["signature"] = STANDARD
        .encode(key.sign(&d.signature_message().unwrap()).to_bytes())
        .into();
    rebind(&mut f);
    assert!(check(&f).is_err());
}
#[test]
fn pair_exact_manifest_origin_and_version_are_not_advisory() {
    for (pointer, value) in [
        ("/source/manifest/sha256", json!("a".repeat(64))),
        ("/target/manage_origin", json!("https://other.example.test")),
        ("/target/release_version", json!("0.2.49")),
        ("/source/unknown", json!(true)),
    ] {
        let mut f = release_fixture();
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        f["pair"].pointer_mut(parent).unwrap()[field] = value;
        let key = signer(&f);
        seal_r(&mut f["pair"], b"TIARIS-NEST-ORIGIN-TRANSITION-V1\n", &key);
        f["pair_bytes"] = STANDARD.encode(r(&f["pair"])).into();
        assert!(
            check(&f)
                .unwrap_err()
                .to_string()
                .contains("exact releases")
        );
    }
}
