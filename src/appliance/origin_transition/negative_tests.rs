use super::tests::{
    check_evidence, evidence_fixture, release_fixture, release_identity, release_key, sign_new,
    vectors,
};
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
fn test_signer(f: &Value) -> SigningKey {
    SigningKey::from_bytes(
        &hex::decode(f["test_signer"]["seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

#[test]
fn exact_shared_signing_inputs_and_request_hash() {
    let f = vectors();
    for v in f["vectors"].as_array().unwrap() {
        let unsigned = canonical(&unsigned(&v["signed_object"]).unwrap()).unwrap();
        assert_eq!(hex::encode(&unsigned), v["unsigned_canonical_hex"]);
        let mut message = domain(&v["signed_object"]).unwrap().to_vec();
        message.extend(unsigned);
        assert_eq!(hex::encode(message), v["signature_input_hex"]);
    }
    let req = &f["contact_request"];
    wire::validate("OriginContactRequest", req).unwrap();
    assert_eq!(
        hex::encode(canonical(req).unwrap()),
        f["contact_request_canonical_hex"]
    );
    assert_eq!(object_digest(req).unwrap(), f["contact_request_sha256"]);
}
#[test]
fn all_new_signatures_reject_wrong_key_lf_padding_and_weak_key() {
    let f = vectors();
    let key = test_signer(&f);
    for v in f["vectors"].as_array().unwrap() {
        let object = &v["signed_object"];
        let bytes = canonical(object).unwrap();
        let wrong = SigningKey::from_bytes(&[42; 32]).verifying_key();
        assert!(verify_signed(&bytes, &wrong).is_err());
        let mut lf = bytes.clone();
        lf.push(b'\n');
        assert!(verify_signed(&lf, &key.verifying_key()).is_err());
        let mut changed = object.clone();
        changed["signature"] = format!("{}==", object["signature"].as_str().unwrap()).into();
        assert!(verify_signed(&canonical(&changed).unwrap(), &key.verifying_key()).is_err());
        changed["signature"] = STANDARD
            .encode(
                URL_SAFE_NO_PAD
                    .decode(object["signature"].as_str().unwrap())
                    .unwrap(),
            )
            .into();
        assert!(verify_signed(&canonical(&changed).unwrap(), &key.verifying_key()).is_err());
        let mut message = domain(object).unwrap().to_vec();
        message.extend(canonical(&unsigned(object).unwrap()).unwrap());
        message.push(b'\n');
        changed["signature"] = URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes()).into();
        assert!(verify_signed(&canonical(&changed).unwrap(), &key.verifying_key()).is_err());
        let mut weak_bytes = [0; 32];
        weak_bytes[0] = 1;
        let weak = VerifyingKey::from_bytes(&weak_bytes).unwrap();
        assert!(verify_signed(&bytes, &weak).is_err());
    }
}
#[test]
fn nested_duplicates_unknowns_floats_exponents_and_replay_mutations_fail() {
    let f = vectors();
    let key = test_signer(&f);
    let original = &f["vectors"][1]["signed_object"];
    let raw = String::from_utf8(canonical(original).unwrap()).unwrap();
    for replacement in ["1.0", "1e0", "-0", "9007199254740992"] {
        let changed = raw.replace("\"revision\":1", &format!("\"revision\":{replacement}"));
        assert_ne!(changed, raw);
        assert!(verify_signed(changed.as_bytes(), &key.verifying_key()).is_err());
    }
    let duplicate = raw.replace(
        "\"source\":{",
        "\"source\":{\"system_toplevel\":\"ignored\",",
    );
    assert!(verify_signed(duplicate.as_bytes(), &key.verifying_key()).is_err());
    let mut v = original.clone();
    v["source"]["unknown"] = true.into();
    sign_new(&mut v, &key);
    assert!(verify_signed(&canonical(&v).unwrap(), &key.verifying_key()).is_err());
    for field in [
        "binding_sha256",
        "attempt_id",
        "source_system_generation",
        "revision",
        "target_origin",
    ] {
        let mut changed = original.clone();
        changed[field] = match field {
            "revision" => json!(2),
            "source_system_generation" => json!("8"),
            "target_origin" => json!("https://attacker.example.test"),
            "binding_sha256" => json!("f".repeat(64)),
            _ => json!("11111111-1111-4111-8111-000000000099"),
        };
        assert!(verify_signed(&canonical(&changed).unwrap(), &key.verifying_key()).is_err());
    }
}
#[test]
fn ipv4_mapped_ipv6_uses_release_tools_hex_canonical_form() {
    assert!(wire::origin("https://[::ffff:c000:201]").is_ok());
    assert!(wire::origin("https://[::ffff:192.0.2.1]").is_err());
}
#[test]
fn origins_and_scalar_encodings_are_canonical() {
    for good in [
        "https://a.example.test",
        "https://127.0.0.1",
        "https://[2001:db8::1]:8443",
    ] {
        wire::origin(good).unwrap();
    }
    for bad in [
        "https://",
        "https://A.test",
        "https://a.test/",
        "https://a.test:443",
        "https://a.test:0443",
        "https://a.test?",
        "https://a.test#",
        "https://a.test:",
        "https://a.test:0",
        "https://a.test:65536",
        "https://user@a.test",
        "https://a.test\\x",
        "https://-a.test",
        "https://a_.test",
        "https://a.test.",
        "https://[2001:0db8::1]",
        "https://é.test",
    ] {
        assert!(wire::origin(bad).is_err(), "accepted {bad}");
    }
    let f = vectors();
    let key = test_signer(&f);
    for (field, value) in [
        ("boot_nonce", json!("AAAA=")),
        ("boot_id", json!("11111111-1111-4111-8111-00000000000A")),
        ("target_system_generation", json!("08")),
        ("target_system_generation", json!("18446744073709551616")),
        ("issued_at", json!(9_007_199_254_740_992u64)),
        ("target_origin", json!("https://a.test\n")),
    ] {
        let mut v = f["vectors"][2]["signed_object"].clone();
        v[field] = value;
        sign_new(&mut v, &key);
        assert!(
            verify_signed(&canonical(&v).unwrap(), &key.verifying_key()).is_err(),
            "accepted {field}"
        );
    }
}
#[test]
fn pair_and_compatibility_require_original_lf_and_standard_base64() {
    let f = release_fixture();
    let key = release_key(&f);
    let source = release_identity(&f, "source");
    let target = release_identity(&f, "target");
    for field in [
        "pair_authorization",
        "source_compatibility",
        "target_compatibility",
    ] {
        for mutation in ["no_lf", "extra_lf", "signature_url", "signature_no_lf"] {
            let mut e = serde_json::to_value(evidence_fixture(&f)).unwrap();
            let mut bytes = STANDARD.decode(e[field].as_str().unwrap()).unwrap();
            match mutation {
                "no_lf" => {
                    assert_eq!(bytes.pop(), Some(b'\n'));
                }
                "extra_lf" => bytes.push(b'\n'),
                _ => {
                    let mut v: Value = serde_json::from_slice(&bytes).unwrap();
                    if mutation == "signature_url" {
                        v["signature"] = URL_SAFE_NO_PAD
                            .encode(STANDARD.decode(v["signature"].as_str().unwrap()).unwrap())
                            .into();
                    } else {
                        let signer = SigningKey::from_bytes(
                            &hex::decode(f["release_seed_hex"].as_str().unwrap())
                                .unwrap()
                                .try_into()
                                .unwrap(),
                        );
                        let domain: &[u8] = if field == "pair_authorization" {
                            b"TIARIS-NEST-ORIGIN-TRANSITION-V1\n"
                        } else {
                            b"TIARIS-NEST-RELEASE-COMPATIBILITY-V1\n"
                        };
                        let mut msg = domain.to_vec();
                        msg.extend(canonical(&unsigned(&v).unwrap()).unwrap());
                        v["signature"] = STANDARD.encode(signer.sign(&msg).to_bytes()).into();
                    }
                    bytes = canonical(&v).unwrap();
                    bytes.push(b'\n');
                }
            }
            let mut source = source.clone();
            let mut target = target.clone();
            if field != "pair_authorization" {
                // Keep every outer hash/signature authentic so this reaches
                // the exact compatibility signature/encoding check.
                let (side, identity) = if field == "source_compatibility" {
                    ("source", &mut source)
                } else {
                    ("target", &mut target)
                };
                identity.compatibility_sha256 = digest(&bytes);
                let mut pair = f["pair"].clone();
                pair[side]["compatibility_sha256"] = identity.compatibility_sha256.clone().into();
                let signer = SigningKey::from_bytes(
                    &hex::decode(f["release_seed_hex"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                );
                let mut msg = b"TIARIS-NEST-ORIGIN-TRANSITION-V1\n".to_vec();
                msg.extend(canonical(&unsigned(&pair).unwrap()).unwrap());
                msg.push(b'\n');
                pair["signature"] = STANDARD.encode(signer.sign(&msg).to_bytes()).into();
                let mut pair_bytes = canonical(&pair).unwrap();
                pair_bytes.push(b'\n');
                e["pair_authorization"] = STANDARD.encode(pair_bytes).into();
            }
            e[field] = STANDARD.encode(bytes).into();
            let e = serde_json::from_value(e).unwrap();
            let error = check_evidence(&e, &source, &target, &key)
                .unwrap_err()
                .to_string();
            assert!(
                !error.contains("raw hash mismatch"),
                "hash masked {field} {mutation}"
            );
        }
    }
}
#[test]
fn evidence_false_hashes_wrong_key_manifest_and_closure_fail() {
    let f = release_fixture();
    let e = evidence_fixture(&f);
    let key = release_key(&f);
    let source = release_identity(&f, "source");
    let target = release_identity(&f, "target");
    assert!(
        check_evidence(
            &e,
            &source,
            &target,
            &SigningKey::from_bytes(&[81; 32]).verifying_key()
        )
        .is_err()
    );
    for field in [
        "compatibility_sha256",
        "manifest_sha256",
        "descriptor_sha256",
        "system_closure_sha256",
    ] {
        for side in ["source", "target"] {
            let mut id =
                serde_json::to_value(if side == "source" { &source } else { &target }).unwrap();
            id[field] = "a".repeat(64).into();
            let id = serde_json::from_value(id).unwrap();
            assert!(
                check_evidence(
                    &e,
                    if side == "source" { &id } else { &source },
                    if side == "target" { &id } else { &target },
                    &key
                )
                .is_err()
            );
        }
    }
    let mut changed = e.clone();
    changed.target_manifest = changed.source_manifest.clone();
    assert!(check_evidence(&changed, &source, &target, &key).is_err());
    let mut invalid = e.clone();
    invalid.pair_authorization.push('=');
    assert!(check_evidence(&invalid, &source, &target, &key).is_err());
    invalid = e.clone();
    invalid.source_manifest = "A".repeat(524288usize.div_ceil(3) * 4 + 4);
    assert!(check_evidence(&invalid, &source, &target, &key).is_err());
    let fake: wire::DeviceOriginTransition =
        serde_json::from_value(vectors()["vectors"][1]["signed_object"].clone()).unwrap();
    assert!(check_evidence(&e, &fake.source, &fake.target, &key).is_err());
}
