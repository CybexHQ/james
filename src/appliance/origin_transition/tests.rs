use super::*;
use ed25519_dalek::{Signer, SigningKey};
pub(super) fn sign_new(v: &mut Value, key: &SigningKey) {
    let mut m = domain(v).unwrap().to_vec();
    m.extend(canonical(&unsigned(v).unwrap()).unwrap());
    v["signature"] = URL_SAFE_NO_PAD.encode(key.sign(&m).to_bytes()).into();
}
#[test]
fn signed_objects_reject_unknown_fields_and_noncanonical_primitives() {
    let f = vectors();
    let key = SigningKey::from_bytes(
        &hex::decode(f["test_signer"]["seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    for (field, value) in [
        ("unknown", serde_json::json!(true)),
        (
            "organization_id",
            serde_json::json!("11111111111141118111000000000002"),
        ),
        (
            "organization_id",
            serde_json::json!("00000000-0000-0000-0000-000000000000"),
        ),
        (
            "source_origin",
            serde_json::json!("https://OLD-origin.example.test"),
        ),
        (
            "source_origin",
            serde_json::json!("https://old-origin.example.test:443"),
        ),
        ("device_id", serde_json::json!("dev_nope")),
        ("issued_at", serde_json::json!(0)),
        ("base_plan_sha256", serde_json::json!("A".repeat(64))),
    ] {
        let mut v = f["vectors"][0]["signed_object"].clone();
        v[field] = value;
        sign_new(&mut v, &key);
        assert!(
            verify_signed(&canonical(&v).unwrap(), &key.verifying_key()).is_err(),
            "accepted {field}"
        );
    }
}

use sha2::{Digest, Sha256};

#[test]
fn binding_authenticates_historical_plan_and_protected_permanent_identity() {
    let (mut plan, envelope, _, signer) = crate::provisioning::protocol::tests::signed_plan_fixture(
        "tiaris.nest.install-plan.v1",
        "TIARIS-NEST-INSTALL-PLAN-V1",
    );
    plan["schema"] = "tiaris.nest.install-plan.v3".into();
    plan["base_os"] = "nixos".into();
    plan["base_os_version"] = "26.05".into();
    plan["package_delivery"] = "system-closure-v1".into();
    let release = release_fixture()["source"]["manifest"]["appliance_release_v1"].clone();
    plan["package_transport_url"] = release["system_closure"]["url"].clone();
    plan["appliance_release"] = release;
    plan = crate::provisioning::protocol::tests::resign_plan(
        plan,
        "TIARIS-NEST-INSTALL-PLAN-V3",
        &signer,
    );
    // Historical plan verification deliberately retains its own byte/hash rules.
    let plan_bytes = serde_json::to_vec_pretty(&plan).unwrap();
    let key = SigningKey::from_bytes(&[73; 32]);
    let trusted = [signer.verifying_key()];
    let org = plan["organization_id"].as_str().unwrap();
    let session = envelope.session_id.to_string();
    let context = InstalledContext {
        original_plan: &plan_bytes,
        trusted_provisioning_keys: &trusted,
        original_signer: &trusted[0],
        permanent_key: &key,
        organization_id: org,
        device_id: plan["reserved_device_id"].as_str().unwrap(),
        session_id: &session,
        original_origin: &envelope.manage_origin,
        existing_binding: None,
        signed_schedule: None,
    };
    let mut binding = vectors()["vectors"][0]["signed_object"].clone();
    binding["organization_id"] = org.into();
    binding["device_id"] = context.device_id.into();
    binding["provisioning_session_id"] = session.clone().into();
    binding["source_origin"] = envelope.manage_origin.clone().into();
    binding["base_plan_sha256"] = plan["plan_sha256"].clone();
    binding["base_signed_plan_sha256"] = object_digest(&plan).unwrap().into();
    binding["device_public_key_sha256"] = digest(key.verifying_key().as_bytes()).into();
    binding["management_signing_key_sha256"] = digest(trusted[0].as_bytes()).into();
    sign_new(&mut binding, &signer);
    let bytes = canonical(&binding).unwrap();
    assert_eq!(
        verify_binding(&bytes, &context).unwrap().sha256(),
        digest(&bytes)
    );
    for field in [
        "organization_id",
        "provisioning_session_id",
        "base_plan_sha256",
        "base_signed_plan_sha256",
        "device_public_key_sha256",
        "management_signing_key_sha256",
        "source_origin",
        "device_id",
    ] {
        let mut changed = binding.clone();
        changed[field] = vectors()["vectors"][0]["signed_object"][field].clone();
        assert_ne!(changed[field], binding[field]);
        sign_new(&mut changed, &signer);
        assert!(
            verify_binding(&canonical(&changed).unwrap(), &context).is_err(),
            "accepted {field}"
        );
    }
}
pub(super) fn release_fixture() -> Value {
    serde_json::from_slice(include_bytes!("release-fixture.json")).unwrap()
}
pub(super) fn release_key(f: &Value) -> VerifyingKey {
    VerifyingKey::from_bytes(
        &STANDARD
            .decode(f["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}
pub(super) fn evidence_fixture(f: &Value) -> wire::OriginEvidence {
    wire::OriginEvidence {
        pair_authorization: f["pair_bytes"].as_str().unwrap().into(),
        source_compatibility: f["source"]["compatibility_bytes"].as_str().unwrap().into(),
        target_compatibility: f["target"]["compatibility_bytes"].as_str().unwrap().into(),
        source_manifest: f["source"]["manifest_bytes"].as_str().unwrap().into(),
        target_manifest: f["target"]["manifest_bytes"].as_str().unwrap().into(),
    }
}
pub(super) fn release_identity(f: &Value, side: &str) -> wire::ReleaseIdentity {
    let r = &f[side]["manifest"]["appliance_release_v1"];
    wire::ReleaseIdentity {
        release_version: r["release_id"].as_str().unwrap().into(),
        compatibility_sha256: digest(
            &STANDARD
                .decode(f[side]["compatibility_bytes"].as_str().unwrap())
                .unwrap(),
        ),
        manifest_sha256: digest(
            &STANDARD
                .decode(f[side]["manifest_bytes"].as_str().unwrap())
                .unwrap(),
        ),
        descriptor_sha256: object_digest(r).unwrap(),
        system_closure_sha256: r["system_closure"]["sha256"].as_str().unwrap().into(),
        system_toplevel: r["system_toplevel"].as_str().unwrap().into(),
    }
}
pub(super) fn check_evidence(
    e: &wire::OriginEvidence,
    source: &wire::ReleaseIdentity,
    target: &wire::ReleaseIdentity,
    key: &VerifyingKey,
) -> Result<VerifiedEvidence> {
    verify_evidence(
        e,
        source,
        target,
        &digest(&STANDARD.decode(&e.pair_authorization)?),
        "https://old-origin.example.test",
        "https://new-origin.example.test",
        key,
    )
}
#[test]
fn independent_release_pair_and_both_manifest_descriptors_verify() {
    let f = release_fixture();
    let e = evidence_fixture(&f);
    assert!(
        check_evidence(
            &e,
            &release_identity(&f, "source"),
            &release_identity(&f, "target"),
            &release_key(&f)
        )
        .is_ok()
    );
}
pub(super) fn vectors() -> Value {
    let bytes = include_bytes!("vectors-v1.json");
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        "54a2db1de704df7c900bcaccf186a192acbfbb3c70a9423dbd163ca0f7cf7dac"
    );
    serde_json::from_slice(bytes).unwrap()
}
fn vector_key(v: &Value) -> VerifyingKey {
    VerifyingKey::from_bytes(
        &hex::decode(v["test_signer"]["public_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}
#[test]
fn shared_three_signatures_use_exact_no_lf_bytes() {
    let fixture = vectors();
    for v in fixture["vectors"].as_array().unwrap() {
        let bytes = hex::decode(v["signed_canonical_hex"].as_str().unwrap()).unwrap();
        let object = verify_signed(&bytes, &vector_key(&fixture)).unwrap();
        assert_eq!(object, v["signed_object"]);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            v["signed_object_sha256"]
        );
    }
}
