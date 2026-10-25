use super::tests::{
    evidence_fixture, release_fixture, release_identity, release_key, sign_new, vectors,
};
use super::*;
use ed25519_dalek::SigningKey;
use serde_json::json;
struct Fixture {
    plan: Vec<u8>,
    binding: Value,
    bundle: Value,
    management: SigningKey,
    permanent: SigningKey,
    trusted: [VerifyingKey; 1],
    release_key: VerifyingKey,
    source: release_v3::NixosRelease,
    target: release_v3::NixosRelease,
}
impl Fixture {
    fn new() -> Self {
        let f = release_fixture();
        let source: release_v3::NixosRelease =
            serde_json::from_value(f["source"]["manifest"]["appliance_release_v1"].clone())
                .unwrap();
        let target =
            serde_json::from_value(f["target"]["manifest"]["appliance_release_v1"].clone())
                .unwrap();
        let (mut plan, _, _, management) =
            crate::provisioning::protocol::tests::signed_plan_fixture(
                "tiaris.nest.install-plan.v1",
                "TIARIS-NEST-INSTALL-PLAN-V1",
            );
        plan["schema"] = "tiaris.nest.install-plan.v3".into();
        plan["base_os"] = "nixos".into();
        plan["base_os_version"] = "26.05".into();
        plan["package_delivery"] = "system-closure-v1".into();
        plan["appliance_release"] = serde_json::to_value(&source).unwrap();
        plan["package_transport_url"] = source.system_closure.url.clone().into();
        plan["display_name"] = "Historical Unicode Nest é".into();
        plan = crate::provisioning::protocol::tests::resign_plan(
            plan,
            "TIARIS-NEST-INSTALL-PLAN-V3",
            &management,
        );
        let permanent = SigningKey::from_bytes(&[73; 32]);
        let trusted = [management.verifying_key()];
        let mut binding = vectors()["vectors"][0]["signed_object"].clone();
        binding["organization_id"] = plan["organization_id"].clone();
        binding["device_id"] = plan["reserved_device_id"].clone();
        binding["provisioning_session_id"] = plan["session_id"].clone();
        binding["base_plan_sha256"] = plan["plan_sha256"].clone();
        binding["base_signed_plan_sha256"] = object_digest(&plan).unwrap().into();
        binding["device_public_key_sha256"] = digest(permanent.verifying_key().as_bytes()).into();
        binding["management_signing_key_sha256"] = digest(trusted[0].as_bytes()).into();
        sign_new(&mut binding, &management);
        let mut transition = vectors()["vectors"][1]["signed_object"].clone();
        for field in [
            "organization_id",
            "device_id",
            "device_incarnation_id",
            "provisioning_session_id",
            "base_plan_sha256",
            "base_signed_plan_sha256",
            "device_public_key_sha256",
            "source_origin",
        ] {
            transition[field] = binding[field].clone();
        }
        transition["binding_sha256"] = object_digest(&binding).unwrap().into();
        transition["source"] = serde_json::to_value(release_identity(&f, "source")).unwrap();
        transition["target"] = serde_json::to_value(release_identity(&f, "target")).unwrap();
        transition["pair_authorization_sha256"] =
            digest(&STANDARD.decode(f["pair_bytes"].as_str().unwrap()).unwrap()).into();
        sign_new(&mut transition, &management);
        let bundle =
            json!({"binding":binding,"transition":transition,"evidence":evidence_fixture(&f)});
        Self {
            plan: serde_json::to_vec_pretty(&plan).unwrap(),
            binding,
            bundle,
            management,
            permanent,
            trusted,
            release_key: release_key(&f),
            source,
            target,
        }
    }
    fn installed(&self) -> InstalledContext<'_> {
        InstalledContext {
            original_plan: &self.plan,
            trusted_provisioning_keys: &self.trusted,
            original_signer: &self.trusted[0],
            permanent_key: &self.permanent,
            organization_id: self.binding["organization_id"].as_str().unwrap(),
            device_id: self.binding["device_id"].as_str().unwrap(),
            session_id: self.binding["provisioning_session_id"].as_str().unwrap(),
            original_origin: self.binding["source_origin"].as_str().unwrap(),
            existing_binding: None,
            signed_schedule: None,
        }
    }
    fn context(&self) -> TransitionContext<'_> {
        TransitionContext {
            installed: self.installed(),
            release_key: &self.release_key,
            source_release: &self.source,
            target_release: &self.target,
            source_generation: "7",
            booted_source_toplevel: &self.source.system_toplevel,
            expected_target_origin: "https://new-origin.example.test",
            expected_attempt_id: self.bundle["transition"]["attempt_id"].as_str().unwrap(),
            now: 1700000100,
        }
    }
}
#[test]
fn installed_binding_is_write_once_and_agrees_with_protected_schedule() {
    use ed25519_dalek::Signer;
    let f = Fixture::new();
    let bytes = canonical(&f.binding).unwrap();
    let mut context = f.installed();
    context.existing_binding = Some(&bytes);
    verify_binding(&bytes, &context).unwrap();
    let mut changed = f.binding.clone();
    changed["issued_at"] = 1700000001.into();
    sign_new(&mut changed, &f.management);
    assert!(verify_binding(&canonical(&changed).unwrap(), &context).is_err());
    let mut schedule = json!({"schema":"tiaris.nest.update-schedule.v1","device_id":f.binding["device_id"],"device_incarnation_id":f.binding["device_incarnation_id"],"provisioning_session_id":f.binding["provisioning_session_id"],"revision":1,"schedule":{"timezone":"UTC","weekdays":[0],"start":"02:00","duration_minutes":120},"run_now":null,"signature":""});
    for correct in [true, false] {
        if !correct {
            schedule["device_incarnation_id"] = "11111111-1111-4111-8111-000000000099".into();
        }
        let mut m = b"TIARIS-NEST-UPDATE-SCHEDULE-V1\n".to_vec();
        m.extend(canonical(&unsigned(&schedule).unwrap()).unwrap());
        schedule["signature"] = URL_SAFE_NO_PAD
            .encode(f.management.sign(&m).to_bytes())
            .into();
        let sb = canonical(&schedule).unwrap();
        let mut context = f.installed();
        context.signed_schedule = Some(&sb);
        assert_eq!(verify_binding(&bytes, &context).is_ok(), correct);
    }
}
#[test]
fn legacy_plan_cannot_seed_a_nixos_installed_origin_binding() {
    let mut f = Fixture::new();
    let mut p: Value = serde_json::from_slice(&f.plan).unwrap();
    for k in [
        "package_delivery",
        "appliance_release",
        "package_transport_url",
    ] {
        p.as_object_mut().unwrap().remove(k);
    }
    p["schema"] = "tiaris.nest.install-plan.v1".into();
    p["base_os"] = "ubuntu".into();
    p["base_os_version"] = "26.04".into();
    p = crate::provisioning::protocol::tests::resign_plan(
        p,
        "TIARIS-NEST-INSTALL-PLAN-V1",
        &f.management,
    );
    f.binding["base_plan_sha256"] = p["plan_sha256"].clone();
    f.binding["base_signed_plan_sha256"] = object_digest(&p).unwrap().into();
    sign_new(&mut f.binding, &f.management);
    f.plan = canonical(&p).unwrap();
    assert!(verify_binding(&canonical(&f.binding).unwrap(), &f.installed()).is_err());
}
#[test]
fn binding_rejects_untrusted_original_signer_and_modified_plan() {
    let mut f = Fixture::new();
    let bytes = canonical(&f.binding).unwrap();
    let wrong = [SigningKey::from_bytes(&[31; 32]).verifying_key()];
    let mut context = f.installed();
    context.trusted_provisioning_keys = &wrong;
    assert!(verify_binding(&bytes, &context).is_err());
    let mut plan: Value = serde_json::from_slice(&f.plan).unwrap();
    plan["display_name"] = "forged".into();
    f.plan = canonical(&plan).unwrap();
    assert!(verify_binding(&bytes, &f.installed()).is_err());
}
#[test]
fn bundle_context_and_signed_identity_mutations_fail() {
    let f = Fixture::new();
    let bytes = canonical(&f.bundle).unwrap();
    let mut c = f.context();
    c.source_generation = "8";
    assert!(verify_bundle(&bytes, &c).is_err());
    let mut c = f.context();
    c.booted_source_toplevel = &f.target.system_toplevel;
    assert!(verify_bundle(&bytes, &c).is_err());
    let mut c = f.context();
    c.expected_target_origin = "https://other.example.test";
    assert!(verify_bundle(&bytes, &c).is_err());
    let mut c = f.context();
    c.target_release = &f.source;
    assert!(verify_bundle(&bytes, &c).is_err());
    for (field, value) in [
        (
            "organization_id",
            json!("11111111-1111-4111-8111-000000000099"),
        ),
        ("base_signed_plan_sha256", json!("f".repeat(64))),
        (
            "device_incarnation_id",
            json!("11111111-1111-4111-8111-000000000099"),
        ),
        ("source_origin", json!("https://elsewhere.example.test")),
    ] {
        let mut b = f.bundle.clone();
        b["transition"][field] = value;
        sign_new(&mut b["transition"], &f.management);
        assert!(
            verify_bundle(&canonical(&b).unwrap(), &f.context()).is_err(),
            "accepted {field}"
        );
    }
}
#[test]
fn bundle_unknown_duplicate_integer_and_size_bounds_fail_closed() {
    let f = Fixture::new();
    let raw = String::from_utf8(canonical(&f.bundle).unwrap()).unwrap();
    for scope in [
        "",
        "/binding",
        "/transition",
        "/transition/source",
        "/transition/target",
        "/evidence",
    ] {
        let mut b = f.bundle.clone();
        b.pointer_mut(scope).unwrap()["unexpected"] = true.into();
        assert!(verify_bundle(&canonical(&b).unwrap(), &f.context()).is_err());
    }
    for altered in [
        raw.replace(
            "\"evidence\":{",
            "\"evidence\":{\"source_manifest\":\"ignored\",",
        ),
        raw.replace("\"revision\":1", "\"revision\":1e0"),
        format!("{raw}\n"),
    ] {
        assert!(verify_bundle(altered.as_bytes(), &f.context()).is_err());
    }
    assert!(
        verify_bundle(&vec![b' '; MAX_BUNDLE_BYTES + 1], &f.context())
            .unwrap_err()
            .to_string()
            .contains("8 MiB")
    );
    let verified = verify_bundle(raw.as_bytes(), &f.context()).unwrap();
    let mut changed = raw.into_bytes();
    changed.fill(0);
    assert_eq!(verified.snapshot(), canonical(&f.bundle).unwrap());
}
#[test]
fn transition_expiry_and_future_issue_boundaries() {
    let f = Fixture::new();
    for (issued, expires, now, valid) in [
        (100, 200, 100, true),
        (100, 200, 200, false),
        (161, 200, 100, false),
        (160, 200, 100, true),
        (100, 86500, 100, true),
        (100, 86501, 100, false),
        (200, 100, 100, false),
    ] {
        let mut b = f.bundle.clone();
        b["transition"]["issued_at"] = issued.into();
        b["transition"]["expires_at"] = expires.into();
        sign_new(&mut b["transition"], &f.management);
        let mut c = f.context();
        c.now = now;
        assert_eq!(
            verify_bundle(&canonical(&b).unwrap(), &c).is_ok(),
            valid,
            "{issued}/{expires}/{now}"
        );
    }
}
#[test]
fn acknowledgement_matches_exact_root_request_and_boot_nonce() {
    let f = Fixture::new();
    let authority = verify_bundle(&canonical(&f.bundle).unwrap(), &f.context()).unwrap();
    let mut ack = vectors()["vectors"][2]["signed_object"].clone();
    for field in [
        "transition_id",
        "attempt_id",
        "revision",
        "organization_id",
        "device_id",
        "device_incarnation_id",
        "target_origin",
    ] {
        ack[field] = f.bundle["transition"][field].clone();
    }
    ack["transition_sha256"] = authority.sha256().into();
    ack["binding_sha256"] = authority.binding().sha256().into();
    ack["target_system_toplevel"] = f.target.system_toplevel.clone().into();
    ack["target_system_closure_sha256"] = f.target.system_closure.sha256.clone().into();
    let mut req = ack.clone();
    for field in ["request_sha256", "signature", "issued_at", "expires_at"] {
        req.as_object_mut().unwrap().remove(field);
    }
    req["schema"] = "tiaris.nest.origin-contact.v1".into();
    ack["request_sha256"] = object_digest(&req).unwrap().into();
    sign_new(&mut ack, &f.management);
    let bytes = canonical(&ack).unwrap();
    let request = canonical(&req).unwrap();
    assert_eq!(
        verify_acknowledgement(&bytes, &request, &authority, 1700000100)
            .unwrap()
            .sha256(),
        digest(&bytes)
    );
    for field in [
        "boot_nonce",
        "boot_id",
        "attempt_id",
        "target_system_toplevel",
        "request_sha256",
    ] {
        let mut changed = ack.clone();
        changed[field] = match field {
            "boot_nonce" => URL_SAFE_NO_PAD.encode([42; 32]).into(),
            "target_system_toplevel" => f.source.system_toplevel.clone().into(),
            "request_sha256" => "f".repeat(64).into(),
            _ => "11111111-1111-4111-8111-000000000099".into(),
        };
        sign_new(&mut changed, &f.management);
        assert!(
            verify_acknowledgement(
                &canonical(&changed).unwrap(),
                &request,
                &authority,
                1700000100
            )
            .is_err(),
            "ack accepted {field}"
        );
    }
    assert!(verify_acknowledgement(&bytes, &request, &authority, 1700000330).is_err());
}
#[test]
fn bundle_returns_verified_authority_only_after_all_cross_links() {
    let f = Fixture::new();
    let verified = verify_bundle(&canonical(&f.bundle).unwrap(), &f.context()).unwrap();
    assert_eq!(
        verified.digest,
        object_digest(&f.bundle["transition"]).unwrap()
    );
    let mut fake = f.bundle.clone();
    fake["transition"]["source"] = vectors()["vectors"][1]["signed_object"]["source"].clone();
    sign_new(&mut fake["transition"], &f.management);
    assert!(verify_bundle(&canonical(&fake).unwrap(), &f.context()).is_err());
}
