use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn sign<T: Serialize>(value: &T, domain: &str, key: &SigningKey) -> String {
    let mut value = serde_json::to_value(value).unwrap();
    value.as_object_mut().unwrap().remove("signature");
    let mut body = format!("{domain}\n").into_bytes();
    body.extend(serde_json::to_vec(&value).unwrap());
    URL_SAFE_NO_PAD.encode(key.sign(&body).to_bytes())
}

fn fixture(mode: &str) -> (Receipt, DurableProvisioningState, SigningKey) {
    let (plan, envelope, _, key) = protocol::tests::signed_plan_fixture(
        protocol::INSTALL_PLAN_SCHEMA_V2,
        "CYBEX-JAMES-INSTALL-PLAN-V2",
    );
    let plan = serde_json::from_value(plan).unwrap();
    let state = DurableProvisioningState {
        schema: "cybex.james.provisioning-state.v1".into(),
        session_id: envelope.session_id,
        plan,
        manage_origin: envelope.manage_origin,
        management_signing_public_key_b64: protocol::standard_base64(
            key.verifying_key().to_bytes(),
        ),
        device_private_key_b64: String::new(),
        device_public_key_b64: String::new(),
        device_public_key_fingerprint: String::new(),
        next_event_sequence: 12,
        identity_active: true,
        installation_complete: true,
        updated_at: Utc::now(),
    };
    let now = Utc::now() - chrono::Duration::days(3);
    let network = appliance::ApplianceNetworkInput {
        mode: mode.into(),
        interface_id: state.plan.network.interface_id.clone(),
        address_cidr: (mode == "static").then(|| "192.0.2.25/24".into()),
        gateway: (mode == "static").then(|| "192.0.2.1".into()),
        dns_servers: if mode == "static" {
            vec!["192.0.2.53".into()]
        } else {
            vec![]
        },
    };
    let mut change = SignedApplianceNetworkChange {
        schema: "cybex.james.network-change.v1".into(),
        id: Uuid::new_v4(),
        device_id: state.plan.reserved_device_id.clone(),
        device_incarnation_id: Uuid::new_v4(),
        revision: 2,
        config_sha256: protocol::sha256_hex(
            serde_json::to_vec(&serde_json::to_value(&network).unwrap()).unwrap(),
        ),
        network,
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        signature: String::new(),
    };
    change.signature = sign(&change, "CYBEX-JAMES-NETWORK-CHANGE-V1", &key);
    let network = protocol::JamesProvisioningNetworkPlan {
        mode: change.network.mode.clone(),
        interface_id: change.network.interface_id.clone(),
        address_cidr: change.network.address_cidr.clone(),
        gateway: change.network.gateway.clone(),
        dns_servers: change.network.dns_servers.clone(),
    };
    let candidate = serde_json::to_string(&storage::netplan(&network, &state.plan)).unwrap();
    let mut acknowledgement = SignedApplianceNetworkAcknowledgement {
        schema: "cybex.james.network-ack.v1".into(),
        change_id: change.id,
        device_id: change.device_id.clone(),
        candidate_sha256: protocol::sha256_hex(&candidate),
        issued_at: now + chrono::Duration::seconds(30),
        expires_at: now + chrono::Duration::minutes(2),
        signature: String::new(),
    };
    acknowledgement.signature = sign(&acknowledgement, "CYBEX-JAMES-NETWORK-ACK-V1", &key);
    (
        Receipt {
            schema: SCHEMA.into(),
            change,
            acknowledgement,
            candidate,
        },
        state,
        key,
    )
}

#[test]
fn reboot_accepts_signed_static_ip_and_dhcp_changes_after_live_expiry() {
    for mode in ["static", "dhcp"] {
        let (receipt, state, _) = fixture(mode);
        let interface = (
            state.plan.network_interface.name.clone(),
            state.plan.network_interface.mac.clone(),
        );
        assert!(validate(&receipt, &state, &interface, true).is_ok());
        assert!(validate(&receipt, &state, &interface, false).is_err());
        if mode == "static" {
            assert_ne!(
                serde_json::from_str::<Value>(&receipt.candidate).unwrap(),
                storage::netplan(&state.plan.network, &state.plan)
            );
        }
    }
}

#[test]
fn unsigned_or_mismatched_committed_network_evidence_is_rejected() {
    let (mut receipt, state, key) = fixture("static");
    let interface = (
        state.plan.network_interface.name.clone(),
        state.plan.network_interface.mac.clone(),
    );
    receipt.candidate.push(' ');
    assert!(validate(&receipt, &state, &interface, true).is_err());
    receipt.acknowledgement.candidate_sha256 = protocol::sha256_hex(&receipt.candidate);
    assert!(validate(&receipt, &state, &interface, true).is_err()); // unsigned changed acknowledgement
    receipt.acknowledgement.signature =
        sign(&receipt.acknowledgement, "CYBEX-JAMES-NETWORK-ACK-V1", &key);
    assert!(validate(&receipt, &state, &interface, true).is_ok());
    receipt.change.network.address_cidr = Some("192.0.2.99/24".into());
    assert!(validate(&receipt, &state, &interface, true).is_err());
    let (mut receipt, mut state, key) = fixture("dhcp");
    receipt.acknowledgement.change_id = Uuid::new_v4();
    receipt.acknowledgement.signature =
        sign(&receipt.acknowledgement, "CYBEX-JAMES-NETWORK-ACK-V1", &key);
    assert!(validate(&receipt, &state, &interface, true).is_err());
    receipt.acknowledgement.change_id = receipt.change.id;
    receipt.acknowledgement.signature =
        sign(&receipt.acknowledgement, "CYBEX-JAMES-NETWORK-ACK-V1", &key);
    state.plan.reserved_device_id = "dev_other_installed_identity".into();
    assert!(validate(&receipt, &state, &interface, true).is_err());
}

#[test]
fn even_a_signed_acknowledgement_cannot_commit_a_different_network_than_its_change() {
    let (mut receipt, state, key) = fixture("static");
    let interface = (
        state.plan.network_interface.name.clone(),
        state.plan.network_interface.mac.clone(),
    );
    let mut candidate: Value = serde_json::from_str(&receipt.candidate).unwrap();
    candidate["network"]["ethernets"]["cybex-james"]["addresses"] = json!(["192.0.2.250/24"]);
    receipt.candidate = serde_json::to_string(&candidate).unwrap();
    receipt.acknowledgement.candidate_sha256 = protocol::sha256_hex(&receipt.candidate);
    receipt.acknowledgement.signature =
        sign(&receipt.acknowledgement, "CYBEX-JAMES-NETWORK-ACK-V1", &key);
    assert!(validate(&receipt, &state, &interface, true).is_err());
    let (receipt, state, _) = fixture("dhcp");
    assert!(
        validate(
            &receipt,
            &state,
            &("different-interface".into(), interface.1),
            true
        )
        .is_err()
    );
}

#[test]
fn interrupted_commit_repairs_derived_profile_only_from_verified_receipt() {
    let (receipt, state, _) = fixture("static");
    let interface = (
        state.plan.network_interface.name.clone(),
        state.plan.network_interface.mac.clone(),
    );
    validate(&receipt, &state, &interface, true).unwrap();
    let root = std::env::temp_dir().join(format!("james-network-receipt-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("netplan-approved.json");
    fs::write(
        &path,
        serde_json::to_vec(&storage::netplan(&state.plan.network, &state.plan)).unwrap(),
    )
    .unwrap();
    restore_profile(&path, receipt.candidate.as_bytes(), |path, bytes| {
        storage::atomic_write(path, bytes, 0o600)
    })
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), receipt.candidate.as_bytes());
    restore_profile(&path, receipt.candidate.as_bytes(), |_, _| {
        panic!("unchanged verified profile must not be rewritten")
    })
    .unwrap();
    fs::remove_file(&path).unwrap();
    restore_profile(&path, receipt.candidate.as_bytes(), |path, bytes| {
        storage::atomic_write(path, bytes, 0o600)
    })
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), receipt.candidate.as_bytes());
    fs::remove_dir_all(root).unwrap();
}
