use super::*;
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::any,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn fixture() -> (
    Value,
    protocol::VerifiedEnvelope,
    JamesProvisioningInventory,
) {
    let (mut plan, envelope, inventory, signing) = protocol::tests::signed_plan_fixture(
        protocol::INSTALL_PLAN_SCHEMA_V2,
        "CYBEX-JAMES-INSTALL-PLAN-V2",
    );
    let release: Value = serde_json::from_str(include_str!(
        "../../../protocol/fixtures/james-appliance-v3.json"
    ))
    .unwrap();
    plan["schema"] = protocol::INSTALL_PLAN_SCHEMA_V3.into();
    plan["base_os"] = "nixos".into();
    plan["base_os_version"] = "26.05".into();
    plan["package_delivery"] = "system-closure-v1".into();
    plan["appliance_release"] = release["appliance_release"].clone();
    plan["package_transport_url"] = release["appliance_release"]["system_closure"]["url"].clone();
    // Model a server-acknowledged plan after its short approval window passed.
    plan["issued_at"] = json!(chrono::Utc::now() - chrono::Duration::hours(2));
    plan["expires_at"] = json!(chrono::Utc::now() - chrono::Duration::minutes(100));
    (
        protocol::tests::resign_plan(plan, "CYBEX-JAMES-INSTALL-PLAN-V3", &signing),
        protocol::VerifiedEnvelope {
            envelope,
            signing_key: signing.verifying_key(),
        },
        inventory,
    )
}

fn response(plan: &Value, state: &str) -> protocol::AgentSessionResponse {
    serde_json::from_value(
        json!({"session_id":plan["session_id"],"state":state,"session_revision":3,
        "poll_after_seconds":2,"plan":plan}),
    )
    .unwrap()
}

#[test]
fn expired_retained_media_boots_completed_identity_without_network_or_closure() {
    let (plan, mut verified, mut inventory) = fixture();
    verified.envelope.issued_at = chrono::Utc::now() - chrono::Duration::days(2);
    verified.envelope.expires_at = verified.envelope.issued_at + chrono::Duration::hours(24);
    // A completed boot must not need the original install-time network.
    inventory.ethernet_interfaces[0].link_up = false;
    inventory.ethernet_interfaces[0].addresses.clear();
    inventory.ethernet_interfaces[0].gateway = None;
    let key = SigningKey::from_bytes(&[81; 32]);
    let mut durable = super::super::DurableProvisioningState {
        schema: "cybex.james.provisioning-state.v1".into(),
        session_id: verified.envelope.session_id,
        plan: serde_json::from_value(plan).unwrap(),
        manage_origin: verified.envelope.manage_origin.clone(),
        management_signing_public_key_b64: protocol::standard_base64(
            verified.signing_key.to_bytes(),
        ),
        device_private_key_b64: protocol::standard_base64(key.to_bytes()),
        device_public_key_b64: protocol::standard_base64(key.verifying_key().to_bytes()),
        device_public_key_fingerprint: protocol::sha256_hex(key.verifying_key().to_bytes()),
        next_event_sequence: 9,
        identity_active: true,
        installation_complete: true,
        updated_at: chrono::Utc::now(),
    };
    assert!(durable_plan(&durable, &verified, &inventory).is_ok());
    assert!(protocol::require_current_envelope(&verified).is_err()); // no new install
    durable.installation_complete = false;
    durable.next_event_sequence = 6;
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    verified.envelope.issued_at = chrono::Utc::now();
    verified.envelope.expires_at = verified.envelope.issued_at + chrono::Duration::hours(1);
    for sequence in 7..=9 {
        durable.next_event_sequence = sequence;
        assert!(
            durable_plan(&durable, &verified, &inventory).is_ok(),
            "resume seq{sequence}"
        );
    }
    durable.next_event_sequence = 10;
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    durable.installation_complete = true;
    durable.next_event_sequence = 9;
    durable.identity_active = false;
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    durable.identity_active = true;
    inventory.disks[0].path = "/dev/sdz".into();
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    inventory.disks[0].path = durable.plan.target_disk.path.clone();
    durable.plan.target_disk.path = "/dev/sdz".into();
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
}

#[test]
fn acknowledged_plan_recovers_missing_state_across_each_interruption_boundary() {
    let (plan, verified, mut inventory) = fixture();
    // Poll returns the same authority whether GPT is empty, STATE is unformatted,
    // or mkfs finished before the random permanent key was durably persisted.
    for boundary in [
        "ack1 accepted",
        "ack2 accepted",
        "GPT erased",
        "STATE partition created",
        "STATE formatted",
    ] {
        inventory.kernel_version = boundary.to_owned(); // volatile inventory may change
        let recovered = active_plan(&response(&plan, "installing"), &verified, &inventory).unwrap();
        assert_eq!(recovered.plan_sha256, plan["plan_sha256"]);
    }
    assert!(
        protocol::verify_install_plan(plan, &verified.signing_key, &verified.envelope, &inventory)
            .is_err()
    );
}

#[test]
fn missing_state_never_authorizes_foreign_media_disk_or_terminal_sessions() {
    let (plan, mut verified, inventory) = fixture();
    for state in [
        "created",
        "awaiting_approval",
        "failed",
        "revoked",
        "expired",
        "ready",
    ] {
        assert!(
            active_plan(&response(&plan, state), &verified, &inventory).is_err(),
            "{state}"
        );
    }
    let session = response(&plan, "installing");
    let original = verified.envelope.session_id;
    verified.envelope.session_id = Uuid::new_v4();
    assert!(active_plan(&session, &verified, &inventory).is_err());
    verified.envelope.session_id = original;
    let mut changed = inventory.clone();
    changed.disks[0].path = "/dev/sdz".into();
    assert!(active_plan(&session, &verified, &changed).is_err());
    changed = inventory.clone();
    changed.disks[0].serial = "replacement".into();
    assert!(active_plan(&session, &verified, &changed).is_err());
    changed = inventory.clone();
    changed.disks[0].mounted = true;
    assert!(active_plan(&session, &verified, &changed).is_err());
    changed = inventory.clone();
    changed.disks[0].eligible = false;
    assert!(active_plan(&session, &verified, &changed).is_err());
    let mut altered = plan.clone();
    altered["target_disk"]["path"] = "/dev/sdz".into();
    assert!(active_plan(&response(&altered, "installing"), &verified, &inventory).is_err());
    verified.signing_key = SigningKey::from_bytes(&[44; 32]).verifying_key();
    assert!(active_plan(&session, &verified, &inventory).is_err());
}

#[derive(Default)]
struct Server {
    replies: VecDeque<(StatusCode, Value)>,
    requests: Vec<(Method, Value)>,
    events: BTreeMap<i64, Value>,
    lose_response: Option<i64>,
}
async fn handle(
    State(state): State<Arc<Mutex<Server>>>,
    method: Method,
    body: Bytes,
) -> impl IntoResponse {
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    let mut server = state.lock().unwrap();
    server.requests.push((method, value.clone()));
    if let Some(reply) = server.replies.pop_front() {
        return (reply.0, Json(reply.1));
    }
    let sequence = value["sequence"].as_i64().unwrap();
    let existing = server.events.get(&sequence);
    if existing.is_some_and(|old| old != &value) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"code":"different_event_evidence"})),
        );
    }
    let accepted = existing.is_none();
    server.events.insert(sequence, value);
    if server.lose_response == Some(sequence) {
        server.lose_response = None;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"code":"response_lost"})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"accepted":accepted,"session_state":"installing","session_revision":3})),
    )
}
async fn server(
    state: Arc<Mutex<Server>>,
    session_id: Uuid,
) -> (protocol::ProvisioningClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handle)).with_state(state),
        )
        .await
        .unwrap()
    });
    (
        protocol::ProvisioningClient::test_client(origin, session_id),
        handle,
    )
}

#[tokio::test]
async fn only_an_unclaimed_session_can_fall_back_from_poll_to_claim() {
    let (plan, verified, inventory) = fixture();
    let key = protocol::derive_provisioning_key(&verified.envelope.media_secret).unwrap();
    let hardware = inventory::hardware_digest(&inventory).unwrap();
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::CONFLICT,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let state = Arc::new(Mutex::new(Server {
            replies: VecDeque::from([
                (status, json!({"code":"request_rejected"})),
                (
                    StatusCode::OK,
                    json!({"session_id":verified.envelope.session_id,"state":"awaiting_approval","session_revision":1,"poll_after_seconds":2,"plan":null}),
                ),
            ]),
            ..Default::default()
        }));
        let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
        let result = initial_session(&client, &verified, &key, &inventory, &hardware).await;
        assert_eq!(result.is_ok(), status == StatusCode::UNAUTHORIZED);
        let state = state.lock().unwrap();
        assert_eq!(state.requests[0].0, Method::GET);
        assert_eq!(
            state.requests.len(),
            if status == StatusCode::UNAUTHORIZED {
                2
            } else {
                1
            }
        );
        assert!(state.events.is_empty()); // retired/wrong authority cannot reach disk authorization
        handle.abort();
    }
    let state = Arc::new(Mutex::new(Server {
        replies: VecDeque::from([(
            StatusCode::OK,
            json!({
        "session_id":verified.envelope.session_id,"state":"installing","session_revision":3,
        "poll_after_seconds":2,"plan":plan}),
        )]),
        ..Default::default()
    }));
    let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
    assert!(
        initial_session(&client, &verified, &key, &inventory, &hardware)
            .await
            .unwrap()
            .1
    );
    assert_eq!(state.lock().unwrap().requests.len(), 1);
    handle.abort();
}

#[tokio::test]
async fn lost_acknowledgements_replay_identical_bytes_before_target_creation() {
    let (plan, verified, inventory) = fixture();
    let plan = active_plan(&response(&plan, "installing"), &verified, &inventory).unwrap();
    let key = protocol::derive_provisioning_key(&verified.envelope.media_secret).unwrap();
    for lose_response in [1, 2] {
        let state = Arc::new(Mutex::new(Server {
            lose_response: Some(lose_response),
            ..Default::default()
        }));
        let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
        assert!(
            client
                .authorize_storage_creation(&key, &plan)
                .await
                .is_err()
        );
        client
            .authorize_storage_creation(&key, &plan)
            .await
            .unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.events.len(), 2);
        for (_, event) in &state.requests {
            assert_eq!(
                event,
                state
                    .events
                    .get(&event["sequence"].as_i64().unwrap())
                    .unwrap()
            );
        }
        assert_eq!(
            state.events[&1]["message"],
            "Approved install plan validated"
        );
        assert_eq!(
            state.events[&2]["message"],
            "Creating plan-bound appliance storage"
        );
        handle.abort();
    }
}
