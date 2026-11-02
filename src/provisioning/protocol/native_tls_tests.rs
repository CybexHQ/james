//! Linux real-constructor TLS regression. Python and OpenSSL are existing
//! appliance qualification tools; no new test dependencies or process-global
//! environment changes are needed. The driver owns certificates, loopback listeners,
//! child processes and cleanup, and exports only fixed public result codes.
use super::*;
use std::process::Command;

const CHILD_TEST: &str = "provisioning::protocol::native_tls_tests::native_tls_child";

#[test]
fn native_constructor_honors_os_ca_and_preserves_tls_validation() {
    let mut command = Command::new("python3");
    command
        .args(["-I", "-B"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/provisioning/protocol/native_tls_fixture.py"
        ))
        .arg(std::env::current_exe().expect("native TLS test executable unavailable"))
        .arg(CHILD_TEST)
        .env_clear();
    // Preserve tool/library discovery, but never inherited proxy, trust or
    // credential settings. Each native client runs with its own SSL_CERT_FILE.
    for name in ["PATH", "LD_LIBRARY_PATH"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let status = command.status().expect("native TLS fixture unavailable");
    assert!(status.success(), "native TLS witness rejected");
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildCase {
    mode: String,
    origin: String,
    capture: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestCapture {
    path: String,
    request_id: String,
    timestamp: String,
    signature: String,
}

fn certificate_failure(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        // Examine error text only in memory. Nothing from it enters output.
        let text = cause.to_string();
        if text.contains("UnknownIssuer") {
            return "tls-unknown-issuer";
        }
        if text.contains("NotValidForName") || text.contains("certificate not valid for name") {
            return "tls-name-mismatch";
        }
        if (text.contains("Expired") && text.contains("certificate"))
            || text.contains("certificate expired:")
        {
            return "tls-expired";
        }
    }
    "transport-unclassified"
}

#[test]
#[ignore = "private subprocess entry for the native TLS witness"]
fn native_tls_child() {
    let encoded =
        std::env::var("TIARIS_NATIVE_TLS_CASE").expect("native TLS case configuration unavailable");
    let case: ChildCase =
        serde_json::from_str(&encoded).expect("native TLS case configuration invalid");
    let key = SigningKey::generate(&mut OsRng);
    let session_id = Uuid::new_v4();
    let client = ProvisioningClient::new(&case.origin, session_id)
        .unwrap_or_else(|_| panic!("native TLS client construction failed"));
    let runtime = tokio::runtime::Runtime::new().expect("native TLS runtime unavailable");
    let error = match runtime.block_on(client.poll_plan(&key)) {
        Err(error) => error,
        Ok(_) => panic!("native TLS stub unexpectedly returned a session"),
    };
    match case.mode.as_str() {
        "trusted" | "redirect" => {
            let response = error.downcast_ref::<ProvisioningHttpError>();
            if response.is_none() {
                println!("NATIVE_TLS_WITNESS {}", certificate_failure(&error));
            }
            let response = response.expect("native TLS trusted request did not reach HTTP");
            if case.mode == "trusted" {
                assert!(
                    response.status == StatusCode::UNAUTHORIZED
                        && response.code == "native_tls_unclaimed"
                        && unclaimed_session(&error),
                    "native TLS fixed unclaimed response rejected"
                );
            } else {
                assert!(
                    response.status == StatusCode::FOUND && !unclaimed_session(&error),
                    "native TLS redirect policy changed"
                );
            }
            let bytes = fs::read(&case.capture).expect("native TLS request capture unavailable");
            let capture: RequestCapture =
                serde_json::from_slice(&bytes).expect("native TLS request capture invalid");
            let path = format!("/v1/agent/nest/provisioning-sessions/{session_id}/plan");
            assert!(capture.path == path, "native TLS plan path changed");
            assert!(
                capture.request_id.starts_with("req_") && capture.request_id.len() == 36,
                "native TLS request identity changed"
            );
            assert!(
                DateTime::parse_from_rfc3339(&capture.timestamp).is_ok(),
                "native TLS request timestamp changed"
            );
            let canonical = format!(
                "{REQUEST_SIGNATURE_DOMAIN}\nGET\n{path}\n{}\n{}\n{}",
                capture.timestamp,
                capture.request_id,
                sha256_hex([]),
            );
            let signature = URL_SAFE_NO_PAD
                .decode(capture.signature)
                .ok()
                .and_then(|bytes| Signature::from_slice(&bytes).ok())
                .expect("native TLS request signature invalid");
            assert!(
                key.verifying_key()
                    .verify(canonical.as_bytes(), &signature)
                    .is_ok(),
                "native TLS signed request changed"
            );
        }
        "unrelated" | "wrong_san" | "expired" => {
            assert!(
                error.downcast_ref::<ProvisioningHttpError>().is_none()
                    && certificate_failure(&error) != "transport-unclassified",
                "native TLS invalid certificate was not rejected at TLS"
            );
        }
        "http" => {
            assert!(
                error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_builder),
                "native TLS HTTPS-only policy changed"
            );
        }
        _ => panic!("native TLS case mode invalid"),
    }
    println!("NATIVE_TLS_CHILD_PASS");
}
