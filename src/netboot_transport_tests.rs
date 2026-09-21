// Included in netboot::tests so these exercise the same signed descriptors,
// SQLite fixture and downloader as normal runtime reconciliation.
fn fixture_transport(descriptor: &WorkstationNetbootDescriptor, port: u16) -> String {
    let filename = descriptor.url.rsplit('/').next().unwrap();
    format!("http://10.20.30.40:{port}/{filename}")
}

#[test]
fn transport_url_accepts_only_exact_canonical_rfc1918_endpoints() {
    let descriptor = fixture_descriptor();
    let filename = descriptor.url.rsplit('/').next().unwrap();
    for ip in ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1"] {
        for port in [80, 8080, 65535] {
            transport::validate_url(&format!("http://{ip}:{port}/{filename}"), &descriptor)
                .unwrap();
        }
    }
    for value in [
        format!("http://127.0.0.1:8080/{filename}"),
        format!("http://169.254.169.254:8080/{filename}"),
        format!("http://100.64.0.1:8080/{filename}"),
        format!("http://172.32.0.1:8080/{filename}"),
        format!("http://8.8.8.8:8080/{filename}"),
        format!("http://0.0.0.0:8080/{filename}"),
        format!("http://[::ffff:10.0.0.1]:8080/{filename}"),
        format!("http://[fd00::1]:8080/{filename}"),
        format!("http://fixture.test:8080/{filename}"),
        format!("https://10.0.0.1:8080/{filename}"),
        format!("http://10.0.0.1/{filename}"),
        format!("http://10.0.0.1:0/{filename}"),
        format!("http://10.0.0.1:080/{filename}"),
        format!("http://010.0.0.1:8080/{filename}"),
        format!("http://167772161:8080/{filename}"),
        format!("http://user@10.0.0.1:8080/{filename}"),
        format!("http://10.0.0.1:8080/extra/{filename}"),
        format!("http://10.0.0.1:8080/../{filename}"),
        format!("http://10.0.0.1:8080/%63{}", &filename[1..]),
        format!("http://10.0.0.1:8080/{filename}?"),
        format!("http://10.0.0.1:8080/{filename}#"),
        format!("http://10.0.0.1:8080/{filename}\n"),
        "http://10.0.0.1:8080/wrong.tar.zst".to_owned(),
    ] {
        assert!(
            transport::validate_url(&value, &descriptor).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn transport_desired_decode_is_additive_and_preserves_signed_identity() {
    let descriptor = fixture_descriptor();
    let mut value = serde_json::json!({ "descriptor": descriptor, "reconcile_generation": 1 });
    let legacy = decode_desired(value.clone()).unwrap();
    assert!(legacy.bundle_transport_url.is_none());
    assert!(
        serde_json::to_value(&legacy)
            .unwrap()
            .get("bundle_transport_url")
            .is_none()
    );
    value["bundle_transport_url"] = serde_json::json!(fixture_transport(&descriptor, 8080));
    let desired = decode_desired(value).unwrap();
    assert_eq!(
        serde_json::to_value(&desired.descriptor).unwrap(),
        serde_json::to_value(&descriptor).unwrap()
    );
    assert_eq!(desired.compatibility_epoch, COMPATIBILITY_EPOCH);
}

#[tokio::test]
async fn transport_forces_signatures_even_when_development_bypass_is_enabled() {
    let fixture = RuntimeFilesystemFixture::new().await;
    let mut descriptor = fixture_descriptor();
    fixture.sign_descriptor(&mut descriptor);
    let mut desired = DesiredWorkstationNetboot {
        bundle_transport_url: Some(fixture_transport(&descriptor, 8080)),
        descriptor,
        compatibility_epoch: COMPATIBILITY_EPOCH,
        reconcile_generation: 1,
    };
    let key = &fixture.state.config.update.trusted_public_key;
    transport::validate_desired(&desired, key, true).unwrap();
    desired.descriptor.signature = STANDARD.encode([0_u8; 64]);
    assert!(transport::validate_desired(&desired, key, true).is_err());
    // The same historical bypass still exists for old development fixtures;
    // the new transport is explicitly unable to inherit it.
    desired.bundle_transport_url = None;
    transport::validate_desired(&desired, key, true).unwrap();
    fixture.cleanup();
}

#[tokio::test]
async fn transport_invalid_signature_cannot_reuse_a_complete_partial() {
    let fixture = RuntimeFilesystemFixture::new().await;
    let descriptor = fixture_descriptor();
    let part = fixture.root.join("complete.part");
    fs::write(&part, b"1234").unwrap();
    fs::set_permissions(&part, fs::Permissions::from_mode(0o600)).unwrap();
    let error = download_bundle(
        &fixture.state,
        &descriptor,
        &part,
        Some(&fixture_transport(&descriptor, 8080)),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("signature"));
    assert_eq!(fs::read(&part).unwrap(), b"1234");
    fixture.cleanup();
}

#[tokio::test]
async fn transport_changes_fence_retry_and_partial_identity_without_changing_descriptor() {
    let fixture = RuntimeFilesystemFixture::new().await;
    let descriptor = fixture_descriptor();
    let canonical = sha256_bytes(&serde_json::to_vec(&descriptor).unwrap());
    let first = fixture_transport(&descriptor, 8080);
    let second = fixture_transport(&descriptor, 8081);
    let old_identity = transport::attempt_identity(&canonical, Some(&first));
    let new_identity = transport::attempt_identity(&canonical, Some(&second));
    assert_ne!(old_identity, new_identity);
    assert_ne!(new_identity, transport::attempt_identity(&canonical, None));
    record_reconcile_attempt(
        &fixture.state,
        COMPATIBILITY_EPOCH,
        1,
        &old_identity,
        FAILURE_INVALID_DESCRIPTOR,
    )
    .await
    .unwrap();
    assert!(
        !reconcile_attempt_is_due(&fixture.state, COMPATIBILITY_EPOCH, 1, &old_identity)
            .await
            .unwrap()
    );
    assert!(
        reconcile_attempt_is_due(&fixture.state, COMPATIBILITY_EPOCH, 1, &new_identity)
            .await
            .unwrap()
    );
    let malformed = transport::raw_attempt_identity(&canonical, Some(&serde_json::json!(true)));
    assert_ne!(malformed, canonical);
    assert_ne!(malformed, new_identity);
    let old_part = transport::partial_path(&fixture.root, &descriptor, Some(&first)).unwrap();
    let new_part = transport::partial_path(&fixture.root, &descriptor, Some(&second)).unwrap();
    fs::write(&old_part, b"old partial").unwrap();
    fs::write(&new_part, b"new partial").unwrap();
    transport::discard_other_partials(&fixture.root, &descriptor, &new_part)
        .await
        .unwrap();
    assert!(!old_part.exists());
    assert_eq!(fs::read(&new_part).unwrap(), b"new partial");
    fixture.cleanup();
}

#[tokio::test]
async fn transport_http_client_does_not_follow_redirects() {
    // Client policy is exercised on a loopback test socket; the separate URL
    // admission test proves a desired override can never name loopback.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = redirect.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = redirect.accept().await.unwrap();
        let mut body = [0_u8; 2048];
        let read = socket.read(&mut body).await.unwrap();
        assert!(read > 0);
        socket.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{target_address}/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    });
    let response = transport::client()
        .unwrap()
        .get(format!("http://{address}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
    await_one_shot_server(server).await;
}

#[tokio::test]
async fn transport_cannot_bypass_artifact_or_generation_watermarks() {
    let fixture = RuntimeFilesystemFixture::new().await;
    let active = fixture.install_bundle("2.0.0", &"a".repeat(64)).await;
    fixture.activate(&active, None).await;
    let mut descriptor = fixture_descriptor();
    fixture.sign_descriptor(&mut descriptor);
    let desired = DesiredWorkstationNetboot {
        bundle_transport_url: Some(fixture_transport(&descriptor, 8080)),
        descriptor,
        compatibility_epoch: COMPATIBILITY_EPOCH,
        reconcile_generation: 2,
    };
    transport::validate_desired(
        &desired,
        &fixture.state.config.update.trusted_public_key,
        true,
    )
    .unwrap();
    let signed_identity = sha256_bytes(&serde_json::to_vec(&desired.descriptor).unwrap());
    let error = admit_reconcile_identity(
        &fixture.state,
        &desired.descriptor,
        &signed_identity,
        COMPATIBILITY_EPOCH,
        2,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("downgrade"), "{error}");
    let error = admit_reconcile_identity(
        &fixture.state,
        &desired.descriptor,
        &signed_identity,
        COMPATIBILITY_EPOCH,
        0,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("stale reconcile generation"));
    let report = report(&fixture.state).await.unwrap();
    assert_eq!(report.active_bundle_sha256, active.sha256);
    assert_eq!(report.state, "ready");
    fixture.cleanup();
}
