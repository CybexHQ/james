// Included into `netboot::tests`: the USB installer stick protocol against a
// Nest with a verified, active runtime and a managed identity.
mod usb_installer_routes {
    use super::*;
    use crate::models::{BootProfileType, CreateBootProfileRequest, CreateDeviceRequest};
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::Request,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    const STICK_AGENT: &str = "tiaris-usb-installer/1 (0123456789ab)";
    const MAC: &str = "aa:bb:cc:dd:ee:ff";

    async fn get(app: Router, uri: &str, agent: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder().uri(uri);
        if let Some(agent) = agent {
            request = request.header(header::USER_AGENT, agent);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).map(|value| value.to_str().unwrap()),
            Some("no-store, max-age=0"),
            "{uri}"
        );
        let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    async fn installer_profile(
        state: &AppState,
        name: &str,
        is_default: bool,
        one_time: bool,
    ) -> i64 {
        let profile = crate::db::create_profile(
            &state.db,
            CreateBootProfileRequest {
                name: name.to_string(),
                description: None,
                profile_type: BootProfileType::NestInstaller,
                enabled: Some(true),
                is_default: Some(is_default),
                one_time: Some(one_time),
                raw_script: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE boot_profiles SET managed_profile_id = ? WHERE id = ?")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(profile.id)
            .execute(&state.db)
            .await
            .unwrap();
        profile.id
    }

    async fn custom_profile(state: &AppState) -> i64 {
        crate::db::create_profile(
            &state.db,
            CreateBootProfileRequest {
                name: "Assigned Script".to_string(),
                description: None,
                profile_type: BootProfileType::CustomIpxe,
                enabled: Some(true),
                is_default: Some(false),
                one_time: Some(false),
                raw_script: Some("#!ipxe\necho assigned\n".to_string()),
            },
        )
        .await
        .unwrap()
        .id
    }

    async fn computer(
        state: &AppState,
        serial: Option<&str>,
        default_profile_id: Option<i64>,
        one_time_profile_id: Option<i64>,
    ) -> i64 {
        crate::db::create_device(
            &state.db,
            CreateDeviceRequest {
                mac: MAC.to_string(),
                hostname: None,
                serial_number: serial.map(str::to_string),
                notes: None,
                tags: None,
                default_profile_id,
                one_time_profile_id,
            },
        )
        .await
        .unwrap()
        .id
    }

    async fn active_runtime(fixture: &RuntimeFilesystemFixture) -> WorkstationNetbootDescriptor {
        let descriptor = fixture.install_bundle("1.0.161", &"e".repeat(64)).await;
        fixture.activate(&descriptor, None).await;
        descriptor
    }

    /// The context the launch names, exactly as iPXE would fetch it.
    async fn launch_context(app: Router, launch: &Value) -> Value {
        let url = launch["context_url"].as_str().unwrap();
        let path = url.strip_prefix("http://nest.test").unwrap();
        let response = app
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn a_new_computer_gets_the_same_signed_launch_as_pxe_with_component_digests() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let descriptor = active_runtime(&fixture).await;
        installer_profile(&fixture.state, "Enroll", true, false).await;
        let app = crate::routes::router(fixture.state.clone());

        let (status, body) = get(
            app.clone(),
            "/usb-installer/v1/boot?mac=aa-bb-cc-dd-ee-ff&serial_hex=35434731323334414141",
            Some(STICK_AGENT),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["schema"], "tiaris.nest.usb-installer.v1");
        assert_eq!(body["action"], "launch");
        let launch = &body["launch"];
        assert_eq!(launch["schema"], "tiaris.nest.kexec.v1");
        assert_eq!(launch["bundle_sha256"], descriptor.sha256);
        assert_eq!(launch["runtime_version"], "1.0.161");
        assert_eq!(
            launch["kernel_url"],
            format!("http://nest.test/netboot/{}/bzImage", descriptor.sha256)
        );
        assert_eq!(
            launch["squashfs_url"],
            format!(
                "http://nest.test/netboot/{}/nix-store.squashfs",
                descriptor.sha256
            )
        );
        assert_eq!(
            launch["components"],
            serde_json::to_value(&descriptor.components).unwrap()
        );
        let command_line = launch["command_line"].as_str().unwrap();
        assert_eq!(
            command_line
                .matches(launch["squashfs_url"].as_str().unwrap())
                .count(),
            1
        );

        let context = launch_context(app, launch).await;
        let claims = &context["nest_boot_grant"]["claims"];
        assert_eq!(context["schema"], "tiaris.nest.boot-context.v1");
        assert_eq!(claims["mac"], MAC);
        assert_eq!(claims["nest_device_id"], "nest-runtime-test");
        assert_eq!(claims["organization_slug"], "test-org");
        assert_eq!(claims["bundle_sha256"], descriptor.sha256);
        assert_eq!(claims["expires_at"], launch["expires_at"]);
        assert!(claims["managed_device_id"].is_null());

        let device = crate::db::get_device_by_mac(&fixture.state.db, MAC)
            .await
            .unwrap()
            .expect("the stick's adapter is recorded like a PXE client");
        assert_eq!(device.serial_number.as_deref(), Some("5CG1234AAA"));
        let events = crate::db::list_boot_events(&fixture.state.db, 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_agent.as_deref(), Some(STICK_AGENT));
        assert_eq!(events[0].selected_profile_name.as_deref(), Some("Enroll"));
        assert_eq!(events[0].serial_number.as_deref(), Some("5CG1234AAA"));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn a_known_computer_assigned_elsewhere_gets_the_installer_menu() {
        let fixture = RuntimeFilesystemFixture::new().await;
        active_runtime(&fixture).await;
        let enroll = installer_profile(&fixture.state, "Enroll", true, false).await;
        installer_profile(&fixture.state, "Reinstall", false, true).await;
        let custom = custom_profile(&fixture.state).await;
        computer(&fixture.state, Some("5CG1234AAA"), Some(custom), None).await;
        let app = crate::routes::router(fixture.state.clone());

        let (status, body) = get(
            app,
            "/usb-installer/v1/boot?mac=aa:bb:cc:dd:ee:ff&serial_hex=35434731323334414141",
            Some(STICK_AGENT),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["action"], "menu");
        assert_eq!(body["notice"], "known_computer");
        // Only installer profiles; never the one-time reinstall profile,
        // custom iPXE, or the local disk.
        assert_eq!(
            body["profiles"],
            serde_json::json!([{"id": enroll, "name": "Enroll"}])
        );
        let events = crate::db::list_boot_events(&fixture.state.db, 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].selected_profile_id.is_none());
        assert!(events[0].known_device);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn another_laptop_on_a_registered_adapter_gets_the_menu_without_its_reinstall() {
        let fixture = RuntimeFilesystemFixture::new().await;
        active_runtime(&fixture).await;
        let reinstall = installer_profile(&fixture.state, "Reinstall", false, true).await;
        let enroll = installer_profile(&fixture.state, "Enroll", true, false).await;
        let laptop_a = computer(&fixture.state, Some("5CG1234AAA"), None, Some(reinstall)).await;
        sqlx::query(
            "UPDATE devices SET managed_device_id = 'laptop-a', reinstall_request_id = ? WHERE id = ?",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(laptop_a)
        .execute(&fixture.state.db)
        .await
        .unwrap();
        let app = crate::routes::router(fixture.state.clone());

        // "5CG1234BBB": another laptop with laptop A's adapter.
        let (status, body) = get(
            app.clone(),
            "/usb-installer/v1/boot?mac=aa:bb:cc:dd:ee:ff&serial_hex=35434731323334424242",
            Some(STICK_AGENT),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["action"], "menu");
        assert_eq!(body["notice"], "adapter_of_another_computer");
        let row = crate::db::get_device_by_mac(&fixture.state.db, MAC)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.one_time_profile_id, Some(reinstall), "not consumed");

        // Its menu choice launches without laptop A's reinstall binding.
        let (status, body) = get(
            app.clone(),
            &format!("/usb-installer/v1/select/{enroll}?mac=aa:bb:cc:dd:ee:ff&serial_hex=35434731323334424242"),
            Some(STICK_AGENT),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["action"], "launch");
        let context = launch_context(app.clone(), &body["launch"]).await;
        assert!(context["nest_boot_grant"]["claims"]["managed_device_id"].is_null());
        assert!(context["nest_boot_grant"]["claims"]["reinstall_request_id"].is_null());

        // Laptop A itself takes its one-time reinstall, bound to it.
        let (status, body) = get(
            app,
            "/usb-installer/v1/boot?mac=aa:bb:cc:dd:ee:ff&serial_hex=35434731323334414141",
            Some(STICK_AGENT),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["action"], "launch");
        let row = crate::db::get_device_by_mac(&fixture.state.db, MAC)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.one_time_profile_id, None, "consumed as on PXE");
        fixture.cleanup();
    }

    #[tokio::test]
    async fn select_starts_only_installer_profiles_from_the_menu() {
        let fixture = RuntimeFilesystemFixture::new().await;
        active_runtime(&fixture).await;
        let reinstall = installer_profile(&fixture.state, "Reinstall", false, true).await;
        let custom = custom_profile(&fixture.state).await;
        let app = crate::routes::router(fixture.state.clone());
        for profile in [reinstall.to_string(), custom.to_string(), "0".to_string(), "x".to_string()] {
            let (status, body) = get(
                app.clone(),
                &format!("/usb-installer/v1/select/{profile}?mac=aa:bb:cc:dd:ee:ff"),
                Some(STICK_AGENT),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{profile}");
            assert_eq!(body["error"], "profile_unavailable");
        }
        fixture.cleanup();
    }

    #[tokio::test]
    async fn requests_without_a_mac_or_from_an_outdated_stick_are_refused() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let app = crate::routes::router(fixture.state.clone());
        let (status, body) = get(app.clone(), "/usb-installer/v1/boot", Some(STICK_AGENT)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
        let (status, body) = get(
            app,
            "/usb-installer/v1/boot?mac=aa:bb:cc:dd:ee:ff",
            Some("tiaris-usb-installer/0"),
        )
        .await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(body["error"], "usb_installer_outdated");
        assert_eq!(body["minimum_stick_protocol"], 1);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn runtime_identity_needs_no_session_and_fails_closed_without_a_runtime() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let app = crate::routes::router(fixture.state.clone());
        let (status, body) = get(app.clone(), "/usb-installer/v1/runtime", Some(STICK_AGENT)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "runtime_unavailable");

        // A new computer's automatic enrollment fails closed the same way and
        // leaves no row behind, as on PXE.
        installer_profile(&fixture.state, "Enroll", true, false).await;
        let (status, body) = get(
            app.clone(),
            "/usb-installer/v1/boot?mac=aa:bb:cc:dd:ee:ff",
            Some(STICK_AGENT),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "runtime_unavailable");
        assert!(
            crate::db::get_device_by_mac(&fixture.state.db, MAC)
                .await
                .unwrap()
                .is_none()
        );

        let descriptor = active_runtime(&fixture).await;
        let (status, body) = get(app, "/usb-installer/v1/runtime", Some(STICK_AGENT)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["runtime"]["bundle_sha256"], descriptor.sha256);
        assert_eq!(body["runtime"]["runtime_version"], "1.0.161");
        assert_eq!(
            body["runtime"]["components"],
            serde_json::to_value(&descriptor.components).unwrap()
        );
        let sessions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nest_boot_sessions")
            .fetch_one(&fixture.state.db)
            .await
            .unwrap();
        assert_eq!(sessions.0, 0, "the runtime identity creates no session");
        fixture.cleanup();
    }
}
