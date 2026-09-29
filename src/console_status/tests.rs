use super::*;
use serde_json::json;

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_790_000_000 + seconds, 0).unwrap()
}

fn healthy_units() -> UnitStates {
    UnitStates {
        failed: Vec::new(),
        inactive_required: Vec::new(),
        first_boot_active: true,
    }
}

fn observation(now: i64) -> Observation {
    Observation {
        now: at(now),
        observing_since: at(0),
        units: Some(healthy_units()),
        health_ready: true,
        last_contact: Some(at(now - 20)),
        contacted_this_boot: true,
        identity: Identity {
            name: Some("Acme Nest".into()),
            organization: Some("acme-engineering".into()),
            tiaris_host: Some("manage.cybex.net".into()),
            address: Some("10.20.0.2".into()),
            interface: Some("eno1".into()),
            system: Some("NixOS 26.05".into()),
            booted_at: Some(at(-300)),
        },
        pxe: Some(Pxe::Active),
        active_installs: Some(3),
    }
}

#[test]
fn healthy_status_serializes_the_public_contract() {
    let status = ReadinessTracker::default().evaluate(&observation(60));
    let value = serde_json::to_value(&status).unwrap();
    assert_eq!(
        value,
        json!({
            "schema": "tiaris.nest-console-status.v1",
            "state": "healthy",
            "updated_at": timestamp(at(60)),
            "name": "Acme Nest",
            "organization": "acme-engineering",
            "tiaris_host": "manage.cybex.net",
            "address": "10.20.0.2",
            "interface": "eno1",
            "pxe": "active",
            "active_installs": 3,
            "last_contact_at": timestamp(at(40)),
            "booted_at": timestamp(at(-300)),
            "system": "NixOS 26.05",
        })
    );
}

#[test]
fn a_failed_unit_takes_precedence_with_its_friendly_name() {
    let mut tracker = ReadinessTracker::default();
    let mut current = observation(60);
    current.units = Some(UnitStates {
        failed: vec!["tftpd-hpa.service"],
        inactive_required: vec!["tftpd-hpa.service"],
        first_boot_active: false,
    });
    current.last_contact = None;
    current.observing_since = at(-3600);
    let status = tracker.evaluate(&current);
    assert_eq!(status.state, ConsoleState::Attention);
    assert!(status.stage.is_none());
    let attention = status.attention.unwrap();
    assert_eq!(attention.code, AttentionCode::ServiceFailed);
    assert_eq!(
        attention.check,
        Some(CheckRow {
            label: "TFTP boot server".into(),
            value: "Failed".into()
        })
    );
    assert_eq!(attention.since, Some(timestamp(at(60))));
    // The first observation time is retained while the same unit stays failed.
    current.now = at(75);
    let attention = tracker.evaluate(&current).attention.unwrap();
    assert_eq!(attention.since, Some(timestamp(at(60))));
}

#[test]
fn first_boot_and_enrollment_are_starting_stages() {
    let mut tracker = ReadinessTracker::default();
    let mut current = observation(10);
    current.units = Some(UnitStates {
        first_boot_active: false,
        ..healthy_units()
    });
    let status = tracker.evaluate(&current);
    assert_eq!(status.state, ConsoleState::Starting);
    assert_eq!(status.stage, Some(Stage::FirstBoot));

    let mut current = observation(10);
    current.contacted_this_boot = false;
    let status = tracker.evaluate(&current);
    assert_eq!(status.state, ConsoleState::Starting);
    assert_eq!(status.stage, Some(Stage::Enrolling));

    // Without a Tiaris report this boot, health waiting is enrollment and
    // never escalates to not_ready: the unreachable rule bounds it instead.
    current.health_ready = false;
    for second in (10..500).step_by(15) {
        current.now = at(second);
        let status = tracker.evaluate(&current);
        assert_eq!(status.stage, Some(Stage::Enrolling));
        assert_eq!(status.state, ConsoleState::Starting);
    }
}

#[test]
fn not_ready_needs_six_consecutive_checks_across_the_window() {
    let mut tracker = ReadinessTracker::default();
    let mut current = observation(0);
    current.health_ready = false;
    for check in 0..5 {
        current.now = at(check * 15);
        current.last_contact = Some(current.now);
        let status = tracker.evaluate(&current);
        assert_eq!(status.state, ConsoleState::Starting, "check {check}");
        assert_eq!(status.stage, Some(Stage::Services));
    }
    // Prompt refreshes cannot shorten the window.
    current.now = at(61);
    assert_eq!(tracker.evaluate(&current).state, ConsoleState::Starting);
    current.now = at(75);
    let status = tracker.evaluate(&current);
    assert_eq!(status.state, ConsoleState::Attention);
    let attention = status.attention.unwrap();
    assert_eq!(attention.code, AttentionCode::NotReady);
    assert_eq!(attention.check.unwrap().label, "Boot services");

    // Recovery resets the count.
    current.health_ready = true;
    current.now = at(90);
    assert_eq!(tracker.evaluate(&current).state, ConsoleState::Healthy);
    current.health_ready = false;
    current.units = Some(UnitStates {
        inactive_required: vec!["nginx.service"],
        ..healthy_units()
    });
    current.now = at(105);
    assert_eq!(tracker.evaluate(&current).state, ConsoleState::Starting);
    for check in 1..6 {
        current.now = at(105 + check * 15);
        current.last_contact = Some(current.now);
        tracker.evaluate(&current);
    }
    let attention = tracker.evaluate(&current).attention.unwrap();
    assert_eq!(attention.check.unwrap().label, "Web server");
}

#[test]
fn stale_tiaris_contact_needs_attention_with_since() {
    let mut tracker = ReadinessTracker::default();
    let mut current = observation(3_600);
    current.last_contact = Some(at(3_600 - 23 * 60));
    let status = tracker.evaluate(&current);
    assert_eq!(status.state, ConsoleState::Attention);
    let attention = status.attention.unwrap();
    assert_eq!(attention.code, AttentionCode::TiarisUnreachable);
    assert_eq!(attention.since, Some(timestamp(at(3_600 - 23 * 60))));
    assert_eq!(attention.title, "Acme Nest can't reach Tiaris");
    assert!(attention.detail.contains("eno1"));
    assert_eq!(
        attention.check,
        Some(CheckRow {
            label: "Connection to Tiaris".into(),
            value: "Unreachable · 23 min".into()
        })
    );
    // Ten minutes is the threshold.
    current.last_contact = Some(at(3_600 - 9 * 60));
    assert_eq!(tracker.evaluate(&current).state, ConsoleState::Healthy);
}

#[test]
fn a_long_power_off_is_not_unreachable_at_boot() {
    let mut tracker = ReadinessTracker::default();
    let mut current = observation(120);
    current.observing_since = at(0);
    current.last_contact = Some(at(-86_400));
    current.contacted_this_boot = false;
    let status = tracker.evaluate(&current);
    assert_eq!(status.state, ConsoleState::Starting);
    assert_eq!(status.stage, Some(Stage::Enrolling));
    current.now = at(11 * 60);
    let status = tracker.evaluate(&current);
    assert_eq!(status.state, ConsoleState::Attention);
    let attention = status.attention.unwrap();
    assert_eq!(attention.code, AttentionCode::TiarisUnreachable);
    assert_eq!(attention.since, Some(timestamp(at(-86_400))));
}

#[test]
fn unobservable_systemd_is_never_a_failed_unit() {
    let mut tracker = ReadinessTracker::default();
    let mut current = observation(0);
    current.units = None;
    for check in 0..6 {
        current.now = at(check * 15);
        current.last_contact = Some(current.now);
        let status = tracker.evaluate(&current);
        assert_ne!(
            status.attention.as_ref().map(|a| a.code),
            Some(AttentionCode::ServiceFailed)
        );
    }
    let attention = tracker.evaluate(&current).attention.unwrap();
    assert_eq!(attention.code, AttentionCode::NotReady);
    assert_eq!(attention.check.unwrap().label, "Service status");
}

#[test]
fn systemctl_show_output_is_parsed_in_argument_order() {
    let queried: Vec<&'static str> = WATCHED_UNITS.iter().map(|(unit, _)| *unit).collect();
    let states = [
        "active", "active", "active", "active", "failed", "inactive", "active", "active",
    ];
    let output = queried
        .iter()
        .zip(states)
        .map(|(unit, state)| {
            let id = if *unit == "ssh.service" {
                "sshd.service"
            } else {
                unit
            };
            format!("Id={id}\nActiveState={state}\n")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_unit_states(&output, &queried).unwrap();
    assert_eq!(parsed.failed, vec!["nginx.service"]);
    assert_eq!(parsed.inactive_required, vec!["tftpd-hpa.service"]);
    assert!(parsed.first_boot_active);
    assert!(parse_unit_states("Id=a\nActiveState=active\n", &queried).is_none());
}

#[test]
fn contact_receipts_bind_to_the_current_boot() {
    let body = br#"{"schema":"tiaris.nest.manage-contact.v1","device_id":"dev","public_key_fingerprint":"f","manage_origin":"https://manage.cybex.net","reported_at":"2026-09-29T10:00:00Z","boot_id":"abc"}"#;
    let (at, same) = parse_manage_contact(body, "abc\n").unwrap();
    assert_eq!(timestamp(at), "2026-09-29T10:00:00Z");
    assert!(same);
    assert!(!parse_manage_contact(body, "other").unwrap().1);
    assert!(parse_manage_contact(br#"{"schema":"other","reported_at":"x"}"#, "abc").is_none());
}

#[test]
fn plan_identity_accepts_only_public_names() {
    let plan = json!({
        "display_name": "Acme Nest (lab-1)",
        "organization_slug": "acme-engineering",
        "network_interface": {"name": "eno1", "mac": "52:54:00:12:34:56"},
        "reserved_device_id": "dev_secret",
    });
    assert_eq!(
        plan_identity(&plan),
        (
            Some("Acme Nest (lab-1)".into()),
            Some("acme-engineering".into()),
            Some("eno1".into())
        )
    );
    let hostile = json!({
        "display_name": "\u{1b}[2JEvil",
        "organization_slug": "Acme/../x",
        "network_interface": {"name": "../../etc"},
    });
    assert_eq!(plan_identity(&hostile), (None, None, None));
}

#[test]
fn system_and_boot_time_are_read_from_their_sources() {
    assert_eq!(
        system_label(&json!({"base_os": "nixos", "base_os_version": "26.05"})),
        Some("NixOS 26.05".into())
    );
    assert_eq!(system_label(&json!({"base_os": "ubuntu"})), None);
    assert_eq!(
        parse_boot_time("cpu 1 2 3\nbtime 1790000000\nprocesses 4\n"),
        Some(at(0))
    );
    assert_eq!(parse_boot_time("cpu 1\n"), None);
    assert_eq!(runtime_ipv4("http://10.20.0.2"), Some("10.20.0.2".into()));
    assert_eq!(runtime_ipv4("http://nest.example"), None);
    assert_eq!(
        url_host("https://manage.cybex.net/api"),
        Some("manage.cybex.net".into())
    );
}

#[test]
fn pxe_statuses_outside_the_contract_are_omitted() {
    assert_eq!(Pxe::parse("standby"), Some(Pxe::Standby));
    assert_eq!(Pxe::parse("starting"), None);
    let mut current = observation(0);
    current.pxe = None;
    current.active_installs = None;
    let value = serde_json::to_value(ReadinessTracker::default().evaluate(&current)).unwrap();
    assert!(value.get("pxe").is_none());
    assert!(value.get("active_installs").is_none());
}

#[tokio::test]
async fn active_installs_count_distinct_unexpired_boot_grants() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::query(
        "CREATE TABLE nest_boot_sessions (session_id TEXT PRIMARY KEY, normalized_mac TEXT NOT NULL, expires_at INTEGER NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (session, mac, expires) in [
        ("a", "02:00:00:00:00:01", 700),
        ("b", "02:00:00:00:00:01", 800),
        ("c", "02:00:00:00:00:02", 650),
        ("d", "02:00:00:00:00:03", 500),
    ] {
        sqlx::query(
            "INSERT INTO nest_boot_sessions (session_id, normalized_mac, expires_at) VALUES (?, ?, ?)",
        )
        .bind(session)
        .bind(mac)
        .bind(at(expires).timestamp())
        .execute(&pool)
        .await
        .unwrap();
    }
    assert_eq!(count_active_installs(&pool, at(600)).await.unwrap(), 2);
}

#[test]
fn writer_publishes_a_world_readable_document() {
    let dir = std::env::temp_dir().join(format!(
        "tiaris-nest-console-status-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let path = dir.join("console-status.json");
    let status = ReadinessTracker::default().evaluate(&observation(0));
    write_status(&path, &status).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(mode, 0o644);
    assert_eq!(value["schema"], CONSOLE_STATUS_SCHEMA);
    assert_eq!(value["state"], "healthy");
}
