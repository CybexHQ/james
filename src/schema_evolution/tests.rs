//! The predecessor here is this release (`MIGRATOR` and its real `db`
//! queries); the candidate is this release plus fixture migrations, resolved
//! at runtime the way `sqlx::migrate!` resolves `migrations/` at build time.
use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

use sqlx::{Row, SqlitePool, migrate::Migrator};

use super::*;
use crate::{db, models::CreateDeviceRequest};

const EXPAND: (&str, &str) = (
    "20261201000000_fixture_notes.sql",
    "-- tiaris-nest-schema: expand
CREATE TABLE fixture_notes (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    note TEXT NOT NULL
);
CREATE INDEX fixture_notes_device ON fixture_notes(device_id);
ALTER TABLE devices ADD COLUMN fixture_label TEXT;
ALTER TABLE devices ADD COLUMN fixture_rank INTEGER NOT NULL DEFAULT 0;
UPDATE devices SET fixture_rank = 1 WHERE hostname IS NOT NULL;
",
);

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tiaris-schema-{label}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// This release's migrations plus `extra`, as a later release would carry.
async fn candidate(scratch: &Scratch, name: &str, extra: &[(&str, &str)]) -> Migrator {
    let directory = scratch.join(name);
    fs::create_dir_all(&directory).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), directory.join(entry.file_name())).unwrap();
    }
    for (file, sql) in extra {
        fs::write(directory.join(file), sql).unwrap();
    }
    Migrator::new(directory.as_path()).await.unwrap()
}

async fn open(path: &Path) -> SqlitePool {
    db::connect_with_url(&format!("sqlite://{}", path.display()))
        .await
        .unwrap()
}

fn later() -> semver::Version {
    semver::Version::parse("99.0.0").unwrap()
}

async fn device(pool: &SqlitePool, mac: &str, hostname: Option<&str>) -> i64 {
    db::create_device(
        pool,
        CreateDeviceRequest {
            mac: mac.into(),
            hostname: hostname.map(Into::into),
            serial_number: None,
            notes: None,
            tags: None,
            default_profile_id: None,
            one_time_profile_id: None,
        },
    )
    .await
    .unwrap()
    .id
}

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn expand_survives_rollback_and_reupgrade_with_data_intact() {
    let scratch = Scratch::new("round-trip");
    let path = scratch.join("tiaris-nest.sqlite");
    let next = candidate(&scratch, "next", &[EXPAND]).await;

    // The predecessor installs and writes.
    let pool = open(&path).await;
    db::migrate(&pool).await.unwrap();
    let kept = device(&pool, "02:00:00:00:00:01", Some("kept")).await;
    let removed = device(&pool, "02:00:00:00:00:02", None).await;
    pool.close().await;

    // Upgrade: the candidate migrates and writes into what it added.
    let pool = open(&path).await;
    let plan = db::migrate_with(&pool, &next, &later()).await.unwrap();
    assert_eq!(plan.pending, vec![20261201000000]);
    for id in [kept, removed] {
        sqlx::query("INSERT INTO fixture_notes (device_id, note) VALUES (?, 'from the candidate')")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE devices SET fixture_label = 'labelled' WHERE id = ?")
        .bind(kept)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        count(
            &pool,
            "SELECT fixture_rank FROM devices WHERE hostname = 'kept'"
        )
        .await,
        1
    );
    pool.close().await;

    // Roll back: the predecessor starts, reads and writes on the new schema.
    let pool = open(&path).await;
    let plan = db::migrate_with(&pool, &MIGRATOR, &own_release())
        .await
        .unwrap();
    assert!(plan.pending.is_empty());
    assert_eq!(
        plan.tolerated,
        vec![Tolerated {
            version: 20261201000000,
            class: "expand".into(),
            reader_floor: None
        }]
    );
    let macs: Vec<String> = db::list_devices(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|device| device.mac)
        .collect();
    assert_eq!(macs.len(), 2);
    let added_on_rollback = device(&pool, "02:00:00:00:00:03", Some("rollback")).await;
    // The candidate's notes reference this device: the delete still works.
    db::delete_device(&pool, removed).await.unwrap();
    exercise(&pool).await.unwrap();
    pool.close().await;
    verify_rollback_target_with(&path, &MIGRATOR, &own_release())
        .await
        .unwrap();

    // Re-upgrade: nothing to apply; both releases' data is there.
    let pool = open(&path).await;
    let plan = db::migrate_with(&pool, &next, &later()).await.unwrap();
    assert!(plan.pending.is_empty() && plan.tolerated.is_empty());
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM fixture_notes").await,
        1,
        "the note of the kept device survives; the removed device's cascaded"
    );
    let label: Option<String> =
        sqlx::query_scalar("SELECT fixture_label FROM devices WHERE id = ?")
            .bind(kept)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(label.as_deref(), Some("labelled"));
    let rank: i64 = sqlx::query_scalar("SELECT fixture_rank FROM devices WHERE id = ?")
        .bind(added_on_rollback)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rank, 0, "a row the predecessor wrote takes the default");
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM tiaris_nest_schema_changes WHERE class = 'expand'"
        )
        .await,
        1
    );
    pool.close().await;
}

#[tokio::test]
async fn rehearsal_migrates_only_a_copy_and_the_predecessor_accepts_it() {
    let scratch = Scratch::new("rehearsal");
    let live = scratch.join("live.sqlite");
    let pool = open(&live).await;
    db::migrate(&pool).await.unwrap();
    device(&pool, "02:00:00:00:00:11", Some("seen")).await;
    pool.close().await;
    let next = candidate(&scratch, "next", &[EXPAND]).await;

    let rehearsal = scratch.join("rehearsal.sqlite");
    let plan = rehearse_with(&live, &rehearsal, &next, &later())
        .await
        .unwrap();
    assert_eq!(plan.pending, vec![20261201000000]);
    // The live database is untouched; the copy has the expansion.
    assert!(
        verify_openable_with(&live, &MIGRATOR, &own_release())
            .await
            .unwrap()
            .tolerated
            .is_empty()
    );
    let rehearsed = verify_rollback_target_with(&rehearsal, &MIGRATOR, &own_release())
        .await
        .unwrap();
    assert_eq!(rehearsed.tolerated.len(), 1);
    // The rollback check works on its own copy and leaves no files.
    let left: Vec<_> = fs::read_dir(&scratch.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(".rollback-target"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    // A second rehearsal never overwrites an existing output.
    assert!(
        rehearse_with(&live, &rehearsal, &next, &later())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn everything_that_is_not_a_compatible_declared_change_is_refused() {
    let scratch = Scratch::new("refusals");
    let live = scratch.join("live.sqlite");
    let pool = open(&live).await;
    db::migrate(&pool).await.unwrap();
    pool.close().await;
    let cases: [(&str, (&str, &str), &str); 5] = [
        (
            "undeclared",
            (
                "20261201000000_undeclared.sql",
                "CREATE TABLE fixture_plain (id INTEGER PRIMARY KEY);",
            ),
            "does not start with",
        ),
        (
            "not-additive",
            (
                "20261201000000_drop.sql",
                "-- tiaris-nest-schema: expand\nALTER TABLE devices DROP COLUMN notes;",
            ),
            "may only ADD a column",
        ),
        (
            "blocking-reference",
            (
                "20261201000000_restrict.sql",
                "-- tiaris-nest-schema: expand\nCREATE TABLE fixture_hold (device_id INTEGER REFERENCES devices(id));",
            ),
            "ON DELETE CASCADE",
        ),
        (
            "contract-above-floor",
            (
                "20261201000000_contract.sql",
                "-- tiaris-nest-schema: contract reader-floor=99.0.0\nCREATE TABLE fixture_later (id INTEGER PRIMARY KEY);",
            ),
            "needs release 99.0.0",
        ),
        (
            "contract-removing-what-the-predecessor-reads",
            (
                "20261201000000_contract.sql",
                "-- tiaris-nest-schema: contract reader-floor=0.0.1\nALTER TABLE devices DROP COLUMN notes;",
            ),
            "column devices.notes was removed",
        ),
    ];
    for (name, migration, expected) in cases {
        let next = candidate(&scratch, name, &[migration]).await;
        let rehearsal = scratch.join(&format!("{name}.sqlite"));
        let error = match rehearse_with(&live, &rehearsal, &next, &later()).await {
            Err(error) => error,
            Ok(_) => {
                assert!(!name.starts_with("undeclared") && !name.starts_with("not-additive"));
                verify_rollback_target_with(&rehearsal, &MIGRATOR, &own_release())
                    .await
                    .expect_err(name)
            }
        };
        let text = format!("{error:#}");
        assert!(text.contains(INCOMPATIBLE), "{name}: {text}");
        assert!(text.contains(expected), "{name}: {text}");
    }
}

#[tokio::test]
async fn newer_history_without_a_declaration_stays_refused() {
    let scratch = Scratch::new("undeclared-history");
    let path = scratch.join("tiaris-nest.sqlite");
    let pool = open(&path).await;
    db::migrate(&pool).await.unwrap();
    // What a release without schema evolution would leave: SQLx history only.
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (20990101000000, 'old style', TRUE, X'00', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let error = db::migrate(&pool).await.unwrap_err().to_string();
    assert!(error.contains("carries no declaration"), "{error}");
    sqlx::query(DECLARATIONS_DDL).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO tiaris_nest_schema_changes (version, class, description)
         VALUES (20990101000000, 'expand', 'declared')",
    )
    .execute(&pool)
    .await
    .unwrap();
    db::migrate(&pool).await.unwrap();
    // A failed (dirty) migration is never run alongside.
    sqlx::query("UPDATE _sqlx_migrations SET success = FALSE WHERE version = 20990101000000")
        .execute(&pool)
        .await
        .unwrap();
    let error = db::migrate(&pool).await.unwrap_err().to_string();
    assert!(error.contains("recorded as failed"), "{error}");
    pool.close().await;
}

fn copy_crash_image(database: &Path, image: &Path) {
    fs::create_dir_all(image).unwrap();
    for suffix in ["", "-wal"] {
        let mut from = database.as_os_str().to_owned();
        from.push(suffix);
        let from = PathBuf::from(from);
        if from.exists() {
            let mut to = image.join("tiaris-nest.sqlite").into_os_string();
            to.push(suffix);
            fs::copy(&from, PathBuf::from(to)).unwrap();
        }
    }
}

async fn expansion_state(pool: &SqlitePool) -> [bool; 4] {
    let table = |name: &'static str| {
        let pool = pool.clone();
        async move {
            count(
                &pool,
                &format!(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '{name}'"
                ),
            )
            .await
                > 0
        }
    };
    let history = count(
        pool,
        "SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 20261201000000",
    )
    .await
        > 0;
    let declared = table(DECLARATIONS_TABLE).await
        && count(
            pool,
            "SELECT COUNT(*) FROM tiaris_nest_schema_changes WHERE version = 20261201000000",
        )
        .await
            > 0;
    let column = sqlx::query("PRAGMA table_info(devices)")
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .any(|row| row.get::<String, _>("name") == "fixture_label");
    [history, declared, table("fixture_notes").await, column]
}

/// Power loss at each boundary of the candidate's first-boot migration: the
/// database files as they were at that moment open to a consistent state
/// (all of the expansion or none of it), the predecessor runs on it, and the
/// candidate's next boot completes the migration.
#[tokio::test]
async fn power_loss_at_each_migration_boundary_leaves_a_consistent_database() {
    let scratch = Scratch::new("power-loss");
    let path = scratch.join("tiaris-nest.sqlite");
    let pool = open(&path).await;
    db::migrate(&pool).await.unwrap();
    device(&pool, "02:00:00:00:00:21", Some("before")).await;
    pool.close().await;
    let next = candidate(&scratch, "next", &[EXPAND]).await;

    let images: Rc<RefCell<Vec<(&'static str, PathBuf)>>> = Rc::default();
    {
        let images = images.clone();
        let database = path.clone();
        let root = scratch.0.clone();
        set_crash_point(Some(Box::new(move |point| {
            let image = root.join(format!("image-{point}"));
            copy_crash_image(&database, &image);
            images.borrow_mut().push((point, image));
        })));
    }
    let pool = open(&path).await;
    let migrated = db::migrate_with(&pool, &next, &later()).await;
    set_crash_point(None);
    migrated.unwrap();
    pool.close().await;
    let images = images.borrow().clone();
    assert_eq!(
        images.iter().map(|(point, _)| *point).collect::<Vec<_>>(),
        ["after_migration_sql", "before_commit", "after_commit"]
    );

    for (point, image) in images {
        let database = image.join("tiaris-nest.sqlite");
        let pool = open(&database).await;
        let state = expansion_state(&pool).await;
        let committed = point == "after_commit";
        assert_eq!(state, [committed; 4], "{point}: {state:?}");
        // The predecessor (rollback) runs on the image...
        db::migrate(&pool).await.unwrap();
        assert_eq!(db::list_devices(&pool).await.unwrap().len(), 1, "{point}");
        // ...and the candidate's next boot finishes the migration once.
        db::migrate_with(&pool, &next, &later()).await.unwrap();
        assert_eq!(expansion_state(&pool).await, [true; 4], "{point}");
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(integrity, "ok", "{point}");
        pool.close().await;
    }
}

/// A Nest state record interrupted mid-write keeps its previous content: the
/// file side of the same boundaries (`state_files` writes then renames).
#[test]
fn power_loss_during_a_state_record_write_keeps_the_previous_record() {
    let scratch = Scratch::new("state-file");
    let directory = scratch.join("records");
    crate::state_files::write(&directory, "fixture.json", "tiaris.fixture.v1", 4096, &1u32)
        .unwrap();
    // A crash after the temporary file was written but before its rename.
    fs::write(
        directory.join(".fixture.json.tmp-0011223344556677"),
        b"{\"schema\":\"tiaris.fix",
    )
    .unwrap();
    let value: Option<u32> =
        crate::state_files::read(&directory, "fixture.json", "tiaris.fixture.v1", 4096);
    assert_eq!(value, Some(1));
    crate::state_files::write(&directory, "fixture.json", "tiaris.fixture.v1", 4096, &2u32)
        .unwrap();
    let value: Option<u32> =
        crate::state_files::read(&directory, "fixture.json", "tiaris.fixture.v1", 4096);
    assert_eq!(value, Some(2));
}

#[test]
fn declarations_are_parsed_strictly() {
    assert_eq!(
        declared_class(BASELINE_LAST_VERSION, "CREATE TABLE x (id INTEGER)").unwrap(),
        Class::Baseline
    );
    assert_eq!(
        declared_class(BASELINE_LAST_VERSION + 1, "-- tiaris-nest-schema: expand\n").unwrap(),
        Class::Expand
    );
    assert_eq!(
        declared_class(
            BASELINE_LAST_VERSION + 1,
            "-- tiaris-nest-schema: contract reader-floor=0.2.130\n"
        )
        .unwrap(),
        Class::Contract {
            reader_floor: semver::Version::parse("0.2.130").unwrap()
        }
    );
    for refused in [
        "CREATE TABLE x (id INTEGER);",
        "-- tiaris-nest-schema: contract\n",
        "-- tiaris-nest-schema: expand please\n",
        "-- tiaris-nest-schema: contract reader-floor=soon\n",
        "\n-- tiaris-nest-schema: expand\n",
    ] {
        assert!(
            declared_class(BASELINE_LAST_VERSION + 1, refused).is_err(),
            "{refused}"
        );
    }
}

#[test]
fn the_expansion_lint_admits_only_additive_statements() {
    let ok = [
        "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, name TEXT NOT NULL UNIQUE)",
        "CREATE TABLE t (id INTEGER PRIMARY KEY); CREATE TABLE u (t_id INTEGER REFERENCES t(id))",
        "CREATE INDEX i ON devices(hostname)",
        "CREATE TABLE t (id INTEGER PRIMARY KEY); CREATE UNIQUE INDEX i ON t(id)",
        "CREATE VIEW v AS SELECT id FROM devices",
        "ALTER TABLE devices ADD COLUMN c TEXT",
        "ALTER TABLE devices ADD c INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE devices ADD COLUMN c TEXT; UPDATE devices SET c = 'x; y' WHERE id > 0",
        "ALTER TABLE devices ADD COLUMN p INTEGER REFERENCES boot_profiles(id) ON DELETE SET NULL",
        "CREATE TABLE t (id INTEGER PRIMARY KEY, n TEXT); INSERT INTO t (id, n) SELECT id, mac FROM devices",
        "/* a comment; with a semicolon */ CREATE TABLE \"t\" (id INTEGER) -- trailing",
    ];
    for sql in ok {
        lint(BASELINE_LAST_VERSION + 1, sql, &Class::Expand).unwrap_or_else(|error| {
            panic!("{sql}: {error:#}");
        });
    }
    let refused = [
        ("DROP TABLE devices", "not additive"),
        ("ALTER TABLE devices RENAME TO machines", "may only ADD"),
        ("ALTER TABLE devices DROP COLUMN notes", "may only ADD"),
        (
            "ALTER TABLE devices ADD COLUMN c TEXT NOT NULL",
            "without a DEFAULT",
        ),
        (
            "ALTER TABLE devices ADD COLUMN c TEXT CHECK (c <> '')",
            "CHECK",
        ),
        ("CREATE UNIQUE INDEX i ON devices(hostname)", "unique index"),
        (
            "CREATE TABLE t (d INTEGER REFERENCES devices(id))",
            "ON DELETE CASCADE",
        ),
        (
            "CREATE TABLE t (d INTEGER REFERENCES devices(id) ON DELETE RESTRICT)",
            "ON DELETE CASCADE",
        ),
        (
            "CREATE TRIGGER x AFTER INSERT ON devices BEGIN SELECT 1; END",
            "triggers",
        ),
        ("DELETE FROM devices", "not additive"),
        ("UPDATE devices SET notes = ''", "only backfill"),
        (
            "INSERT INTO devices (mac) VALUES ('x')",
            "only into the tables it creates",
        ),
        (
            "INSERT OR REPLACE INTO devices (mac) VALUES ('x')",
            "REPLACE",
        ),
        ("PRAGMA foreign_keys = OFF", "not allowed"),
        ("CREATE TABLE t (id INTEGER); BEGIN; COMMIT", "not allowed"),
        (
            "-- no-transaction\nCREATE TABLE t (id INTEGER)",
            "one transaction",
        ),
        ("CREATE TABLE t AS SELECT * FROM devices", "AS SELECT"),
        ("INSERT INTO _sqlx_migrations VALUES (1)", "bookkeeping"),
        ("CREATE TABLE main.t (id INTEGER)", "schema-qualified"),
        ("CREATE TABLE 't (id INTEGER)", "unterminated"),
        ("", "empty"),
    ];
    for (sql, expected) in refused {
        let error = lint(BASELINE_LAST_VERSION + 1, sql, &Class::Expand)
            .expect_err(sql)
            .to_string();
        assert!(
            error.contains(expected) && error.contains(INCOMPATIBLE),
            "{sql}: {error}"
        );
    }
    let contract = Class::Contract {
        reader_floor: semver::Version::new(0, 2, 130),
    };
    lint(
        1,
        "ALTER TABLE devices DROP COLUMN notes; DROP TABLE x",
        &contract,
    )
    .unwrap();
    assert!(lint(1, "PRAGMA foreign_keys = OFF", &contract).is_err());
    assert!(lint(1, "UPDATE _sqlx_migrations SET success = 1", &contract).is_err());
}

async fn schema_after(sql: &str) -> Schema {
    let options = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
    let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
    migrate_connection(&mut conn, &MIGRATOR, &own_release())
        .await
        .unwrap();
    (&mut conn).execute(sql).await.unwrap();
    schema(&mut conn).await.unwrap()
}

#[tokio::test]
async fn the_superset_check_refuses_what_breaks_a_predecessor_query() {
    let reference = reference_schema(&MIGRATOR).await.unwrap();
    compatible_superset(&reference, &reference).unwrap();
    compatible_superset(
        &reference,
        &schema_after(
            "ALTER TABLE devices ADD COLUMN c TEXT;
             CREATE TABLE t (d INTEGER REFERENCES devices(id) ON DELETE CASCADE);
             CREATE INDEX i ON devices(c);",
        )
        .await,
    )
    .unwrap();
    for (sql, expected) in [
        (
            "ALTER TABLE devices DROP COLUMN notes",
            "devices.notes was removed",
        ),
        (
            "ALTER TABLE devices RENAME TO machines",
            "table devices was removed",
        ),
        (
            "CREATE UNIQUE INDEX i ON devices(hostname)",
            "new unique index on devices",
        ),
        (
            "CREATE TABLE t (d INTEGER REFERENCES devices(id))",
            "new table t blocks deletes from devices",
        ),
        (
            "CREATE TRIGGER x AFTER INSERT ON devices BEGIN SELECT 1; END",
            "new trigger x on devices",
        ),
        (
            "ALTER TABLE devices RENAME TO old_devices;
             CREATE TABLE devices AS SELECT * FROM old_devices;
             ALTER TABLE devices ADD COLUMN required TEXT;",
            "devices",
        ),
    ] {
        let error = compatible_superset(&reference, &schema_after(sql).await)
            .expect_err(sql)
            .to_string();
        assert!(error.contains(expected), "{sql}: {error}");
    }
}

#[tokio::test]
async fn this_release_declares_every_migration_after_the_baseline() {
    lint_migrator(&MIGRATOR).unwrap();
    let newest = up_migrations(&MIGRATOR)
        .map(|migration| migration.version)
        .max()
        .unwrap();
    assert!(newest >= BASELINE_LAST_VERSION);
    // A fresh install's schema is the reference the rollback check uses.
    let scratch = Scratch::new("reference");
    let path = scratch.join("tiaris-nest.sqlite");
    let pool = open(&path).await;
    db::migrate(&pool).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        schema(&mut conn).await.unwrap(),
        reference_schema(&MIGRATOR).await.unwrap()
    );
    drop(conn);
    pool.close().await;
    assert!(status()["compiled_newest_version"].as_i64().unwrap() >= BASELINE_LAST_VERSION);
}
