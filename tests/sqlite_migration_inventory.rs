//! NixOS appliances refuse an update whose SQLite migrations their installed
//! release cannot run on after a rollback (`src/schema_evolution.rs`,
//! `rollback_database_incompatible`). `migrations/` must therefore start with
//! exactly the inventory pinned in `release/sqlite-migrations.sha256`, the one
//! of the releases appliances update from. Later migrations are allowed only
//! as declared expand/contract changes, and only once
//! `release/sqlite-schema-evolution.json` says those releases run them. Do not
//! change the pin or that file to make this pass; see
//! `docs/sqlite-schema-evolution.md`.
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};

fn version(name: &str) -> i64 {
    name.split_once('_').unwrap().0.parse().unwrap()
}

/// The inventory exactly as `nixos-appliance/metadata.py migrations` writes
/// it (canonical JSON: sorted keys, compact, and a newline), of the migrations
/// up to `last`.
fn inventory(directory: &Path, last: i64) -> Vec<u8> {
    let mut files = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql") && version(name) <= last)
        .collect::<Vec<_>>();
    files.sort();
    let rows = files
        .iter()
        .map(|name| {
            let body = std::fs::read(directory.join(name)).unwrap();
            let version: u64 = name.split_once('_').unwrap().0.parse().unwrap();
            json!({
                "filename": name,
                "version": version,
                "sha256": hex::encode(Sha256::digest(&body)),
                "sqlx_checksum": hex::encode(Sha384::digest(&body)),
            })
        })
        .collect::<Vec<Value>>();
    let mut bytes = serde_json::to_vec(&json!({
        "schema": "tiaris.nest.sqlite-migrations.v1",
        "migrations": rows,
    }))
    .unwrap();
    bytes.push(b'\n');
    bytes
}

fn pinned() -> String {
    let pin = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("release/sqlite-migrations.sha256"),
    )
    .unwrap();
    let values = pin
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1, "the pin holds exactly one digest");
    values[0].to_string()
}

fn evolution() -> Value {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("release/sqlite-schema-evolution.json"),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn migrations_keep_the_inventory_appliances_update_from() {
    let evolution = evolution();
    assert_eq!(
        evolution["schema"],
        "tiaris.nest.sqlite-schema-evolution.v1"
    );
    assert_eq!(
        evolution.as_object().unwrap().len(),
        4,
        "exactly the documented fields"
    );
    assert_eq!(
        evolution["baseline_last_version"],
        tiaris_nest::schema_evolution::BASELINE_LAST_VERSION
    );
    let last = evolution["predecessor_last_version"].as_i64().unwrap();
    assert!(last >= tiaris_nest::schema_evolution::BASELINE_LAST_VERSION);
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let built = hex::encode(Sha256::digest(inventory(&directory, last)));
    assert_eq!(
        built,
        pinned(),
        "migrations/ no longer starts with release/sqlite-migrations.sha256: NixOS appliances \
         would refuse this release with rollback_database_incompatible. Existing migrations \
         are immutable; see docs/sqlite-schema-evolution.md."
    );
    let added: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql") && version(name) > last)
        .collect();
    if !added.is_empty() {
        assert_eq!(
            evolution["predecessor_runs_declared_changes"], true,
            "{added:?} would strand the releases appliances update from: they do not run \
             declared schema changes yet (docs/sqlite-schema-evolution.md). Keep new state in \
             files (src/state_files.rs) until they do."
        );
    }
    // Every added migration is declared and passes the expand/contract rules.
    tiaris_nest::schema_evolution::lint_migrator(&sqlx::migrate!()).unwrap();
}

#[test]
fn the_embedded_migrations_are_exactly_the_pinned_files() {
    // What the binary applies (`sqlx::migrate!`) is what the inventory names.
    let migrator = sqlx::migrate!();
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let files = std::fs::read_dir(&directory)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".sql")
        })
        .count();
    assert_eq!(migrator.iter().count(), files);
    for migration in migrator.iter() {
        let name = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .find(|name| name.starts_with(&format!("{}_", migration.version)))
            .unwrap();
        let body = std::fs::read(directory.join(name)).unwrap();
        assert_eq!(
            migration.checksum.as_ref(),
            Sha384::digest(&body).as_slice()
        );
    }
}
