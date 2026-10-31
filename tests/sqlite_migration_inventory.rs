//! NixOS appliances refuse an update whose SQLite migration inventory differs
//! from the installed release's (`src/appliance/nixos.rs` `validate_migrations`,
//! `rollback_database_incompatible`). `migrations/` must therefore produce the
//! inventory pinned in `release/sqlite-migrations.sha256`, the one of the
//! releases appliances update from. Do not change the pin to make this pass:
//! a schema change needs a separate update-contract design first; keep new
//! state in files under the Nest state directory (`src/state_files.rs`).
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};

/// The inventory exactly as `nixos-appliance/metadata.py migrations` writes
/// it: canonical JSON (sorted keys, compact) and a newline.
fn inventory(directory: &Path) -> Vec<u8> {
    let mut files = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql"))
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

#[test]
fn migrations_keep_the_inventory_appliances_update_from() {
    let built = hex::encode(Sha256::digest(inventory(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"),
    )));
    assert_eq!(
        built,
        pinned(),
        "migrations/ no longer matches release/sqlite-migrations.sha256: NixOS appliances \
         would refuse this release with rollback_database_incompatible. Keep new state in \
         files (src/state_files.rs); a schema change needs a separate update-contract design."
    );
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
