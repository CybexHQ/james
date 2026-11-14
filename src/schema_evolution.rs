//! Rollback-compatible SQLite schema evolution (expand/contract).
//!
//! A NixOS Nest update can roll back after the candidate already booted and
//! migrated the live database: the predecessor then starts again on that
//! database (`nixos-appliance/runtime/generation_update.py`, which never
//! restores an old database). Plain SQLx refuses that (`VersionMissing`), so
//! until this module every migration blocked Nest updates
//! (`rollback_database_incompatible`). Here a release may change the schema
//! only in ways its predecessors can open and ignore:
//!
//! - Migrations up to [`BASELINE_LAST_VERSION`] are the baseline every
//!   installed Nest already has.
//! - Every later migration starts with a declaration line, covered by its
//!   SQLx checksum: `-- tiaris-nest-schema: expand` (additive only, checked by
//!   [`lint`]) or `-- tiaris-nest-schema: contract reader-floor=<release>`
//!   (destructive; only releases at or above the floor may run on the result).
//! - [`migrate`] applies a declared migration and records its declaration in
//!   `tiaris_nest_schema_changes` in the same transaction as SQLx's own
//!   history row, so a power cut leaves both or neither.
//! - An older release that finds applied migrations it does not know starts
//!   only when each one is newer than all of its own and is declared there as
//!   an expansion (or a contraction whose floor it meets); anything else is
//!   refused as before.
//! - Before an update, the candidate migrates a private copy of the live
//!   database ([`rehearse`]) and the running release opens that copy as its
//!   rollback target ([`verify_rollback_target`]): it checks that the result
//!   is a structural superset of its own schema ([`compatible_superset`]) and
//!   runs its own startup and queries on it.
//!
//! See `docs/sqlite-schema-evolution.md`.
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;
use sqlx::{
    Connection, Executor, Row, SqliteConnection, SqlitePool,
    migrate::{Migrate, Migration, Migrator},
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

/// The newest migration every installed Nest already has: the inventory of
/// `release/sqlite-migrations.sha256` (Nest 0.2.121 and its predecessors).
pub const BASELINE_LAST_VERSION: i64 = 20260928000000;
/// Where each applied declared migration records its class.
pub const DECLARATIONS_TABLE: &str = "tiaris_nest_schema_changes";
/// The first line of every migration after the baseline.
pub const HEADER_PREFIX: &str = "-- tiaris-nest-schema:";
/// The reason code Manage already knows for a refused schema.
pub const INCOMPATIBLE: &str = "rollback_database_incompatible";

/// The migrations compiled into this release.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

const DECLARATIONS_DDL: &str = "CREATE TABLE IF NOT EXISTS tiaris_nest_schema_changes (
    version BIGINT PRIMARY KEY,
    class TEXT NOT NULL CHECK (class IN ('expand', 'contract')),
    reader_floor TEXT,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)";
const MAX_DATABASE_BYTES: u64 = 1024 * 1024 * 1024;

/// This release, as a reader of contracted schemas.
pub fn own_release() -> semver::Version {
    semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("the crate version is SemVer")
}

/// What a migration declares about the predecessors that must keep working.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Class {
    /// Shipped before schema evolution; every installed Nest has it.
    Baseline,
    /// Additive: older releases open the result and ignore what was added.
    Expand,
    /// Destructive: only releases at or above `reader_floor` may run on it.
    Contract { reader_floor: semver::Version },
}

impl Class {
    fn name(&self) -> &'static str {
        match self {
            Class::Baseline => "baseline",
            Class::Expand => "expand",
            Class::Contract { .. } => "contract",
        }
    }
}

/// The declared class of one migration (see the module documentation).
pub fn declared_class(version: i64, sql: &str) -> Result<Class> {
    if version <= BASELINE_LAST_VERSION {
        return Ok(Class::Baseline);
    }
    let first = sql.lines().next().unwrap_or_default().trim_end();
    let rest = first.strip_prefix(HEADER_PREFIX).ok_or_else(|| {
        anyhow!(
            "{INCOMPATIBLE}: migration {version} does not start with \
             `{HEADER_PREFIX} expand` or `{HEADER_PREFIX} contract reader-floor=<release>`"
        )
    })?;
    match rest.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["expand"] => Ok(Class::Expand),
        ["contract", floor] => {
            let floor = floor.strip_prefix("reader-floor=").ok_or_else(|| {
                anyhow!("{INCOMPATIBLE}: contract migration {version} names no reader-floor")
            })?;
            Ok(Class::Contract {
                reader_floor: semver::Version::parse(floor).with_context(|| {
                    format!("{INCOMPATIBLE}: contract migration {version} reader-floor")
                })?,
            })
        }
        _ => bail!("{INCOMPATIBLE}: migration {version} has an unknown schema declaration"),
    }
}

mod lint;
pub use lint::lint;

/// Every migration of `migrator` after the baseline is declared, lint-clean
/// and newer than the baseline; versions are unique (SQLx already sorts).
pub fn lint_migrator(migrator: &Migrator) -> Result<()> {
    for migration in up_migrations(migrator) {
        let class = declared_class(migration.version, &migration.sql)?;
        if class != Class::Baseline {
            lint(migration.version, &migration.sql, &class)?;
        }
    }
    Ok(())
}

fn up_migrations(migrator: &Migrator) -> impl Iterator<Item = &Migration> {
    migrator
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
}

/// An applied migration this release does not know but may run alongside.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tolerated {
    pub version: i64,
    pub class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_floor: Option<String>,
}

/// What [`migrate`] found and did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// Applied migrations this release knows.
    pub applied: usize,
    /// Compiled migrations not applied yet, oldest first.
    pub pending: Vec<i64>,
    /// Newer declared migrations of a later release (after a rollback).
    pub tolerated: Vec<Tolerated>,
}

async fn table_exists(conn: &mut SqliteConnection, name: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await?
        > 0)
}

/// Decides whether this release (`migrator`, as `reader`) can run on the
/// database behind `conn`; never writes.
pub async fn plan(
    conn: &mut SqliteConnection,
    migrator: &Migrator,
    reader: &semver::Version,
) -> Result<Plan> {
    let compiled: BTreeMap<i64, &Migration> = up_migrations(migrator)
        .map(|migration| (migration.version, migration))
        .collect();
    let applied: Vec<(i64, Vec<u8>, bool)> = if table_exists(conn, "_sqlx_migrations").await? {
        sqlx::query("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&mut *conn)
            .await?
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<i64, _>("version")?,
                    row.try_get::<Vec<u8>, _>("checksum")?,
                    row.try_get::<bool, _>("success")?,
                ))
            })
            .collect::<Result<_>>()?
    } else {
        Vec::new()
    };
    let mut plan = Plan::default();
    let mut unknown = Vec::new();
    for (version, checksum, success) in &applied {
        ensure!(
            *success,
            "{INCOMPATIBLE}: migration {version} is recorded as failed"
        );
        match compiled.get(version) {
            Some(migration) => {
                ensure!(
                    migration.checksum.as_ref() == checksum.as_slice(),
                    "{INCOMPATIBLE}: applied migration {version} differs from this release's"
                );
                plan.applied += 1;
            }
            None => unknown.push(*version),
        }
    }
    let applied_versions: BTreeSet<i64> = applied.iter().map(|row| row.0).collect();
    plan.pending = compiled
        .keys()
        .copied()
        .filter(|version| !applied_versions.contains(version))
        .collect();
    let newest_compiled = compiled.keys().next_back().copied().unwrap_or(0);
    if !unknown.is_empty() {
        ensure!(
            plan.pending.is_empty(),
            "{INCOMPATIBLE}: this release's migration {} is missing below newer ones",
            plan.pending[0]
        );
        ensure!(
            unknown[0] > newest_compiled,
            "{INCOMPATIBLE}: applied migration {} is unknown to this release",
            unknown[0]
        );
        ensure!(
            table_exists(conn, DECLARATIONS_TABLE).await?,
            "{INCOMPATIBLE}: newer migration {} carries no declaration",
            unknown[0]
        );
        let declared: BTreeMap<i64, (String, Option<String>)> = sqlx::query(
            "SELECT version, class, reader_floor FROM tiaris_nest_schema_changes ORDER BY version",
        )
        .fetch_all(&mut *conn)
        .await?
        .iter()
        .map(|row| {
            Ok((
                row.try_get::<i64, _>("version")?,
                (
                    row.try_get::<String, _>("class")?,
                    row.try_get::<Option<String>, _>("reader_floor")?,
                ),
            ))
        })
        .collect::<Result<_>>()?;
        for version in unknown {
            let (class, floor) = declared.get(&version).cloned().ok_or_else(|| {
                anyhow!("{INCOMPATIBLE}: newer migration {version} carries no declaration")
            })?;
            match class.as_str() {
                "expand" => {}
                "contract" => {
                    let floor = semver::Version::parse(floor.as_deref().unwrap_or_default())
                        .with_context(|| {
                            format!("{INCOMPATIBLE}: contract migration {version} floor")
                        })?;
                    ensure!(
                        reader >= &floor,
                        "{INCOMPATIBLE}: contract migration {version} needs release {floor} \
                         or later; this is {reader}"
                    );
                }
                _ => bail!("{INCOMPATIBLE}: newer migration {version} has unknown class"),
            }
            plan.tolerated.push(Tolerated {
                version,
                class,
                reader_floor: floor,
            });
        }
    }
    let newest_applied = applied_versions.iter().next_back().copied().unwrap_or(0);
    for version in &plan.pending {
        let migration = compiled[version];
        let class = declared_class(*version, &migration.sql)?;
        if class != Class::Baseline {
            ensure!(
                *version > newest_applied,
                "{INCOMPATIBLE}: declared migration {version} is older than an applied one"
            );
            lint(*version, &migration.sql, &class)?;
        }
    }
    Ok(plan)
}

/// Called at each named migration boundary (tests only).
type CrashHook = Box<dyn Fn(&'static str)>;

thread_local! {
    static CRASH_POINT: RefCell<Option<CrashHook>> = const { RefCell::new(None) };
}

/// Tests take a crash image (a copy of the database files) at each boundary.
#[cfg(test)]
pub(crate) fn set_crash_point(hook: Option<CrashHook>) {
    CRASH_POINT.with(|cell| *cell.borrow_mut() = hook);
}

fn crash_point(name: &'static str) {
    CRASH_POINT.with(|cell| {
        if let Some(hook) = cell.borrow().as_ref() {
            hook(name);
        }
    });
}

async fn apply_declared(
    conn: &mut SqliteConnection,
    migration: &Migration,
    class: &Class,
) -> Result<()> {
    let started = Instant::now();
    let mut tx = conn.begin().await?;
    (&mut *tx).execute(DECLARATIONS_DDL).await?;
    (&mut *tx)
        .execute(&*migration.sql)
        .await
        .with_context(|| format!("migration {} failed", migration.version))?;
    crash_point("after_migration_sql");
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (?1, ?2, TRUE, ?3, -1)",
    )
    .bind(migration.version)
    .bind(&*migration.description)
    .bind(&*migration.checksum)
    .execute(&mut *tx)
    .await?;
    let floor = match class {
        Class::Contract { reader_floor } => Some(reader_floor.to_string()),
        _ => None,
    };
    sqlx::query(
        "INSERT INTO tiaris_nest_schema_changes (version, class, reader_floor, description)
         VALUES (?, ?, ?, ?)",
    )
    .bind(migration.version)
    .bind(class.name())
    .bind(floor)
    .bind(&*migration.description)
    .execute(&mut *tx)
    .await?;
    crash_point("before_commit");
    tx.commit().await?;
    crash_point("after_commit");
    // As SQLx: only lineage, so losing it to a crash here is harmless.
    sqlx::query("UPDATE _sqlx_migrations SET execution_time = ? WHERE version = ?")
        .bind(i64::try_from(started.elapsed().as_nanos()).unwrap_or(i64::MAX))
        .bind(migration.version)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Applies what [`plan`] allows on `conn`: baseline migrations exactly as SQLx
/// does, declared ones with their declaration row.
pub async fn migrate_connection(
    conn: &mut SqliteConnection,
    migrator: &Migrator,
    reader: &semver::Version,
) -> Result<Plan> {
    conn.ensure_migrations_table().await?;
    let plan = plan(conn, migrator, reader).await?;
    for version in &plan.pending {
        let migration = up_migrations(migrator)
            .find(|migration| migration.version == *version)
            .expect("pending migrations come from the migrator");
        match declared_class(*version, &migration.sql)? {
            Class::Baseline => {
                conn.apply(migration).await?;
            }
            class => apply_declared(conn, migration, &class).await?,
        }
    }
    Ok(plan)
}

/// [`migrate_connection`] on one connection of `pool`.
pub async fn migrate(
    pool: &SqlitePool,
    migrator: &Migrator,
    reader: &semver::Version,
) -> Result<Plan> {
    let mut conn = pool.acquire().await?;
    migrate_connection(&mut conn, migrator, reader).await
}

static STATUS: Mutex<Option<Plan>> = Mutex::new(None);

/// Remembers the startup plan for the Nest report.
pub fn record_status(plan: &Plan) {
    if let Ok(mut status) = STATUS.lock() {
        *status = Some(plan.clone());
    }
    if !plan.tolerated.is_empty() {
        tracing::warn!(
            tolerated = ?plan.tolerated.iter().map(|row| row.version).collect::<Vec<_>>(),
            "SQLite has declared migrations of a newer release (rolled back); running on them"
        );
    }
}

/// The schema state for `local_health`: what this release applied and which
/// newer declared migrations it runs alongside.
pub fn status() -> serde_json::Value {
    let newest = up_migrations(&MIGRATOR)
        .map(|migration| migration.version)
        .max()
        .unwrap_or(0);
    match STATUS.lock().ok().and_then(|status| status.clone()) {
        Some(plan) => serde_json::json!({
            "compiled_newest_version": newest,
            "applied": plan.applied + plan.pending.len(),
            "tolerated_newer": plan.tolerated,
        }),
        None => serde_json::json!({"compiled_newest_version": newest}),
    }
}

/// One column as SQLite reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub declared_type: String,
    pub not_null: bool,
    pub has_default: bool,
    pub primary_key: i64,
}

/// One foreign key of a table.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ForeignKey {
    pub columns: Vec<String>,
    pub parent: String,
    pub on_delete: String,
}

/// What a predecessor's statements depend on in one table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub columns: BTreeMap<String, Column>,
    pub unique: BTreeSet<Vec<String>>,
    pub foreign_keys: BTreeSet<ForeignKey>,
}

/// A database schema, without SQLx and declaration bookkeeping.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schema {
    pub tables: BTreeMap<String, Table>,
    /// Trigger name → its table.
    pub triggers: BTreeMap<String, String>,
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Reads the schema of `conn`.
pub async fn schema(conn: &mut SqliteConnection) -> Result<Schema> {
    let mut schema = Schema::default();
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%' AND name NOT IN ('_sqlx_migrations', ?)
         ORDER BY name",
    )
    .bind(DECLARATIONS_TABLE)
    .fetch_all(&mut *conn)
    .await?;
    for name in names {
        let mut table = Table::default();
        for row in sqlx::query(&format!("PRAGMA table_info({})", quoted(&name)))
            .fetch_all(&mut *conn)
            .await?
        {
            table.columns.insert(
                row.try_get::<String, _>("name")?.to_lowercase(),
                Column {
                    declared_type: row.try_get::<String, _>("type")?.to_uppercase(),
                    not_null: row.try_get::<i64, _>("notnull")? != 0,
                    has_default: row.try_get::<Option<String>, _>("dflt_value")?.is_some(),
                    primary_key: row.try_get::<i64, _>("pk")?,
                },
            );
        }
        for row in sqlx::query(&format!("PRAGMA index_list({})", quoted(&name)))
            .fetch_all(&mut *conn)
            .await?
        {
            if row.try_get::<i64, _>("unique")? == 0 {
                continue;
            }
            let index: String = row.try_get("name")?;
            let columns = sqlx::query(&format!("PRAGMA index_info({})", quoted(&index)))
                .fetch_all(&mut *conn)
                .await?
                .iter()
                .map(|row| {
                    Ok(row
                        .try_get::<Option<String>, _>("name")?
                        .map(|name| name.to_lowercase())
                        .unwrap_or_else(|| "<expression>".into()))
                })
                .collect::<Result<Vec<_>>>()?;
            table.unique.insert(columns);
        }
        let mut keys: BTreeMap<i64, ForeignKey> = BTreeMap::new();
        for row in sqlx::query(&format!("PRAGMA foreign_key_list({})", quoted(&name)))
            .fetch_all(&mut *conn)
            .await?
        {
            let key = keys
                .entry(row.try_get::<i64, _>("id")?)
                .or_insert_with(|| ForeignKey {
                    columns: Vec::new(),
                    parent: String::new(),
                    on_delete: String::new(),
                });
            key.columns
                .push(row.try_get::<String, _>("from")?.to_lowercase());
            key.parent = row.try_get::<String, _>("table")?.to_lowercase();
            key.on_delete = row.try_get::<String, _>("on_delete")?.to_uppercase();
        }
        table.foreign_keys = keys.into_values().collect();
        schema.tables.insert(name.to_lowercase(), table);
    }
    for row in
        sqlx::query("SELECT name, tbl_name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
            .fetch_all(&mut *conn)
            .await?
    {
        schema.triggers.insert(
            row.try_get::<String, _>("name")?.to_lowercase(),
            row.try_get::<String, _>("tbl_name")?.to_lowercase(),
        );
    }
    Ok(schema)
}

/// The schema a fresh database gets from `migrator`.
pub async fn reference_schema(migrator: &Migrator) -> Result<Schema> {
    let options = SqliteConnectOptions::from_str("sqlite::memory:")?;
    let mut conn = SqliteConnection::connect_with(&options).await?;
    migrate_connection(&mut conn, migrator, &semver::Version::new(u64::MAX, 0, 0)).await?;
    let schema = schema(&mut conn).await?;
    conn.close().await?;
    Ok(schema)
}

fn releases_parent_deletes(key: &ForeignKey) -> bool {
    matches!(key.on_delete.as_str(), "CASCADE" | "SET NULL")
}

/// Whether every statement written against `reference` still works on
/// `target`: nothing it reads was removed or changed, and nothing new can
/// refuse a row it writes or a row it deletes.
pub fn compatible_superset(reference: &Schema, target: &Schema) -> Result<()> {
    let mut problems = Vec::new();
    for (name, old) in &reference.tables {
        let Some(new) = target.tables.get(name) else {
            problems.push(format!("table {name} was removed"));
            continue;
        };
        for (column, before) in &old.columns {
            match new.columns.get(column) {
                None => problems.push(format!("column {name}.{column} was removed")),
                Some(after) => {
                    if after.declared_type != before.declared_type {
                        problems.push(format!("column {name}.{column} changed type"));
                    }
                    if after.not_null && !before.not_null {
                        problems.push(format!("column {name}.{column} became NOT NULL"));
                    }
                    if after.primary_key != before.primary_key {
                        problems.push(format!("column {name}.{column} changed primary key"));
                    }
                }
            }
        }
        for (column, added) in &new.columns {
            if old.columns.contains_key(column) {
                continue;
            }
            if added.not_null && !added.has_default {
                problems.push(format!(
                    "new column {name}.{column} is NOT NULL without a default"
                ));
            }
            if added.primary_key != 0 {
                problems.push(format!("new column {name}.{column} is in the primary key"));
            }
        }
        for unique in new.unique.difference(&old.unique) {
            problems.push(format!("new unique index on {name}({})", unique.join(", ")));
        }
        for key in new.foreign_keys.difference(&old.foreign_keys) {
            if !releases_parent_deletes(key) {
                problems.push(format!(
                    "new foreign key {name}({}) blocks deletes from {}",
                    key.columns.join(", "),
                    key.parent
                ));
            }
        }
    }
    for (name, table) in &target.tables {
        if reference.tables.contains_key(name) {
            continue;
        }
        for key in &table.foreign_keys {
            if reference.tables.contains_key(&key.parent) && !releases_parent_deletes(key) {
                problems.push(format!(
                    "new table {name} blocks deletes from {} (use ON DELETE CASCADE or SET NULL)",
                    key.parent
                ));
            }
        }
    }
    for (trigger, table) in &target.triggers {
        if !reference.triggers.contains_key(trigger) && reference.tables.contains_key(table) {
            problems.push(format!("new trigger {trigger} on {table}"));
        }
    }
    ensure!(
        problems.is_empty(),
        "{INCOMPATIBLE}: {}",
        problems.into_iter().take(8).collect::<Vec<_>>().join("; ")
    );
    Ok(())
}

async fn integrity(conn: &mut SqliteConnection) -> Result<()> {
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check(1)")
        .fetch_one(&mut *conn)
        .await?;
    ensure!(
        integrity == "ok",
        "{INCOMPATIBLE}: SQLite integrity failure"
    );
    Ok(())
}

async fn open_read_only(path: &Path) -> Result<SqliteConnection> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .busy_timeout(Duration::from_secs(5));
    Ok(SqliteConnection::connect_with(&options).await?)
}

/// Read-only: whether this release can start on the database at `path`.
pub async fn verify_openable(path: &Path) -> Result<Plan> {
    verify_openable_with(path, &MIGRATOR, &own_release()).await
}

pub(crate) async fn verify_openable_with(
    path: &Path,
    migrator: &Migrator,
    reader: &semver::Version,
) -> Result<Plan> {
    let mut conn = open_read_only(path).await?;
    integrity(&mut conn).await?;
    let plan = plan(&mut conn, migrator, reader).await?;
    conn.close().await?;
    Ok(plan)
}

/// A consistent copy of `source` (also while it is in use) in a new private file.
pub(crate) async fn private_copy(source: &Path, target: &Path) -> Result<()> {
    ensure!(!target.exists(), "database copy target already exists");
    let target_text = target
        .to_str()
        .ok_or_else(|| anyhow!("database copy path is not UTF-8"))?
        .to_owned();
    // Reserve the name privately first; VACUUM INTO fills an empty file.
    drop(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(target)?,
    );
    let copied = async {
        let mut conn = open_read_only(source).await?;
        sqlx::query("VACUUM INTO ?")
            .bind(target_text)
            .execute(&mut conn)
            .await?;
        conn.close().await?;
        anyhow::Ok(())
    }
    .await;
    if copied.is_err() {
        let _ = fs::remove_file(target);
    }
    copied?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

async fn open_pool(path: &Path, journal: SqliteJournalMode) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .journal_mode(journal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);
    Ok(SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?)
}

/// Candidate side of an update: copies the snapshot at `input` to `output`
/// (a new private file) and runs this release's startup migration on the copy
/// only, as the candidate's first boot would on the live database.
pub async fn rehearse(input: &Path, output: &Path) -> Result<Plan> {
    rehearse_with(input, output, &MIGRATOR, &own_release()).await
}

pub(crate) async fn rehearse_with(
    input: &Path,
    output: &Path,
    migrator: &Migrator,
    reader: &semver::Version,
) -> Result<Plan> {
    let size = fs::symlink_metadata(input)?.len();
    ensure!(
        size <= MAX_DATABASE_BYTES,
        "database rehearsal exceeds its bound"
    );
    verify_openable_with(input, migrator, reader).await?;
    private_copy(input, output).await?;
    let result = async {
        let pool = open_pool(output, SqliteJournalMode::Delete).await?;
        let plan = crate::db::migrate_with(&pool, migrator, reader)
            .await
            .map_err(|error| anyhow!("{INCOMPATIBLE}: rehearsal migration failed: {error}"))?;
        {
            let mut conn = pool.acquire().await?;
            integrity(&mut conn).await?;
            let migrated = schema(&mut conn).await?;
            compatible_superset(&reference_schema(migrator).await?, &migrated)?;
        }
        pool.close().await;
        anyhow::Ok(plan)
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

/// Predecessor side of an update: whether this release, as the rollback
/// target, still works on a database migrated by the candidate. Works on its
/// own private copy and leaves `path` untouched.
pub async fn verify_rollback_target(path: &Path) -> Result<Plan> {
    verify_rollback_target_with(path, &MIGRATOR, &own_release()).await
}

pub(crate) async fn verify_rollback_target_with(
    path: &Path,
    migrator: &Migrator,
    reader: &semver::Version,
) -> Result<Plan> {
    let plan = verify_openable_with(path, migrator, reader).await?;
    ensure!(
        plan.pending.is_empty(),
        "{INCOMPATIBLE}: the rollback database lacks this release's migration {}",
        plan.pending.first().copied().unwrap_or_default()
    );
    let copy = scratch_path(path)?;
    let result = async {
        private_copy(path, &copy).await?;
        let pool = open_pool(&copy, SqliteJournalMode::Wal).await?;
        // The real startup path, then the release's own reads and writes.
        let plan = crate::db::migrate_with(&pool, migrator, reader)
            .await
            .map_err(|error| anyhow!("{INCOMPATIBLE}: startup on rollback failed: {error}"))?;
        {
            let mut conn = pool.acquire().await?;
            compatible_superset(
                &reference_schema(migrator).await?,
                &schema(&mut conn).await?,
            )?;
        }
        exercise(&pool)
            .await
            .map_err(|error| anyhow!("{INCOMPATIBLE}: rollback queries failed: {error}"))?;
        pool.close().await;
        anyhow::Ok(plan)
    }
    .await;
    for suffix in ["", "-wal", "-shm"] {
        let mut name = copy.clone().into_os_string();
        name.push(suffix);
        let _ = fs::remove_file(PathBuf::from(name));
    }
    result
}

fn scratch_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("database has no directory"))?;
    Ok(parent.join(format!(
        ".rollback-target-{}.sqlite",
        uuid::Uuid::new_v4().simple()
    )))
}

/// The reads and a write/delete cycle a running Nest performs, so foreign
/// keys and constraints of newer tables are exercised too.
pub async fn exercise(pool: &SqlitePool) -> Result<()> {
    crate::db::list_devices(pool).await?;
    crate::db::list_profiles(pool).await?;
    crate::db::list_boot_events(pool, 50).await?;
    crate::db::list_build_jobs(pool).await?;
    crate::db::list_cache_artifacts(pool).await?;
    crate::db::active_build_job_count(pool).await?;
    let mut mac = None;
    for n in 1..=16u8 {
        let candidate = format!("02:7e:57:00:00:{n:02x}");
        if crate::db::get_device_by_mac(pool, &candidate)
            .await?
            .is_none()
        {
            mac = Some(candidate);
            break;
        }
    }
    let mac = mac.ok_or_else(|| anyhow!("no free probe address"))?;
    let device = crate::db::create_device(
        pool,
        crate::models::CreateDeviceRequest {
            mac,
            hostname: None,
            serial_number: None,
            notes: Some("schema rollback probe".into()),
            tags: None,
            default_profile_id: None,
            one_time_profile_id: None,
        },
    )
    .await?;
    crate::db::delete_device(pool, device.id).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
