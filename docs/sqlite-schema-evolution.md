# SQLite schema evolution (expand/contract)

How a Nest release may change its SQLite schema without breaking a rollback.
Code: `src/schema_evolution.rs` (rules, migrator, rehearsal),
`nixos-appliance/runtime/generation_update.py` (update admission),
`release/sqlite-schema-evolution.json` (release policy).

## Why the schema was frozen

A NixOS Nest update can roll back after the candidate already booted and
migrated the live database: the predecessor then starts again on that
database. Nothing restores an old copy. Plain SQLx refuses to start when the
database has a migration it does not know, so until now any migration
stranded the predecessor, the updater refused every inventory change
(`rollback_database_incompatible`) and new state went into files
(`src/state_files.rs`).

## The rules

Migrations up to `20260928000000` (the inventory in
`release/sqlite-migrations.sha256`, Nest 0.2.121 and its predecessors) are the
**baseline**. Every later migration starts with one declaration line, which
its SQLx checksum covers:

```sql
-- tiaris-nest-schema: expand
```

An **expansion** adds only what an older release can open and ignore. The
lint (`src/schema_evolution/lint.rs`) allows:

- `CREATE TABLE`, `CREATE VIEW`, `CREATE INDEX`; a `UNIQUE` index only on a
  table the same migration creates;
- `ALTER TABLE … ADD COLUMN`, nullable or `NOT NULL DEFAULT …`, without
  `CHECK`, `UNIQUE`, `PRIMARY KEY` or generated values;
- `INSERT` into tables the migration creates; `UPDATE` that backfills only
  the columns it adds;
- `REFERENCES` to an existing table only with `ON DELETE CASCADE` or
  `ON DELETE SET NULL`, so an older release can still delete the parent row.

Everything else is refused: drops, renames, type changes, `DELETE`,
`REPLACE`, triggers, `PRAGMA`, transaction control, `-- no-transaction`, and
any statement on `_sqlx_migrations` or `tiaris_nest_schema_changes`.

A **contraction** removes what older releases needed:

```sql
-- tiaris-nest-schema: contract reader-floor=0.2.140
```

Only releases at or above the floor may run on the result. Write one only
when no Nest can roll back to a release below the floor (the floor's release
has been everywhere for at least three updates: a Nest keeps the current and
two preceding generations), and only after an expansion that the floor
release already stopped using. Never rename or retype in one step: expand
(add the new column, write both), ship, then contract (drop the old one).

## What the Nest does

- **Applying.** `db::migrate` applies baseline migrations as SQLx does and each
  declared one in one transaction with its SQLx history row and a row in
  `tiaris_nest_schema_changes` (version, class, reader floor). A power cut
  leaves all three or none (`power_loss_at_each_migration_boundary…` test).
- **Running after a rollback.** A release that finds applied migrations it does
  not know starts only when each is newer than all of its own and declared
  there as an expansion, or as a contraction whose floor it meets. Anything
  else (undeclared, failed, older, a floor above it) is refused as before.
  `local_health.database.tolerated_newer` and the attention code
  `database_newer_than_release` report this state.
- **Admitting an update.** The root verifier accepts another candidate
  inventory only to rehearse it. Before anything is prepared, the candidate
  migrates a private copy of the root database snapshot
  (`tiaris-nest rehearse-appliance-database`), and the running release opens
  that copy as its rollback target
  (`tiaris-nest verify-appliance-database --rollback-target`): it checks that
  the schema is a structural superset of its own (no table, column, type or
  primary key gone; no new `NOT NULL` without default, unique index, trigger
  or blocking foreign key on its tables), runs its own startup migration and
  its reads, and creates and deletes a device. Failure refuses the update
  with `rollback_database_incompatible`; the live database is never touched.
- **Retained generations.** Each other retained generation is checked the same
  way. Those that cannot run on the new schema (every release before schema
  evolution) leave the boot menu before the candidate migrates the live
  database, because they could no longer start on it.

## Releasing a schema change

1. Releases that do not know schema evolution (0.2.121 and earlier) refuse any
   candidate with another inventory. First ship a release that contains this
   code, with the unchanged inventory, and let it reach every Nest (dev and
   production) that will take the schema change.
2. Then set `predecessor_runs_declared_changes` to `true` in
   `release/sqlite-schema-evolution.json`. `predecessor_last_version` and
   `release/sqlite-migrations.sha256` keep naming the inventory those
   releases carry.
3. Append declared migrations. `cargo test` (the inventory and lint tests),
   the tool tests and `tools/nest-release.py manifest` now accept exactly the
   pinned inventory plus declared migrations, and still refuse edits to
   existing migrations or undeclared ones.
4. After that release is everywhere, move `predecessor_last_version` and the
   pin to its inventory.

Manage offers one Nest release target; a Nest that still runs a release
without schema evolution refuses the schema-changing one with
`rollback_database_incompatible`. Step 1 must therefore come first, and
Manage must not skip the stepping-stone release for such Nests.

## Tests

`src/schema_evolution/tests.rs`: upgrade → write → roll back → the
predecessor starts, reads, writes and deletes → re-upgrade with both
releases' data intact; rehearsal on a copy; refusal of undeclared,
non-additive, blocking-reference and contract changes; crash images at each
migration boundary; the lint and superset rules. `tests/sqlite_migration_inventory.rs`
and `tools/tests/test_sqlite_migrations_pin.py` pin the release policy;
`nixos-appliance/tests/test_runtime.py` (`SchemaRehearsal`) the updater steps.
