# Nest state backup and restore

How to back up a Nest's state and keys, and restore them onto a replacement.
Code: `src/state_backup.rs` (backup and restore), `src/state_backup/schedule.rs`
(the daily backup) and `src/state_backup/upload.rs` (the upload to Manage);
tests next to each (`tests.rs`, `schedule_tests.rs`, `upload_tests.rs`) and
`nixos-appliance/tests/test_state_backup_units.py` for the timer.

## What is in a backup

Every file of the STATE partition (`/var/lib/tiaris-nest/state`): Manage
identity and credentials, the workstation cache signing key, the signed
install plan, network and SSH authority, update receipts and the state
records, plus a consistent snapshot of the SQLite database taken while the
Nest runs. Left out, because the Nest downloads or rebuilds them: the vulnix
database, netboot staging and sessions, cache quarantine, the inbox, and
everything outside STATE (the Nix store and `/var/cache/tiaris-nest`).

A backup is encrypted to a backup key (X25519 with ChaCha20-Poly1305, in
authenticated chunks). The Nest needs only the public half; keep the private
half off the Nest, like any other recovery secret. A damaged, truncated or
altered backup fails to open. Commands print names, sizes and digests only.

## Make a backup key (once, off the Nest)

```sh
tiaris-nest generate-state-backup-key \
  --private-key nest-backup.key --public-key nest-backup.pub
```

Store `nest-backup.key` (mode 0600) in the school's password manager or safe.
Copy `nest-backup.pub` to the Nest. Never copy the private key to the Nest:
the Nest never needs it, and `set-state-backup-key` refuses it.

## Automatic daily backups (on the Nest, as root, once)

```sh
sudo tiaris-nest set-state-backup-key --public-key /root/nest-backup.pub
```

This keeps the public key in STATE at `backup/recipient.pub` (0644) and
prints its fingerprint. From then on `tiaris-nest-state-backup.timer` runs
once a day at a random time in a four-hour window (and after a Nest was off
at that time) and:

- writes one encrypted backup to `/var/cache/tiaris-nest/state-backups/`
  (`<backup id>.backup` and a description `<backup id>.json` with its time,
  size and digest), outside STATE, so a backup never fills STATE;
- starts only if at least 4 GiB, or a tenth of that disk when more, stays
  free after it (it holds the Nix store and the workstation cache too);
  otherwise it records `low_disk` and tries again the next day;
- keeps the newest three backups within 2 GiB (always the newest one) and
  removes what an interrupted run left;
- records what it did in `status/state-backup-schedule.json`.

Without a key the timer does nothing and the Nest reports
`backup_key_missing`. To change the key, run the command again with the new
public key; to stop, delete `backup/recipient.pub`.

The Nest service then uploads every kept backup once to Manage, newest first,
as a signed Nest request:

```text
PUT /v1/agent/nest/state-backups/{backup_id}
Content-Type: application/octet-stream    (the encrypted file, at most 256 MiB)
X-Tiaris-Backup-Sha256: <hex>
X-Tiaris-Backup-Created-At: <RFC 3339>
X-Tiaris-Backup-Format: tiaris.nest-state-backup.v1
-> 200 {"backup_id", "sha256", "size_bytes", "stored_at"}
```

Cloudflare, in front of Manage, caps one request body at 100 MB on its Free
and Pro plans. A backup over 32 MiB therefore goes in chunks when Manage
says it accepts them (`state_backup_chunked_upload_supported` in the Nest
configuration, confirmed within the last day):

```text
POST /v1/agent/nest/state-backups/{backup_id}/upload       {sha256, size_bytes, created_at, format}
-> 200 {"state": "open"|"stored", "chunk_bytes", "chunk_count", "received_chunks", "next_chunk", "receipt"}
PUT  /v1/agent/nest/state-backups/{backup_id}/chunks/{n}   (one chunk, X-Tiaris-Chunk-Sha256: <hex>)
POST /v1/agent/nest/state-backups/{backup_id}/complete     -> 200 the receipt above
```

Every request is signed and at most one chunk (32 MiB) long; the Nest reads
one chunk at a time. It keeps no upload state of its own: a failed chunk
fails the attempt (retried with the back-off below), and the next attempt
opens the upload again and sends only the chunks Manage is missing. Manage
removes an upload nobody continued for a day; the next attempt then starts
over. A Manage that answers the open with 404 or 405 (rolled back) gets the
single `PUT` in the same attempt; smaller backups always go in one `PUT`.

The id is a UUID. Sending the same backup again gets the same answer; a 409
(Manage holds other bytes under that id) is not retried. Other failures are
retried after 1, 2, 4 … minutes, at most six hours apart. A Manage without
the route (404 or 405) is asked again once a day; until then the backups stay
on the Nest only (`backup_upload_unsupported`). A backup over 256 MiB is kept
on the Nest and not sent. What was sent is recorded in
`agent/state-backup-uploads.json`; a `data` restore keeps the replacement's
own record.

### What the Nest reports

`local_health.state_backup` is the last backup's receipt (`created_at`,
`size_bytes`, `files`), as before. `local_health.state_backup_upload` adds:

| Field | Meaning |
| --- | --- |
| `key_configured` | a backup public key is set |
| `status` | `none` (no backup kept yet), `pending`, `uploaded` (the newest is in Manage), `failing` or `unsupported` |
| `last_local` | the newest kept backup: `backup_id`, `created_at`, `size_bytes` |
| `kept` | how many backups the Nest keeps |
| `last_uploaded` | the newest backup Manage confirmed: `backup_id`, `created_at`, `size_bytes`, `stored_at` |
| `last_error` | the newest backup's last upload error code (`network`, `http_503`, `conflict`, `too_large`, `damaged`; for chunks also `upload_expired`, `upload_incomplete`, `upload_digest_mismatch`, `chunk_conflict`, …) |
| `unsupported_since` | when Manage first answered 404/405 |
| `last_run` | the last scheduled run: `at`, `outcome` (`backed_up`, `key_missing`, `low_disk`, `failed`) |

Attention codes: `backup_key_missing` (no key set) and `backup_upload_failing`
(the newest backup failed three uploads, or cannot be sent: conflict, too
large, damaged).

## Back up by hand (on the Nest, as root)

```sh
sudo tiaris-nest backup-appliance-state \
  --recipient /root/nest-backup.pub --output /var/cache/tiaris-nest/nest-$(date +%F).backup
```

The output must be a new file outside STATE; an existing file is refused
and left as it is (a second backup on the same day needs another name). Copy
it off the Nest (for example `scp` through the support certificate) and
delete the local copy. An automatic backup from
`/var/cache/tiaris-nest/state-backups/` restores the same way.
Each backup leaves `status/state-backup.json` (time, size, digest; no
secrets), which the Nest reports to Manage as `local_health.state_backup`.

## Restore onto a replacement Nest

1. Install and enrol the replacement normally from the Nest ISO (Manage's
   existing-device recovery gives it a new key and incarnation).
2. Copy the backup and the private key to it, then:

   ```sh
   sudo tiaris-nest restore-appliance-state --backup nest.backup \
     --identity nest-backup.key --dry-run
   sudo systemctl stop tiaris-nest.service
   sudo tiaris-nest restore-appliance-state --backup nest.backup --identity nest-backup.key
   sudo systemctl start tiaris-nest.service
   ```

3. Delete the private key and backup from the replacement, then set the
   backup public key again (`set-state-backup-key`): a `data` restore keeps
   the replacement's own (none).

The default `--scope data` restores the database, the workstation cache
signing key (so installed computers keep trusting the Nest's cache) and the
state records. It keeps the replacement's own Manage identity and
credentials, signed plan, network, SSH authority and update receipts, and
lists what it kept. It refuses a database the installed release cannot run
on (`rollback_database_incompatible`): install a release at least as new as
the one that made the backup.

`--scope full` restores everything into an empty STATE: the same Nest on a
new disk, from rescue media, before its first boot. It refuses a STATE that
already has files.

Nothing is written unless the whole backup opens, matches its manifest and
passes the database check; `--dry-run` stops after those checks.
