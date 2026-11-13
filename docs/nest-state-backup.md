# Nest state backup and restore

How to back up a Nest's state and keys, and restore them onto a replacement.
Code: `src/state_backup.rs`; tests: `src/state_backup/tests.rs`.

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
Copy `nest-backup.pub` to the Nest.

## Back up (on the Nest, as root)

```sh
sudo tiaris-nest backup-appliance-state \
  --recipient /root/nest-backup.pub --output /var/cache/tiaris-nest/nest-$(date +%F).backup
```

The output must be a new file outside STATE. Copy it off the Nest (for
example `scp` through the support certificate) and delete the local copy.
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

3. Delete the private key and backup from the replacement.

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
