# NixOS appliance protocol V3

Protocol 4 and workstation runtime epoch 1 remain unchanged. Additive capability
`appliance_update_v3` admits current NixOS updates; `appliance_update_v1` retains
signed networking and recovery SSH. Ubuntu V1/V2 records remain readable but
new installation, update and qualification require V3 and state schema 3.

The release descriptor domain is `CYBEX-JAMES-APPLIANCE-RELEASE-V3\n` followed by
canonical sorted compact unsigned JSON. The exclusive `installer_iso_template_v3`
uses `CYBEX-JAMES-INSTALLER-ISO-TEMPLATE-V3\n` and the same canonical JSON rule.
The retained outer `appliance_release_v1` member contains the inner V3 schema;
the compatibility identity retains the historical `appliance_package_snapshot`
name. These names do not imply Ubuntu delivery.

The shared signed [golden fixture](fixtures/james-appliance-v3.json) is consumed
independently by the producer and Manage. `tools/appliance_v3.py` and
`src/appliance/release_v3.rs` enforce exact fields, canonical URLs/base64, bounded
integers, store paths, source revisions and distinct signature domains. No
unknown fields, duplicate JSON keys or mixed V2/V3 descriptors are accepted.

Closure signatures use the independently trusted named Nix key
`cybex-james-appliance-1:<release-public-key>`. A key or manifest inside an archive
never establishes trust. Both readers validate the entire bounded archive and
NAR reference graph before disk destruction/import. The embedded Manage source
is a plain-file store root whose content hash, size and Git revision are verified.

Appliance reports bind `base_os=nixos`, NixOS/nixpkgs identities, system toplevel,
positive generation, closure and migration hashes, systemd-boot version, hardware
and informational firmware Secure Boot state. Update receipts bind the exact
attempt, source/candidate generations and closure. Qualification additionally
binds device incarnation and prior installed state.

Schedules retain their v1 schema/domain. A V3 `run_now` binding contains
`attempt_id`, `release_id` and `system_closure_sha256`; it contains no legacy
snapshot field. Signed network changes/acknowledgements retain their existing
schemas. A protected committed network receipt preserves their exact signatures
and hashes across reboot; only its derived runtime files may be repaired.

See [release operations](../RELEASES.md) and
[appliance implementation](../nixos-appliance/README.md).
