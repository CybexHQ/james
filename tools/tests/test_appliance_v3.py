from copy import deepcopy
import base64
import json
from pathlib import Path
import runpy
import unittest


ROOT = Path(__file__).resolve().parents[2]
API = runpy.run_path(str(ROOT / "tools/james-release.py"))
V3 = API["appliance_v3"]
FIXTURE = json.loads((ROOT / "protocol/fixtures/james-appliance-v3.json").read_text())


class ApplianceV3Tests(unittest.TestCase):
    def test_shared_release_and_iso_signature_vectors(self):
        public = API["ED25519_PUBLIC_DER_PREFIX"] + base64.b64decode(FIXTURE["public_key"])
        for field, message_field, callback in (
            ("appliance_release", "appliance_release_message_base64", API["_appliance_release_message"]),
            ("installer_iso_template", "installer_iso_template_message_base64", API["_installer_iso_template_message"]),
        ):
            with self.subTest(field=field):
                message = callback(FIXTURE[field])
                self.assertEqual(message, base64.b64decode(FIXTURE[message_field]))
                API["_self_verify"](public, base64.b64decode(FIXTURE[field]["signature"]), message)
                with self.assertRaises(API["ReleaseError"]):
                    API["_self_verify"](public, base64.b64decode(FIXTURE[field]["signature"]), message + b"\n")

    def test_release_binds_closure_source_and_migrations(self):
        public = API["ED25519_PUBLIC_DER_PREFIX"] + base64.b64decode(FIXTURE["public_key"])
        original = FIXTURE["appliance_release"]
        for key, value in (
            ("source_revision", "f" * 40), ("nixpkgs_revision", "f" * 40),
            ("manage_source_revision", "f" * 40), ("sqlite_migrations_sha256", "f" * 64),
            ("system_toplevel", "/nix/store/" + "1" * 32 + "-different"),
            ("system_closure", {**original["system_closure"], "sha256": "f" * 64}),
        ):
            with self.subTest(key=key):
                modified = {**original, key: value}
                with self.assertRaises(API["ReleaseError"]):
                    API["_self_verify"](public, base64.b64decode(original["signature"]),
                                        V3.descriptor_message(modified))

    def test_legacy_fields_unknown_fields_and_missing_anchors_fail(self):
        for key in ("ubuntu_snapshot_id", "cybex_repository_snapshot", "required_package_versions", "expected_kernel", "other"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                V3.validate_descriptor({**FIXTURE["appliance_release"], key: "legacy"})
        for key in V3.DESCRIPTOR_FIELDS:
            modified = deepcopy(FIXTURE["appliance_release"])
            del modified[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                V3.validate_descriptor(modified)
        modified = deepcopy(FIXTURE["appliance_release"])
        del modified["required_system_versions"]["nix"]
        with self.assertRaises(ValueError):
            V3.validate_descriptor(modified)

    def test_integrity_and_path_bounds(self):
        for size in (0, -1, True, 2**32 + 1, 1.0, "100"):
            modified = deepcopy(FIXTURE["appliance_release"])
            modified["system_closure"]["size_bytes"] = size
            with self.subTest(size=size), self.assertRaises(ValueError):
                V3.validate_descriptor(modified)
        for path in ("/nix/store/../../etc", "/nix/store/" + "e" * 32 + "-system",
                     FIXTURE["appliance_release"]["system_toplevel"] + "/bin"):
            modified = {**FIXTURE["appliance_release"], "system_toplevel": path}
            with self.subTest(path=path), self.assertRaises(ValueError):
                V3.validate_descriptor(modified)

    def test_template_generation_and_slot_are_exact(self):
        for key, value in (("package_delivery", "network-snapshot-v1"), ("base_os", "ubuntu"),
                           ("personalization_size", 8191), ("personalization_offset", 2**64),
                           ("placeholder_sha256", "0" * 64), ("manage_origin", "http://console.example")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                V3.validate_template({**FIXTURE["installer_iso_template"], key: value})

    def test_duplicate_json_members_are_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"schema":"one","schema":"two"}', object_pairs_hook=V3.unique_object)


if __name__ == "__main__":
    unittest.main()
