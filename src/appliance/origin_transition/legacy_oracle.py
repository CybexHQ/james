#!/usr/bin/env python3
"""Test-only oracle: no production imports of this harness, no legacy edits."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import platform
import sys

MODULE = Path(__file__).resolve().parent
ROOT = MODULE.parents[2]
spec = importlib.util.spec_from_file_location("nest_release", ROOT / "tools/nest-release.py")
assert spec is not None and spec.loader is not None
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


def verify_cases(cases):
    for case in cases:
        fixture, side = case["fixture"], case["side"]
        public_der = legacy.ED25519_PUBLIC_DER_PREFIX + base64.b64decode(fixture["public_key"])
        pair = fixture["pair"]
        assert base64.b64decode(fixture["pair_bytes"]) == legacy._canonical_json_body(pair)
        legacy._self_verify(public_der, base64.b64decode(pair["signature"]),
                            b"TIARIS-NEST-ORIGIN-TRANSITION-V1\n" +
                            legacy._canonical_json_body({k: v for k, v in pair.items() if k != "signature"}))
        for release_side in ("source", "target"):
            release = fixture[release_side]
            manifest, compatibility = release["manifest"], release["compatibility"]
            mb, cb = (base64.b64decode(release[k]) for k in ("manifest_bytes", "compatibility_bytes"))
            assert mb == legacy._canonical_json_body(manifest)
            assert cb == legacy._canonical_json_body(compatibility)
            assert hashlib.sha256(mb).hexdigest() == compatibility["release_manifest"]["sha256"]
            assert hashlib.sha256(cb).hexdigest() == pair[release_side]["compatibility_sha256"]
            assert pair[release_side]["manifest"] == compatibility["release_manifest"]
            legacy._self_verify(public_der, base64.b64decode(compatibility["signature"]),
                                legacy._release_compatibility_message(
                                    {k: v for k, v in compatibility.items() if k != "signature"}))
            iso = manifest["installer_iso_template_v3"]
            assert iso["manage_origin"] == pair[release_side]["manage_origin"]
            assert iso["manage_origin"] == compatibility["artifacts"]["appliance_iso_template"]["manage_origin"]
            # Verify the changed ISO independently, even when the semantic
            # validator below rejects before yielding its signature messages.
            legacy._self_verify(public_der, base64.b64decode(iso["signature"]),
                                legacy._installer_iso_template_message(
                                    {k: v for k, v in iso.items() if k != "signature"}))
            try:
                _, _, messages = legacy._release_manifest_artifact_identities(manifest)
            except legacy.ReleaseError as error:
                assert release_side == side and not case["accepted"], str(error)
                assert "weak Ed25519 key" in str(error), str(error)
            else:
                assert release_side != side or case["accepted"], "legacy accepted denied ISO key"
                legacy._verify_signed_messages(public_der, messages)
    print(json.dumps({"python": platform.python_version(), "signed_key_cases": len(cases),
                      "rejected": sum(not case["accepted"] for case in cases)}))


def profile_origin(origin):
    # Explicit transition-only exclusions precede the unmodified validator;
    # neither the interpreter version nor its formatter decides mapped policy.
    if "%" in origin:
        raise ValueError("scoped origin outside transition profile")
    if origin.startswith("https://["):
        host = origin[len("https://["):].split("]", 1)[0]
        if ipaddress.IPv6Address(host).ipv4_mapped is not None:
            raise ValueError("mapped origin outside transition profile")
    return legacy._validate_manage_origin(origin)


def accepts(validator, origin):
    try:
        result = validator(origin)
    except (ValueError, legacy.ReleaseError):
        return False
    assert result == origin, "validator normalized signed text"
    return True


def verify_profile():
    profile_bytes = (MODULE / "origin-profile-v1.json").read_bytes()
    assert hashlib.sha256(profile_bytes).hexdigest() == "fe129ccdfe5ffa633df3a46a7a18eca940c1e3f68ff049b457ee0a49d86ef956"
    vectors = json.loads(profile_bytes)["vectors"]
    for vector in vectors:
        origin, expected = vector["origin"], vector["accepted"]
        assert accepts(profile_origin, origin) == expected, origin
        if expected:
            # Positive subset proof against the actual authoritative parser,
            # not only against the independent profile wrapper.
            assert legacy._validate_manage_origin(origin) == origin, origin
    differing = ["https://[::ffff:c000:201]", "https://[::ffff:192.0.2.1]",
                 "https://[fe80::1%eth0]", "https://[fe80::1%25eth0]"]
    print(json.dumps({"python": platform.python_version(), "profile_vectors": len(vectors),
                      "accepted": sum(v["accepted"] for v in vectors),
                      "legacy_runtime_observations": {
                          origin: accepts(legacy._validate_manage_origin, origin) for origin in differing}}))


if __name__ == "__main__":
    verify_profile()
    if "--profile-only" not in sys.argv:
        verify_cases(json.load(sys.stdin))
