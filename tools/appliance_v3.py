"""Strict public NixOS appliance contracts shared by producer operations.

Historical Ubuntu descriptors have their own reader in james-release.py. These
functions never coerce one descriptor generation into another.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import urlsplit


SCHEMA = "cybex.james.appliance-release.v3"
DOMAIN = "CYBEX-JAMES-APPLIANCE-RELEASE-V3"
TEMPLATE_DOMAIN = "CYBEX-JAMES-INSTALLER-ISO-TEMPLATE-V3"
DELIVERY = "system-closure-v1"
MAX_ARCHIVE_BYTES = 4 * 1024**3
NIX_BASE32 = "0123456789abcdfghijklmnpqrsvwxyz"
STORE_PATH = re.compile(r"/nix/store/[" + NIX_BASE32 + r"]{32}-[A-Za-z0-9+._?=-]+")
VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
ANCHORS = {"kernel", "linux-firmware", "nix", "cybex-james", "systemd-boot"}
DESCRIPTOR_FIELDS = {
    "schema", "release_id", "source_revision", "base_os", "base_os_version",
    "nixpkgs_revision", "manage_source_revision", "system_toplevel", "system_closure",
    "required_system_versions", "sqlite_migrations_sha256", "minimum_protocol",
    "minimum_state_schema", "rollback_compatible", "release_notes", "signature",
}
TEMPLATE_ORDER = (
    "version", "architecture", "base_os", "base_os_version", "url", "size_bytes",
    "template_sha256", "personalization_offset", "personalization_size",
    "placeholder_sha256", "provisioning_public_keys", "package_delivery", "manage_origin",
)


class ContractError(ValueError):
    """Public-safe contract failure, never including signing material."""


def fail(message):
    raise ContractError(message)


def exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        fail(label + " fields are not the exact supported set")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("JSON contains a duplicate member")
        value[key] = item
    return value


def hex_value(value, length, label):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{" + str(length) + "}", value):
        fail(label + " is not canonical lowercase hexadecimal")
    return value


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        fail(label + " is outside its bound")
    return value


def token(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+._:~=-]{1,256}", value):
        fail(label + " is not a bounded version token")
    return value


def store_path(value):
    if not isinstance(value, str) or len(value) > 255 or STORE_PATH.fullmatch(value) is None:
        fail("NixOS system toplevel is not one canonical store path")
    return value


def https_url(value, label):
    if (not isinstance(value, str) or not 1 <= len(value) <= 2048
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)):
        fail(label + " is not a bounded canonical URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail(label + " is not a valid URL")
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or "?" in value or "#" in value or "\\" in value
            or "%" in value or parsed.netloc != parsed.netloc.lower()
            or port == 443 or parsed.geturl() != value
            or "//" in parsed.path
            or any(part in {".", ".."} for part in parsed.path.split("/"))):
        fail(label + " must be canonical HTTPS without credentials, query or fragment")
    return parsed


def base64_bytes(value, size, label):
    try:
        body = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
    except (ValueError, TypeError):
        fail(label + " is not canonical Base64")
    if len(body) != size or base64.b64encode(body).decode() != value:
        fail(label + " is not canonical Base64")
    return body


def archive_name(version):
    return f"cybex-james-appliance-closure-{version}-x86_64-linux.tar.zst"


def validate_descriptor(value, version=None, *, signed=True):
    exact(value, DESCRIPTOR_FIELDS if signed else DESCRIPTOR_FIELDS - {"signature"},
          "NixOS appliance release")
    if (value["schema"] != SCHEMA or value["base_os"] != "nixos"
            or not isinstance(value["release_id"], str)
            or VERSION.fullmatch(value["release_id"]) is None
            or version is not None and value["release_id"] != version
            or value["minimum_protocol"] != 4 or type(value["minimum_protocol"]) is not int
            or value["minimum_state_schema"] != 3 or type(value["minimum_state_schema"]) is not int
            or value["rollback_compatible"] is not True):
        fail("NixOS appliance release contract is incompatible")
    if not isinstance(value["base_os_version"], str) or not re.fullmatch(r"[0-9]{2}\.(05|11)", value["base_os_version"]):
        fail("NixOS release must use the release YY.MM identity")
    for field in ("source_revision", "nixpkgs_revision", "manage_source_revision"):
        hex_value(value[field], 40, field)
    hex_value(value["sqlite_migrations_sha256"], 64, "SQLite migration inventory digest")
    store_path(value["system_toplevel"])
    anchors = exact(value["required_system_versions"], ANCHORS, "NixOS system anchors")
    for name, version_value in anchors.items():
        token(version_value, name)
    if anchors["cybex-james"] != value["release_id"]:
        fail("James system anchor must match its release")
    closure = exact(value["system_closure"], {"url", "sha256", "size_bytes"}, "NixOS closure")
    url = https_url(closure["url"], "NixOS closure URL")
    if url.path.rsplit("/", 1)[-1] != archive_name(value["release_id"]):
        fail("NixOS closure URL must bind its exact release filename")
    hex_value(closure["sha256"], 64, "NixOS closure digest")
    integer(closure["size_bytes"], 1, MAX_ARCHIVE_BYTES, "NixOS closure size")
    https_url(value["release_notes"], "NixOS release notes")
    if signed:
        base64_bytes(value["signature"], 64, "NixOS release signature")
    return value


def descriptor_message(value):
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    validate_descriptor(unsigned, signed=False)
    return DOMAIN.encode() + b"\n" + canonical(unsigned)


def validate_template(value, version=None, *, signed=True):
    exact(value, set(TEMPLATE_ORDER) | ({"signature"} if signed else set()), "NixOS ISO template")
    if (not isinstance(value["version"], str) or VERSION.fullmatch(value["version"]) is None
            or version is not None and value["version"] != version
            or value["architecture"] != "x86_64-linux" or value["base_os"] != "nixos"
            or value["package_delivery"] != DELIVERY
            or not isinstance(value["base_os_version"], str)
            or re.fullmatch(r"[0-9]{2}\.(05|11)", value["base_os_version"]) is None):
        fail("NixOS ISO template contract is incompatible")
    url = https_url(value["url"], "NixOS ISO URL")
    if url.path.rsplit("/", 1)[-1] != f"cybex-james-appliance-template-{value['version']}-x86_64-linux.iso":
        fail("NixOS ISO URL must bind its exact release filename")
    size = integer(value["size_bytes"], 8192, 16 * 1024**3, "NixOS ISO size")
    integer(value["personalization_offset"], 0, size - 8192, "NixOS ISO slot offset")
    integer(value["personalization_size"], 8192, 8192, "NixOS ISO slot size")
    hex_value(value["template_sha256"], 64, "NixOS ISO digest")
    if value["placeholder_sha256"] != hashlib.sha256(bytes(8192)).hexdigest():
        fail("NixOS ISO slot must be exactly 8192 zero bytes")
    keys = value["provisioning_public_keys"]
    if (not isinstance(keys, list) or not 1 <= len(keys) <= 8
            or any(not isinstance(key, str) for key in keys)
            or keys != sorted(set(keys))):
        fail("NixOS ISO provisioning keys must be sorted and unique")
    for key in keys:
        base64_bytes(key, 32, "NixOS ISO provisioning public key")
    origin = https_url(value["manage_origin"], "NixOS ISO Management origin")
    if origin.path:
        fail("NixOS ISO Management origin must not have a path")
    if signed:
        base64_bytes(value["signature"], 64, "NixOS ISO signature")
    return value


def template_message(value):
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    validate_template(unsigned, signed=False)
    lines = [TEMPLATE_DOMAIN]
    for field in TEMPLATE_ORDER:
        item = unsigned[field]
        lines.append(",".join(item) if field == "provisioning_public_keys" else str(item))
    return ("\n".join(lines) + "\n").encode()
