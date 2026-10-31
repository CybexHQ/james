//! Per-commit identities of the source-build preflight.
//!
//! The preflight admits local work only by reviewed content (store-normalized
//! script fingerprints, exact stock commands and builder file hashes) run by
//! exact tool providers. The content does not depend on the nixpkgs commit;
//! the providers do. A [`WorkstationBuildProfile`] carries the providers of
//! one commit: stdenv, bash, the link-farm and substitution builders, the
//! reviewed tool inputs and the security-wrapper include path.
//!
//! The compiled 74cc63f values are the built-in profile. Every check names an
//! identity by its built-in path and asks the profile for that commit's path,
//! so the built-in profile reproduces today's comparisons byte for byte.
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{
    COREDUMP_SOURCE, COREDUMP_SUBSTITUTION_TARGET, DBUS_GENERATOR_TOOL_INPUTS,
    DESKTOP_FILE_VALIDATE, FIREFOX_WRAPPER_TOOL_INPUTS, GTK_IMMODULE_TOOL_INPUTS,
    IBUS_LINK_FARM_TOOL_INPUTS, INITRD_GENERATOR_TOOL_INPUTS, LOGROTATE_CHECK_INPUTS,
    NIX_CONFIG_CHECK_INPUT, NIXOS_GENERATE_CONFIG_TOOL_INPUTS, NIXOS_SYSTEM_SETUP_HOOK,
    PERL_ENV_LINK_FARM_TOOL_INPUTS, REMARSHAL_GENERATOR_TOOL_INPUTS, SECURITY_WRAPPER_TOOL_INPUTS,
    STOCK_CONCAT_TEXT_COMMAND, STOCK_JSON_TO_TOML_COMMAND, STOCK_WRITE_TEXT_COMMAND,
    SYSTEM_PATH_POST_BUILD_TOOLS, TRUSTED_DEFAULT_BUILDER_SHA256, TRUSTED_LINK_FARM_BUILDER,
    TRUSTED_LINK_FARM_BUILDER_SHA256, TRUSTED_LINK_FARM_PERL, TRUSTED_SECURITY_WRAPPER_INCLUDE_DRV,
    TRUSTED_SECURITY_WRAPPER_INCLUDE_PATH, TRUSTED_SECURITY_WRAPPER_SHA256,
    TRUSTED_STDENV_BASH_BUILDER, TRUSTED_STDENV_BASH_DRV, TRUSTED_STDENV_FULL_OUTPUT,
    TRUSTED_STDENV_NO_CC_OUTPUT, TRUSTED_STDENV_SOURCE_SHA256, TRUSTED_STDENV_STATIC_OUTPUT,
    TRUSTED_SUBSTITUTE_BUILDER, TRUSTED_SUBSTITUTE_BUILDER_SHA256, UDEV_GENERATOR_TOOL_INPUTS,
    XKB_VALIDATION_CONFIG_DIR, XKB_VALIDATION_TOOL_INPUTS, executable_pinned_script_sha256,
    normalize_derivation_store_path, normalized_script_sha256, safe_nix_store_path,
};

/// The nixpkgs commit whose reviewed identities are compiled into Nest.
pub(crate) const BUILTIN_NIXPKGS_COMMIT: &str = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac";
/// The NixOS release of the built-in commit. Detected commits never cross it.
pub(crate) const BUILTIN_NIXOS_RELEASE: &str = "26.05";
/// `lastModified` of the built-in commit (2026-07-08). A detected commit must
/// be newer.
pub(crate) const BUILTIN_LAST_MODIFIED: i64 = 1_783_549_019;
/// NixOS names a system built from a nixpkgs flake
/// `<release>.<yyyymmdd of lastModified>.<short revision>`; `nixos-version`
/// and the system closure embed that label and the full revision. Both are
/// commit identities: a detected profile renders them back to the built-in
/// commit's before fingerprinting.
pub(crate) fn nixos_version_label(last_modified: i64, commit: &str) -> Option<String> {
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(last_modified, 0)?;
    Some(format!(
        "{BUILTIN_NIXOS_RELEASE}.{}.{}",
        date.format("%Y%m%d"),
        commit.get(..7)?
    ))
}

/// Upper bound on the local derivations of the Tiaris packages' build
/// closure one detected commit admits; a larger closure blocks the commit.
pub(crate) const MAX_TIARIS_PACKAGE_DERIVATIONS: usize = 256;

/// `nixos-init`'s executables appear in reviewed `/etc` and service-link
/// scripts; no check names the path itself, so it is a fingerprint-only
/// identity: a profile maps it so those scripts render to their reviewed
/// executable-pinned bytes.
const NIXOS_INIT: &str = "/nix/store/wy0mh9ah0alglg3ab5djg3jv6f0garyc-nixos-init-0.1.0";
const NIXOS_INIT_DRV: &str = "/nix/store/2r230dqp2pg1jpcxp3va7wvbx812zaaq-nixos-init-0.1.0.drv";

/// What a derived profile renders a built-in provider to when the detected
/// commit has its own: not a store path, so no fingerprint half can match.
const REPLACED_BUILTIN_PROVIDER: &str = "\0replaced-built-in-provider";

/// Returned for an identity a profile does not carry. It is not a store path,
/// so no derivation attribute, input or script can ever equal it.
const UNMAPPED_IDENTITY: &str = "\0unmapped-commit-identity";

/// One commit identity: a store output (or plain store source) the preflight
/// trusts by exact path, named by its built-in path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CommitIdentity {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) role: &'static str,
    pub(crate) path: &'static str,
    pub(crate) drv_path: Option<&'static str>,
}

const fn identity(role: &'static str, path: &'static str, drv: &'static str) -> CommitIdentity {
    CommitIdentity {
        role,
        path,
        drv_path: Some(drv),
    }
}

/// Every commit identity the preflight compares against, keyed by role.
/// Several roles share a store item (the gtk3 `out` output provides the icon
/// cache tool and the Firefox wrapper's `dev` input comes from the same
/// derivation); a profile maps each store item once.
pub(crate) const COMMIT_IDENTITIES: &[CommitIdentity] = &[
    identity(
        "stdenv.shell",
        TRUSTED_STDENV_BASH_BUILDER,
        TRUSTED_STDENV_BASH_DRV,
    ),
    identity(
        "stdenvNoCC",
        TRUSTED_STDENV_NO_CC_OUTPUT.path,
        TRUSTED_STDENV_NO_CC_OUTPUT.drv_path,
    ),
    identity(
        "stdenv",
        TRUSTED_STDENV_FULL_OUTPUT.path,
        TRUSTED_STDENV_FULL_OUTPUT.drv_path,
    ),
    identity(
        "pkgsStatic.stdenv",
        TRUSTED_STDENV_STATIC_OUTPUT.path,
        TRUSTED_STDENV_STATIC_OUTPUT.drv_path,
    ),
    CommitIdentity {
        role: "substitute.sh",
        path: TRUSTED_SUBSTITUTE_BUILDER,
        drv_path: None,
    },
    identity(
        "buildEnv builder.pl",
        TRUSTED_LINK_FARM_BUILDER.path,
        TRUSTED_LINK_FARM_BUILDER.drv_path,
    ),
    identity(
        "buildEnv perl",
        TRUSTED_LINK_FARM_PERL.path,
        TRUSTED_LINK_FARM_PERL.drv_path,
    ),
    identity(
        "dbus",
        DBUS_GENERATOR_TOOL_INPUTS[0].path,
        DBUS_GENERATOR_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "libxslt.bin",
        DBUS_GENERATOR_TOOL_INPUTS[1].path,
        DBUS_GENERATOR_TOOL_INPUTS[1].drv_path,
    ),
    identity(
        "findXMLCatalogs",
        DBUS_GENERATOR_TOOL_INPUTS[2].path,
        DBUS_GENERATOR_TOOL_INPUTS[2].drv_path,
    ),
    identity(
        "systemdMinimal",
        UDEV_GENERATOR_TOOL_INPUTS[0].path,
        UDEV_GENERATOR_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "remarshal",
        REMARSHAL_GENERATOR_TOOL_INPUTS[0].path,
        REMARSHAL_GENERATOR_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "makeInitrdNG",
        INITRD_GENERATOR_TOOL_INPUTS[0].path,
        INITRD_GENERATOR_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "cpio",
        INITRD_GENERATOR_TOOL_INPUTS[1].path,
        INITRD_GENERATOR_TOOL_INPUTS[1].drv_path,
    ),
    identity(
        "installShellFiles",
        NIXOS_GENERATE_CONFIG_TOOL_INPUTS[0].path,
        NIXOS_GENERATE_CONFIG_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "makeBinaryWrapper",
        PERL_ENV_LINK_FARM_TOOL_INPUTS[0].path,
        PERL_ENV_LINK_FARM_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "stdenv.cc",
        PERL_ENV_LINK_FARM_TOOL_INPUTS[1].path,
        PERL_ENV_LINK_FARM_TOOL_INPUTS[1].drv_path,
    ),
    identity(
        "ibus.dev",
        IBUS_LINK_FARM_TOOL_INPUTS[0].path,
        IBUS_LINK_FARM_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "makeShellWrapper",
        IBUS_LINK_FARM_TOOL_INPUTS[1].path,
        IBUS_LINK_FARM_TOOL_INPUTS[1].drv_path,
    ),
    identity(
        "ibus-with-plugins",
        GTK_IMMODULE_TOOL_INPUTS[0].path,
        GTK_IMMODULE_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "gtk3.dev",
        FIREFOX_WRAPPER_TOOL_INPUTS[0].path,
        FIREFOX_WRAPPER_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "xorg.lndir",
        FIREFOX_WRAPPER_TOOL_INPUTS[2].path,
        FIREFOX_WRAPPER_TOOL_INPUTS[2].drv_path,
    ),
    identity(
        "jq.dev",
        FIREFOX_WRAPPER_TOOL_INPUTS[3].path,
        FIREFOX_WRAPPER_TOOL_INPUTS[3].drv_path,
    ),
    identity(
        "dconf",
        super::DCONF_GENERATOR_TOOL_INPUTS[0].path,
        super::DCONF_GENERATOR_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "makeShellWrapper setup hook",
        NIXOS_SYSTEM_SETUP_HOOK.path,
        NIXOS_SYSTEM_SETUP_HOOK.drv_path,
    ),
    identity(
        "texinfo install-info",
        SYSTEM_PATH_POST_BUILD_TOOLS[0].path,
        SYSTEM_PATH_POST_BUILD_TOOLS[0].drv_path,
    ),
    identity(
        "shared-mime-info update-mime-database",
        SYSTEM_PATH_POST_BUILD_TOOLS[1].path,
        SYSTEM_PATH_POST_BUILD_TOOLS[1].drv_path,
    ),
    identity(
        "desktop-file-utils update-desktop-database",
        SYSTEM_PATH_POST_BUILD_TOOLS[2].path,
        SYSTEM_PATH_POST_BUILD_TOOLS[2].drv_path,
    ),
    identity(
        "gtk3 gtk-update-icon-cache",
        SYSTEM_PATH_POST_BUILD_TOOLS[3].path,
        SYSTEM_PATH_POST_BUILD_TOOLS[3].drv_path,
    ),
    identity(
        "desktop-file-utils desktop-file-validate",
        DESKTOP_FILE_VALIDATE.path,
        DESKTOP_FILE_VALIDATE.drv_path,
    ),
    identity(
        "coreutils",
        LOGROTATE_CHECK_INPUTS[0].path,
        LOGROTATE_CHECK_INPUTS[0].drv_path,
    ),
    identity(
        "logrotate",
        LOGROTATE_CHECK_INPUTS[1].path,
        LOGROTATE_CHECK_INPUTS[1].drv_path,
    ),
    identity(
        "nix",
        NIX_CONFIG_CHECK_INPUT.path,
        NIX_CONFIG_CHECK_INPUT.drv_path,
    ),
    identity(
        "systemd coredump sysctl",
        COREDUMP_SOURCE.path,
        COREDUMP_SOURCE.drv_path,
    ),
    identity(
        "systemd coredump substitution target",
        COREDUMP_SUBSTITUTION_TARGET.path,
        COREDUMP_SUBSTITUTION_TARGET.drv_path,
    ),
    identity(
        "pkgsStatic.linuxHeaders",
        SECURITY_WRAPPER_TOOL_INPUTS[0].path,
        SECURITY_WRAPPER_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "security wrapper unsecvars",
        TRUSTED_SECURITY_WRAPPER_INCLUDE_PATH,
        TRUSTED_SECURITY_WRAPPER_INCLUDE_DRV,
    ),
    identity(
        "xkbvalidate",
        XKB_VALIDATION_TOOL_INPUTS[0].path,
        XKB_VALIDATION_TOOL_INPUTS[0].drv_path,
    ),
    identity(
        "xkeyboard-config",
        XKB_VALIDATION_CONFIG_DIR.path,
        XKB_VALIDATION_CONFIG_DIR.drv_path,
    ),
    identity("nixos-init", NIXOS_INIT, NIXOS_INIT_DRV),
];

/// One identity as evaluated at a detected commit.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DerivedIdentity {
    pub(crate) path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) drv: Option<String>,
}

/// The commit identities of one nixpkgs commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkstationBuildProfile {
    nixpkgs_commit: String,
    builtin: bool,
    /// Built-in store item (`<hash>-<name>`, including `.drv` items) of every
    /// identity to this commit's store item.
    items: Arc<BTreeMap<String, String>>,
    /// The inverse for a derived profile: this commit's identity store items
    /// to their built-in items, so a script is fingerprinted as the reviewed
    /// script it renders. Empty for the built-in profile.
    reviewed_items: Arc<BTreeMap<String, String>>,
    /// This commit's full revision and NixOS version label, each with the
    /// built-in commit's. Empty for the built-in profile.
    reviewed_labels: Arc<Vec<(String, String)>>,
    /// Exact Tiaris package derivations this detected commit may compile.
    tiaris_derivations: Arc<BTreeSet<String>>,
    /// Counterpart content per derivation role (package name). Empty for the
    /// built-in profile.
    counterparts: Arc<BTreeMap<String, RoleCounterparts>>,
    /// The role of the derivation under classification
    /// ([`Self::for_derivation`]): only that role's counterparts apply.
    role: Option<String>,
}

/// One derivation role's counterpart content at a detected commit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RoleCounterparts {
    /// This commit's script fingerprint pair → the pin pair it replaces.
    fingerprints: BTreeMap<(String, String), (String, String)>,
    /// This commit's bytes → the reviewed stock command they replace.
    stock_commands: BTreeMap<String, &'static str>,
    /// Reviewed builder file hash at the pin → its hash at this commit.
    builder_files: BTreeMap<&'static str, String>,
}

/// The role of a derivation: its name up to its version, as Nix's
/// `parseDrvName` splits it (up to the first `-` followed by a digit).
/// `firefox-153.6.0esr` and `firefox-152.4.0esr` have the same role.
pub(crate) fn package_name(name: &str) -> &str {
    let bytes = name.as_bytes();
    (0..bytes.len().saturating_sub(1))
        .find(|index| bytes[*index] == b'-' && bytes[index + 1].is_ascii_digit())
        .map_or(name, |index| &name[..index])
}

/// The reviewed builder files and their commit-independent hashes at the pin.
pub(crate) const REVIEWED_BUILDER_FILES: [(&str, &str); 5] = [
    ("source-stdenv.sh", TRUSTED_STDENV_SOURCE_SHA256),
    ("default-builder.sh", TRUSTED_DEFAULT_BUILDER_SHA256),
    ("substitute.sh", TRUSTED_SUBSTITUTE_BUILDER_SHA256),
    ("wrapper.c", TRUSTED_SECURITY_WRAPPER_SHA256),
    ("builder.pl", TRUSTED_LINK_FARM_BUILDER_SHA256),
];

/// The stock nixpkgs materializer commands compared byte for byte.
pub(crate) const STOCK_COMMANDS: [&str; 3] = [
    STOCK_WRITE_TEXT_COMMAND,
    STOCK_CONCAT_TEXT_COMMAND,
    STOCK_JSON_TO_TOML_COMMAND,
];

/// Reviewed content a detected commit derives from itself: for every
/// derivation admitted at the pin in a reference configuration of the
/// shipped Tiaris source, the same derivation of the same reference evaluated
/// at the detected commit (its counterpart). Each entry pairs the
/// counterpart's content with the pin content it replaces, for that
/// derivation's role only, so every existing check applies unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewedContent {
    #[serde(default)]
    pub(crate) fingerprints: Vec<FingerprintCounterpart>,
    #[serde(default)]
    pub(crate) stock_commands: Vec<StockCommandCounterpart>,
    #[serde(default)]
    pub(crate) builder_files: Vec<BuilderFileCounterpart>,
}

/// `[normalized, executable-pinned]` fingerprints of a counterpart script at
/// the detected commit and of the pin script it replaces, for one role.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FingerprintCounterpart {
    pub(crate) role: String,
    pub(crate) commit: [String; 2],
    pub(crate) reviewed: [String; 2],
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StockCommandCounterpart {
    pub(crate) role: String,
    pub(crate) commit: String,
    pub(crate) reviewed: String,
}

/// A reviewed builder file whose bytes changed at the detected commit, as
/// one role's counterpart uses it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuilderFileCounterpart {
    pub(crate) role: String,
    pub(crate) file: String,
    pub(crate) sha256: String,
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The store item of a store path: `<hash>-<name>` without `/nix/store/` and
/// without a subpath.
pub(crate) fn store_item(path: &str) -> Option<&str> {
    let relative = path.strip_prefix("/nix/store/")?;
    let item = relative.split('/').next()?;
    (!item.is_empty()).then_some(item)
}

impl WorkstationBuildProfile {
    /// The reviewed 74cc63f profile compiled into Nest.
    pub(crate) fn builtin() -> &'static Self {
        static BUILTIN: OnceLock<WorkstationBuildProfile> = OnceLock::new();
        BUILTIN.get_or_init(|| {
            let items = COMMIT_IDENTITIES
                .iter()
                .flat_map(|identity| std::iter::once(identity.path).chain(identity.drv_path))
                .filter_map(store_item)
                .map(|item| (item.to_string(), item.to_string()))
                .collect();
            Self {
                nixpkgs_commit: BUILTIN_NIXPKGS_COMMIT.to_string(),
                builtin: true,
                items: Arc::new(items),
                reviewed_items: Arc::default(),
                reviewed_labels: Arc::default(),
                tiaris_derivations: Arc::default(),
                counterparts: Arc::default(),
                role: None,
            }
        })
    }

    /// The profile of a ready detected commit: every identity of
    /// [`COMMIT_IDENTITIES`] evaluated at `nixpkgs_commit` by the same
    /// attribute, plus the exact Tiaris package derivations Nest may compile
    /// at that commit. Fails unless every role is present with the same
    /// subpath and output shape, and the mapping is one-to-one.
    pub(crate) fn derived(
        nixpkgs_commit: &str,
        last_modified: i64,
        identities: &BTreeMap<String, DerivedIdentity>,
        tiaris_derivations: BTreeSet<String>,
    ) -> Result<Self> {
        if nixpkgs_commit.len() != 40
            || !nixpkgs_commit
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            bail!("detected nixpkgs commit must be 40 lowercase hex characters");
        }
        let (Some(label), Some(reviewed_label)) = (
            nixos_version_label(last_modified, nixpkgs_commit),
            nixos_version_label(BUILTIN_LAST_MODIFIED, BUILTIN_NIXPKGS_COMMIT),
        ) else {
            bail!("detected commit lastModified is out of range");
        };
        if last_modified <= BUILTIN_LAST_MODIFIED || nixpkgs_commit == BUILTIN_NIXPKGS_COMMIT {
            bail!("a detected commit must be newer than the built-in commit");
        }
        if identities.len() != COMMIT_IDENTITIES.len() {
            bail!("derived build profile must carry exactly the reviewed identities");
        }
        if tiaris_derivations.len() > MAX_TIARIS_PACKAGE_DERIVATIONS
            || tiaris_derivations
                .iter()
                .any(|path| normalize_derivation_store_path(path).as_deref() != Some(path))
        {
            bail!("derived build profile lists invalid Tiaris package derivations");
        }
        let mut items = BTreeMap::<String, String>::new();
        let mut reviewed_items = BTreeMap::<String, String>::new();
        let mut map = |reviewed: &str, derived: &str| -> Result<()> {
            let (Some(reviewed_item), Some(derived_item)) =
                (store_item(reviewed), store_item(derived))
            else {
                bail!("derived identity is not a store path");
            };
            let reviewed_rest = &reviewed["/nix/store/".len() + reviewed_item.len()..];
            let derived_rest = &derived["/nix/store/".len() + derived_item.len()..];
            if !safe_nix_store_path(derived)
                || reviewed_rest != derived_rest
                || reviewed_item.ends_with(".drv") != derived_item.ends_with(".drv")
            {
                bail!("derived identity {derived} does not have the reviewed shape");
            }
            let previous = items.insert(reviewed_item.to_string(), derived_item.to_string());
            let reverse =
                reviewed_items.insert(derived_item.to_string(), reviewed_item.to_string());
            if previous.is_some_and(|previous| previous != derived_item)
                || reverse.is_some_and(|reverse| reverse != reviewed_item)
            {
                bail!("derived identities do not map store items one to one");
            }
            Ok(())
        };
        for identity in COMMIT_IDENTITIES {
            let Some(derived) = identities.get(identity.role) else {
                bail!("derived build profile lacks {}", identity.role);
            };
            map(identity.path, &derived.path)?;
            match (identity.drv_path, derived.drv.as_deref()) {
                (Some(reviewed), Some(derived)) => map(reviewed, derived)?,
                (None, None) => {}
                _ => bail!(
                    "derived identity {} has the wrong derivation shape",
                    identity.role
                ),
            }
        }
        Ok(Self {
            nixpkgs_commit: nixpkgs_commit.to_string(),
            builtin: false,
            items: Arc::new(items),
            reviewed_items: Arc::new(reviewed_items),
            reviewed_labels: Arc::new(vec![
                (
                    nixpkgs_commit.to_string(),
                    BUILTIN_NIXPKGS_COMMIT.to_string(),
                ),
                (label, reviewed_label),
            ]),
            tiaris_derivations: Arc::new(tiaris_derivations),
            counterparts: Arc::default(),
            role: None,
        })
    }

    /// The derived profile with the reviewed content its counterparts give
    /// it, per derivation role. Every entry must be well formed and
    /// unambiguous within its role: one commit fingerprint pair or command
    /// maps to exactly one reviewed one, a reviewed command is a stock
    /// command and a builder file is one of the reviewed files.
    pub(crate) fn with_reviewed_content(mut self, content: &ReviewedContent) -> Result<Self> {
        if self.builtin {
            bail!("the built-in profile has no counterparts");
        }
        let valid_role = |role: &str| {
            !role.is_empty()
                && role.len() <= 211
                && role
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
        };
        let mut counterparts = BTreeMap::<String, RoleCounterparts>::new();
        for entry in &content.fingerprints {
            if !valid_role(&entry.role)
                || !entry
                    .commit
                    .iter()
                    .chain(&entry.reviewed)
                    .all(|value| is_sha256_hex(value))
            {
                bail!("counterpart fingerprints must name a role and be sha256 hex");
            }
            let key = (entry.commit[0].clone(), entry.commit[1].clone());
            let value = (entry.reviewed[0].clone(), entry.reviewed[1].clone());
            if counterparts
                .entry(entry.role.clone())
                .or_default()
                .fingerprints
                .insert(key, value.clone())
                .is_some_and(|previous| previous != value)
            {
                bail!("a counterpart fingerprint maps to two reviewed scripts");
            }
        }
        for entry in &content.stock_commands {
            let Some(reviewed) = STOCK_COMMANDS
                .iter()
                .find(|command| **command == entry.reviewed)
            else {
                bail!("a counterpart command does not replace a stock command");
            };
            if !valid_role(&entry.role)
                || counterparts
                    .entry(entry.role.clone())
                    .or_default()
                    .stock_commands
                    .insert(entry.commit.clone(), reviewed)
                    .is_some_and(|previous| previous != *reviewed)
            {
                bail!("a counterpart command maps to two stock commands");
            }
        }
        for entry in &content.builder_files {
            let Some((_, reviewed)) = REVIEWED_BUILDER_FILES
                .iter()
                .find(|(file, _)| *file == entry.file)
            else {
                bail!("{} is not a reviewed builder file", entry.file);
            };
            if !valid_role(&entry.role) || !is_sha256_hex(&entry.sha256) {
                bail!("counterpart builder file must name a role and be sha256 hex");
            }
            counterparts
                .entry(entry.role.clone())
                .or_default()
                .builder_files
                .insert(reviewed, entry.sha256.clone());
        }
        self.counterparts = Arc::new(counterparts);
        Ok(self)
    }

    /// The profile as it applies to one derivation: only the counterpart
    /// content of that derivation's role, so content derived for one role
    /// cannot admit another derivation.
    pub(crate) fn for_derivation(&self, drv_path: &str) -> Self {
        let mut scoped = self.clone();
        if !self.builtin {
            scoped.role = Some(self.derivation_role(drv_path));
        }
        scoped
    }

    /// The role of a derivation at this profile's commit: its name with the
    /// version label rendered back, up to its version.
    pub(crate) fn derivation_role(&self, drv_path: &str) -> String {
        let name = crate::nix_log::derivation_display_name(drv_path);
        package_name(&self.reviewed_script(&name)).to_string()
    }

    fn role_counterparts(&self) -> Option<&RoleCounterparts> {
        self.counterparts.get(self.role.as_deref()?)
    }

    /// This commit's hash for the reviewed builder file with the pin hash
    /// `reviewed`, when this role's counterpart uses a changed copy of it.
    pub(crate) fn builder_file_counterpart(&self, reviewed: &str) -> Option<&str> {
        self.role_counterparts()?
            .builder_files
            .get(reviewed)
            .map(String::as_str)
    }

    /// Every counterpart hash of a reviewed builder file, in any role: for
    /// checks that precede per-derivation classification (fetching the
    /// buildEnv helper). Its users are then checked in their own role.
    pub(crate) fn any_builder_file_counterparts(&self, reviewed: &str) -> Vec<&str> {
        self.counterparts
            .values()
            .filter_map(|role| role.builder_files.get(reviewed).map(String::as_str))
            .collect()
    }

    /// The reviewed stock command `command` is, or replaces in this role.
    pub(crate) fn stock_command<'a>(&'a self, command: &'a str) -> &'a str {
        self.role_counterparts()
            .and_then(|role| role.stock_commands.get(command).copied())
            .unwrap_or(command)
    }

    /// The profile a build job's preflight uses for the commit it was
    /// admitted at: the built-in profile at the built-in commit, the ready
    /// detected commit's persisted profile at that commit, and none for any
    /// other commit or no commit. There is no fallback.
    pub(crate) fn for_build<'a>(
        admitted_commit: Option<&str>,
        detected: Option<&'a WorkstationBuildProfile>,
    ) -> Option<&'a Self> {
        let commit = admitted_commit?;
        if commit == BUILTIN_NIXPKGS_COMMIT {
            return Some(Self::builtin());
        }
        detected.filter(|profile| !profile.builtin && profile.nixpkgs_commit() == commit)
    }

    /// Whether `drv_path` is one of the Tiaris packages (workstation agent,
    /// gsettings helpers, patched Avahi and their uncached dependencies)
    /// evaluated from the shipped Tiaris source at this detected commit.
    /// The built-in profile admits none: its outputs are signed seeds.
    pub(crate) fn admits_tiaris_package(&self, drv_path: &str) -> bool {
        self.tiaris_derivations.contains(drv_path)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn nixpkgs_commit(&self) -> &str {
        &self.nixpkgs_commit
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_builtin(&self) -> bool {
        self.builtin
    }

    /// This commit's path for the identity named by its built-in `reviewed`
    /// path (a store item, optionally followed by a subpath). A path that is
    /// not one of [`COMMIT_IDENTITIES`] has no counterpart and never matches.
    pub(crate) fn path<'a>(&'a self, reviewed: &'a str) -> Cow<'a, str> {
        let Some(item) = store_item(reviewed) else {
            return Cow::Borrowed(UNMAPPED_IDENTITY);
        };
        match self.items.get(item) {
            Some(mapped) if mapped == item => Cow::Borrowed(reviewed),
            Some(mapped) => {
                let subpath = &reviewed["/nix/store/".len() + item.len()..];
                Cow::Owned(format!("/nix/store/{mapped}{subpath}"))
            }
            None => Cow::Borrowed(UNMAPPED_IDENTITY),
        }
    }

    /// Whether `actual` is this commit's path for the identity `reviewed`.
    pub(crate) fn is(&self, actual: &str, reviewed: &str) -> bool {
        actual == self.path(reviewed)
    }

    /// The script with this commit's identity store items, revision and NixOS
    /// version label replaced by the built-in commit's. Everything else,
    /// including every other store path, is unchanged, so the result is the
    /// reviewed script only when the commit renders the same script with its
    /// own tool providers.
    pub(crate) fn reviewed_script<'a>(&self, script: &'a str) -> Cow<'a, str> {
        if self.builtin {
            return Cow::Borrowed(script);
        }
        let mut rendered = self.reviewed_store_items(script);
        for (label, reviewed) in self.reviewed_labels.iter() {
            if rendered.contains(label.as_str()) {
                rendered = Cow::Owned(rendered.replace(label.as_str(), reviewed));
            }
        }
        rendered
    }

    fn reviewed_store_items<'a>(&self, script: &'a str) -> Cow<'a, str> {
        if !script.contains("/nix/store/") {
            return Cow::Borrowed(script);
        }
        let bytes = script.as_bytes();
        let mut rendered = String::with_capacity(script.len());
        let mut copied = 0;
        let mut index = 0;
        const PREFIX: &str = "/nix/store/";
        while let Some(offset) = script[index..].find(PREFIX) {
            let item_start = index + offset + PREFIX.len();
            let mut item_end = item_start;
            while item_end < bytes.len()
                && (bytes[item_end].is_ascii_alphanumeric()
                    || matches!(bytes[item_end], b'.' | b'_' | b'+' | b'-'))
            {
                item_end += 1;
            }
            let item = &script[item_start..item_end];
            if let Some(reviewed) = self.reviewed_items.get(item) {
                rendered.push_str(&script[copied..item_start]);
                rendered.push_str(reviewed);
                copied = item_end;
            } else if self
                .items
                .get(item)
                .is_some_and(|mapped| mapped.as_str() != item)
            {
                // A built-in provider this commit replaced. Rendering it
                // unchanged would make it fingerprint like the commit's own
                // provider; it renders to text no reviewed script contains.
                rendered.push_str(&script[copied..item_start - PREFIX.len()]);
                rendered.push_str(REPLACED_BUILTIN_PROVIDER);
                copied = item_end;
            }
            index = item_end.max(item_start);
        }
        rendered.push_str(&script[copied..]);
        Cow::Owned(rendered)
    }

    /// `(store-normalized, executable-pinned)` fingerprints of the reviewed
    /// script this commit's script renders, or of the pin script it is the
    /// counterpart of. Both halves come from one script, so a counterpart
    /// never mixes with another script's half.
    pub(crate) fn fingerprints(&self, script: &str) -> (String, String) {
        let rendered = self.reviewed_script(script);
        let pair = (
            normalized_script_sha256(&rendered),
            executable_pinned_script_sha256(&rendered),
        );
        match self
            .role_counterparts()
            .and_then(|role| role.fingerprints.get(&pair))
        {
            Some(reviewed) => reviewed.clone(),
            None => pair,
        }
    }

    /// Store-normalized half of [`Self::fingerprints`].
    pub(crate) fn normalized_sha256(&self, script: &str) -> String {
        self.fingerprints(script).0
    }

    /// Executable-pinned half of [`Self::fingerprints`]: an executable from
    /// any provider other than this commit's identity for the reviewed one
    /// changes it.
    pub(crate) fn executable_sha256(&self, script: &str) -> String {
        self.fingerprints(script).1
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        BINARY_WRAPPER_TOOL_INPUTS, DCONF_GENERATOR_TOOL_INPUTS, JQ_GENERATOR_TOOL_INPUTS,
        ReviewedStoreOutput, ReviewedToolInput, SHELL_WRAPPER_TOOL_INPUTS, TRUSTED_STDENV_NO_CC,
        TRUSTED_STDENV_NO_CC_DRV,
    };
    use super::*;

    const ALL_TOOL_INPUTS: &[&[ReviewedToolInput]] = &[
        DBUS_GENERATOR_TOOL_INPUTS,
        UDEV_GENERATOR_TOOL_INPUTS,
        REMARSHAL_GENERATOR_TOOL_INPUTS,
        INITRD_GENERATOR_TOOL_INPUTS,
        NIXOS_GENERATE_CONFIG_TOOL_INPUTS,
        BINARY_WRAPPER_TOOL_INPUTS,
        PERL_ENV_LINK_FARM_TOOL_INPUTS,
        IBUS_LINK_FARM_TOOL_INPUTS,
        GTK_IMMODULE_TOOL_INPUTS,
        SHELL_WRAPPER_TOOL_INPUTS,
        FIREFOX_WRAPPER_TOOL_INPUTS,
        DCONF_GENERATOR_TOOL_INPUTS,
        JQ_GENERATOR_TOOL_INPUTS,
        SECURITY_WRAPPER_TOOL_INPUTS,
        XKB_VALIDATION_TOOL_INPUTS,
    ];

    fn reviewed_outputs() -> Vec<ReviewedStoreOutput> {
        let mut outputs = vec![
            TRUSTED_STDENV_NO_CC_OUTPUT,
            TRUSTED_STDENV_FULL_OUTPUT,
            TRUSTED_STDENV_STATIC_OUTPUT,
            TRUSTED_LINK_FARM_BUILDER,
            TRUSTED_LINK_FARM_PERL,
            NIXOS_SYSTEM_SETUP_HOOK,
            DESKTOP_FILE_VALIDATE,
            NIX_CONFIG_CHECK_INPUT,
            COREDUMP_SOURCE,
            COREDUMP_SUBSTITUTION_TARGET,
            XKB_VALIDATION_CONFIG_DIR,
        ];
        outputs.extend_from_slice(SYSTEM_PATH_POST_BUILD_TOOLS);
        outputs.extend_from_slice(LOGROTATE_CHECK_INPUTS);
        outputs
    }

    #[test]
    fn builtin_profile_is_the_compiled_pin_and_maps_every_identity_to_itself() {
        let profile = WorkstationBuildProfile::builtin();
        assert_eq!(profile.nixpkgs_commit(), BUILTIN_NIXPKGS_COMMIT);
        assert!(profile.is_builtin());
        assert!(std::ptr::eq(
            WorkstationBuildProfile::for_build(Some(BUILTIN_NIXPKGS_COMMIT), None).unwrap(),
            profile
        ));
        assert!(WorkstationBuildProfile::for_build(None, None).is_none());
        assert!(WorkstationBuildProfile::for_build(Some(&"1".repeat(40)), None).is_none());

        // Every path a preflight check asks the profile for is an identity,
        // and the built-in profile returns the compiled bytes unchanged.
        let mut reviewed = vec![
            TRUSTED_STDENV_BASH_BUILDER,
            TRUSTED_STDENV_BASH_DRV,
            TRUSTED_STDENV_NO_CC,
            TRUSTED_STDENV_NO_CC_DRV,
            TRUSTED_SUBSTITUTE_BUILDER,
            TRUSTED_SECURITY_WRAPPER_INCLUDE_PATH,
            TRUSTED_SECURITY_WRAPPER_INCLUDE_DRV,
        ];
        for output in reviewed_outputs() {
            reviewed.extend([output.path, output.drv_path]);
        }
        for inputs in ALL_TOOL_INPUTS {
            for input in *inputs {
                reviewed.extend([input.path, input.drv_path]);
            }
        }
        for identity in COMMIT_IDENTITIES {
            reviewed.push(identity.path);
            reviewed.extend(identity.drv_path);
        }
        for path in reviewed {
            assert!(
                matches!(profile.path(path), Cow::Borrowed(mapped) if mapped == path),
                "{path} is not a built-in identity"
            );
            assert!(profile.is(path, path));
        }

        let script = format!("exec {TRUSTED_STDENV_BASH_BUILDER}\n");
        assert!(matches!(profile.reviewed_script(&script), Cow::Borrowed(_)));
        assert_eq!(
            profile.normalized_sha256(&script),
            normalized_script_sha256(&script)
        );
        assert_eq!(
            profile.executable_sha256(&script),
            executable_pinned_script_sha256(&script)
        );
    }

    #[test]
    fn paths_outside_the_identity_table_never_match() {
        let profile = WorkstationBuildProfile::builtin();
        let unknown = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bash-5.3p9/bin/bash";
        assert!(!profile.is(unknown, unknown));
        assert!(!profile.is("", ""));
        assert!(!profile.is("relative", "relative"));
        assert_eq!(profile.path(unknown), UNMAPPED_IDENTITY);
    }

    #[test]
    fn commit_identities_are_unique_safe_store_paths() {
        let mut roles = std::collections::HashSet::new();
        for identity in COMMIT_IDENTITIES {
            assert!(
                roles.insert(identity.role),
                "duplicate role {}",
                identity.role
            );
            assert!(safe_nix_store_path(identity.path));
            if let Some(drv_path) = identity.drv_path {
                assert!(normalize_derivation_store_path(drv_path).is_some());
            }
        }
    }
}
