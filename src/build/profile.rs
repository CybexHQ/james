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
    sync::OnceLock,
};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{
    COREDUMP_SOURCE, COREDUMP_SUBSTITUTION_TARGET, DBUS_GENERATOR_TOOL_INPUTS,
    DESKTOP_FILE_VALIDATE, FIREFOX_WRAPPER_TOOL_INPUTS, GTK_IMMODULE_TOOL_INPUTS,
    IBUS_LINK_FARM_TOOL_INPUTS, INITRD_GENERATOR_TOOL_INPUTS, LOGROTATE_CHECK_INPUTS,
    NIX_CONFIG_CHECK_INPUT, NIXOS_GENERATE_CONFIG_TOOL_INPUTS, NIXOS_SYSTEM_SETUP_HOOK,
    PERL_ENV_LINK_FARM_TOOL_INPUTS, REMARSHAL_GENERATOR_TOOL_INPUTS, SECURITY_WRAPPER_TOOL_INPUTS,
    SYSTEM_PATH_POST_BUILD_TOOLS, TRUSTED_LINK_FARM_BUILDER, TRUSTED_LINK_FARM_PERL,
    TRUSTED_SECURITY_WRAPPER_INCLUDE_DRV, TRUSTED_SECURITY_WRAPPER_INCLUDE_PATH,
    TRUSTED_STDENV_BASH_BUILDER, TRUSTED_STDENV_BASH_DRV, TRUSTED_STDENV_FULL_OUTPUT,
    TRUSTED_STDENV_NO_CC_OUTPUT, TRUSTED_STDENV_STATIC_OUTPUT, TRUSTED_SUBSTITUTE_BUILDER,
    UDEV_GENERATOR_TOOL_INPUTS, XKB_VALIDATION_CONFIG_DIR, XKB_VALIDATION_TOOL_INPUTS,
    executable_pinned_script_sha256, normalize_derivation_store_path, normalized_script_sha256,
    safe_nix_store_path,
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

/// Upper bound on the Tiaris package derivations one detected commit admits.
pub(crate) const MAX_TIARIS_PACKAGE_DERIVATIONS: usize = 512;

/// `nixos-init`'s executables appear in reviewed `/etc` and service-link
/// scripts; no check names the path itself, so it is a fingerprint-only
/// identity: a profile maps it so those scripts render to their reviewed
/// executable-pinned bytes.
const NIXOS_INIT: &str = "/nix/store/wy0mh9ah0alglg3ab5djg3jv6f0garyc-nixos-init-0.1.0";
const NIXOS_INIT_DRV: &str = "/nix/store/2r230dqp2pg1jpcxp3va7wvbx812zaaq-nixos-init-0.1.0.drv";

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
    items: BTreeMap<String, String>,
    /// The inverse for a derived profile: this commit's identity store items
    /// to their built-in items, so a script is fingerprinted as the reviewed
    /// script it renders. Empty for the built-in profile.
    reviewed_items: BTreeMap<String, String>,
    /// This commit's full revision and NixOS version label, each with the
    /// built-in commit's. Empty for the built-in profile.
    reviewed_labels: Vec<(String, String)>,
    /// Exact Tiaris package derivations this detected commit may compile.
    tiaris_derivations: BTreeSet<String>,
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
                items,
                reviewed_items: BTreeMap::new(),
                reviewed_labels: Vec::new(),
                tiaris_derivations: BTreeSet::new(),
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
            items,
            reviewed_items,
            reviewed_labels: vec![
                (
                    nixpkgs_commit.to_string(),
                    BUILTIN_NIXPKGS_COMMIT.to_string(),
                ),
                (label, reviewed_label),
            ],
            tiaris_derivations,
        })
    }

    /// The profile a build job's preflight uses: the ready detected commit's
    /// profile when the job builds at that commit, otherwise the built-in
    /// profile of the release pin (`build_target` refuses any other commit).
    pub(crate) fn for_build<'a>(
        nixpkgs_commit: Option<&str>,
        detected: Option<&'a WorkstationBuildProfile>,
    ) -> &'a Self {
        match detected {
            Some(profile) if nixpkgs_commit == Some(profile.nixpkgs_commit()) => profile,
            _ => Self::builtin(),
        }
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
        for (label, reviewed) in &self.reviewed_labels {
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
            if let Some(reviewed) = self.reviewed_items.get(&script[item_start..item_end]) {
                rendered.push_str(&script[copied..item_start]);
                rendered.push_str(reviewed);
                copied = item_end;
            }
            index = item_end.max(item_start);
        }
        rendered.push_str(&script[copied..]);
        Cow::Owned(rendered)
    }

    /// Store-normalized fingerprint of the reviewed script this commit's
    /// script renders.
    pub(crate) fn normalized_sha256(&self, script: &str) -> String {
        normalized_script_sha256(&self.reviewed_script(script))
    }

    /// Executable-pinned fingerprint of the reviewed script this commit's
    /// script renders: an executable from any provider other than this
    /// commit's identity for the reviewed one changes it.
    pub(crate) fn executable_sha256(&self, script: &str) -> String {
        executable_pinned_script_sha256(&self.reviewed_script(script))
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
            WorkstationBuildProfile::for_build(Some(BUILTIN_NIXPKGS_COMMIT), None),
            profile
        ));
        assert!(std::ptr::eq(
            WorkstationBuildProfile::for_build(None, None),
            profile
        ));

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
