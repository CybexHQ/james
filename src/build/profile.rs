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
use std::{borrow::Cow, collections::BTreeMap, sync::OnceLock};

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
    executable_pinned_script_sha256, normalized_script_sha256,
};

/// The nixpkgs commit whose reviewed identities are compiled into Nest.
pub(crate) const BUILTIN_NIXPKGS_COMMIT: &str = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac";

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
];

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
            }
        })
    }

    /// The profile a build job's preflight uses. Until Nest supports more
    /// than one commit, every admitted job builds at the configured pin,
    /// whose reviewed values are the built-in profile.
    pub(crate) fn for_build(_nixpkgs_commit: Option<&str>) -> &'static Self {
        Self::builtin()
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

    /// The script with this commit's identity store items replaced by their
    /// built-in items. Everything else, including every other store path,
    /// is unchanged, so the result is the reviewed script only when the
    /// commit renders the same script with its own tool providers.
    pub(crate) fn reviewed_script<'a>(&self, script: &'a str) -> Cow<'a, str> {
        if self.builtin || !script.contains("/nix/store/") {
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
        TRUSTED_STDENV_NO_CC_DRV, normalize_derivation_store_path, safe_nix_store_path,
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
            WorkstationBuildProfile::for_build(Some(BUILTIN_NIXPKGS_COMMIT)),
            profile
        ));
        assert!(std::ptr::eq(
            WorkstationBuildProfile::for_build(None),
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
