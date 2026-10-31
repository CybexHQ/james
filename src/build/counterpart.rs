//! Counterparts: the reviewed content a detected commit derives from itself.
//!
//! The reference set is exactly the local derivations admitted at the pin in
//! jobs Nest already built there. The same job inputs, evaluated with only
//! nixpkgs replaced, give each of them a counterpart at the detected commit:
//! the derivation of the same name in the same job. A counterpart's scripts,
//! stock commands and builder files become reviewed content of the detected
//! commit's profile, recorded against the pin content they replace, so every
//! existing check applies unchanged. Everything in that content is produced
//! by the detected commit's nixpkgs (pinned by `narHash`) from inputs that
//! were already admitted at the pin; a Blueprint cannot add a derivation that
//! was not admitted there. A derivation without an unambiguous counterpart
//! gains nothing and stays rejected.
use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    REVIEWED_BUILDER_FILES, ReviewedContent, UnadmittedDerivations, WorkstationBuildProfile,
    derivation_attr_text, derivation_attributes, derivation_input_sources,
    etc_script_with_time_zone_placeholder,
    profile::{
        BuilderFileCounterpart, FingerprintCounterpart, STOCK_COMMANDS, StockCommandCounterpart,
        package_name,
    },
};
use crate::nix_log::derivation_display_name;

/// The script attributes the preflight fingerprints or compares.
const SCRIPT_ATTRIBUTES: [&str; 5] = [
    "buildCommand",
    "postBuild",
    "buildPhase",
    "checkPhase",
    "installPhase",
];

/// Counterparts collected over every reference of one detected commit, per
/// derivation role.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counterparts {
    fingerprints: BTreeMap<(String, (String, String)), (String, String)>,
    conflicting: BTreeSet<(String, (String, String))>,
    stock_commands: BTreeMap<(String, String), String>,
    /// `(role, builder file)` → its sha256 at the detected commit.
    pub(crate) builder_files: BTreeMap<(String, String), String>,
    /// Roles whose content differs from the pin's.
    pub(crate) changed: BTreeSet<String>,
    /// Roles at the detected commit without a counterpart.
    pub(crate) unpaired: BTreeSet<String>,
    pub(crate) paired: usize,
}

impl Counterparts {
    /// The reviewed content for the detected commit's profile. A commit
    /// fingerprint that two counterparts of one role would map to different
    /// pin scripts is ambiguous and dropped.
    pub(crate) fn content(&self) -> ReviewedContent {
        ReviewedContent {
            fingerprints: self
                .fingerprints
                .iter()
                .filter(|(key, _)| !self.conflicting.contains(*key))
                .map(|((role, commit), reviewed)| FingerprintCounterpart {
                    role: role.clone(),
                    commit: [commit.0.clone(), commit.1.clone()],
                    reviewed: [reviewed.0.clone(), reviewed.1.clone()],
                })
                .collect(),
            stock_commands: self
                .stock_commands
                .iter()
                .map(|((role, commit), reviewed)| StockCommandCounterpart {
                    role: role.clone(),
                    commit: commit.clone(),
                    reviewed: reviewed.clone(),
                })
                .collect(),
            builder_files: self
                .builder_files
                .iter()
                .map(|((role, file), sha256)| BuilderFileCounterpart {
                    role: role.clone(),
                    file: file.clone(),
                    sha256: sha256.clone(),
                })
                .collect(),
        }
    }

    fn add_fingerprint(
        &mut self,
        role: &str,
        commit: (String, String),
        reviewed: (String, String),
    ) {
        if commit == reviewed {
            return;
        }
        let key = (role.to_string(), commit);
        if let Some(previous) = self.fingerprints.get(&key) {
            if *previous != reviewed {
                self.conflicting.insert(key);
            }
            return;
        }
        self.fingerprints.insert(key, reviewed);
    }
}

/// Pair one reference job's local derivations at the pin (`pin`, classified
/// with the built-in profile) with the same job's at the detected commit
/// (`detected`, classified with `base`: the detected commit's identities and
/// Tiaris packages, no counterparts yet). `commit_files` are the reviewed
/// builder files' hashes at the detected commit.
pub(crate) fn add_counterparts(
    base: &WorkstationBuildProfile,
    commit_files: &BTreeMap<String, String>,
    pin: &UnadmittedDerivations,
    detected: &UnadmittedDerivations,
    counterparts: &mut Counterparts,
) {
    let builtin = WorkstationBuildProfile::builtin();
    let pin_rejected = pin.rejected_on_their_own.iter().collect::<HashSet<_>>();
    let group = |derivations: &UnadmittedDerivations, profile: &WorkstationBuildProfile| {
        let mut groups = BTreeMap::<String, Vec<String>>::new();
        for path in &derivations.would_build {
            let display = derivation_display_name(path);
            let name = profile.reviewed_script(&display);
            groups
                .entry(package_name(&name).to_string())
                .or_default()
                .push(path.clone());
        }
        groups
    };
    let pin_groups = group(pin, builtin);
    for (name, commit_paths) in group(detected, base) {
        let pin_paths = pin_groups.get(&name);
        let eligible = pin_paths.is_some_and(|pin_paths| {
            pin_paths.len() == commit_paths.len()
                && pin_paths.iter().all(|path| !pin_rejected.contains(path))
        });
        let pairs = if eligible {
            pair_group(
                base,
                pin_paths.expect("eligible group exists"),
                &commit_paths,
                pin,
                detected,
            )
        } else {
            None
        };
        let Some(pairs) = pairs else {
            counterparts.unpaired.insert(name);
            continue;
        };
        for (pin_path, commit_path) in pairs {
            let (Some(pin_drv), Some(commit_drv)) = (
                pin.derivations.get(&pin_path),
                detected.derivations.get(&commit_path),
            ) else {
                counterparts.unpaired.insert(name.clone());
                continue;
            };
            if !same_shape(base, pin_drv, commit_drv) {
                counterparts.unpaired.insert(name.clone());
                continue;
            }
            counterparts.paired += 1;
            if add_pair(
                &name,
                builtin,
                base,
                commit_files,
                pin_drv,
                commit_drv,
                counterparts,
            ) {
                counterparts.changed.insert(name.clone());
            }
        }
    }
}

/// One-to-one pairs within a name group: a single member pairs directly;
/// several pair only by identical attributes after whole store paths and the
/// version label are set aside, and only when that is unambiguous.
fn pair_group(
    base: &WorkstationBuildProfile,
    pin_paths: &[String],
    commit_paths: &[String],
    pin: &UnadmittedDerivations,
    detected: &UnadmittedDerivations,
) -> Option<Vec<(String, String)>> {
    if let ([pin_path], [commit_path]) = (pin_paths, commit_paths) {
        return Some(vec![(pin_path.clone(), commit_path.clone())]);
    }
    let shape = |profile: &WorkstationBuildProfile, drv: &Value| {
        let mut digest = Sha256::new();
        for (key, value) in derivation_attributes(drv) {
            let text = match &value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            digest.update(key.as_bytes());
            digest.update([0]);
            digest.update(without_store_paths(&profile.reviewed_script(&text)));
            digest.update([0]);
        }
        hex::encode(digest.finalize())
    };
    let mut by_shape = BTreeMap::<String, String>::new();
    for path in pin_paths {
        let key = shape(
            WorkstationBuildProfile::builtin(),
            pin.derivations.get(path)?,
        );
        if by_shape.insert(key, path.clone()).is_some() {
            return None;
        }
    }
    let mut pairs = Vec::new();
    for path in commit_paths {
        let key = shape(base, detected.derivations.get(path)?);
        pairs.push((by_shape.remove(&key)?, path.clone()));
    }
    Some(pairs)
}

fn without_store_paths(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut rendered = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(offset) = text[index..].find("/nix/store/") {
        let start = index + offset;
        rendered.push_str(&text[index..start]);
        let mut end = start + "/nix/store/".len();
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric()
                || matches!(bytes[end], b'.' | b'_' | b'+' | b'-'))
        {
            end += 1;
        }
        rendered.push_str("/nix/store/<path>");
        index = end;
    }
    rendered.push_str(&text[index..]);
    rendered
}

/// A counterpart is the same kind of derivation: the same builder (the
/// commit's provider of the pin's builder) and the same attribute names.
fn same_shape(base: &WorkstationBuildProfile, pin_drv: &Value, commit_drv: &Value) -> bool {
    let builder = |drv: &Value| {
        drv.get("builder")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let (Some(pin_builder), Some(commit_builder)) = (builder(pin_drv), builder(commit_drv)) else {
        return false;
    };
    let same_builder = if pin_builder.starts_with("/nix/store/") {
        base.is(&commit_builder, &pin_builder)
    } else {
        pin_builder == commit_builder
    };
    let keys = |drv: &Value| {
        derivation_attributes(drv)
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    same_builder && keys(pin_drv) == keys(commit_drv)
}

/// Record a pair's content. Returns whether any of it differs from the pin.
fn add_pair(
    role: &str,
    builtin: &WorkstationBuildProfile,
    base: &WorkstationBuildProfile,
    commit_files: &BTreeMap<String, String>,
    pin_drv: &Value,
    commit_drv: &Value,
    counterparts: &mut Counterparts,
) -> bool {
    let pin_attrs = derivation_attributes(pin_drv);
    let commit_attrs = derivation_attributes(commit_drv);
    let mut changed = false;
    for key in SCRIPT_ATTRIBUTES {
        let pin_text = derivation_attr_text(&pin_attrs, key);
        let commit_text = derivation_attr_text(&commit_attrs, key);
        if pin_text.is_empty() || commit_text.is_empty() {
            continue;
        }
        let reviewed = builtin.fingerprints(pin_text);
        let commit = base.fingerprints(commit_text);
        changed |= reviewed != commit;
        counterparts.add_fingerprint(role, commit, reviewed);
        // `/etc` recipes are also compared with their zone set aside.
        if let (Some(pin_zone), Some(commit_zone)) = (
            etc_script_with_time_zone_placeholder(pin_text),
            etc_script_with_time_zone_placeholder(commit_text),
        ) {
            counterparts.add_fingerprint(
                role,
                base.fingerprints(&commit_zone),
                builtin.fingerprints(&pin_zone),
            );
        }
        if STOCK_COMMANDS.contains(&pin_text) && commit_text != pin_text {
            counterparts.stock_commands.insert(
                (role.to_string(), commit_text.to_string()),
                pin_text.to_string(),
            );
        }
    }
    for (name, reviewed_sha256) in REVIEWED_BUILDER_FILES {
        let Some(commit_sha256) = commit_files.get(name) else {
            continue;
        };
        if commit_sha256 != reviewed_sha256
            && uses_builder_file(pin_drv, name)
            && uses_builder_file(commit_drv, name)
        {
            counterparts
                .builder_files
                .insert((role.to_string(), name.to_string()), commit_sha256.clone());
            changed = true;
        }
    }
    changed
}

fn uses_builder_file(drv: &Value, name: &str) -> bool {
    if name == "builder.pl" {
        let attrs = derivation_attributes(drv);
        return derivation_attr_text(&attrs, "buildCommand").contains("-builder.pl");
    }
    let suffix = format!("-{name}");
    derivation_input_sources(drv)
        .is_some_and(|sources| sources.iter().any(|source| source.ends_with(&suffix)))
}
