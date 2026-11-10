//! Which SMBIOS serial numbers may tell two computers apart at network boot.
//!
//! The Nest still finds a computer by the MAC address it boots with. A USB
//! Ethernet adapter moved between laptops brings that MAC to every one of
//! them, so a serial number that is real and differs from the one stored for
//! the MAC means another computer is using the adapter. Firmware often
//! reports a placeholder instead of a serial; those never decide anything.

const MAX_SERIAL_CHARS: usize = 128;

/// Values firmware vendors leave in SMBIOS instead of a real serial number,
/// compared case-insensitively.
const PLACEHOLDER_SERIALS: &[&str] = &[
    "default string",
    "default",
    "to be filled by o.e.m.",
    "oem",
    "system serial number",
    "chassis serial number",
    "base board serial number",
    "serial number",
    "not specified",
    "not applicable",
    "not available",
    "n/a",
    "na",
    "none",
    "unknown",
    "invalid",
    "0123456789",
    "1234567890",
    "123456789",
    "12345678",
];

/// The serial number as stored and compared, or `None` when the value cannot
/// identify a computer: empty, longer than 128 characters, a known
/// placeholder, or one repeated character such as `00000000`.
pub fn usable_serial(value: &str) -> Option<String> {
    let cleaned: String = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_SERIAL_CHARS {
        return None;
    }
    let lowercase = trimmed.to_lowercase();
    if PLACEHOLDER_SERIALS.contains(&lowercase.as_str()) {
        return None;
    }
    let mut alphanumerics = trimmed
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase());
    let first = alphanumerics.next()?;
    if alphanumerics.all(|ch| ch == first) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Two usable serial numbers name the same computer. Case is ignored because
/// an operator may retype a serial in Manage.
pub fn same_serial(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(test)]
mod tests {
    use super::{same_serial, usable_serial};

    #[test]
    fn real_serials_are_usable_and_trimmed() {
        assert_eq!(usable_serial(" 5CG1234XYZ ").as_deref(), Some("5CG1234XYZ"));
        assert_eq!(usable_serial("PF2ABCDE").as_deref(), Some("PF2ABCDE"));
        assert_eq!(usable_serial("0F00-1A").as_deref(), Some("0F00-1A"));
    }

    #[test]
    fn placeholders_are_not_usable_in_any_case() {
        for value in [
            "Default string",
            "To Be Filled By O.E.M.",
            "SYSTEM SERIAL NUMBER",
            "Not Specified",
            "N/A",
            "None",
            "0123456789",
            "OEM",
        ] {
            assert_eq!(usable_serial(value), None, "{value}");
        }
    }

    #[test]
    fn empty_repeated_and_oversized_values_are_not_usable() {
        assert_eq!(usable_serial(""), None);
        assert_eq!(usable_serial(" \t\n "), None);
        assert_eq!(usable_serial("00000000"), None);
        assert_eq!(usable_serial("FFFF-FFFF"), None);
        assert_eq!(usable_serial("xxxxXXXX"), None);
        assert_eq!(usable_serial("----"), None);
        assert_eq!(usable_serial(&"A1".repeat(65)), None);
        assert!(usable_serial(&"A1".repeat(64)).is_some());
    }

    #[test]
    fn control_characters_cannot_hide_a_placeholder() {
        assert_eq!(usable_serial("Default\u{0}string"), None);
        assert_eq!(usable_serial("\u{7}None\u{7}"), None);
    }

    #[test]
    fn serial_comparison_ignores_case_only() {
        assert!(same_serial("5cg1234xyz", "5CG1234XYZ"));
        assert!(!same_serial("5CG1234XYZ", "5CG1234XY0"));
    }
}
