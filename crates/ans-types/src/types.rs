//! Core domain types for ANS verification.

use crate::error::ParseError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A Fully Qualified Domain Name (FQDN).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fqdn(String);

impl Fqdn {
    /// Create a new FQDN from a string.
    ///
    /// # Errors
    /// Returns `ParseError::InvalidFqdn` if the string is not a valid FQDN.
    pub fn new(domain: impl Into<String>) -> Result<Self, ParseError> {
        let domain = domain.into();

        // Basic validation
        if domain.is_empty() {
            return Err(ParseError::InvalidFqdn("empty domain".to_string()));
        }

        // Remove trailing dot if present
        let domain = domain.trim_end_matches('.');

        // Check for valid characters and structure
        for label in domain.split('.') {
            if label.is_empty() {
                return Err(ParseError::InvalidFqdn("empty label".to_string()));
            }
            if label.len() > 63 {
                return Err(ParseError::InvalidFqdn("label too long".to_string()));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(ParseError::InvalidFqdn(format!(
                    "invalid character in label: {label}"
                )));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(ParseError::InvalidFqdn(
                    "label cannot start or end with hyphen".to_string(),
                ));
            }
        }

        Ok(Self(domain.to_lowercase()))
    }

    /// Get the FQDN as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the `_ans-badge` subdomain for this FQDN (primary DNS record name).
    pub fn ans_badge_name(&self) -> String {
        format!("_ans-badge.{}", self.0)
    }

    /// Get the `_ra-badge` subdomain for this FQDN (legacy fallback).
    pub fn ra_badge_name(&self) -> String {
        format!("_ra-badge.{}", self.0)
    }

    /// Get the `_ans` subdomain for this FQDN (`ANS_TXT` discovery records).
    ///
    /// The `ANS_DNSAID` SVCB discovery records live at the bare FQDN itself
    /// ([`Fqdn::as_str`]), not at a child label.
    pub fn ans_discovery_name(&self) -> String {
        format!("_ans.{}", self.0)
    }

    /// Get the TLSA record name for this FQDN and port.
    pub fn tlsa_name(&self, port: u16) -> String {
        format!("_{port}._tcp.{}", self.0)
    }
}

impl fmt::Display for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Fqdn {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for Fqdn {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Fqdn {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<String> for Fqdn {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

/// A semantic version (e.g., v1.0.0).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    /// Create a new version.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Get the major version number.
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// Get the minor version number.
    pub const fn minor(&self) -> u32 {
        self.minor
    }

    /// Get the patch version number.
    pub const fn patch(&self) -> u32 {
        self.patch
    }

    /// Parse a version string (e.g., "v1.0.0" or "1.0.0").
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 3 {
            return Err(ParseError::InvalidVersion(format!(
                "expected 3 parts, got {}: {}",
                parts.len(),
                s
            )));
        }

        let major = parts[0].parse().map_err(|_| {
            ParseError::InvalidVersion(format!("invalid major version: {}", parts[0]))
        })?;
        let minor = parts[1].parse().map_err(|_| {
            ParseError::InvalidVersion(format!("invalid minor version: {}", parts[1]))
        })?;
        let patch = parts[2].parse().map_err(|_| {
            ParseError::InvalidVersion(format!("invalid patch version: {}", parts[2]))
        })?;

        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for Version {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Version {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

/// An ANS Name URI (e.g., <ans://v1.0.0.agent.example.com>).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnsName {
    version: Version,
    fqdn: Fqdn,
}

impl AnsName {
    /// Returns the version component.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Returns the FQDN component.
    pub fn fqdn(&self) -> &Fqdn {
        &self.fqdn
    }

    /// Parse an ANS name from a URI string.
    ///
    /// Format: `ans://v<major>.<minor>.<patch>.<fqdn>`
    pub fn parse(uri: &str) -> Result<Self, ParseError> {
        const PREFIX: &str = "ans://";

        if !uri.starts_with(PREFIX) {
            return Err(ParseError::InvalidAnsName(format!(
                "ANS name must start with '{PREFIX}': {uri}"
            )));
        }

        let rest = &uri[PREFIX.len()..];

        // The format is: v<major>.<minor>.<patch>.<fqdn>
        // We need to find where the version ends and the FQDN begins
        if !rest.starts_with('v') {
            return Err(ParseError::InvalidAnsName(format!(
                "ANS name version must start with 'v': {uri}"
            )));
        }

        let parts: Vec<&str> = rest.splitn(4, '.').collect();
        if parts.len() < 4 {
            return Err(ParseError::InvalidAnsName(format!(
                "ANS name must have format 'ans://vX.Y.Z.fqdn', got: {uri}"
            )));
        }

        // Parse version from first 3 parts (including the 'v' prefix)
        let version_str = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        let version = Version::parse(&version_str)?;

        // The rest is the FQDN
        let fqdn = Fqdn::new(parts[3])?;

        Ok(Self { version, fqdn })
    }
}

impl fmt::Display for AnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ans://{}.{}", self.version, self.fqdn)
    }
}

impl FromStr for AnsName {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for AnsName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AnsName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for AnsName {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for AnsName {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    mod fqdn_tests {
        use super::*;

        #[test]
        fn test_valid_fqdn() {
            let fqdn = Fqdn::new("agent.example.com").unwrap();
            assert_eq!(fqdn.as_str(), "agent.example.com");
        }

        #[test]
        fn test_fqdn_with_trailing_dot() {
            let fqdn = Fqdn::new("agent.example.com.").unwrap();
            assert_eq!(fqdn.as_str(), "agent.example.com");
        }

        #[test]
        fn test_fqdn_lowercased() {
            let fqdn = Fqdn::new("Agent.Example.COM").unwrap();
            assert_eq!(fqdn.as_str(), "agent.example.com");
        }

        #[test]
        fn test_ans_badge_name() {
            let fqdn = Fqdn::new("agent.example.com").unwrap();
            assert_eq!(fqdn.ans_badge_name(), "_ans-badge.agent.example.com");
        }

        #[test]
        fn test_ra_badge_name() {
            let fqdn = Fqdn::new("agent.example.com").unwrap();
            assert_eq!(fqdn.ra_badge_name(), "_ra-badge.agent.example.com");
        }

        #[test]
        fn test_tlsa_name() {
            let fqdn = Fqdn::new("agent.example.com").unwrap();
            assert_eq!(fqdn.tlsa_name(443), "_443._tcp.agent.example.com");
        }

        #[test]
        fn test_ans_discovery_name() {
            let fqdn = Fqdn::new("agent.example.com").unwrap();
            assert_eq!(fqdn.ans_discovery_name(), "_ans.agent.example.com");
        }

        #[test]
        fn test_empty_fqdn() {
            assert!(Fqdn::new("").is_err());
        }

        #[test]
        fn test_fqdn_with_invalid_chars() {
            assert!(Fqdn::new("agent_test.example.com").is_err());
        }
    }

    mod version_tests {
        use super::*;

        #[test]
        fn test_parse_with_v_prefix() {
            let v = Version::parse("v1.2.3").unwrap();
            assert_eq!(v.major(), 1);
            assert_eq!(v.minor(), 2);
            assert_eq!(v.patch(), 3);
        }

        #[test]
        fn test_parse_without_v_prefix() {
            let v = Version::parse("1.2.3").unwrap();
            assert_eq!(v.major(), 1);
            assert_eq!(v.minor(), 2);
            assert_eq!(v.patch(), 3);
        }

        #[test]
        fn test_version_display() {
            let v = Version::new(1, 2, 3);
            assert_eq!(v.to_string(), "v1.2.3");
        }

        #[test]
        fn test_version_ordering() {
            let v1 = Version::new(1, 0, 0);
            let v2 = Version::new(1, 0, 1);
            let v3 = Version::new(1, 1, 0);
            let v4 = Version::new(2, 0, 0);
            assert!(v1 < v2);
            assert!(v2 < v3);
            assert!(v3 < v4);
        }

        #[test]
        fn test_invalid_version() {
            assert!(Version::parse("1.2").is_err());
            assert!(Version::parse("1.2.3.4").is_err());
            assert!(Version::parse("a.b.c").is_err());
        }
    }

    mod fqdn_extra_tests {
        use super::*;

        #[test]
        fn test_fqdn_single_label() {
            let fqdn = Fqdn::new("localhost").unwrap();
            assert_eq!(fqdn.as_str(), "localhost");
        }

        #[test]
        fn test_fqdn_label_too_long() {
            let long_label = "a".repeat(64);
            assert!(Fqdn::new(&long_label).is_err());
        }

        #[test]
        fn test_fqdn_leading_hyphen() {
            assert!(Fqdn::new("-example.com").is_err());
        }

        #[test]
        fn test_fqdn_trailing_hyphen() {
            assert!(Fqdn::new("example-.com").is_err());
        }

        #[test]
        fn test_fqdn_double_dots() {
            assert!(Fqdn::new("agent..example.com").is_err());
        }

        #[test]
        fn test_fqdn_display() {
            let fqdn = Fqdn::new("agent.example.com").unwrap();
            assert_eq!(format!("{fqdn}"), "agent.example.com");
        }

        #[test]
        fn test_fqdn_as_ref() {
            let fqdn = Fqdn::new("agent.example.com").unwrap();
            let s: &str = fqdn.as_ref();
            assert_eq!(s, "agent.example.com");
        }

        #[test]
        fn test_fqdn_try_from_str() {
            let fqdn = Fqdn::try_from("agent.example.com").unwrap();
            assert_eq!(fqdn.as_str(), "agent.example.com");
        }

        #[test]
        fn test_fqdn_try_from_string() {
            let fqdn = Fqdn::try_from("agent.example.com".to_string()).unwrap();
            assert_eq!(fqdn.as_str(), "agent.example.com");
        }

        #[test]
        fn test_fqdn_from_str() {
            let fqdn: Fqdn = "agent.example.com".parse().unwrap();
            assert_eq!(fqdn.as_str(), "agent.example.com");
        }
    }

    mod version_extra_tests {
        use super::*;

        #[test]
        fn test_version_try_from_str() {
            let v = Version::try_from("v1.2.3").unwrap();
            assert_eq!(v, Version::new(1, 2, 3));
        }

        #[test]
        fn test_version_try_from_string() {
            let v = Version::try_from("1.2.3".to_string()).unwrap();
            assert_eq!(v, Version::new(1, 2, 3));
        }

        #[test]
        fn test_version_from_str() {
            let v: Version = "v1.0.0".parse().unwrap();
            assert_eq!(v, Version::new(1, 0, 0));
        }

        #[test]
        fn test_version_hash_equality() {
            use std::collections::HashSet;
            let mut set = HashSet::new();
            set.insert(Version::new(1, 0, 0));
            assert!(set.contains(&Version::new(1, 0, 0)));
            assert!(!set.contains(&Version::new(1, 0, 1)));
        }
    }

    mod ans_name_tests {
        use super::*;

        #[test]
        fn test_parse_ans_name() {
            let name = AnsName::parse("ans://v1.0.0.agent.example.com").unwrap();
            assert_eq!(name.version, Version::new(1, 0, 0));
            assert_eq!(name.fqdn.as_str(), "agent.example.com");
        }

        #[test]
        fn test_parse_ans_name_complex_fqdn() {
            let name = AnsName::parse("ans://v2.1.3.agent.example.com").unwrap();
            assert_eq!(name.version, Version::new(2, 1, 3));
            assert_eq!(name.fqdn.as_str(), "agent.example.com");
        }

        #[test]
        fn test_invalid_ans_name_no_prefix() {
            assert!(AnsName::parse("v1.0.0.agent.example.com").is_err());
        }

        #[test]
        fn test_invalid_ans_name_no_version() {
            assert!(AnsName::parse("ans://agent.example.com").is_err());
        }

        #[test]
        fn test_ans_name_display() {
            let name = AnsName::parse("ans://v1.0.0.agent.example.com").unwrap();
            assert_eq!(format!("{name}"), "ans://v1.0.0.agent.example.com");
        }

        #[test]
        fn test_ans_name_serde_roundtrip() {
            let name = AnsName::parse("ans://v1.0.0.agent.example.com").unwrap();
            let json = serde_json::to_string(&name).unwrap();
            let deserialized: AnsName = serde_json::from_str(&json).unwrap();
            assert_eq!(name, deserialized);
        }

        #[test]
        fn test_ans_name_serde_invalid() {
            let result = serde_json::from_str::<AnsName>(r#""not-an-ans-name""#);
            assert!(result.is_err());
        }

        #[test]
        fn test_ans_name_try_from_str() {
            let name = AnsName::try_from("ans://v1.0.0.agent.example.com").unwrap();
            assert_eq!(name.version(), &Version::new(1, 0, 0));
        }

        #[test]
        fn test_ans_name_try_from_string() {
            let name = AnsName::try_from("ans://v1.0.0.agent.example.com".to_string()).unwrap();
            assert_eq!(name.fqdn().as_str(), "agent.example.com");
        }

        #[test]
        fn test_ans_name_from_str() {
            let name: AnsName = "ans://v1.0.0.agent.example.com".parse().unwrap();
            assert_eq!(name.version(), &Version::new(1, 0, 0));
        }

        #[test]
        fn test_ans_name_accessors() {
            let name = AnsName::parse("ans://v2.1.3.agent.example.com").unwrap();
            assert_eq!(name.version(), &Version::new(2, 1, 3));
            assert_eq!(name.fqdn().as_str(), "agent.example.com");
        }

        #[test]
        fn test_ans_name_no_v_prefix_error() {
            let result = AnsName::parse("ans://1.0.0.agent.example.com");
            assert!(result.is_err());
        }
    }
}
