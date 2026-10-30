#![warn(missing_docs)]

//! Shared types for the Agent Name Service (ANS) ecosystem.
//!
//! This crate provides common data structures and types used across ANS crates:
//!
//! - [`Fqdn`] - Fully Qualified Domain Name validation
//! - [`Version`] - Semantic versioning for ANS agents
//! - [`AnsName`] - ANS URI format (e.g., `ans://v1.0.0.agent.example.com`)
//! - [`Badge`] - Badge data from the Transparency Log API
//! - [`CertFingerprint`] - SHA-256 certificate fingerprints
//!
//! # Example
//!
//! ```rust
//! use ans_types::{Fqdn, AnsName, Version};
//!
//! // Parse an FQDN
//! let fqdn = Fqdn::new("agent.example.com").unwrap();
//! assert_eq!(fqdn.ans_badge_name(), "_ans-badge.agent.example.com");
//!
//! // Parse an ANS name
//! let name = AnsName::parse("ans://v1.0.0.agent.example.com").unwrap();
//! assert_eq!(*name.version(), Version::new(1, 0, 0));
//! assert_eq!(name.to_string(), "ans://v1.0.0.agent.example.com");
//! ```

pub mod badge;
pub mod error;
pub mod fingerprint;
pub mod identity;
pub mod scitt;
pub mod types;

// Re-export commonly used types at crate root
pub use badge::{
    AgentEvent, AgentInfo, Attestations, Badge, BadgePayload, BadgeStatus, CertAttestation,
    EventType, MerkleProof, Producer,
};
pub use error::{CryptoError, ParseError};
pub use fingerprint::CertFingerprint;
pub use identity::*;
pub use scitt::{CertEntry, CertType, StatusTokenPayload, VerificationTier};
pub use types::{AnsName, Fqdn, Version};
