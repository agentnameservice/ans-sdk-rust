//! DNS resolution for ANS records: `_ans-badge` / `_ra-badge` trust TXT
//! records, TLSA records, and the discovery records of both DNS discovery
//! profiles — `ANS_DNSAID` (SVCB rows at the bare FQDN, RFC 9460) and
//! `ANS_TXT` (`_ans.{fqdn}` TXT rows).

use async_trait::async_trait;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    CLOUDFLARE, GOOGLE, NameServerConfig, QUAD9, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError, NoRecords as HickoryNoRecords};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::rdata::svcb::{SVCB, SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
/// Well-known DNS resolver configurations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DnsResolverConfig {
    /// System default resolver configuration.
    #[default]
    System,
    /// Cloudflare DNS (1.1.1.1, 1.0.0.1).
    Cloudflare,
    /// Cloudflare DNS over TLS.
    CloudflareTls,
    /// Google Public DNS (8.8.8.8, 8.8.4.4).
    Google,
    /// Google DNS over TLS.
    GoogleTls,
    /// Quad9 DNS (9.9.9.9) - includes malware blocking.
    Quad9,
    /// Quad9 DNS over TLS.
    Quad9Tls,
}

impl DnsResolverConfig {
    /// Convert to hickory `ResolverConfig` and `ResolverOpts`.
    ///
    /// For `System`, reads the OS DNS configuration (e.g., `/etc/resolv.conf`
    /// on Linux, `scutil --dns` on macOS). Other presets return hardcoded
    /// public DNS configurations.
    pub(crate) fn to_resolver_config(self) -> Result<(ResolverConfig, ResolverOpts), DnsError> {
        match self {
            Self::System => hickory_resolver::system_conf::read_system_conf().map_err(|e| {
                DnsError::LookupFailed {
                    fqdn: "(system config)".to_string(),
                    reason: format!("failed to read system DNS config: {e}"),
                }
            }),
            Self::Cloudflare => Ok((
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                ResolverOpts::default(),
            )),
            Self::CloudflareTls => Ok((ResolverConfig::tls(&CLOUDFLARE), ResolverOpts::default())),
            Self::Google => Ok((
                ResolverConfig::udp_and_tcp(&GOOGLE),
                ResolverOpts::default(),
            )),
            Self::GoogleTls => Ok((ResolverConfig::tls(&GOOGLE), ResolverOpts::default())),
            Self::Quad9 => Ok((ResolverConfig::udp_and_tcp(&QUAD9), ResolverOpts::default())),
            Self::Quad9Tls => Ok((ResolverConfig::tls(&QUAD9), ResolverOpts::default())),
        }
    }
}

use crate::dane::TlsaRecord;
use crate::error::{DaneError, DnsError};
use ans_types::{Fqdn, ParseError, Version};

/// Parsed badge TXT record from `_ans-badge` or `_ra-badge` DNS records.
///
/// In production, construct via [`BadgeRecord::parse`]. A `BadgeRecord::new`
/// constructor is available only when the `test-support` feature is enabled.
#[derive(Debug, Clone)]
pub struct BadgeRecord {
    /// Format version (e.g., "ans-badge1" or "ra-badge1").
    pub(crate) format_version: String,
    /// Agent version this badge represents (optional - may not be in DNS record).
    pub(crate) version: Option<Version>,
    /// URL to fetch the badge from the transparency log.
    pub(crate) url: String,
}

impl BadgeRecord {
    /// Returns the format version (e.g., "ans-badge1" or "ra-badge1").
    pub fn format_version(&self) -> &str {
        &self.format_version
    }

    /// Returns the agent version this badge represents, if specified.
    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    /// Returns the URL to fetch the badge from the transparency log.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Parse from TXT record string.
    ///
    /// Accepts both new and legacy formats:
    /// - `v=ans-badge1; version=v1.0.0; url=https://...`
    /// - `v=ra-badge1; version=v1.0.0; url=https://...`
    /// - `v=ans-badge1;version=v1.0.0;url=https://...` (no spaces)
    ///
    /// Version field is optional.
    pub fn parse(txt: &str) -> Result<Self, ParseError> {
        let mut format_version = None;
        let mut version = None;
        let mut url = None;

        for part in txt.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("v=") {
                format_version = Some(v.to_string());
            } else if let Some(v) = part.strip_prefix("version=") {
                version = Version::parse(v).ok();
            } else if let Some(u) = part.strip_prefix("url=") {
                // Validate URL syntax but store as String to avoid exposing url::Url
                url::Url::parse(u).map_err(|e| ParseError::InvalidUrl(e.to_string()))?;
                url = Some(u.to_string());
            }
        }

        let format_version =
            format_version.ok_or_else(|| ParseError::MissingField("v".to_string()))?;
        let url = url.ok_or_else(|| ParseError::MissingField("url".to_string()))?;

        tracing::debug!(
            format_version = %format_version,
            version = ?version,
            url = %url,
            "Parsed badge TXT record"
        );

        Ok(Self {
            format_version,
            version,
            url,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl BadgeRecord {
    /// Create a `BadgeRecord` for testing.
    ///
    /// In production, use [`BadgeRecord::parse`] to construct from DNS TXT record data.
    pub fn new(
        format_version: impl Into<String>,
        version: Option<Version>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            format_version: format_version.into(),
            version,
            url: url.into(),
        }
    }
}

// ---------------------------------------------------------------------
// Discovery records (ANS-3 discovery profiles)
// ---------------------------------------------------------------------

/// DNS-AID draft-02 `cap` `SvcParam` — the endpoint's capability locator
/// (`metadataUrl`), in the RFC 9460 §14.3.1 Private Use range.
const SVCPARAM_KEY_CAP: u16 = 65400;
/// DNS-AID draft-02 `cap-sha256` `SvcParam` — `base64url(raw SHA-256)` of the
/// endpoint's metadata document.
const SVCPARAM_KEY_CAP_SHA256: u16 = 65401;
/// DNS-AID draft-02 `bap` `SvcParam` — the authoritative agent-protocol token.
const SVCPARAM_KEY_BAP: u16 = 65402;
/// DNS-AID draft-02 `well-known` `SvcParam` — the RFC 8615 suffix under
/// `https://{fqdn}/.well-known/`.
const SVCPARAM_KEY_WELL_KNOWN: u16 = 65409;

/// Agent protocol identified by a discovery record.
///
/// The two discovery profiles share the `a2a` and `mcp` tokens but spell the
/// plain-HTTP protocol differently: `http-api` in `ANS_TXT`, `x-http` in
/// `ANS_DNSAID`. Both normalize to [`AgentProtocol::HttpApi`]; unrecognized
/// tokens are preserved verbatim in [`AgentProtocol::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AgentProtocol {
    /// Agent-to-Agent protocol (`a2a`).
    A2a,
    /// Model Context Protocol (`mcp`).
    Mcp,
    /// Plain HTTP API (`http-api` in `ANS_TXT`, `x-http` in `ANS_DNSAID`).
    HttpApi,
    /// Unrecognized or future protocol token, preserved verbatim.
    Other(String),
}

impl AgentProtocol {
    /// Map a wire protocol token from either discovery profile.
    pub fn from_token(token: &str) -> Self {
        match token {
            "a2a" => Self::A2a,
            "mcp" => Self::Mcp,
            "http-api" | "x-http" => Self::HttpApi,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Parsed `ANS_DNSAID` SVCB discovery record from the agent's bare FQDN.
///
/// One record per protocol endpoint, in `ServiceMode` with the DNS-AID
/// `SvcParams` (`cap` / `cap-sha256` / `bap` / `well-known`) carried in the
/// RFC 9460 Private Use `keyNNNNN` form. Malformed optional params are
/// dropped with a warning; the record itself survives as long as it is in
/// `ServiceMode` and carries a protocol token.
///
/// In production these are produced by DNS lookups. Custom [`DnsResolver`]
/// implementations that read SVCB rows from another source build them with
/// [`SvcbDiscoveryRecord::from_parts`]. A `new` shorthand is available only
/// when the `test-support` feature is enabled.
#[derive(Debug, Clone)]
pub struct SvcbDiscoveryRecord {
    /// `SvcPriority` (`ServiceMode`, so always >= 1).
    pub(crate) priority: u16,
    /// `TargetName`; `.` means the owner name itself (RFC 9460 §2.5.2).
    pub(crate) target_name: String,
    /// Agent-protocol token from `bap` (key65402), falling back to `alpn`.
    pub(crate) protocol_token: String,
    /// TCP port from the `port` `SvcParam`; absent means the scheme default.
    pub(crate) port: Option<u16>,
    /// Capability locator (`metadataUrl`) from `cap` (key65400).
    pub(crate) metadata_url: Option<String>,
    /// Decoded SHA-256 of the metadata document from `cap-sha256` (key65401).
    pub(crate) metadata_sha256: Option<[u8; 32]>,
    /// RFC 8615 well-known suffix from `well-known` (key65409).
    pub(crate) well_known: Option<String>,
}

impl SvcbDiscoveryRecord {
    /// Returns the `SvcPriority` (always >= 1: `ServiceMode`).
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the `TargetName`; `.` means the owner name itself.
    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    /// Returns the raw agent-protocol token (e.g. `a2a`, `mcp`, `x-http`).
    pub fn protocol_token(&self) -> &str {
        &self.protocol_token
    }

    /// Returns the normalized agent protocol.
    pub fn protocol(&self) -> AgentProtocol {
        AgentProtocol::from_token(&self.protocol_token)
    }

    /// Returns the TCP port, if the record carries a `port` `SvcParam`.
    ///
    /// Absence means the authority endpoint's default port applies
    /// (RFC 9460 §7.2) — `443` for the https endpoints ANS registers.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the endpoint's capability locator (`metadataUrl`), if any.
    pub fn metadata_url(&self) -> Option<&str> {
        self.metadata_url.as_deref()
    }

    /// Returns the SHA-256 digest of the endpoint's metadata document, if any.
    pub fn metadata_sha256(&self) -> Option<&[u8; 32]> {
        self.metadata_sha256.as_ref()
    }

    /// Returns the RFC 8615 well-known suffix, if any.
    pub fn well_known(&self) -> Option<&str> {
        self.well_known.as_deref()
    }

    /// Build a record from already-parsed SVCB fields.
    ///
    /// This is the production constructor for custom [`DnsResolver`]
    /// implementations that read SVCB rows from somewhere other than
    /// hickory — it takes plain values rather than hickory RDATA. Attach the
    /// optional DNS-AID params with [`with_metadata_url`](Self::with_metadata_url),
    /// [`with_metadata_sha256`](Self::with_metadata_sha256), and
    /// [`with_well_known`](Self::with_well_known).
    ///
    /// `port` of `None` means the scheme default applies (RFC 9460 §7.2).
    ///
    /// # Errors
    ///
    /// Rejects the same rows the hickory parser rejects: `priority` 0
    /// (an `AliasMode` record, not an ANS discovery row) and an empty
    /// `protocol_token`.
    pub fn from_parts(
        priority: u16,
        target_name: impl Into<String>,
        protocol_token: impl Into<String>,
        port: Option<u16>,
    ) -> Result<Self, ParseError> {
        if priority == 0 {
            return Err(ParseError::InvalidRecord(
                "AliasMode SVCB record (SvcPriority 0) is not an ANS discovery record".to_string(),
            ));
        }

        let protocol_token = protocol_token.into();
        if protocol_token.is_empty() {
            return Err(ParseError::MissingField(
                "key65402 (bap) or alpn protocol token".to_string(),
            ));
        }

        Ok(Self {
            priority,
            target_name: target_name.into(),
            protocol_token,
            port,
            metadata_url: None,
            metadata_sha256: None,
            well_known: None,
        })
    }

    /// Set the capability locator (`cap` / key65400).
    #[must_use]
    pub fn with_metadata_url(mut self, url: impl Into<String>) -> Self {
        self.metadata_url = Some(url.into());
        self
    }

    /// Set the metadata digest (`cap-sha256` / key65401).
    #[must_use]
    pub fn with_metadata_sha256(mut self, digest: [u8; 32]) -> Self {
        self.metadata_sha256 = Some(digest);
        self
    }

    /// Set the well-known suffix (`well-known` / key65409).
    #[must_use]
    pub fn with_well_known(mut self, suffix: impl Into<String>) -> Self {
        self.well_known = Some(suffix.into());
        self
    }

    /// Parse from SVCB RDATA.
    ///
    /// Errors when the record is not usable as an ANS discovery row: an
    /// `AliasMode` record (`SvcPriority` 0), or a row with no protocol token in
    /// either `bap` (key65402) or `alpn`. Malformed *optional* params
    /// (`cap`, `cap-sha256`, `well-known`) are dropped with a warning.
    pub(crate) fn from_rdata(svcb: &SVCB) -> Result<Self, ParseError> {
        if svcb.svc_priority == 0 {
            return Err(ParseError::InvalidRecord(
                "AliasMode SVCB record (SvcPriority 0) is not an ANS discovery record".to_string(),
            ));
        }

        let mut alpn_token = None;
        let mut port = None;
        let mut metadata_url = None;
        let mut metadata_sha256 = None;
        let mut bap_token = None;
        let mut well_known = None;

        // RFC 9460 §2.1: each SvcParamKey appears at most once; first wins.
        for (key, value) in &svcb.svc_params {
            match (key, value) {
                (SvcParamKey::Alpn, SvcParamValue::Alpn(alpn)) if alpn_token.is_none() => {
                    alpn_token = alpn.0.first().cloned();
                }
                (SvcParamKey::Port, SvcParamValue::Port(p)) if port.is_none() => {
                    port = Some(*p);
                }
                (SvcParamKey::Key(SVCPARAM_KEY_CAP), SvcParamValue::Unknown(raw))
                    if metadata_url.is_none() =>
                {
                    metadata_url = parse_cap_url(&raw.0);
                }
                (SvcParamKey::Key(SVCPARAM_KEY_CAP_SHA256), SvcParamValue::Unknown(raw))
                    if metadata_sha256.is_none() =>
                {
                    metadata_sha256 = parse_cap_sha256(&raw.0);
                }
                (SvcParamKey::Key(SVCPARAM_KEY_BAP), SvcParamValue::Unknown(raw))
                    if bap_token.is_none() =>
                {
                    bap_token = std::str::from_utf8(&raw.0)
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(String::from);
                }
                (SvcParamKey::Key(SVCPARAM_KEY_WELL_KNOWN), SvcParamValue::Unknown(raw))
                    if well_known.is_none() =>
                {
                    well_known = std::str::from_utf8(&raw.0)
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(String::from);
                }
                _ => {}
            }
        }

        // key65402 (bap) is authoritative; alpn is the fallback carrier.
        let protocol_token = bap_token.or(alpn_token).ok_or_else(|| {
            ParseError::MissingField("key65402 (bap) or alpn protocol token".to_string())
        })?;

        Ok(Self {
            priority: svcb.svc_priority,
            target_name: svcb.target_name.to_string(),
            protocol_token,
            port,
            metadata_url,
            metadata_sha256,
            well_known,
        })
    }
}

/// Decode a `cap` (key65400) `SvcParam` value into a validated URL string.
fn parse_cap_url(raw: &[u8]) -> Option<String> {
    let Ok(s) = std::str::from_utf8(raw) else {
        tracing::warn!("Dropping non-UTF-8 cap (key65400) SvcParam");
        return None;
    };
    if url::Url::parse(s).is_err() {
        tracing::warn!(value = %s, "Dropping invalid cap (key65400) URL");
        return None;
    }
    Some(s.to_string())
}

/// Decode a `cap-sha256` (key65401) `SvcParam` value: base64url, no padding,
/// raw 32-byte SHA-256.
fn parse_cap_sha256(raw: &[u8]) -> Option<[u8; 32]> {
    let decoded = std::str::from_utf8(raw)
        .ok()
        .and_then(|s| BASE64_URL_SAFE_NO_PAD.decode(s).ok());
    let Some(bytes) = decoded else {
        tracing::warn!("Dropping undecodable cap-sha256 (key65401) SvcParam");
        return None;
    };
    match <[u8; 32]>::try_from(bytes) {
        Ok(digest) => Some(digest),
        Err(bytes) => {
            tracing::warn!(
                len = bytes.len(),
                "Dropping cap-sha256 (key65401) with wrong digest length"
            );
            None
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SvcbDiscoveryRecord {
    /// Create an `SvcbDiscoveryRecord` for testing (`ServiceMode`, target `.`).
    ///
    /// Infallible shorthand for the common test shape. In production, records
    /// come from DNS lookups or [`SvcbDiscoveryRecord::from_parts`].
    pub fn new(protocol_token: impl Into<String>, port: u16) -> Self {
        Self {
            priority: 1,
            target_name: ".".to_string(),
            protocol_token: protocol_token.into(),
            port: Some(port),
            metadata_url: None,
            metadata_sha256: None,
            well_known: None,
        }
    }
}

/// Parsed `ANS_TXT` discovery record from `_ans.{fqdn}` TXT.
///
/// Wire form: `v=ans1; version=v{version}; p={token}; mode=direct; url={agentUrl}`.
/// One record per protocol endpoint. `v`, `p`, and `url` are required;
/// `version` is parsed leniently for runtime compatibility with legacy
/// records.
///
/// In production, construct via [`TxtDiscoveryRecord::parse`]. A `new`
/// constructor is available only when the `test-support` feature is enabled.
#[derive(Debug, Clone)]
pub struct TxtDiscoveryRecord {
    /// Format version (e.g. "ans1").
    pub(crate) format_version: String,
    /// Agent version this endpoint belongs to (optional — parsed leniently).
    pub(crate) version: Option<Version>,
    /// Agent-protocol token from `p=` (e.g. `a2a`, `mcp`, `http-api`).
    pub(crate) protocol_token: String,
    /// Connection mode from `mode=`; the profile always emits `direct`.
    pub(crate) mode: Option<String>,
    /// The endpoint URL (`agentUrl`), verbatim.
    pub(crate) url: String,
}

impl TxtDiscoveryRecord {
    /// Returns the format version (e.g. "ans1").
    pub fn format_version(&self) -> &str {
        &self.format_version
    }

    /// Returns the agent version this endpoint belongs to, if specified.
    pub fn version(&self) -> Option<&Version> {
        self.version.as_ref()
    }

    /// Returns the raw agent-protocol token (e.g. `a2a`, `mcp`, `http-api`).
    pub fn protocol_token(&self) -> &str {
        &self.protocol_token
    }

    /// Returns the normalized agent protocol.
    pub fn protocol(&self) -> AgentProtocol {
        AgentProtocol::from_token(&self.protocol_token)
    }

    /// Returns the connection mode; ANS-3 §3.1 clients follow [`Self::url`]
    /// directly when this is `direct` (the only mode the profile emits).
    pub fn mode(&self) -> Option<&str> {
        self.mode.as_deref()
    }

    /// Returns the endpoint URL (`agentUrl`).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Parse from a `_ans` TXT record string.
    ///
    /// Accepts both spaced and unspaced field separators:
    /// - `v=ans1; version=v1.0.0; p=a2a; mode=direct; url=https://...`
    /// - `v=ans1;version=v1.0.0;p=a2a;mode=direct;url=https://...`
    pub fn parse(txt: &str) -> Result<Self, ParseError> {
        let mut format_version = None;
        let mut version = None;
        let mut protocol_token = None;
        let mut mode = None;
        let mut url = None;

        for part in txt.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("v=") {
                format_version = Some(v.to_string());
            } else if let Some(v) = part.strip_prefix("version=") {
                version = Version::parse(v).ok();
            } else if let Some(p) = part.strip_prefix("p=") {
                protocol_token = Some(p.to_string());
            } else if let Some(m) = part.strip_prefix("mode=") {
                mode = Some(m.to_string());
            } else if let Some(u) = part.strip_prefix("url=") {
                // Validate URL syntax but store as String to avoid exposing url::Url
                url::Url::parse(u).map_err(|e| ParseError::InvalidUrl(e.to_string()))?;
                url = Some(u.to_string());
            }
        }

        let format_version =
            format_version.ok_or_else(|| ParseError::MissingField("v".to_string()))?;
        let protocol_token =
            protocol_token.ok_or_else(|| ParseError::MissingField("p".to_string()))?;
        let url = url.ok_or_else(|| ParseError::MissingField("url".to_string()))?;

        tracing::debug!(
            format_version = %format_version,
            version = ?version,
            protocol = %protocol_token,
            url = %url,
            "Parsed _ans discovery TXT record"
        );

        Ok(Self {
            format_version,
            version,
            protocol_token,
            mode,
            url,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl TxtDiscoveryRecord {
    /// Create a `TxtDiscoveryRecord` for testing (`mode=direct`).
    ///
    /// In production, use [`TxtDiscoveryRecord::parse`] to construct from
    /// DNS TXT record data.
    pub fn new(
        format_version: impl Into<String>,
        version: Option<Version>,
        protocol_token: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            format_version: format_version.into(),
            version,
            protocol_token: protocol_token.into(),
            mode: Some("direct".to_string()),
            url: url.into(),
        }
    }
}

/// A discovery record from whichever profile DNS autodiscovery found.
///
/// Produced by [`DnsResolver::lookup_discovery`], which probes the
/// `ANS_DNSAID` SVCB rows at the bare FQDN first, then the `ANS_TXT` rows at
/// `_ans.{fqdn}`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DiscoveryRecord {
    /// An `ANS_DNSAID` SVCB row from the agent's bare FQDN.
    Svcb(SvcbDiscoveryRecord),
    /// An `ANS_TXT` row from `_ans.{fqdn}`.
    Txt(TxtDiscoveryRecord),
}

impl DiscoveryRecord {
    /// Returns the raw agent-protocol token from the underlying record.
    pub fn protocol_token(&self) -> &str {
        match self {
            Self::Svcb(record) => record.protocol_token(),
            Self::Txt(record) => record.protocol_token(),
        }
    }

    /// Returns the normalized agent protocol.
    pub fn protocol(&self) -> AgentProtocol {
        AgentProtocol::from_token(self.protocol_token())
    }

    /// Returns the discovery-profile registry ID that produced this record
    /// (`"ANS_DNSAID"` or `"ANS_TXT"`).
    pub fn profile_id(&self) -> &'static str {
        match self {
            Self::Svcb(_) => "ANS_DNSAID",
            Self::Txt(_) => "ANS_TXT",
        }
    }
}

/// Apply RFC 9460 §2.4.1 `RRset` semantics and parse each usable row.
///
/// If the `RRset` contains an `AliasMode` record, every `ServiceMode` record MUST
/// be ignored — the zone is doing SVCB aliasing, not ANS discovery.
/// Otherwise, malformed rows are skipped with a warning so one bad row
/// cannot hide its valid siblings.
fn collect_svcb_discovery(rows: &[&SVCB], fqdn: &Fqdn) -> Vec<SvcbDiscoveryRecord> {
    if rows.iter().any(|svcb| svcb.svc_priority == 0) {
        tracing::warn!(
            fqdn = %fqdn,
            "SVCB RRset contains an AliasMode record; ignoring ServiceMode rows (RFC 9460 §2.4.1)"
        );
        return Vec::new();
    }

    rows.iter()
        .filter_map(|svcb| match SvcbDiscoveryRecord::from_rdata(svcb) {
            Ok(record) => Some(record),
            Err(error) => {
                tracing::warn!(
                    fqdn = %fqdn,
                    error = %error,
                    "Skipping malformed SVCB discovery record"
                );
                None
            }
        })
        .collect()
}

/// DNS lookup result distinguishing between "not found" and "error".
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DnsLookupResult<T> {
    /// Records were found.
    Found(Vec<T>),
    /// Record does not exist (NXDOMAIN).
    NotFound,
}

/// DNS resolver trait for looking up badge, TLSA, and discovery records.
///
/// Badge records are queried from `_ans-badge.{fqdn}` (primary) with
/// fallback to `_ra-badge.{fqdn}` (legacy).
///
/// Discovery records are queried per profile: `ANS_DNSAID` SVCB rows at the
/// bare FQDN and `ANS_TXT` rows at `_ans.{fqdn}`. The provided
/// [`lookup_discovery`](Self::lookup_discovery) method autodiscovers which
/// profile an agent publishes by probing them in turn.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Query badge TXT records for an FQDN.
    ///
    /// Implementations should query `_ans-badge` first, falling back to `_ra-badge`.
    async fn lookup_badge(&self, fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError>;

    /// Query TLSA records for an FQDN and port.
    ///
    /// Returns TLSA records from `_<port>._tcp.<fqdn>`.
    /// Used for DANE verification of server certificates.
    async fn lookup_tlsa(
        &self,
        fqdn: &Fqdn,
        port: u16,
    ) -> Result<DnsLookupResult<TlsaRecord>, DnsError>;

    /// Query `ANS_DNSAID` SVCB discovery records at the bare FQDN.
    ///
    /// One record per protocol endpoint. Implementations must honor
    /// RFC 9460 §2.4.1: an `RRset` containing an `AliasMode` record yields no
    /// discovery records.
    ///
    /// Defaults to [`DnsLookupResult::NotFound`] — "this resolver serves no
    /// `ANS_DNSAID` records" — so resolvers written before discovery existed
    /// keep compiling. Override it to serve the profile, building rows with
    /// [`SvcbDiscoveryRecord::from_parts`].
    async fn lookup_svcb_discovery(
        &self,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<SvcbDiscoveryRecord>, DnsError> {
        let _ = fqdn;
        Ok(DnsLookupResult::NotFound)
    }

    /// Query `ANS_TXT` discovery records at `_ans.{fqdn}`.
    ///
    /// One record per protocol endpoint.
    ///
    /// Defaults to [`DnsLookupResult::NotFound`] — "this resolver serves no
    /// `ANS_TXT` records" — so resolvers written before discovery existed keep
    /// compiling. Override it to serve the profile, building rows with
    /// [`TxtDiscoveryRecord::parse`].
    async fn lookup_txt_discovery(
        &self,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<TxtDiscoveryRecord>, DnsError> {
        let _ = fqdn;
        Ok(DnsLookupResult::NotFound)
    }

    /// Query all badge records and return them.
    /// Convenience method that unwraps the result.
    async fn get_badge_records(&self, fqdn: &Fqdn) -> Result<Vec<BadgeRecord>, DnsError> {
        match self.lookup_badge(fqdn).await? {
            DnsLookupResult::Found(records) => Ok(records),
            DnsLookupResult::NotFound => Err(DnsError::NotFound {
                fqdn: fqdn.to_string(),
            }),
        }
    }

    /// Get TLSA records, returning empty vec if not found.
    async fn get_tlsa_records(&self, fqdn: &Fqdn, port: u16) -> Result<Vec<TlsaRecord>, DaneError> {
        match self.lookup_tlsa(fqdn, port).await {
            Ok(DnsLookupResult::Found(records)) => Ok(records),
            Ok(DnsLookupResult::NotFound) => Ok(vec![]),
            Err(e) => Err(DaneError::DnsError(e)),
        }
    }

    /// Find the badge record matching a specific version.
    async fn find_badge_for_version(
        &self,
        fqdn: &Fqdn,
        version: &Version,
    ) -> Result<Option<BadgeRecord>, DnsError> {
        let records = self.get_badge_records(fqdn).await?;
        // Find record with matching version, or if version is None in record, it matches any
        Ok(records.into_iter().find(|r| {
            match &r.version {
                Some(v) => v == version,
                None => true, // Record without version can match any version
            }
        }))
    }

    /// Find the first ACTIVE badge (or any if none specified as active).
    /// During version changes, prefer newer versions.
    async fn find_preferred_badge(&self, fqdn: &Fqdn) -> Result<Option<BadgeRecord>, DnsError> {
        let mut records = self.get_badge_records(fqdn).await?;

        if records.is_empty() {
            return Ok(None);
        }

        // Sort by version descending (newest first), None versions go last
        records.sort_by(|a, b| match (&b.version, &a.version) {
            (Some(vb), Some(va)) => vb.cmp(va),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });

        Ok(Some(records.remove(0)))
    }

    /// Autodiscover the discovery profile an agent publishes.
    ///
    /// Probes each profile in turn, stopping at the first that resolves: the
    /// `ANS_DNSAID` SVCB rows at the bare FQDN, then the `ANS_TXT` rows at
    /// `_ans.{fqdn}`.
    ///
    /// **The probe order is an SDK convention, not spec-defined.** ANS-3 §3.1
    /// orders DNS ahead of the Transparency Log; it does not rank the discovery
    /// profiles against each other. The `[ANS_TXT, ANS_DNSAID]` order in §6.4
    /// is the registry's emission order, not a read-side ranking.
    ///
    /// SVCB is probed first because `ANS_DNSAID` is the spec default profile
    /// (ANS-3 §6.1) and `ANS_TXT` is opt-in, so the first probe resolves for an
    /// agent on the default and misses only one that opted into `ANS_TXT`
    /// alone. SVCB rows also carry richer endpoint data — a capability locator
    /// (`cap`), its digest (`cap-sha256`), and a well-known suffix — where an
    /// `ANS_TXT` row carries only a URL.
    ///
    /// One wrinkle worth knowing: in the `["ANS_DNSAID", "ANS_TXT"]` transition
    /// union both families are published, and §6.4 flips the SVCB rows to
    /// `Required=false` while the `_ans` TXT rows keep `Required=true`. In that
    /// one case first-found-wins returns the rows carrying the weaker required
    /// flag, and a stale SVCB row wins over a fresh TXT row if the two drift
    /// apart.
    ///
    /// That does not affect trust: discovery records carry no trust weight, and
    /// ANS-3 §9 forbids scoring an agent down for its profile choice. Trust
    /// still derives from the badge and certificate fingerprints alone.
    ///
    /// Only `NotFound` triggers the fallback — a lookup *error* propagates so
    /// an outage is never masked as a profile downgrade.
    async fn lookup_discovery(
        &self,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<DiscoveryRecord>, DnsError> {
        match self.lookup_svcb_discovery(fqdn).await? {
            DnsLookupResult::Found(records) => Ok(DnsLookupResult::Found(
                records.into_iter().map(DiscoveryRecord::Svcb).collect(),
            )),
            DnsLookupResult::NotFound => {
                tracing::debug!(
                    fqdn = %fqdn,
                    "No ANS_DNSAID SVCB discovery records, falling back to ANS_TXT"
                );
                match self.lookup_txt_discovery(fqdn).await? {
                    DnsLookupResult::Found(records) => Ok(DnsLookupResult::Found(
                        records.into_iter().map(DiscoveryRecord::Txt).collect(),
                    )),
                    DnsLookupResult::NotFound => Ok(DnsLookupResult::NotFound),
                }
            }
        }
    }

    /// Autodiscover discovery records and return them.
    /// Convenience method that unwraps the result.
    async fn get_discovery_records(&self, fqdn: &Fqdn) -> Result<Vec<DiscoveryRecord>, DnsError> {
        match self.lookup_discovery(fqdn).await? {
            DnsLookupResult::Found(records) => Ok(records),
            DnsLookupResult::NotFound => Err(DnsError::NotFound {
                fqdn: fqdn.to_string(),
            }),
        }
    }
}

/// DNS resolver implementation using hickory-resolver.
pub struct HickoryDnsResolver {
    resolver: TokioResolver,
    /// Separate resolver with DNSSEC validation for TLSA lookups.
    dnssec_resolver: TokioResolver,
}

impl fmt::Debug for HickoryDnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HickoryDnsResolver").finish_non_exhaustive()
    }
}

// The constructors below stay `async` for API consistency even though they do
// no awaiting, so callers can write `HickoryDnsResolver::with_preset(..).await`
// alongside every other resolver entry point. Clippy 1.98 split this diagnostic
// out of `unused_async` into `unused_async_trait_impl`, so both names are listed;
// `unknown_lints` keeps the newer name from warning on older toolchains (MSRV is
// 1.88).
#[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)]
impl HickoryDnsResolver {
    /// Create a new resolver with system configuration.
    ///
    /// Regular queries use the default resolver.
    /// TLSA queries use a DNSSEC-validating resolver for security.
    pub async fn new() -> Result<Self, DnsError> {
        Self::with_preset(DnsResolverConfig::System).await
    }

    /// Create a resolver with a preset configuration (Cloudflare, Google, etc.).
    ///
    /// For `System`, reads the OS DNS configuration. This uses the actual
    /// nameservers configured on the machine (not hardcoded Google DNS).
    pub async fn with_preset(preset: DnsResolverConfig) -> Result<Self, DnsError> {
        let (config, opts) = preset.to_resolver_config()?;

        let mut builder =
            TokioResolver::builder_with_config(config.clone(), TokioRuntimeProvider::default());
        *builder.options_mut() = opts.clone();
        let resolver = builder.build().map_err(|e| DnsError::LookupFailed {
            fqdn: "(resolver init)".to_string(),
            reason: e.to_string(),
        })?;

        // Create DNSSEC-validating resolver for TLSA lookups
        let mut dnssec_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let dnssec_opts = dnssec_builder.options_mut();
        *dnssec_opts = opts;
        dnssec_opts.validate = true;
        let dnssec_resolver = dnssec_builder.build().map_err(|e| DnsError::LookupFailed {
            fqdn: "(dnssec resolver init)".to_string(),
            reason: e.to_string(),
        })?;

        tracing::debug!(preset = ?preset, "Created DNS resolver");
        Ok(Self {
            resolver,
            dnssec_resolver,
        })
    }

    /// Create a resolver with custom nameserver IP addresses.
    ///
    /// # Example
    /// ```rust,no_run
    /// use ans_verify::HickoryDnsResolver;
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use custom nameservers
    /// let resolver = HickoryDnsResolver::with_nameservers(&[
    ///     Ipv4Addr::new(1, 1, 1, 1),
    ///     Ipv4Addr::new(8, 8, 8, 8),
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_nameservers(nameservers: &[Ipv4Addr]) -> Result<Self, DnsError> {
        let ips: Vec<IpAddr> = nameservers.iter().map(|ip| IpAddr::V4(*ip)).collect();

        let ns_configs: Vec<NameServerConfig> = ips
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect();
        let config = ResolverConfig::from_parts(None, vec![], ns_configs);

        let resolver =
            TokioResolver::builder_with_config(config.clone(), TokioRuntimeProvider::default())
                .build()
                .map_err(|e| DnsError::LookupFailed {
                    fqdn: "(resolver init)".to_string(),
                    reason: e.to_string(),
                })?;

        // Create DNSSEC-validating resolver for TLSA lookups
        let mut dnssec_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        dnssec_builder.options_mut().validate = true;
        let dnssec_resolver = dnssec_builder.build().map_err(|e| DnsError::LookupFailed {
            fqdn: "(dnssec resolver init)".to_string(),
            reason: e.to_string(),
        })?;

        tracing::debug!(nameservers = ?nameservers, "Created DNS resolver with custom nameservers");
        Ok(Self {
            resolver,
            dnssec_resolver,
        })
    }

    /// Create a new resolver with custom configuration.
    pub async fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Result<Self, DnsError> {
        let mut builder =
            TokioResolver::builder_with_config(config.clone(), TokioRuntimeProvider::default());
        *builder.options_mut() = opts.clone();
        let resolver = builder.build().map_err(|e| DnsError::LookupFailed {
            fqdn: "(resolver init)".to_string(),
            reason: e.to_string(),
        })?;

        // Create DNSSEC-validating resolver for TLSA lookups
        let mut dnssec_builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let dnssec_opts = dnssec_builder.options_mut();
        *dnssec_opts = opts;
        dnssec_opts.validate = true;
        let dnssec_resolver = dnssec_builder.build().map_err(|e| DnsError::LookupFailed {
            fqdn: "(dnssec resolver init)".to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self {
            resolver,
            dnssec_resolver,
        })
    }

    /// Create a resolver with DNSSEC validation enabled for all queries.
    pub async fn with_dnssec() -> Result<Self, DnsError> {
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        );
        builder.options_mut().validate = true;
        let resolver = builder.build().map_err(|e| DnsError::LookupFailed {
            fqdn: "(resolver init)".to_string(),
            reason: e.to_string(),
        })?;

        let mut dnssec_builder = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        );
        dnssec_builder.options_mut().validate = true;
        let dnssec_resolver = dnssec_builder.build().map_err(|e| DnsError::LookupFailed {
            fqdn: "(dnssec resolver init)".to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self {
            resolver,
            dnssec_resolver,
        })
    }
}

impl HickoryDnsResolver {
    /// Query TXT records at a DNS name, returning each record's
    /// character-strings concatenated (RFC 1035 §3.3.14).
    ///
    /// Returns `None` when the name has no TXT records.
    async fn query_txt_strings(
        &self,
        query_name: &str,
        fqdn: &Fqdn,
    ) -> Result<Option<Vec<String>>, DnsError> {
        let response = match self.resolver.txt_lookup(query_name).await {
            Ok(response) => response,
            Err(NetError::Dns(HickoryDnsError::NoRecordsFound(_))) => {
                return Ok(None);
            }
            Err(NetError::Timeout) => {
                return Err(DnsError::Timeout {
                    fqdn: fqdn.to_string(),
                });
            }
            Err(e) => {
                return Err(DnsError::LookupFailed {
                    fqdn: fqdn.to_string(),
                    reason: e.to_string(),
                });
            }
        };

        let strings = response
            .answers()
            .iter()
            .filter_map(|record| {
                let RData::TXT(txt) = &record.data else {
                    return None;
                };
                Some(
                    txt.txt_data
                        .iter()
                        .map(|d| String::from_utf8_lossy(d))
                        .collect::<String>(),
                )
            })
            .collect();

        Ok(Some(strings))
    }

    /// Query badge TXT records at a specific DNS name.
    async fn query_badge_txt(
        &self,
        query_name: &str,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<BadgeRecord>, DnsError> {
        let Some(strings) = self.query_txt_strings(query_name, fqdn).await? else {
            return Ok(DnsLookupResult::NotFound);
        };

        let mut records = Vec::new();
        for txt_data in strings {
            match BadgeRecord::parse(&txt_data) {
                Ok(badge) => records.push(badge),
                Err(_) => {
                    tracing::warn!(
                        fqdn = %fqdn,
                        record = %txt_data,
                        "Skipping malformed badge TXT record"
                    );
                }
            }
        }

        if records.is_empty() {
            Ok(DnsLookupResult::NotFound)
        } else {
            Ok(DnsLookupResult::Found(records))
        }
    }
}

#[allow(clippy::too_many_lines)]
#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn lookup_badge(&self, fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError> {
        // Try _ans-badge first (primary)
        let primary = fqdn.ans_badge_name();
        tracing::debug!(query = %primary, "Querying primary _ans-badge record");
        match self.query_badge_txt(&primary, fqdn).await? {
            DnsLookupResult::Found(records) => return Ok(DnsLookupResult::Found(records)),
            DnsLookupResult::NotFound => {
                // Fall back to _ra-badge (legacy)
                let fallback = fqdn.ra_badge_name();
                tracing::debug!(query = %fallback, "Primary not found, falling back to _ra-badge");
                self.query_badge_txt(&fallback, fqdn).await
            }
        }
    }

    async fn lookup_svcb_discovery(
        &self,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<SvcbDiscoveryRecord>, DnsError> {
        tracing::debug!(query = %fqdn, "Querying ANS_DNSAID SVCB discovery records");

        let response = match self.resolver.lookup(fqdn.as_str(), RecordType::SVCB).await {
            Ok(response) => response,
            Err(NetError::Dns(HickoryDnsError::NoRecordsFound(_))) => {
                return Ok(DnsLookupResult::NotFound);
            }
            Err(NetError::Timeout) => {
                return Err(DnsError::Timeout {
                    fqdn: fqdn.to_string(),
                });
            }
            Err(e) => {
                return Err(DnsError::LookupFailed {
                    fqdn: fqdn.to_string(),
                    reason: e.to_string(),
                });
            }
        };

        let rows: Vec<&SVCB> = response
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::SVCB(svcb) => Some(svcb),
                _ => None,
            })
            .collect();

        let records = collect_svcb_discovery(&rows, fqdn);
        if records.is_empty() {
            Ok(DnsLookupResult::NotFound)
        } else {
            Ok(DnsLookupResult::Found(records))
        }
    }

    async fn lookup_txt_discovery(
        &self,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<TxtDiscoveryRecord>, DnsError> {
        let query_name = fqdn.ans_discovery_name();
        tracing::debug!(query = %query_name, "Querying ANS_TXT discovery records");

        let Some(strings) = self.query_txt_strings(&query_name, fqdn).await? else {
            return Ok(DnsLookupResult::NotFound);
        };

        let mut records = Vec::new();
        for txt_data in strings {
            match TxtDiscoveryRecord::parse(&txt_data) {
                Ok(record) => records.push(record),
                Err(_) => {
                    tracing::warn!(
                        fqdn = %fqdn,
                        record = %txt_data,
                        "Skipping malformed _ans discovery TXT record"
                    );
                }
            }
        }

        if records.is_empty() {
            Ok(DnsLookupResult::NotFound)
        } else {
            Ok(DnsLookupResult::Found(records))
        }
    }

    async fn lookup_tlsa(
        &self,
        fqdn: &Fqdn,
        port: u16,
    ) -> Result<DnsLookupResult<TlsaRecord>, DnsError> {
        let query_name = fqdn.tlsa_name(port);

        // Use DNSSEC-validating resolver for TLSA lookups
        // This ensures TLSA records are protected by DNSSEC when available
        tracing::debug!(
            query = %query_name,
            "Performing DNSSEC-validated TLSA lookup"
        );

        let response = match self.dnssec_resolver.tlsa_lookup(&query_name).await {
            Ok(response) => response,
            Err(NetError::Dns(HickoryDnsError::NoRecordsFound(HickoryNoRecords {
                response_code,
                ..
            }))) => {
                // ServFail from a DNSSEC-validating resolver typically means
                // the upstream rejected a bogus DNSSEC chain. Don't treat
                // this as "not found" — surface it as a DNSSEC failure.
                if response_code == ResponseCode::ServFail {
                    tracing::error!(
                        fqdn = %fqdn,
                        "TLSA lookup returned ServFail — possible DNSSEC failure"
                    );
                    return Err(DnsError::DnssecFailed {
                        fqdn: fqdn.to_string(),
                    });
                }
                return Ok(DnsLookupResult::NotFound);
            }
            Err(NetError::Timeout) => {
                return Err(DnsError::Timeout {
                    fqdn: fqdn.to_string(),
                });
            }
            // DNSSEC negative proof — NSEC/NSEC3 authenticated denial of existence.
            Err(NetError::Dns(HickoryDnsError::Nsec { .. })) => {
                tracing::error!(
                    fqdn = %fqdn,
                    "DNSSEC validation failed for TLSA record (NSEC proof)"
                );
                return Err(DnsError::DnssecFailed {
                    fqdn: fqdn.to_string(),
                });
            }
            Err(e) => {
                // Fallback: string match for untyped DNSSEC errors.
                let err_str = e.to_string();
                if matches_dnssec_pattern(&err_str) {
                    tracing::error!(
                        fqdn = %fqdn,
                        error = %e,
                        "DNSSEC validation failed for TLSA record"
                    );
                    return Err(DnsError::DnssecFailed {
                        fqdn: fqdn.to_string(),
                    });
                }
                return Err(DnsError::LookupFailed {
                    fqdn: fqdn.to_string(),
                    reason: e.to_string(),
                });
            }
        };

        // Note: If we reach here, either:
        // 1. DNSSEC validated successfully (secure)
        // 2. Domain doesn't have DNSSEC (insecure but not bogus)
        // Hickory doesn't easily expose which case we're in at the high-level API,
        // so we log a general message. For domains without DNSSEC, the TLSA record
        // provides no cryptographic binding guarantee.
        tracing::debug!(
            fqdn = %fqdn,
            port,
            "TLSA lookup succeeded (DNSSEC validated if domain has DNSSEC)"
        );

        let mut records = Vec::new();
        for record in response.answers() {
            let RData::TLSA(tlsa) = &record.data else {
                continue;
            };
            // Build RDATA from TLSA record fields
            let mut rdata = vec![
                u8::from(tlsa.cert_usage),
                u8::from(tlsa.selector),
                u8::from(tlsa.matching),
            ];
            rdata.extend(&tlsa.cert_data);

            match TlsaRecord::from_rdata(&rdata) {
                Ok(record) => {
                    tracing::debug!(
                        fqdn = %fqdn,
                        port,
                        usage = ?record.usage,
                        selector = ?record.selector,
                        matching_type = ?record.matching_type,
                        "Parsed TLSA record"
                    );
                    records.push(record);
                }
                Err(e) => {
                    tracing::warn!(
                        fqdn = %fqdn,
                        port,
                        error = %e,
                        "Skipping malformed TLSA record"
                    );
                }
            }
        }

        if records.is_empty() {
            Ok(DnsLookupResult::NotFound)
        } else {
            Ok(DnsLookupResult::Found(records))
        }
    }
}

/// Returns true if the given error string contains patterns indicating a
/// DNSSEC validation failure. Used as a fallback when hickory-resolver
/// surfaces DNSSEC errors without a typed variant like `ProtoErrorKind::Nsec`.
fn matches_dnssec_pattern(err_str: &str) -> bool {
    err_str.contains("DNSSEC") || err_str.contains("validation")
}

/// Mock DNS resolver for testing.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default, Clone)]
pub struct MockDnsResolver {
    records: std::collections::HashMap<String, Vec<BadgeRecord>>,
    tlsa_records: std::collections::HashMap<String, Vec<TlsaRecord>>,
    svcb_discovery_records: std::collections::HashMap<String, Vec<SvcbDiscoveryRecord>>,
    txt_discovery_records: std::collections::HashMap<String, Vec<TxtDiscoveryRecord>>,
    // Interior-mutable so a resolver already shared with a verifier can
    // change behavior mid-test (e.g. records first, NXDOMAIN after a
    // simulated revocation). Clones share the error map.
    errors: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, DnsError>>>,
    tlsa_errors: std::collections::HashMap<String, DnsError>,
    svcb_discovery_errors: std::collections::HashMap<String, DnsError>,
    txt_discovery_errors: std::collections::HashMap<String, DnsError>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockDnsResolver {
    /// Create a new mock resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add badge records for an FQDN.
    pub fn with_records(mut self, fqdn: &str, records: Vec<BadgeRecord>) -> Self {
        self.records.insert(fqdn.to_lowercase(), records);
        self
    }

    /// Add TLSA records for an FQDN and port.
    pub fn with_tlsa_records(mut self, fqdn: &str, port: u16, records: Vec<TlsaRecord>) -> Self {
        let key = format!("{}:{}", fqdn.to_lowercase(), port);
        self.tlsa_records.insert(key, records);
        self
    }

    /// Add `ANS_DNSAID` SVCB discovery records for an FQDN.
    pub fn with_svcb_discovery_records(
        mut self,
        fqdn: &str,
        records: Vec<SvcbDiscoveryRecord>,
    ) -> Self {
        self.svcb_discovery_records
            .insert(fqdn.to_lowercase(), records);
        self
    }

    /// Add `ANS_TXT` discovery records for an FQDN.
    pub fn with_txt_discovery_records(
        mut self,
        fqdn: &str,
        records: Vec<TxtDiscoveryRecord>,
    ) -> Self {
        self.txt_discovery_records
            .insert(fqdn.to_lowercase(), records);
        self
    }

    /// Configure an error for an FQDN.
    pub fn with_error(self, fqdn: &str, error: DnsError) -> Self {
        self.set_error(fqdn, error);
        self
    }

    /// Set (or replace) the badge-lookup error for an FQDN after
    /// construction. Takes `&self`, so a resolver already shared with a
    /// verifier can change behavior mid-test — e.g. serve records first,
    /// then NXDOMAIN after a simulated revocation.
    pub fn set_error(&self, fqdn: &str, error: DnsError) {
        self.errors
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(fqdn.to_lowercase(), error);
    }

    /// Configure a TLSA-specific error for an FQDN and port.
    ///
    /// This allows TLSA lookups to fail independently of badge lookups.
    /// Useful for testing DNSSEC validation failures on TLSA records
    /// while badge DNS lookups succeed normally.
    pub fn with_tlsa_error(mut self, fqdn: &str, port: u16, error: DnsError) -> Self {
        let key = format!("{}:{}", fqdn.to_lowercase(), port);
        self.tlsa_errors.insert(key, error);
        self
    }

    /// Configure an error for `ANS_DNSAID` SVCB discovery lookups on an FQDN.
    ///
    /// This allows the SVCB query to fail independently of the `_ans` TXT
    /// query — useful for testing that autodiscovery propagates errors
    /// instead of silently falling back.
    pub fn with_svcb_discovery_error(mut self, fqdn: &str, error: DnsError) -> Self {
        self.svcb_discovery_errors
            .insert(fqdn.to_lowercase(), error);
        self
    }

    /// Configure an error for `ANS_TXT` discovery lookups on an FQDN.
    pub fn with_txt_discovery_error(mut self, fqdn: &str, error: DnsError) -> Self {
        self.txt_discovery_errors.insert(fqdn.to_lowercase(), error);
        self
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn lookup_badge(&self, fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError> {
        let key = fqdn.as_str().to_lowercase();

        // Check for configured error first
        if let Some(error) = self
            .errors
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
        {
            return Err(error.clone());
        }

        // Return configured records or NotFound
        match self.records.get(&key) {
            Some(records) if !records.is_empty() => Ok(DnsLookupResult::Found(records.clone())),
            _ => Ok(DnsLookupResult::NotFound),
        }
    }

    async fn lookup_tlsa(
        &self,
        fqdn: &Fqdn,
        port: u16,
    ) -> Result<DnsLookupResult<TlsaRecord>, DnsError> {
        let key = format!("{}:{}", fqdn.as_str().to_lowercase(), port);

        // Check for TLSA-specific error first (takes priority)
        if let Some(error) = self.tlsa_errors.get(&key) {
            return Err(error.clone());
        }

        // Check for general FQDN error
        if let Some(error) = self
            .errors
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&fqdn.as_str().to_lowercase())
        {
            return Err(error.clone());
        }

        // Return configured records or NotFound
        match self.tlsa_records.get(&key) {
            Some(records) if !records.is_empty() => Ok(DnsLookupResult::Found(records.clone())),
            _ => Ok(DnsLookupResult::NotFound),
        }
    }

    async fn lookup_svcb_discovery(
        &self,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<SvcbDiscoveryRecord>, DnsError> {
        let key = fqdn.as_str().to_lowercase();

        // Check for SVCB-specific error first (takes priority)
        if let Some(error) = self.svcb_discovery_errors.get(&key) {
            return Err(error.clone());
        }

        // Check for general FQDN error
        if let Some(error) = self
            .errors
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
        {
            return Err(error.clone());
        }

        // Return configured records or NotFound
        match self.svcb_discovery_records.get(&key) {
            Some(records) if !records.is_empty() => Ok(DnsLookupResult::Found(records.clone())),
            _ => Ok(DnsLookupResult::NotFound),
        }
    }

    async fn lookup_txt_discovery(
        &self,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<TxtDiscoveryRecord>, DnsError> {
        let key = fqdn.as_str().to_lowercase();

        // Check for TXT-discovery-specific error first (takes priority)
        if let Some(error) = self.txt_discovery_errors.get(&key) {
            return Err(error.clone());
        }

        // Check for general FQDN error
        if let Some(error) = self
            .errors
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
        {
            return Err(error.clone());
        }

        // Return configured records or NotFound
        match self.txt_discovery_records.get(&key) {
            Some(records) if !records.is_empty() => Ok(DnsLookupResult::Found(records.clone())),
            _ => Ok(DnsLookupResult::NotFound),
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_badge_record_with_version() {
        let txt = "v=ans-badge1; version=v1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/7b93c61c-e261-488c-89a3-f948119be0a0";
        let record = BadgeRecord::parse(txt).unwrap();

        assert_eq!(record.format_version, "ans-badge1");
        assert_eq!(record.version, Some(Version::new(1, 0, 0)));
        assert_eq!(
            record.url,
            "https://transparency.ans.godaddy.com/v1/agents/7b93c61c-e261-488c-89a3-f948119be0a0"
        );
    }

    #[test]
    fn test_parse_badge_record_without_version() {
        let txt = "v=ans-badge1; url=https://transparency.ans.ote-godaddy.com/v1/agents/835a27a8-6b20-4439-915e-668a9d36e469";
        let record = BadgeRecord::parse(txt).unwrap();

        assert_eq!(record.format_version, "ans-badge1");
        assert_eq!(record.version, None);
        assert_eq!(
            record.url,
            "https://transparency.ans.ote-godaddy.com/v1/agents/835a27a8-6b20-4439-915e-668a9d36e469"
        );
    }

    #[test]
    fn test_parse_badge_record_missing_url() {
        let txt = "v=ans-badge1; version=v1.0.0";
        assert!(BadgeRecord::parse(txt).is_err());
    }

    #[test]
    fn test_parse_badge_record_no_space_after_semicolon() {
        let txt = "v=ans-badge1;version=v1.0.0;url=https://transparency.ans.godaddy.com/v1/agents/7b93c61c-e261-488c-89a3-f948119be0a0";
        let record = BadgeRecord::parse(txt).unwrap();

        assert_eq!(record.format_version, "ans-badge1");
        assert_eq!(record.version, Some(Version::new(1, 0, 0)));
        assert_eq!(
            record.url,
            "https://transparency.ans.godaddy.com/v1/agents/7b93c61c-e261-488c-89a3-f948119be0a0"
        );
    }

    #[test]
    fn test_parse_legacy_ra_badge_format() {
        let txt = "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/test-id";
        let record = BadgeRecord::parse(txt).unwrap();

        assert_eq!(record.format_version, "ra-badge1");
        assert_eq!(record.version, Some(Version::new(1, 0, 0)));
    }

    #[tokio::test]
    async fn test_mock_resolver_found() {
        let record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: "https://example.com/badge".to_string(),
        };

        let resolver =
            MockDnsResolver::new().with_records("agent.example.com", vec![record.clone()]);

        let fqdn = Fqdn::new("agent.example.com").unwrap();
        let result = resolver.lookup_badge(&fqdn).await.unwrap();

        match result {
            DnsLookupResult::Found(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].version, Some(Version::new(1, 0, 0)));
            }
            DnsLookupResult::NotFound => panic!("Expected Found"),
        }
    }

    #[tokio::test]
    async fn test_mock_resolver_not_found() {
        let resolver = MockDnsResolver::new();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();
        let result = resolver.lookup_badge(&fqdn).await.unwrap();

        assert!(matches!(result, DnsLookupResult::NotFound));
    }

    #[tokio::test]
    async fn test_mock_resolver_error() {
        let resolver = MockDnsResolver::new().with_error(
            "error.example.com",
            DnsError::Timeout {
                fqdn: "error.example.com".to_string(),
            },
        );

        let fqdn = Fqdn::new("error.example.com").unwrap();
        let result = resolver.lookup_badge(&fqdn).await;

        assert!(matches!(result, Err(DnsError::Timeout { .. })));
    }

    #[tokio::test]
    async fn test_find_badge_for_version() {
        let v1 = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: "https://example.com/v1".to_string(),
        };
        let v2 = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 1)),
            url: "https://example.com/v2".to_string(),
        };

        let resolver = MockDnsResolver::new().with_records("agent.example.com", vec![v1, v2]);

        let fqdn = Fqdn::new("agent.example.com").unwrap();

        // Find v1.0.0
        let found = resolver
            .find_badge_for_version(&fqdn, &Version::new(1, 0, 0))
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().version, Some(Version::new(1, 0, 0)));

        // Find v1.0.1
        let found = resolver
            .find_badge_for_version(&fqdn, &Version::new(1, 0, 1))
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().version, Some(Version::new(1, 0, 1)));

        // Version not found
        let found = resolver
            .find_badge_for_version(&fqdn, &Version::new(2, 0, 0))
            .await
            .unwrap();
        assert!(found.is_none());
    }

    // -----------------------------------------------------------------
    // DNSSEC string detection regression tests (C1 from REVIEW.md)
    //
    // These verify the string patterns used to detect DNSSEC errors from
    // hickory-resolver Proto errors. If hickory changes its error wording,
    // these tests should be updated to match.
    // -----------------------------------------------------------------

    #[test]
    fn test_dnssec_pattern_matches_uppercase_dnssec() {
        assert!(matches_dnssec_pattern("DNSSEC validation failed"));
        assert!(matches_dnssec_pattern("DNSSEC error: bogus response"));
        assert!(matches_dnssec_pattern("proto error: DNSSEC"));
    }

    #[test]
    fn test_dnssec_pattern_matches_validation_keyword() {
        assert!(matches_dnssec_pattern("validation failed for record"));
        assert!(matches_dnssec_pattern("RRSIG validation error"));
        assert!(matches_dnssec_pattern("chain of trust validation failure"));
    }

    #[test]
    fn test_dnssec_pattern_known_hickory_messages() {
        // Known hickory-resolver error messages that should trigger DNSSEC
        // detection via the string-matching fallback. If these fail after a
        // hickory upgrade, update the patterns in lookup_tlsa().
        let known_messages = [
            "DNSSEC validation failed",
            "DNSSEC error",
            "validation of DNSKEY failed",
            "no DNSKEY proof for DS: validation failed",
        ];
        for msg in &known_messages {
            assert!(
                matches_dnssec_pattern(msg),
                "Expected DNSSEC pattern match for known hickory message: {msg:?}"
            );
        }
    }

    #[test]
    fn test_dnssec_pattern_does_not_match_generic_errors() {
        // These should NOT be classified as DNSSEC errors
        assert!(!matches_dnssec_pattern("connection refused"));
        assert!(!matches_dnssec_pattern("timeout"));
        assert!(!matches_dnssec_pattern("no records found"));
        assert!(!matches_dnssec_pattern("io error: broken pipe"));
        assert!(!matches_dnssec_pattern("proto error: invalid message"));
    }

    #[tokio::test]
    async fn test_mock_tlsa_dnssec_error() {
        let resolver = MockDnsResolver::new().with_tlsa_error(
            "secure.example.com",
            443,
            DnsError::DnssecFailed {
                fqdn: "secure.example.com".to_string(),
            },
        );

        let fqdn = Fqdn::new("secure.example.com").unwrap();
        let result = resolver.lookup_tlsa(&fqdn, 443).await;
        assert!(matches!(result, Err(DnsError::DnssecFailed { .. })));
    }

    /// Integration test: DNSSEC-validating resolver rejects dnssec-failed.org.
    ///
    /// dnssec-failed.org has a valid A record but intentionally broken DNSSEC.
    ///
    /// In hickory 0.25, all DNS errors surface via `ResolveErrorKind::Proto`.
    /// The upstream recursive resolver validates DNSSEC and returns ServFail
    /// for bogus chains, which hickory wraps as `ProtoErrorKind::NoRecordsFound`
    /// with `response_code: ServFail`. If hickory validates the chain itself
    /// (CD=1), it produces typed `Nsec` or string-based DNSSEC errors.
    #[tokio::test]
    #[ignore = "requires network access — run with: cargo test -p ans-verify -- --ignored"]
    async fn test_real_dnssec_chain_validation_fails() {
        use hickory_resolver::TokioResolver;
        use hickory_resolver::config::LookupIpStrategy;
        use hickory_resolver::net::{
            DnsError as HickoryDnsError, NetError, NoRecords as HickoryNoRecords,
        };

        let mut builder = TokioResolver::builder_with_config(
            hickory_resolver::config::ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        );
        let opts = builder.options_mut();
        opts.validate = true;
        opts.ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = builder.build().expect("resolver build must succeed");

        let result = resolver.lookup_ip("dnssec-failed.org.").await;
        let err = result.expect_err("dnssec-failed.org must not resolve — DNSSEC chain is broken");

        match err {
            // Upstream DNSSEC validation: resolver returns ServFail for bogus chain.
            NetError::Dns(HickoryDnsError::NoRecordsFound(HickoryNoRecords {
                response_code: ResponseCode::ServFail,
                ..
            })) => {}

            // Typed DNSSEC negative response (NSEC/NSEC3 denial).
            NetError::Dns(HickoryDnsError::Nsec { .. }) => {}

            // Client-side DNSSEC validation via string-based error.
            other => {
                let err_str = other.to_string();
                assert!(
                    matches_dnssec_pattern(&err_str),
                    "Error from dnssec-failed.org did not match DNSSEC detection patterns. \
                     Hickory may have changed error format. Error: {err_str}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_mock_tlsa_error_independent_of_badge() {
        // TLSA can fail while badge lookups succeed
        let record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: "https://example.com/badge".to_string(),
        };

        let resolver = MockDnsResolver::new()
            .with_records("agent.example.com", vec![record])
            .with_tlsa_error(
                "agent.example.com",
                443,
                DnsError::DnssecFailed {
                    fqdn: "agent.example.com".to_string(),
                },
            );

        let fqdn = Fqdn::new("agent.example.com").unwrap();

        // Badge lookup succeeds
        let badge_result = resolver.lookup_badge(&fqdn).await;
        assert!(badge_result.is_ok());

        // TLSA lookup fails with DNSSEC error
        let tlsa_result = resolver.lookup_tlsa(&fqdn, 443).await;
        assert!(matches!(tlsa_result, Err(DnsError::DnssecFailed { .. })));
    }

    // ── 4a: DnsResolverConfig presets ────────────────────────────────

    #[test]
    fn test_dns_resolver_config_default() {
        assert_eq!(DnsResolverConfig::default(), DnsResolverConfig::System);
    }

    #[test]
    fn test_cloudflare_preset() {
        let (config, _) = DnsResolverConfig::Cloudflare.to_resolver_config().unwrap();
        assert!(!config.name_servers().is_empty());
    }

    #[test]
    fn test_cloudflare_tls_preset() {
        let (config, _) = DnsResolverConfig::CloudflareTls
            .to_resolver_config()
            .unwrap();
        assert!(!config.name_servers().is_empty());
    }

    #[test]
    fn test_google_preset() {
        let (config, _) = DnsResolverConfig::Google.to_resolver_config().unwrap();
        assert!(!config.name_servers().is_empty());
    }

    #[test]
    fn test_google_tls_preset() {
        let (config, _) = DnsResolverConfig::GoogleTls.to_resolver_config().unwrap();
        assert!(!config.name_servers().is_empty());
    }

    #[test]
    fn test_quad9_preset() {
        let (config, _) = DnsResolverConfig::Quad9.to_resolver_config().unwrap();
        assert!(!config.name_servers().is_empty());
    }

    #[test]
    fn test_quad9_tls_preset() {
        let (config, _) = DnsResolverConfig::Quad9Tls.to_resolver_config().unwrap();
        assert!(!config.name_servers().is_empty());
    }

    // ── 4b: HickoryDnsResolver constructors ──────────────────────────

    #[tokio::test]
    async fn test_hickory_with_preset_cloudflare() {
        let resolver = HickoryDnsResolver::with_preset(DnsResolverConfig::Cloudflare).await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_hickory_with_preset_google() {
        let resolver = HickoryDnsResolver::with_preset(DnsResolverConfig::Google).await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_hickory_with_preset_quad9() {
        let resolver = HickoryDnsResolver::with_preset(DnsResolverConfig::Quad9).await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_hickory_with_nameservers() {
        let resolver = HickoryDnsResolver::with_nameservers(&[
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
        ])
        .await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_hickory_with_config() {
        let resolver = HickoryDnsResolver::with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            ResolverOpts::default(),
        )
        .await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_hickory_with_dnssec() {
        let resolver = HickoryDnsResolver::with_dnssec().await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_hickory_debug_format() {
        let resolver = HickoryDnsResolver::with_preset(DnsResolverConfig::Cloudflare)
            .await
            .unwrap();
        let dbg = format!("{resolver:?}");
        assert!(dbg.contains("HickoryDnsResolver"));
    }

    // ── 4c: DnsResolver trait default methods via MockDnsResolver ────

    #[tokio::test]
    async fn test_get_badge_records_found() {
        let record = BadgeRecord::new(
            "ans-badge1",
            Some(Version::new(1, 0, 0)),
            "https://example.com/badge",
        );
        let resolver = MockDnsResolver::new().with_records("agent.example.com", vec![record]);
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        let records = resolver.get_badge_records(&fqdn).await.unwrap();
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn test_get_badge_records_not_found() {
        let resolver = MockDnsResolver::new();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        let result = resolver.get_badge_records(&fqdn).await;
        assert!(matches!(result, Err(DnsError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_get_tlsa_records_found() {
        let tlsa = crate::dane::TlsaRecord::new(
            crate::dane::TlsaUsage::DomainIssuedCertificate,
            crate::dane::TlsaSelector::FullCertificate,
            crate::dane::TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        let resolver =
            MockDnsResolver::new().with_tlsa_records("agent.example.com", 443, vec![tlsa]);
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        let records = resolver.get_tlsa_records(&fqdn, 443).await.unwrap();
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn test_get_tlsa_records_not_found() {
        let resolver = MockDnsResolver::new();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        let records = resolver.get_tlsa_records(&fqdn, 443).await.unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_get_tlsa_records_error_propagation() {
        let resolver = MockDnsResolver::new().with_tlsa_error(
            "agent.example.com",
            443,
            DnsError::DnssecFailed {
                fqdn: "agent.example.com".to_string(),
            },
        );
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        let result = resolver.get_tlsa_records(&fqdn, 443).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_find_preferred_badge_newest_first() {
        let v1 = BadgeRecord::new(
            "ans-badge1",
            Some(Version::new(1, 0, 0)),
            "https://example.com/v1",
        );
        let v2 = BadgeRecord::new(
            "ans-badge1",
            Some(Version::new(2, 0, 0)),
            "https://example.com/v2",
        );
        let resolver = MockDnsResolver::new().with_records("agent.example.com", vec![v1, v2]);
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        let preferred = resolver.find_preferred_badge(&fqdn).await.unwrap().unwrap();
        assert_eq!(preferred.version(), Some(&Version::new(2, 0, 0)));
    }

    #[tokio::test]
    async fn test_find_preferred_badge_none_version_sorting() {
        // The sort puts None-version records BEFORE versioned records
        // (they act as wildcards, so they get priority)
        let versioned = BadgeRecord::new(
            "ans-badge1",
            Some(Version::new(1, 0, 0)),
            "https://example.com/v1",
        );
        let unversioned = BadgeRecord::new("ans-badge1", None, "https://example.com/unversioned");
        let resolver =
            MockDnsResolver::new().with_records("agent.example.com", vec![versioned, unversioned]);
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        let preferred = resolver.find_preferred_badge(&fqdn).await.unwrap().unwrap();
        // None-version records sort first (highest priority)
        assert_eq!(preferred.version(), None);
    }

    #[tokio::test]
    async fn test_find_preferred_badge_empty() {
        let resolver = MockDnsResolver::new();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        // get_badge_records will return NotFound error
        let result = resolver.find_preferred_badge(&fqdn).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_find_badge_for_version_none_matches_any() {
        let unversioned = BadgeRecord::new("ans-badge1", None, "https://example.com/badge");
        let resolver = MockDnsResolver::new().with_records("agent.example.com", vec![unversioned]);
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        let found = resolver
            .find_badge_for_version(&fqdn, &Version::new(99, 0, 0))
            .await
            .unwrap();
        assert!(found.is_some());
    }

    // ── 4d: BadgeRecord accessors ────────────────────────────────────

    #[test]
    fn test_badge_record_accessors() {
        let record = BadgeRecord::new(
            "ans-badge1",
            Some(Version::new(1, 2, 3)),
            "https://example.com/badge",
        );
        assert_eq!(record.format_version(), "ans-badge1");
        assert_eq!(record.version(), Some(&Version::new(1, 2, 3)));
        assert_eq!(record.url(), "https://example.com/badge");
    }

    #[test]
    fn test_badge_record_no_version() {
        let record = BadgeRecord::new("ra-badge1", None, "https://example.com/badge");
        assert_eq!(record.version(), None);
    }

    // -----------------------------------------------------------------
    // Discovery records: ANS_DNSAID (SVCB) and ANS_TXT (`_ans` TXT)
    //
    // Wire shapes are normative per the ans-registry discovery profiles:
    // - discovery-profiles/ans-dnsaid.md (SVCB, DNS-AID SvcParams)
    // - discovery-profiles/ans-txt.md (`_ans` TXT rows)
    // - ans-3-dns-publication.md §3.1 (discoverer fallback chain)
    // -----------------------------------------------------------------

    use hickory_resolver::proto::rr::Name;
    use hickory_resolver::proto::rr::rdata::svcb::{
        Alpn, SVCB, SvcParamKey, SvcParamValue, Unknown,
    };

    /// SHA-256 digest from the ans-dnsaid.md §10 worked example:
    /// `SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27`
    const SAMPLE_DIGEST: [u8; 32] = [
        0x09, 0x8d, 0x65, 0x0c, 0xc6, 0xd2, 0x80, 0xde, 0xe4, 0xc0, 0xf4, 0x74, 0x89, 0xa7, 0x5c,
        0xf1, 0x7b, 0x9b, 0xfb, 0xba, 0xe5, 0x30, 0x51, 0x80, 0x6d, 0x4e, 0x08, 0x41, 0x08, 0xb2,
        0xff, 0x27,
    ];
    /// `base64url(SAMPLE_DIGEST)`, no padding — as it appears in key65401.
    const SAMPLE_DIGEST_B64URL: &str = "CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc";

    /// Build a DNS-AID Private-Use `SvcParam` (key65400–key65409).
    fn dnsaid_param(key: u16, value: &str) -> (SvcParamKey, SvcParamValue) {
        (
            SvcParamKey::Key(key),
            SvcParamValue::Unknown(Unknown(value.as_bytes().to_vec())),
        )
    }

    fn alpn_param(token: &str) -> (SvcParamKey, SvcParamValue) {
        (
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec![token.to_string()])),
        )
    }

    fn port_param(port: u16) -> (SvcParamKey, SvcParamValue) {
        (SvcParamKey::Port, SvcParamValue::Port(port))
    }

    // ── AgentProtocol token mapping ──────────────────────────────────

    #[test]
    fn test_agent_protocol_from_token() {
        assert_eq!(AgentProtocol::from_token("a2a"), AgentProtocol::A2a);
        assert_eq!(AgentProtocol::from_token("mcp"), AgentProtocol::Mcp);
        // ANS_TXT spells the HTTP protocol `http-api`; ANS_DNSAID spells it
        // `x-http`. Both normalize to the same variant.
        assert_eq!(
            AgentProtocol::from_token("http-api"),
            AgentProtocol::HttpApi
        );
        assert_eq!(AgentProtocol::from_token("x-http"), AgentProtocol::HttpApi);
        // Future/extension tokens pass through unchanged.
        assert_eq!(
            AgentProtocol::from_token("x-grpc"),
            AgentProtocol::Other("x-grpc".to_string())
        );
    }

    // ── SvcbDiscoveryRecord::from_rdata ──────────────────────────────

    /// Full A2A row from the ans-dnsaid.md §10 worked example:
    /// `1 . alpn=a2a port=443 key65400=… key65401=… key65402=a2a key65409=agent-card.json`
    #[test]
    fn test_svcb_from_rdata_full_row() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                dnsaid_param(
                    65400,
                    "https://agent.example.com/.well-known/agent-card.json",
                ),
                dnsaid_param(65401, SAMPLE_DIGEST_B64URL),
                dnsaid_param(65402, "a2a"),
                dnsaid_param(65409, "agent-card.json"),
            ],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.priority(), 1);
        assert_eq!(record.target_name(), ".");
        assert_eq!(record.protocol_token(), "a2a");
        assert_eq!(record.protocol(), AgentProtocol::A2a);
        assert_eq!(record.port(), Some(443));
        assert_eq!(
            record.metadata_url(),
            Some("https://agent.example.com/.well-known/agent-card.json")
        );
        assert_eq!(record.metadata_sha256(), Some(&SAMPLE_DIGEST));
        assert_eq!(record.well_known(), Some("agent-card.json"));
    }

    /// Minimal MCP row from the worked example: `1 . alpn=mcp port=443 key65402=mcp`.
    #[test]
    fn test_svcb_from_rdata_minimal_row() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("mcp"),
                port_param(443),
                dnsaid_param(65402, "mcp"),
            ],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.protocol_token(), "mcp");
        assert_eq!(record.protocol(), AgentProtocol::Mcp);
        assert_eq!(record.port(), Some(443));
        assert_eq!(record.metadata_url(), None);
        assert_eq!(record.metadata_sha256(), None);
        assert_eq!(record.well_known(), None);
    }

    /// key65402 (bap) is the authoritative protocol field; alpn is the fallback
    /// when bap is absent.
    #[test]
    fn test_svcb_from_rdata_protocol_falls_back_to_alpn() {
        let svcb = SVCB::new(1, Name::root(), vec![alpn_param("a2a"), port_param(443)]);

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.protocol_token(), "a2a");
    }

    /// bap wins over alpn when both are present and disagree.
    #[test]
    fn test_svcb_from_rdata_bap_authoritative_over_alpn() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("h2"),
                port_param(443),
                dnsaid_param(65402, "mcp"),
            ],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.protocol_token(), "mcp");
    }

    /// A row with neither bap nor alpn carries no ANS protocol — malformed.
    #[test]
    fn test_svcb_from_rdata_missing_protocol() {
        let svcb = SVCB::new(1, Name::root(), vec![port_param(443)]);
        assert!(SvcbDiscoveryRecord::from_rdata(&svcb).is_err());
    }

    /// An empty bap value with no alpn is treated as a missing protocol.
    #[test]
    fn test_svcb_from_rdata_empty_bap_is_missing() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![port_param(443), dnsaid_param(65402, "")],
        );
        assert!(SvcbDiscoveryRecord::from_rdata(&svcb).is_err());
    }

    /// Non-UTF-8 bap bytes are ignored in favor of the alpn fallback.
    #[test]
    fn test_svcb_from_rdata_invalid_utf8_bap_falls_back_to_alpn() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                (
                    SvcParamKey::Key(65402),
                    SvcParamValue::Unknown(Unknown(vec![0xff, 0xfe])),
                ),
            ],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.protocol_token(), "a2a");
    }

    /// `AliasMode` rows (`SvcPriority` 0) are not ANS discovery rows.
    #[test]
    fn test_svcb_from_rdata_alias_mode_rejected() {
        let target = Name::from_utf8("svc.example.net.").unwrap();
        let svcb = SVCB::new(0, target, vec![]);
        assert!(SvcbDiscoveryRecord::from_rdata(&svcb).is_err());
    }

    /// A port param is optional at the RFC 9460 level; absent means
    /// "authority endpoint's port" (the scheme default).
    #[test]
    fn test_svcb_from_rdata_no_port() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![alpn_param("mcp"), dnsaid_param(65402, "mcp")],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.port(), None);
    }

    /// A malformed cap-sha256 (bad base64url) drops the digest but keeps
    /// the row — connection info is still valid.
    #[test]
    fn test_svcb_from_rdata_invalid_digest_base64_dropped() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                dnsaid_param(65401, "!!!not-base64url!!!"),
                dnsaid_param(65402, "a2a"),
            ],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.metadata_sha256(), None);
    }

    /// A digest that decodes to the wrong length is dropped.
    #[test]
    fn test_svcb_from_rdata_wrong_length_digest_dropped() {
        // base64url of 16 bytes, not 32
        let short = "AAAAAAAAAAAAAAAAAAAAAA";
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                dnsaid_param(65401, short),
                dnsaid_param(65402, "a2a"),
            ],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.metadata_sha256(), None);
    }

    /// A cap URL that is not a valid URL is dropped; the row survives.
    #[test]
    fn test_svcb_from_rdata_invalid_metadata_url_dropped() {
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                dnsaid_param(65400, "not a url"),
                dnsaid_param(65402, "a2a"),
            ],
        );

        let record = SvcbDiscoveryRecord::from_rdata(&svcb).unwrap();
        assert_eq!(record.metadata_url(), None);
    }

    // ── SvcbDiscoveryRecord::from_parts ──────────────────────────────

    /// The production constructor for third-party resolvers: plain values in,
    /// optional DNS-AID params attached through the builders.
    #[test]
    fn test_svcb_from_parts_full_row() {
        let record = SvcbDiscoveryRecord::from_parts(1, ".", "a2a", Some(443))
            .unwrap()
            .with_metadata_url("https://agent.example.com/.well-known/agent-card.json")
            .with_metadata_sha256(SAMPLE_DIGEST)
            .with_well_known("agent-card.json");

        assert_eq!(record.priority(), 1);
        assert_eq!(record.target_name(), ".");
        assert_eq!(record.protocol_token(), "a2a");
        assert_eq!(record.protocol(), AgentProtocol::A2a);
        assert_eq!(record.port(), Some(443));
        assert_eq!(
            record.metadata_url(),
            Some("https://agent.example.com/.well-known/agent-card.json")
        );
        assert_eq!(record.metadata_sha256(), Some(&SAMPLE_DIGEST));
        assert_eq!(record.well_known(), Some("agent-card.json"));
    }

    /// Without the builders, the optional params stay absent, and `None` port
    /// means "scheme default" rather than a sentinel value.
    #[test]
    fn test_svcb_from_parts_minimal_row() {
        let record = SvcbDiscoveryRecord::from_parts(3, "svc.example.net.", "mcp", None).unwrap();

        assert_eq!(record.priority(), 3);
        assert_eq!(record.target_name(), "svc.example.net.");
        assert_eq!(record.protocol(), AgentProtocol::Mcp);
        assert_eq!(record.port(), None);
        assert_eq!(record.metadata_url(), None);
        assert_eq!(record.metadata_sha256(), None);
        assert_eq!(record.well_known(), None);
    }

    /// `from_parts` enforces the same invariants as `from_rdata`, so the
    /// `priority() >= 1` guarantee holds for externally built records too.
    #[test]
    fn test_svcb_from_parts_alias_mode_rejected() {
        assert!(SvcbDiscoveryRecord::from_parts(0, "svc.example.net.", "a2a", Some(443)).is_err());
    }

    /// A row with no protocol token carries no ANS endpoint.
    #[test]
    fn test_svcb_from_parts_empty_protocol_rejected() {
        assert!(SvcbDiscoveryRecord::from_parts(1, ".", "", Some(443)).is_err());
    }

    /// Unknown tokens normalize to `Other` but the raw token is preserved,
    /// same as when the row arrives over the wire.
    #[test]
    fn test_svcb_from_parts_preserves_unknown_token() {
        let record = SvcbDiscoveryRecord::from_parts(1, ".", "x-custom", None).unwrap();
        assert_eq!(record.protocol_token(), "x-custom");
        assert_eq!(
            record.protocol(),
            AgentProtocol::Other("x-custom".to_string())
        );
    }

    // ── RRset-level SVCB handling (RFC 9460 §2.4.1) ──────────────────

    /// If an `RRset` contains an `AliasMode` record, all `ServiceMode` records
    /// in the set MUST be ignored.
    #[test]
    fn test_collect_svcb_alias_mode_poisons_rrset() {
        let fqdn = Fqdn::new("agent.example.com").unwrap();
        let alias = SVCB::new(0, Name::from_utf8("svc.example.net.").unwrap(), vec![]);
        let service = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                dnsaid_param(65402, "a2a"),
            ],
        );

        let records = collect_svcb_discovery(&[&alias, &service], &fqdn);
        assert!(records.is_empty());
    }

    /// Malformed rows are skipped; valid siblings survive.
    #[test]
    fn test_collect_svcb_skips_malformed_rows() {
        let fqdn = Fqdn::new("agent.example.com").unwrap();
        let valid = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                dnsaid_param(65402, "a2a"),
            ],
        );
        let malformed = SVCB::new(1, Name::root(), vec![port_param(8443)]);

        let records = collect_svcb_discovery(&[&valid, &malformed], &fqdn);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].protocol_token(), "a2a");
    }

    /// A multi-endpoint `RRset` yields one record per row.
    #[test]
    fn test_collect_svcb_multi_endpoint() {
        let fqdn = Fqdn::new("agent.example.com").unwrap();
        let a2a = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("a2a"),
                port_param(443),
                dnsaid_param(65402, "a2a"),
            ],
        );
        let mcp = SVCB::new(
            1,
            Name::root(),
            vec![
                alpn_param("mcp"),
                port_param(8443),
                dnsaid_param(65402, "mcp"),
            ],
        );

        let records = collect_svcb_discovery(&[&a2a, &mcp], &fqdn);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].port(), Some(443));
        assert_eq!(records[1].port(), Some(8443));
    }

    // ── TxtDiscoveryRecord::parse ────────────────────────────────────

    #[test]
    fn test_parse_txt_discovery_full_row() {
        let txt = "v=ans1; version=v2.1.0; p=a2a; mode=direct; url=https://agent.example.com/a2a";
        let record = TxtDiscoveryRecord::parse(txt).unwrap();

        assert_eq!(record.format_version(), "ans1");
        assert_eq!(record.version(), Some(&Version::new(2, 1, 0)));
        assert_eq!(record.protocol_token(), "a2a");
        assert_eq!(record.protocol(), AgentProtocol::A2a);
        assert_eq!(record.mode(), Some("direct"));
        assert_eq!(record.url(), "https://agent.example.com/a2a");
    }

    #[test]
    fn test_parse_txt_discovery_no_spaces() {
        let txt = "v=ans1;version=v1.0.0;p=mcp;mode=direct;url=https://agent.example.com:8443/mcp";
        let record = TxtDiscoveryRecord::parse(txt).unwrap();

        assert_eq!(record.protocol_token(), "mcp");
        assert_eq!(record.url(), "https://agent.example.com:8443/mcp");
    }

    #[test]
    fn test_parse_txt_discovery_http_api_token() {
        let txt =
            "v=ans1; version=v1.0.0; p=http-api; mode=direct; url=https://agent.example.com/api";
        let record = TxtDiscoveryRecord::parse(txt).unwrap();
        assert_eq!(record.protocol(), AgentProtocol::HttpApi);
    }

    #[test]
    fn test_parse_txt_discovery_missing_version_is_lenient() {
        let txt = "v=ans1; p=a2a; mode=direct; url=https://agent.example.com/a2a";
        let record = TxtDiscoveryRecord::parse(txt).unwrap();
        assert_eq!(record.version(), None);
    }

    #[test]
    fn test_parse_txt_discovery_missing_url() {
        let txt = "v=ans1; version=v1.0.0; p=a2a; mode=direct";
        assert!(TxtDiscoveryRecord::parse(txt).is_err());
    }

    #[test]
    fn test_parse_txt_discovery_missing_protocol() {
        let txt = "v=ans1; version=v1.0.0; mode=direct; url=https://agent.example.com/a2a";
        assert!(TxtDiscoveryRecord::parse(txt).is_err());
    }

    #[test]
    fn test_parse_txt_discovery_missing_format_version() {
        let txt = "version=v1.0.0; p=a2a; mode=direct; url=https://agent.example.com/a2a";
        assert!(TxtDiscoveryRecord::parse(txt).is_err());
    }

    #[test]
    fn test_parse_txt_discovery_invalid_url() {
        let txt = "v=ans1; version=v1.0.0; p=a2a; mode=direct; url=not-a-url";
        assert!(TxtDiscoveryRecord::parse(txt).is_err());
    }

    // ── DiscoveryRecord unified accessors ────────────────────────────

    #[test]
    fn test_discovery_record_accessors() {
        let svcb = DiscoveryRecord::Svcb(SvcbDiscoveryRecord::new("x-http", 443));
        assert_eq!(svcb.protocol_token(), "x-http");
        assert_eq!(svcb.protocol(), AgentProtocol::HttpApi);
        assert_eq!(svcb.profile_id(), "ANS_DNSAID");

        let txt = DiscoveryRecord::Txt(TxtDiscoveryRecord::new(
            "ans1",
            Some(Version::new(1, 0, 0)),
            "http-api",
            "https://agent.example.com/api",
        ));
        assert_eq!(txt.protocol_token(), "http-api");
        assert_eq!(txt.protocol(), AgentProtocol::HttpApi);
        assert_eq!(txt.profile_id(), "ANS_TXT");
    }

    // ── Mock resolver: per-profile lookups ───────────────────────────

    #[tokio::test]
    async fn test_mock_svcb_discovery_found() {
        let record = SvcbDiscoveryRecord::new("a2a", 443)
            .with_metadata_url("https://agent.example.com/.well-known/agent-card.json")
            .with_metadata_sha256(SAMPLE_DIGEST)
            .with_well_known("agent-card.json");

        let resolver =
            MockDnsResolver::new().with_svcb_discovery_records("agent.example.com", vec![record]);
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        match resolver.lookup_svcb_discovery(&fqdn).await.unwrap() {
            DnsLookupResult::Found(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].protocol_token(), "a2a");
                assert_eq!(records[0].metadata_sha256(), Some(&SAMPLE_DIGEST));
            }
            DnsLookupResult::NotFound => panic!("Expected Found"),
        }
    }

    #[tokio::test]
    async fn test_mock_txt_discovery_found() {
        let record = TxtDiscoveryRecord::new(
            "ans1",
            Some(Version::new(1, 0, 0)),
            "a2a",
            "https://agent.example.com/a2a",
        );

        let resolver =
            MockDnsResolver::new().with_txt_discovery_records("agent.example.com", vec![record]);
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        match resolver.lookup_txt_discovery(&fqdn).await.unwrap() {
            DnsLookupResult::Found(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].url(), "https://agent.example.com/a2a");
            }
            DnsLookupResult::NotFound => panic!("Expected Found"),
        }
    }

    #[tokio::test]
    async fn test_mock_discovery_lookups_not_found() {
        let resolver = MockDnsResolver::new();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        assert!(matches!(
            resolver.lookup_svcb_discovery(&fqdn).await.unwrap(),
            DnsLookupResult::NotFound
        ));
        assert!(matches!(
            resolver.lookup_txt_discovery(&fqdn).await.unwrap(),
            DnsLookupResult::NotFound
        ));
    }

    // ── Autodiscovery chain (SDK probe order) ────────────────────────

    /// SVCB is probed first; when present it wins.
    #[tokio::test]
    async fn test_lookup_discovery_prefers_svcb() {
        let resolver = MockDnsResolver::new()
            .with_svcb_discovery_records(
                "agent.example.com",
                vec![SvcbDiscoveryRecord::new("a2a", 443)],
            )
            .with_txt_discovery_records(
                "agent.example.com",
                vec![TxtDiscoveryRecord::new(
                    "ans1",
                    None,
                    "a2a",
                    "https://agent.example.com/a2a",
                )],
            );
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        match resolver.lookup_discovery(&fqdn).await.unwrap() {
            DnsLookupResult::Found(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].profile_id(), "ANS_DNSAID");
            }
            DnsLookupResult::NotFound => panic!("Expected Found"),
        }
    }

    /// No SVCB records → fall back to the `_ans` TXT profile.
    #[tokio::test]
    async fn test_lookup_discovery_falls_back_to_txt() {
        let resolver = MockDnsResolver::new().with_txt_discovery_records(
            "agent.example.com",
            vec![TxtDiscoveryRecord::new(
                "ans1",
                Some(Version::new(1, 0, 0)),
                "mcp",
                "https://agent.example.com/mcp",
            )],
        );
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        match resolver.lookup_discovery(&fqdn).await.unwrap() {
            DnsLookupResult::Found(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].profile_id(), "ANS_TXT");
            }
            DnsLookupResult::NotFound => panic!("Expected Found"),
        }
    }

    #[tokio::test]
    async fn test_lookup_discovery_neither_profile_published() {
        let resolver = MockDnsResolver::new();
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        assert!(matches!(
            resolver.lookup_discovery(&fqdn).await.unwrap(),
            DnsLookupResult::NotFound
        ));
    }

    /// An SVCB lookup *error* (not NotFound) propagates — no silent TXT
    /// fallback that could mask infrastructure problems.
    #[tokio::test]
    async fn test_lookup_discovery_svcb_error_propagates() {
        let resolver = MockDnsResolver::new()
            .with_svcb_discovery_error(
                "agent.example.com",
                DnsError::Timeout {
                    fqdn: "agent.example.com".to_string(),
                },
            )
            .with_txt_discovery_records(
                "agent.example.com",
                vec![TxtDiscoveryRecord::new(
                    "ans1",
                    None,
                    "a2a",
                    "https://agent.example.com/a2a",
                )],
            );
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        assert!(matches!(
            resolver.lookup_discovery(&fqdn).await,
            Err(DnsError::Timeout { .. })
        ));
    }

    #[tokio::test]
    async fn test_lookup_discovery_txt_error_propagates() {
        let resolver = MockDnsResolver::new().with_txt_discovery_error(
            "agent.example.com",
            DnsError::LookupFailed {
                fqdn: "agent.example.com".to_string(),
                reason: "boom".to_string(),
            },
        );
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        assert!(matches!(
            resolver.lookup_discovery(&fqdn).await,
            Err(DnsError::LookupFailed { .. })
        ));
    }

    /// The mock's general per-FQDN error applies to discovery lookups too,
    /// consistent with badge and TLSA lookups.
    #[tokio::test]
    async fn test_mock_general_error_applies_to_discovery() {
        let resolver = MockDnsResolver::new().with_error(
            "agent.example.com",
            DnsError::Timeout {
                fqdn: "agent.example.com".to_string(),
            },
        );
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        assert!(resolver.lookup_svcb_discovery(&fqdn).await.is_err());
        assert!(resolver.lookup_txt_discovery(&fqdn).await.is_err());
    }

    #[tokio::test]
    async fn test_get_discovery_records_found() {
        let resolver = MockDnsResolver::new().with_svcb_discovery_records(
            "agent.example.com",
            vec![
                SvcbDiscoveryRecord::new("a2a", 443),
                SvcbDiscoveryRecord::new("mcp", 8443),
            ],
        );
        let fqdn = Fqdn::new("agent.example.com").unwrap();

        let records = resolver.get_discovery_records(&fqdn).await.unwrap();
        assert_eq!(records.len(), 2);
    }

    #[tokio::test]
    async fn test_get_discovery_records_not_found_is_error() {
        let resolver = MockDnsResolver::new();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        let result = resolver.get_discovery_records(&fqdn).await;
        assert!(matches!(result, Err(DnsError::NotFound { .. })));
    }
}
