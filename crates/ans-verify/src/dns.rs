//! DNS resolution for `_ans-badge` / `_ra-badge` TXT records and TLSA records.

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    CLOUDFLARE, GOOGLE, NameServerConfig, QUAD9, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError, NoRecords as HickoryNoRecords};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RData;
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
            Self::Cloudflare => Ok((ResolverConfig::udp_and_tcp(&CLOUDFLARE), ResolverOpts::default())),
            Self::CloudflareTls => Ok((ResolverConfig::tls(&CLOUDFLARE), ResolverOpts::default())),
            Self::Google => Ok((ResolverConfig::udp_and_tcp(&GOOGLE), ResolverOpts::default())),
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

/// DNS lookup result distinguishing between "not found" and "error".
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DnsLookupResult<T> {
    /// Records were found.
    Found(Vec<T>),
    /// Record does not exist (NXDOMAIN).
    NotFound,
}

/// DNS resolver trait for looking up badge records and TLSA records.
///
/// Badge records are queried from `_ans-badge.{fqdn}` (primary) with
/// fallback to `_ra-badge.{fqdn}` (legacy).
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

#[allow(clippy::unused_async)] // kept async for API consistency; callers use .await
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

        let name_servers: Vec<NameServerConfig> = ips
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect();
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

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
    /// Query badge TXT records at a specific DNS name.
    async fn query_badge_txt(
        &self,
        query_name: &str,
        fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<BadgeRecord>, DnsError> {
        let response = match self.resolver.txt_lookup(query_name).await {
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

        let mut records = Vec::new();
        for record in response.answers() {
            let RData::TXT(txt) = &record.data else {
                continue;
            };
            let txt_data: String = txt
                .txt_data
                .iter()
                .map(|d| String::from_utf8_lossy(d).to_string())
                .collect::<String>();

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
    errors: std::collections::HashMap<String, DnsError>,
    tlsa_errors: std::collections::HashMap<String, DnsError>,
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

    /// Configure an error for an FQDN.
    pub fn with_error(mut self, fqdn: &str, error: DnsError) -> Self {
        self.errors.insert(fqdn.to_lowercase(), error);
        self
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
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn lookup_badge(&self, fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError> {
        let key = fqdn.as_str().to_lowercase();

        // Check for configured error first
        if let Some(error) = self.errors.get(&key) {
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
        if let Some(error) = self.errors.get(&fqdn.as_str().to_lowercase()) {
            return Err(error.clone());
        }

        // Return configured records or NotFound
        match self.tlsa_records.get(&key) {
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
        use hickory_resolver::net::{DnsError as HickoryDnsError, NetError, NoRecords as HickoryNoRecords};

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
        let resolver =
            HickoryDnsResolver::with_config(ResolverConfig::udp_and_tcp(&CLOUDFLARE), ResolverOpts::default())
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
}
