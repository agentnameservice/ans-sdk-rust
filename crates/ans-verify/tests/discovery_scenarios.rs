#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Discovery-record scenarios for the two DNS discovery profiles.
//!
//! The SDK probes the `ANS_DNSAID` SVCB rows at the agent's FQDN first, then
//! falls back to the `ANS_TXT` `_ans.{fqdn}` TXT records, stopping at the
//! first source that resolves. That order is an SDK convention, not a spec
//! ranking — `ANS_DNSAID` is the default profile per ANS-3 §6.1.
//!
//! All DNS is mocked; each scenario exercises the public API.

use ans_types::{Fqdn, Version};
use ans_verify::{
    AgentProtocol, BadgeRecord, DiscoveryRecord, DnsError, DnsLookupResult, DnsResolver,
    MockDnsResolver, SvcbDiscoveryRecord, TlsaRecord, TxtDiscoveryRecord,
};
use async_trait::async_trait;

const AGENT: &str = "agent.example.com";

fn fqdn() -> Fqdn {
    Fqdn::new(AGENT).unwrap()
}

/// D1: an agent on the default `ANS_DNSAID` profile is discovered through its
/// SVCB rows, including the DNS-AID capability locator params.
#[tokio::test]
async fn test_d1_dnsaid_only_agent_discovered_via_svcb() {
    let digest = [0xAB; 32];
    let resolver = MockDnsResolver::new().with_svcb_discovery_records(
        AGENT,
        vec![
            SvcbDiscoveryRecord::new("a2a", 443)
                .with_metadata_url("https://agent.example.com/.well-known/agent-card.json")
                .with_metadata_sha256(digest)
                .with_well_known("agent-card.json"),
            SvcbDiscoveryRecord::new("mcp", 8443),
        ],
    );

    let records = resolver.get_discovery_records(&fqdn()).await.unwrap();
    assert_eq!(records.len(), 2);

    let DiscoveryRecord::Svcb(a2a) = &records[0] else {
        panic!("expected SVCB record");
    };
    assert_eq!(a2a.protocol(), AgentProtocol::A2a);
    assert_eq!(a2a.port(), Some(443));
    assert_eq!(
        a2a.metadata_url(),
        Some("https://agent.example.com/.well-known/agent-card.json")
    );
    assert_eq!(a2a.metadata_sha256(), Some(&digest));
    assert_eq!(a2a.well_known(), Some("agent-card.json"));

    let DiscoveryRecord::Svcb(mcp) = &records[1] else {
        panic!("expected SVCB record");
    };
    assert_eq!(mcp.protocol(), AgentProtocol::Mcp);
    assert_eq!(mcp.port(), Some(8443));
    assert_eq!(mcp.metadata_url(), None);
}

/// D2: an operator publishing only the opt-in `ANS_TXT` profile is
/// discovered through the fallback probe.
#[tokio::test]
async fn test_d2_txt_only_agent_discovered_via_fallback() {
    let resolver = MockDnsResolver::new().with_txt_discovery_records(
        AGENT,
        vec![TxtDiscoveryRecord::new(
            "ans1",
            Some(Version::new(2, 1, 0)),
            "a2a",
            "https://agent.example.com/a2a",
        )],
    );

    let records = resolver.get_discovery_records(&fqdn()).await.unwrap();
    assert_eq!(records.len(), 1);

    let DiscoveryRecord::Txt(txt) = &records[0] else {
        panic!("expected TXT record");
    };
    assert_eq!(txt.format_version(), "ans1");
    assert_eq!(txt.version(), Some(&Version::new(2, 1, 0)));
    assert_eq!(txt.mode(), Some("direct"));
    assert_eq!(txt.url(), "https://agent.example.com/a2a");
}

/// D3: during the `["ANS_DNSAID", "ANS_TXT"]` transition union both record
/// families are published; the chain stops at the first source found, so
/// SVCB wins and the TXT rows are never consumed.
#[tokio::test]
async fn test_d3_transition_union_prefers_svcb() {
    let resolver = MockDnsResolver::new()
        .with_svcb_discovery_records(AGENT, vec![SvcbDiscoveryRecord::new("a2a", 443)])
        .with_txt_discovery_records(
            AGENT,
            vec![TxtDiscoveryRecord::new(
                "ans1",
                Some(Version::new(2, 1, 0)),
                "a2a",
                "https://agent.example.com/a2a",
            )],
        );

    let records = resolver.get_discovery_records(&fqdn()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].profile_id(), "ANS_DNSAID");
}

/// D4: an agent with no discovery records at all reports NotFound rather
/// than an error, so callers can distinguish "not published" from "DNS broke".
#[tokio::test]
async fn test_d4_no_discovery_records() {
    let resolver = MockDnsResolver::new();

    assert!(matches!(
        resolver.lookup_discovery(&fqdn()).await.unwrap(),
        DnsLookupResult::NotFound
    ));
    assert!(matches!(
        resolver.get_discovery_records(&fqdn()).await,
        Err(DnsError::NotFound { .. })
    ));
}

/// D5: a transport error on the SVCB query propagates instead of silently
/// falling back to TXT — masking an outage as a profile downgrade would
/// hide infrastructure problems.
#[tokio::test]
async fn test_d5_svcb_error_does_not_fall_back() {
    let resolver = MockDnsResolver::new()
        .with_svcb_discovery_error(
            AGENT,
            DnsError::Timeout {
                fqdn: AGENT.to_string(),
            },
        )
        .with_txt_discovery_records(
            AGENT,
            vec![TxtDiscoveryRecord::new(
                "ans1",
                None,
                "a2a",
                "https://agent.example.com/a2a",
            )],
        );

    assert!(matches!(
        resolver.lookup_discovery(&fqdn()).await,
        Err(DnsError::Timeout { .. })
    ));
}

/// D6: the two profiles spell the HTTP protocol differently (`x-http` on
/// SVCB, `http-api` on TXT); both normalize to `AgentProtocol::HttpApi` so
/// callers match on one variant regardless of profile.
#[tokio::test]
async fn test_d6_http_protocol_normalized_across_profiles() {
    let svcb = DiscoveryRecord::Svcb(SvcbDiscoveryRecord::new("x-http", 443));
    let txt = DiscoveryRecord::Txt(TxtDiscoveryRecord::new(
        "ans1",
        None,
        "http-api",
        "https://agent.example.com/api",
    ));

    assert_eq!(svcb.protocol(), AgentProtocol::HttpApi);
    assert_eq!(txt.protocol(), AgentProtocol::HttpApi);
    // The raw wire tokens remain observable for callers that need them.
    assert_eq!(svcb.protocol_token(), "x-http");
    assert_eq!(txt.protocol_token(), "http-api");
}

/// D7: discovery lookups coexist with badge lookups on the same resolver —
/// the discovery plane never affects the trust plane.
#[tokio::test]
async fn test_d7_discovery_and_badge_lookups_are_independent() {
    let resolver = MockDnsResolver::new()
        .with_records(
            AGENT,
            vec![BadgeRecord::new(
                "ans-badge1",
                Some(Version::new(1, 0, 0)),
                "https://tlog.example.com/v1/agents/some-uuid",
            )],
        )
        .with_svcb_discovery_records(AGENT, vec![SvcbDiscoveryRecord::new("a2a", 443)]);

    let badges = resolver.get_badge_records(&fqdn()).await.unwrap();
    assert_eq!(badges.len(), 1);

    let discovery = resolver.get_discovery_records(&fqdn()).await.unwrap();
    assert_eq!(discovery.len(), 1);
    assert_eq!(discovery[0].profile_id(), "ANS_DNSAID");
}

/// A third-party `DnsResolver` written before discovery existed: it implements
/// only the two required methods. This has to keep compiling, which is what
/// makes the discovery additions additive rather than a breaking change.
struct TrustOnlyResolver;

#[async_trait]
impl DnsResolver for TrustOnlyResolver {
    async fn lookup_badge(&self, _fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError> {
        Ok(DnsLookupResult::NotFound)
    }

    async fn lookup_tlsa(
        &self,
        _fqdn: &Fqdn,
        _port: u16,
    ) -> Result<DnsLookupResult<TlsaRecord>, DnsError> {
        Ok(DnsLookupResult::NotFound)
    }
}

/// D8: a resolver that implements neither discovery method still satisfies the
/// trait, and reports "no discovery records" rather than failing.
#[tokio::test]
async fn test_d8_resolver_without_discovery_methods_compiles() {
    let resolver = TrustOnlyResolver;

    assert!(matches!(
        resolver.lookup_svcb_discovery(&fqdn()).await.unwrap(),
        DnsLookupResult::NotFound
    ));
    assert!(matches!(
        resolver.lookup_txt_discovery(&fqdn()).await.unwrap(),
        DnsLookupResult::NotFound
    ));
    assert!(matches!(
        resolver.lookup_discovery(&fqdn()).await.unwrap(),
        DnsLookupResult::NotFound
    ));
}

/// A resolver that reads SVCB rows from somewhere other than hickory — a
/// zone file, a config blob, another DNS library — and builds records with
/// the public `from_parts` constructor.
struct ExternalSvcbResolver;

#[async_trait]
impl DnsResolver for ExternalSvcbResolver {
    async fn lookup_badge(&self, _fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError> {
        Ok(DnsLookupResult::NotFound)
    }

    async fn lookup_tlsa(
        &self,
        _fqdn: &Fqdn,
        _port: u16,
    ) -> Result<DnsLookupResult<TlsaRecord>, DnsError> {
        Ok(DnsLookupResult::NotFound)
    }

    async fn lookup_svcb_discovery(
        &self,
        _fqdn: &Fqdn,
    ) -> Result<DnsLookupResult<SvcbDiscoveryRecord>, DnsError> {
        let record = SvcbDiscoveryRecord::from_parts(1, ".", "a2a", Some(443))
            .map_err(|e| DnsError::InvalidFormat {
                record: e.to_string(),
            })?
            .with_metadata_url("https://agent.example.com/.well-known/agent-card.json");

        Ok(DnsLookupResult::Found(vec![record]))
    }
}

/// D9: an externally built SVCB row carries the DNS-AID capability locator
/// all the way through the autodiscovery chain.
#[tokio::test]
async fn test_d9_external_resolver_serves_dnsaid_profile() {
    let resolver = ExternalSvcbResolver;

    let records = resolver.get_discovery_records(&fqdn()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].profile_id(), "ANS_DNSAID");

    let DiscoveryRecord::Svcb(svcb) = &records[0] else {
        panic!("expected SVCB record");
    };
    assert_eq!(svcb.priority(), 1);
    assert_eq!(svcb.protocol(), AgentProtocol::A2a);
    assert_eq!(svcb.port(), Some(443));
    assert_eq!(
        svcb.metadata_url(),
        Some("https://agent.example.com/.well-known/agent-card.json")
    );
}
