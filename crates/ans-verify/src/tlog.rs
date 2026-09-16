//! Transparency Log API client.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

// Note: `url::Url` is used internally for URL parsing/joining but is NOT
// exposed in any public trait method or constructor signature.

use crate::error::TlogError;
use ans_types::Badge;

// =========================================================================
// Audit Types
// =========================================================================

/// Audit response from the transparency log.
///
/// Returns full Badge records representing the complete audit trail
/// for an agent, including all registration events and merkle proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AuditResponse {
    /// List of Badge records in the audit trail.
    /// Each record is a complete Badge with merkle proof and signature.
    pub records: Vec<Badge>,
}

/// Transparency Log API client trait.
#[async_trait]
pub trait TransparencyLogClient: Send + Sync {
    /// Fetch a badge by its full URL.
    async fn fetch_badge(&self, url: &str) -> Result<Badge, TlogError>;

    /// Fetch a badge by agent ID.
    async fn fetch_badge_by_id(&self, agent_id: Uuid) -> Result<Badge, TlogError>;

    /// Fetch the audit trail for an agent.
    ///
    /// Returns a paginated list of all transparency log entries for the agent,
    /// providing a complete audit history of registration events.
    async fn fetch_audit(
        &self,
        agent_id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<AuditResponse, TlogError>;
}

/// HTTP-based Transparency Log client.
#[derive(Debug)]
pub struct HttpTransparencyLogClient {
    client: Client,
    base_url: Option<Url>,
    timeout: Duration,
    extra_headers: Vec<(String, String)>,
}

impl HttpTransparencyLogClient {
    /// Create a new client with default settings.
    ///
    /// HTTPS is required and redirects are rejected, so a trusted badge host
    /// cannot send the request to a different trust root.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client's TLS configuration cannot be initialized.
    #[allow(clippy::expect_used)] // Same initialization contract as reqwest::Client::new().
    pub fn new() -> Self {
        Self {
            client: Self::client_builder()
                .build()
                .expect("failed to initialize the transparency log HTTPS client"),
            base_url: None,
            timeout: Duration::from_secs(30),
            extra_headers: Vec::new(),
        }
    }

    fn client_builder() -> reqwest::ClientBuilder {
        Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
    }

    /// Create a new client with a base URL for agent ID lookups.
    ///
    /// # Errors
    ///
    /// Returns `TlogError::InvalidUrl` unless the URL is an absolute HTTPS URL.
    pub fn with_base_url(base_url: impl AsRef<str>) -> Result<Self, TlogError> {
        let parsed =
            Url::parse(base_url.as_ref()).map_err(|e| TlogError::InvalidUrl(e.to_string()))?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(TlogError::InvalidUrl(
                "transparency log base URL must use HTTPS and include a host".into(),
            ));
        }
        Ok(Self {
            client: Self::client_builder()
                .build()
                .map_err(crate::error::HttpError::from)?,
            base_url: Some(parsed),
            timeout: Duration::from_secs(30),
            extra_headers: Vec::new(),
        })
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add a custom header to include with every request.
    ///
    /// Invalid header names or values will cause an error when making requests.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple custom headers to include with every request.
    ///
    /// Invalid header names or values will cause an error when making requests.
    pub fn with_headers(
        mut self,
        headers: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.extra_headers
            .extend(headers.into_iter().map(|(n, v)| (n.into(), v.into())));
        self
    }

    /// Build a reqwest `HeaderMap` from the stored string pairs.
    fn build_headers(&self) -> Result<reqwest::header::HeaderMap, TlogError> {
        let mut map = reqwest::header::HeaderMap::new();
        for (name, value) in &self.extra_headers {
            let header_name =
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                    TlogError::InvalidHeader(format!("invalid header name '{name}': {e}"))
                })?;
            let header_value = reqwest::header::HeaderValue::from_str(value).map_err(|e| {
                TlogError::InvalidHeader(format!("invalid header value for '{name}': {e}"))
            })?;
            map.insert(header_name, header_value);
        }
        Ok(map)
    }
}

impl Default for HttpTransparencyLogClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransparencyLogClient for HttpTransparencyLogClient {
    async fn fetch_badge(&self, url: &str) -> Result<Badge, TlogError> {
        tracing::debug!(url = %url, "Fetching badge from transparency log");

        let headers = self.build_headers()?;
        let mut req = self.client.get(url).header(
            reqwest::header::USER_AGENT,
            format!("ans-verify/{}", env!("CARGO_PKG_VERSION")),
        );
        for (name, value) in &headers {
            req = req.header(name, value);
        }
        let response = req
            .timeout(self.timeout)
            .send()
            .await
            .map_err(crate::error::HttpError::from)?;

        let status = response.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(TlogError::NotFound {
                url: url.to_string(),
            });
        }

        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(TlogError::ServiceUnavailable);
        }

        if !status.is_success() {
            return Err(TlogError::InvalidResponse(format!(
                "Unexpected status code: {status}"
            )));
        }

        // A failed body read is a transport outage. A complete body containing
        // malformed JSON is determinate adverse evidence and must fail closed.
        let body = response
            .bytes()
            .await
            .map_err(crate::error::HttpError::from)?;
        let badge: Badge = serde_json::from_slice(&body)
            .map_err(|e| TlogError::InvalidResponse(format!("Failed to parse badge JSON: {e}")))?;

        tracing::debug!(
            agent_id = %badge.agent_id(),
            status = ?badge.status,
            "Successfully fetched badge"
        );

        Ok(badge)
    }

    async fn fetch_badge_by_id(&self, agent_id: Uuid) -> Result<Badge, TlogError> {
        let base_url = self.base_url.as_ref().ok_or_else(|| {
            TlogError::InvalidUrl("No base URL configured for agent ID lookups".to_string())
        })?;

        let url = base_url
            .join(&format!("v1/agents/{agent_id}"))
            .map_err(|e| TlogError::InvalidUrl(e.to_string()))?;

        self.fetch_badge(url.as_str()).await
    }

    async fn fetch_audit(
        &self,
        agent_id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<AuditResponse, TlogError> {
        let base_url = self.base_url.as_ref().ok_or_else(|| {
            TlogError::InvalidUrl("No base URL configured for audit lookups".to_string())
        })?;

        let mut url = base_url
            .join(&format!("v1/agents/{agent_id}/audit"))
            .map_err(|e| TlogError::InvalidUrl(e.to_string()))?;

        // Add query parameters
        {
            let mut query = url.query_pairs_mut();
            if let Some(l) = limit {
                query.append_pair("limit", &l.to_string());
            }
            if let Some(o) = offset {
                query.append_pair("offset", &o.to_string());
            }
        }

        tracing::debug!(url = %url, "Fetching audit trail from transparency log");

        let headers = self.build_headers()?;
        let mut req = self.client.get(url.as_str()).header(
            reqwest::header::USER_AGENT,
            format!("ans-verify/{}", env!("CARGO_PKG_VERSION")),
        );
        for (name, value) in &headers {
            req = req.header(name, value);
        }
        let response = req
            .timeout(self.timeout)
            .send()
            .await
            .map_err(crate::error::HttpError::from)?;

        let status = response.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(TlogError::NotFound {
                url: url.to_string(),
            });
        }

        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(TlogError::ServiceUnavailable);
        }

        if !status.is_success() {
            return Err(TlogError::InvalidResponse(format!(
                "Unexpected status code: {status}"
            )));
        }

        let body = response
            .bytes()
            .await
            .map_err(crate::error::HttpError::from)?;
        let audit: AuditResponse = serde_json::from_slice(&body).map_err(|e| {
            TlogError::InvalidResponse(format!("Failed to parse audit response JSON: {e}"))
        })?;

        tracing::debug!(
            agent_id = %agent_id,
            record_count = audit.records.len(),
            "Successfully fetched audit trail"
        );

        Ok(audit)
    }
}

/// Mock Transparency Log client for testing.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct MockTransparencyLogClient {
    badges: std::collections::HashMap<String, Badge>,
    errors: std::collections::HashMap<String, TlogError>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockTransparencyLogClient {
    /// Create a new mock client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a badge response for a URL.
    pub fn with_badge(mut self, url: &str, badge: Badge) -> Self {
        self.badges.insert(url.to_string(), badge);
        self
    }

    /// Add an error response for a URL.
    pub fn with_error(mut self, url: &str, error: TlogError) -> Self {
        self.errors.insert(url.to_string(), error);
        self
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl TransparencyLogClient for MockTransparencyLogClient {
    async fn fetch_badge(&self, url: &str) -> Result<Badge, TlogError> {
        let url_str = url.to_string();

        // Check for configured error first
        if let Some(error) = self.errors.get(&url_str) {
            return Err(match error {
                TlogError::NotFound { url } => TlogError::NotFound { url: url.clone() },
                TlogError::ServiceUnavailable => TlogError::ServiceUnavailable,
                TlogError::StatusUnknown => TlogError::StatusUnknown,
                TlogError::InvalidResponse(msg) => TlogError::InvalidResponse(msg.clone()),
                TlogError::InvalidUrl(msg) => TlogError::InvalidUrl(msg.clone()),
                TlogError::HttpError(e) => {
                    // reqwest::Error is not Clone, so we convert to InvalidResponse.
                    // Mock callers should use InvalidResponse directly to avoid this lossy conversion.
                    TlogError::InvalidResponse(format!("HTTP error: {e}"))
                }
                TlogError::InvalidHeader(msg) => TlogError::InvalidHeader(msg.clone()),
                TlogError::UntrustedDomain { domain, trusted } => TlogError::UntrustedDomain {
                    domain: domain.clone(),
                    trusted: trusted.clone(),
                },
            });
        }

        // Return configured badge or NotFound
        self.badges
            .get(&url_str)
            .cloned()
            .ok_or_else(|| TlogError::NotFound { url: url_str })
    }

    async fn fetch_badge_by_id(&self, _agent_id: Uuid) -> Result<Badge, TlogError> {
        Err(TlogError::InvalidUrl(
            "Mock client does not support fetch_badge_by_id".to_string(),
        ))
    }

    async fn fetch_audit(
        &self,
        _agent_id: Uuid,
        _limit: Option<u32>,
        _offset: Option<u32>,
    ) -> Result<AuditResponse, TlogError> {
        Err(TlogError::InvalidUrl(
            "Mock client does not support fetch_audit".to_string(),
        ))
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use ans_types::*;
    use chrono::Utc;

    fn create_test_badge() -> Badge {
        serde_json::from_value(serde_json::json!({
            "status": "ACTIVE",
            "schemaVersion": "V1",
            "payload": {
                "logId": Uuid::new_v4().to_string(),
                "producer": {
                    "event": {
                        "ansId": Uuid::new_v4().to_string(),
                        "ansName": "ans://v1.0.0.test.example.com",
                        "eventType": "AGENT_REGISTERED",
                        "agent": { "host": "test.example.com", "name": "Test Agent", "version": "v1.0.0" },
                        "attestations": {
                            "domainValidation": "ACME-DNS-01",
                            "identityCert": { "fingerprint": "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496", "type": "X509-OV-CLIENT" },
                            "serverCert": { "fingerprint": "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904", "type": "X509-DV-SERVER" }
                        },
                        "expiresAt": (Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
                        "issuedAt": Utc::now().to_rfc3339(),
                        "raId": "test-ra",
                        "timestamp": Utc::now().to_rfc3339()
                    },
                    "keyId": "test-key",
                    "signature": "test-sig"
                }
            }
        })).expect("test badge JSON should be valid")
    }

    fn local_http_client(base_url: &str) -> HttpTransparencyLogClient {
        // Only the unit-test fixture permits plaintext loopback. Keep the
        // production redirect policy so requests cannot escape the first host.
        HttpTransparencyLogClient {
            client: HttpTransparencyLogClient::client_builder()
                .https_only(false)
                .no_proxy()
                .build()
                .unwrap(),
            base_url: Some(Url::parse(base_url).unwrap()),
            timeout: Duration::from_secs(5),
            extra_headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn production_http_client_rejects_plaintext() {
        let server = wiremock::MockServer::start().await;
        assert!(HttpTransparencyLogClient::with_base_url(server.uri()).is_err());
        assert!(
            HttpTransparencyLogClient::new()
                .fetch_badge(&server.uri())
                .await
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn http_client_does_not_follow_redirects() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let origin = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(create_test_badge()))
            .mount(&destination)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "Location",
                destination.uri().replace("127.0.0.1", "localhost"),
            ))
            .mount(&origin)
            .await;
        let error = local_http_client(&origin.uri())
            .fetch_badge(&origin.uri())
            .await
            .unwrap_err();
        assert!(matches!(error, TlogError::InvalidResponse(_)));
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn http_failures_distinguish_outages_from_denials_and_malformed_json() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (status, unavailable) in [
            (429, true),
            (500, true),
            (503, true),
            (401, false),
            (403, false),
            (404, false),
            (200, false),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status).set_body_string("{"))
                .mount(&server)
                .await;
            let client = local_http_client(&server.uri());
            let badge_error = client.fetch_badge(&server.uri()).await.unwrap_err();
            assert_eq!(
                badge_error.is_unavailable(),
                unavailable,
                "badge {status}: {badge_error}"
            );
            let audit_error = client
                .fetch_audit(Uuid::nil(), None, None)
                .await
                .unwrap_err();
            assert_eq!(
                audit_error.is_unavailable(),
                unavailable,
                "audit {status}: {audit_error}"
            );
        }
    }

    #[tokio::test]
    async fn interrupted_http_bodies_are_outages() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        const TRUNCATED_RESPONSE: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{";
        for audit in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2048];
                stream.read(&mut request).await.unwrap();
                stream.write_all(TRUNCATED_RESPONSE).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let client = local_http_client(&url);
            let error = if audit {
                client
                    .fetch_audit(Uuid::nil(), None, None)
                    .await
                    .unwrap_err()
            } else {
                client.fetch_badge(&url).await.unwrap_err()
            };
            assert!(matches!(error, TlogError::HttpError(_)), "{error}");
            assert!(error.is_unavailable());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_mock_client_fetch_badge() {
        let badge = create_test_badge();
        let url = "https://example.com/v1/agents/test-id";

        let client = MockTransparencyLogClient::new().with_badge(url, badge.clone());

        let result = client.fetch_badge(url).await.unwrap();

        assert_eq!(result.status, BadgeStatus::Active);
        assert_eq!(result.agent_host(), "test.example.com");
    }

    #[tokio::test]
    async fn test_mock_client_not_found() {
        let client = MockTransparencyLogClient::new();

        let result = client.fetch_badge("https://example.com/not-found").await;

        assert!(matches!(result, Err(TlogError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_mock_client_error() {
        let client = MockTransparencyLogClient::new()
            .with_error("https://example.com/error", TlogError::ServiceUnavailable);

        let result = client.fetch_badge("https://example.com/error").await;

        assert!(matches!(result, Err(TlogError::ServiceUnavailable)));
    }

    #[tokio::test]
    async fn test_mock_client_error_not_found() {
        let client = MockTransparencyLogClient::new().with_error(
            "https://example.com/error",
            TlogError::NotFound {
                url: "https://example.com/error".to_string(),
            },
        );

        let result = client.fetch_badge("https://example.com/error").await;

        assert!(matches!(result, Err(TlogError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_mock_client_error_invalid_response() {
        let client = MockTransparencyLogClient::new().with_error(
            "https://example.com/error",
            TlogError::InvalidResponse("Bad JSON".to_string()),
        );

        let result = client.fetch_badge("https://example.com/error").await;

        assert!(matches!(result, Err(TlogError::InvalidResponse(_))));
    }

    #[tokio::test]
    async fn test_mock_client_fetch_badge_by_id_not_supported() {
        let client = MockTransparencyLogClient::new();

        let result = client.fetch_badge_by_id(Uuid::new_v4()).await;

        assert!(matches!(result, Err(TlogError::InvalidUrl(_))));
    }

    #[tokio::test]
    async fn test_mock_client_fetch_audit_not_supported() {
        let client = MockTransparencyLogClient::new();

        let result = client.fetch_audit(Uuid::new_v4(), None, None).await;

        assert!(matches!(result, Err(TlogError::InvalidUrl(_))));
    }

    #[test]
    fn test_http_client_new() {
        let client = HttpTransparencyLogClient::new();
        assert!(client.base_url.is_none());
    }

    #[test]
    fn test_http_client_default() {
        let client: HttpTransparencyLogClient = Default::default();
        assert!(client.base_url.is_none());
    }

    #[test]
    fn test_http_client_with_base_url() {
        let client =
            HttpTransparencyLogClient::with_base_url("https://transparency.example.com/").unwrap();
        assert!(client.base_url.is_some());
        assert_eq!(
            client.base_url.unwrap().as_str(),
            "https://transparency.example.com/"
        );
    }

    #[test]
    fn test_http_client_with_timeout() {
        let client =
            HttpTransparencyLogClient::new().with_timeout(std::time::Duration::from_secs(60));
        assert_eq!(client.timeout, std::time::Duration::from_secs(60));
    }

    #[test]
    fn test_audit_response_serialization() {
        let response = AuditResponse {
            records: vec![create_test_badge()],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("records"));

        let deserialized: AuditResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.records.len(), 1);
    }

    // ── Builder methods ──────────────────────────────────────────────

    #[test]
    fn test_with_header() {
        let client = HttpTransparencyLogClient::new().with_header("X-Custom", "value1");
        assert_eq!(client.extra_headers.len(), 1);
        assert_eq!(
            client.extra_headers[0],
            ("X-Custom".to_string(), "value1".to_string())
        );
    }

    #[test]
    fn test_with_headers() {
        let client =
            HttpTransparencyLogClient::new().with_headers([("X-One", "1"), ("X-Two", "2")]);
        assert_eq!(client.extra_headers.len(), 2);
    }

    // ── build_headers ────────────────────────────────────────────────

    #[test]
    fn test_build_headers_valid() {
        let client = HttpTransparencyLogClient::new()
            .with_header("X-Api-Key", "abc123")
            .with_header("Authorization", "Bearer token");
        let headers = client.build_headers().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("X-Api-Key").unwrap(), "abc123");
    }

    #[test]
    fn test_build_headers_invalid_name() {
        let client = HttpTransparencyLogClient::new().with_header("invalid header\nname", "value");
        let result = client.build_headers();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TlogError::InvalidHeader(_)));
    }

    #[test]
    fn test_build_headers_invalid_value() {
        let client = HttpTransparencyLogClient::new().with_header("X-Custom", "val\x00ue");
        let result = client.build_headers();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TlogError::InvalidHeader(_)));
    }

    #[test]
    fn test_build_headers_empty() {
        let client = HttpTransparencyLogClient::new();
        let headers = client.build_headers().unwrap();
        assert!(headers.is_empty());
    }

    // ── Error paths ──────────────────────────────────────────────────

    #[test]
    fn test_with_base_url_invalid() {
        let result = HttpTransparencyLogClient::with_base_url("not a url ://");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TlogError::InvalidUrl(_)));
    }

    #[test]
    fn test_debug_format() {
        let client = HttpTransparencyLogClient::new();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("HttpTransparencyLogClient"));
    }
}
