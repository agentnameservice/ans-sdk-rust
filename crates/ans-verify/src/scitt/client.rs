//! SCITT Transparency Log API client.
//!
//! Provides [`ScittClient`] trait, [`HttpScittClient`] for production use, and
//! (behind `test-support`) [`MockScittClient`] for unit tests.
//!
//! This is a separate trait from [`crate::tlog::TransparencyLogClient`] because
//! adding methods to an existing trait is a breaking change for all implementors.

use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

use super::error::ScittError;

// =========================================================================
// Trait
// =========================================================================

/// Client for fetching SCITT artifacts from the Transparency Log API.
///
/// This is a separate trait from `TransparencyLogClient` because adding methods
/// to an existing trait is a breaking change for all implementors.
#[async_trait]
pub trait ScittClient: Send + Sync {
    /// Fetch the SCITT receipt for an agent.
    ///
    /// Returns the raw `COSE_Sign1` bytes of the Merkle inclusion receipt.
    async fn fetch_receipt(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError>;

    /// Fetch the current status token for an agent.
    ///
    /// Returns the raw `COSE_Sign1` bytes of the signed status claim.
    async fn fetch_status_token(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError>;

    /// Fetch the root signing keys in C2SP format.
    ///
    /// Returns a list of C2SP-formatted public key strings for the TL instance.
    async fn fetch_root_keys(&self) -> Result<Vec<String>, ScittError>;
}

// =========================================================================
// HTTP implementation
// =========================================================================

/// HTTP-based SCITT Transparency Log client.
///
/// Fetches SCITT artifacts from the TL API using the following endpoints:
/// - `GET /v1/agents/{agent_id}/receipt` → raw `COSE_Sign1` receipt bytes
/// - `GET /v1/agents/{agent_id}/status-token` → raw `COSE_Sign1` status token bytes
/// - `GET /root-keys` → newline-separated C2SP key strings
#[derive(Debug)]
pub struct HttpScittClient {
    client: Client,
    base_url: Url,
    timeout: Duration,
    extra_headers: Vec<(String, String)>,
}

impl HttpScittClient {
    /// Create a new client with the given base URL.
    ///
    /// The base URL should include the scheme and host, e.g.
    /// `https://tl.example.com`. A trailing slash is handled automatically.
    ///
    /// # Errors
    ///
    /// Returns [`ScittError::InvalidUrl`] unless the URL has an HTTPS scheme
    /// and a host. Redirects are rejected to preserve the configured TL origin.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ScittError> {
        let raw = base_url.as_ref();
        // Ensure the URL has a trailing slash so `.join("v1/...")` works correctly.
        let normalised = if raw.ends_with('/') {
            raw.to_string()
        } else {
            format!("{raw}/")
        };
        let parsed = Url::parse(&normalised)
            .map_err(|e| ScittError::InvalidUrl(format!("invalid base URL '{raw}': {e}")))?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(ScittError::InvalidUrl(
                "SCITT base URL must use HTTPS and include a host".into(),
            ));
        }
        Ok(Self {
            client: Self::client_builder()
                .build()
                .map_err(crate::error::HttpError::from)?,
            base_url: parsed,
            timeout: Duration::from_secs(30),
            extra_headers: Vec::new(),
        })
    }

    fn client_builder() -> reqwest::ClientBuilder {
        Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
    }

    /// Set the request timeout (default: 30 s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add a custom header to include with every request.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple custom headers to include with every request.
    pub fn with_headers(
        mut self,
        headers: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.extra_headers
            .extend(headers.into_iter().map(|(n, v)| (n.into(), v.into())));
        self
    }

    /// Build a reqwest `HeaderMap` from the stored string pairs.
    fn build_headers(&self) -> Result<reqwest::header::HeaderMap, ScittError> {
        let mut map = reqwest::header::HeaderMap::new();
        for (name, value) in &self.extra_headers {
            let header_name =
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                    ScittError::InvalidUrl(format!("invalid header name '{name}': {e}"))
                })?;
            let header_value = reqwest::header::HeaderValue::from_str(value).map_err(|e| {
                ScittError::InvalidUrl(format!("invalid header value for '{name}': {e}"))
            })?;
            map.insert(header_name, header_value);
        }
        Ok(map)
    }

    /// Execute a GET request and return the response body as raw bytes.
    ///
    /// Handles 404, 410, 501, and other HTTP error codes uniformly.
    async fn get_bytes(&self, url: &Url, agent_id: Option<Uuid>) -> Result<Vec<u8>, ScittError> {
        /// Maximum response body size for SCITT artifacts (2 MiB).
        const MAX_RESPONSE_SIZE: usize = 2 * 1024 * 1024;

        tracing::debug!(url = %url, "Fetching SCITT artifact");

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
            return Err(ScittError::NotFound {
                agent_id: agent_id.unwrap_or(Uuid::nil()),
            });
        }

        if status == reqwest::StatusCode::GONE {
            return Err(ScittError::AgentTerminal {
                agent_id: agent_id.unwrap_or(Uuid::nil()),
            });
        }

        if status == reqwest::StatusCode::NOT_IMPLEMENTED {
            return Err(ScittError::NotSupported {
                endpoint: url.to_string(),
            });
        }

        if !status.is_success() {
            return Err(ScittError::UnexpectedHttpStatus {
                status: status.as_u16(),
                url: url.to_string(),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(crate::error::HttpError::from)?;

        if bytes.len() > MAX_RESPONSE_SIZE {
            return Err(ScittError::OversizedInput {
                max_bytes: MAX_RESPONSE_SIZE,
            });
        }

        Ok(bytes.to_vec())
    }
}

#[async_trait]
impl ScittClient for HttpScittClient {
    async fn fetch_receipt(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError> {
        let url = self
            .base_url
            .join(&format!("v1/agents/{agent_id}/receipt"))
            .map_err(|e| ScittError::InvalidUrl(format!("URL join error: {e}")))?;

        let bytes = self.get_bytes(&url, Some(agent_id)).await?;
        tracing::debug!(%agent_id, bytes = bytes.len(), "Fetched SCITT receipt");
        Ok(bytes)
    }

    async fn fetch_status_token(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError> {
        let url = self
            .base_url
            .join(&format!("v1/agents/{agent_id}/status-token"))
            .map_err(|e| ScittError::InvalidUrl(format!("URL join error: {e}")))?;

        let bytes = self.get_bytes(&url, Some(agent_id)).await?;
        tracing::debug!(%agent_id, bytes = bytes.len(), "Fetched SCITT status token");
        Ok(bytes)
    }

    async fn fetch_root_keys(&self) -> Result<Vec<String>, ScittError> {
        let url = self
            .base_url
            .join("root-keys")
            .map_err(|e| ScittError::InvalidUrl(format!("URL join error: {e}")))?;

        tracing::debug!(url = %url, "Fetching SCITT root keys");

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

        if status == reqwest::StatusCode::NOT_IMPLEMENTED {
            return Err(ScittError::NotSupported {
                endpoint: url.to_string(),
            });
        }

        if !status.is_success() {
            return Err(ScittError::UnexpectedHttpStatus {
                status: status.as_u16(),
                url: url.to_string(),
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| ScittError::HttpError(e.into()))?;
        let keys: Vec<String> = body
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        if keys.is_empty() {
            return Err(ScittError::InvalidKeyFormat(
                "root-keys endpoint returned no keys".to_string(),
            ));
        }

        tracing::debug!(count = keys.len(), "Fetched SCITT root keys");
        Ok(keys)
    }
}

// =========================================================================
// Mock implementation (test-support)
// =========================================================================

/// Mock SCITT client for unit tests.
///
/// Configure responses via the builder methods before use.
///
/// # Notes on `ScittError` cloneability
///
/// [`ScittError`] is not `Clone` because it contains [`crate::error::HttpError`]
/// which wraps `reqwest::Error` (not `Clone`). Errors stored in this mock are
/// reproduced via a factory closure so each call gets a fresh value.
#[cfg(any(test, feature = "test-support"))]
pub struct MockScittClient {
    receipts: std::collections::HashMap<Uuid, Vec<u8>>,
    status_tokens: std::collections::HashMap<Uuid, Vec<u8>>,
    root_keys: Option<Vec<String>>,
    /// Per-method error factories: key is `"receipt:{uuid}"`, `"status_token:{uuid}"`,
    /// or `"root_keys"`.
    error_factories: std::collections::HashMap<String, Box<dyn Fn() -> ScittError + Send + Sync>>,
}

#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Debug for MockScittClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockScittClient")
            .field("receipts", &self.receipts.keys().collect::<Vec<_>>())
            .field(
                "status_tokens",
                &self.status_tokens.keys().collect::<Vec<_>>(),
            )
            .field("root_keys", &self.root_keys)
            .field("error_count", &self.error_factories.len())
            .finish()
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::derivable_impls)]
impl Default for MockScittClient {
    fn default() -> Self {
        Self {
            receipts: std::collections::HashMap::new(),
            status_tokens: std::collections::HashMap::new(),
            root_keys: None,
            error_factories: std::collections::HashMap::new(),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl MockScittClient {
    /// Create a new empty mock client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a receipt response for the given agent ID.
    pub fn with_receipt(mut self, agent_id: Uuid, receipt: Vec<u8>) -> Self {
        self.receipts.insert(agent_id, receipt);
        self
    }

    /// Configure a status token response for the given agent ID.
    pub fn with_status_token(mut self, agent_id: Uuid, token: Vec<u8>) -> Self {
        self.status_tokens.insert(agent_id, token);
        self
    }

    /// Configure the root keys response.
    pub fn with_root_keys(mut self, keys: Vec<String>) -> Self {
        self.root_keys = Some(keys);
        self
    }

    /// Configure an error factory for a specific method + agent ID combination.
    ///
    /// `key` format:
    /// - `"receipt:{agent_id}"` — error on `fetch_receipt`
    /// - `"status_token:{agent_id}"` — error on `fetch_status_token`
    /// - `"root_keys"` — error on `fetch_root_keys`
    pub fn with_error(
        mut self,
        key: impl Into<String>,
        factory: impl Fn() -> ScittError + Send + Sync + 'static,
    ) -> Self {
        self.error_factories.insert(key.into(), Box::new(factory));
        self
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl ScittClient for MockScittClient {
    async fn fetch_receipt(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError> {
        let key = format!("receipt:{agent_id}");
        if let Some(factory) = self.error_factories.get(&key) {
            return Err(factory());
        }
        self.receipts
            .get(&agent_id)
            .cloned()
            .ok_or(ScittError::NotFound { agent_id })
    }

    async fn fetch_status_token(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError> {
        let key = format!("status_token:{agent_id}");
        if let Some(factory) = self.error_factories.get(&key) {
            return Err(factory());
        }
        self.status_tokens
            .get(&agent_id)
            .cloned()
            .ok_or(ScittError::NotFound { agent_id })
    }

    async fn fetch_root_keys(&self) -> Result<Vec<String>, ScittError> {
        if let Some(factory) = self.error_factories.get("root_keys") {
            return Err(factory());
        }
        self.root_keys
            .clone()
            .ok_or_else(|| ScittError::NotSupported {
                endpoint: "mock://root-keys".to_string(),
            })
    }
}

// =========================================================================
// Tests
// =========================================================================

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    // ── HttpScittClient construction ──────────────────────────────────

    #[test]
    fn http_client_new_valid_url() {
        let client = HttpScittClient::new("https://tl.example.com").unwrap();
        assert_eq!(client.base_url.as_str(), "https://tl.example.com/");
    }

    #[test]
    fn http_client_new_trailing_slash_preserved() {
        let client = HttpScittClient::new("https://tl.example.com/").unwrap();
        assert_eq!(client.base_url.as_str(), "https://tl.example.com/");
    }

    #[test]
    fn http_client_new_invalid_url() {
        let result = HttpScittClient::new("not a url ://");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ScittError::InvalidUrl(_)));
    }

    #[test]
    fn http_client_with_timeout() {
        let client = HttpScittClient::new("https://tl.example.com")
            .unwrap()
            .with_timeout(Duration::from_secs(60));
        assert_eq!(client.timeout, Duration::from_secs(60));
    }

    #[test]
    fn http_client_debug_format() {
        let client = HttpScittClient::new("https://tl.example.com").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("HttpScittClient"));
    }

    #[test]
    fn http_client_rejects_insecure_schemes() {
        for url in [
            "http://tl.example.com",
            "http://localhost:8080",
            "ftp://tl.example.com",
            "file:///root-keys",
        ] {
            assert!(matches!(
                HttpScittClient::new(url),
                Err(ScittError::InvalidUrl(_))
            ));
        }
    }

    fn loopback_client(base_url: &str) -> HttpScittClient {
        let mut client = HttpScittClient::new("https://tl.example.com").unwrap();
        client.base_url = Url::parse(&format!("{base_url}/")).unwrap();
        // Only relax TLS for the loopback fixture; retain the production
        // redirect policy and all request handling.
        client.client = HttpScittClient::client_builder()
            .https_only(false)
            .build()
            .unwrap();
        client
    }

    #[tokio::test]
    async fn scitt_fetches_reject_redirects_and_preserve_direct_responses() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let origin = MockServer::start().await;
        let other = MockServer::start().await;
        let client = loopback_client(&origin.uri());
        let agent_id = Uuid::nil();
        for endpoint in [
            "root-keys".to_string(),
            format!("v1/agents/{agent_id}/receipt"),
            format!("v1/agents/{agent_id}/status-token"),
        ] {
            origin.reset().await;
            Mock::given(method("GET"))
                .and(path(format!("/{endpoint}")))
                .respond_with(ResponseTemplate::new(302).insert_header("Location", other.uri()))
                .mount(&origin)
                .await;
            let result = if endpoint == "root-keys" {
                client.fetch_root_keys().await.map(|_| ())
            } else if endpoint.ends_with("/receipt") {
                client.fetch_receipt(agent_id).await.map(|_| ())
            } else {
                client.fetch_status_token(agent_id).await.map(|_| ())
            };
            assert!(matches!(
                result,
                Err(ScittError::UnexpectedHttpStatus { status: 302, .. })
            ));
        }
        assert!(other.received_requests().await.unwrap().is_empty());
        origin.reset().await;
        Mock::given(method("GET"))
            .and(path("/root-keys"))
            .respond_with(ResponseTemplate::new(200).set_body_string("test-key\n"))
            .mount(&origin)
            .await;
        assert_eq!(client.fetch_root_keys().await.unwrap(), vec!["test-key"]);
    }

    // ── MockScittClient ───────────────────────────────────────────────

    #[tokio::test]
    async fn mock_returns_receipt_when_configured() {
        let agent_id = Uuid::new_v4();
        let receipt_bytes = vec![0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26];

        let client = MockScittClient::new().with_receipt(agent_id, receipt_bytes.clone());

        let result = client.fetch_receipt(agent_id).await.unwrap();
        assert_eq!(result, receipt_bytes);
    }

    #[tokio::test]
    async fn mock_returns_status_token_when_configured() {
        let agent_id = Uuid::new_v4();
        let token_bytes = vec![0xd2, 0x84, 0x53, 0xa1, 0x02, 0x27];

        let client = MockScittClient::new().with_status_token(agent_id, token_bytes.clone());

        let result = client.fetch_status_token(agent_id).await.unwrap();
        assert_eq!(result, token_bytes);
    }

    #[tokio::test]
    async fn mock_returns_root_keys_when_configured() {
        let keys = vec![
            "k1+ES256+AAAAAA==+BBBBBB==".to_string(),
            "k2+ES256+CCCCCC==+DDDDDD==".to_string(),
        ];

        let client = MockScittClient::new().with_root_keys(keys.clone());

        let result = client.fetch_root_keys().await.unwrap();
        assert_eq!(result, keys);
    }

    #[tokio::test]
    async fn mock_returns_error_when_configured() {
        let agent_id = Uuid::new_v4();

        let client = MockScittClient::new().with_error(format!("receipt:{agent_id}"), move || {
            ScittError::SignatureInvalid
        });

        let result = client.fetch_receipt(agent_id).await;
        assert!(matches!(result, Err(ScittError::SignatureInvalid)));
    }

    #[tokio::test]
    async fn mock_returns_not_found_for_unconfigured_agent() {
        let client = MockScittClient::new();
        let agent_id = Uuid::new_v4();

        let result = client.fetch_receipt(agent_id).await;
        assert!(matches!(result, Err(ScittError::NotFound { .. })));

        let result = client.fetch_status_token(agent_id).await;
        assert!(matches!(result, Err(ScittError::NotFound { .. })));
    }

    #[tokio::test]
    async fn mock_root_keys_not_supported_when_unconfigured() {
        let client = MockScittClient::new();

        let result = client.fetch_root_keys().await;
        assert!(matches!(result, Err(ScittError::NotSupported { .. })));
    }

    #[tokio::test]
    async fn mock_root_keys_error_factory() {
        let client = MockScittClient::new().with_error("root_keys", || ScittError::NotACoseSign1);

        let result = client.fetch_root_keys().await;
        assert!(matches!(result, Err(ScittError::NotACoseSign1)));
    }

    #[test]
    fn trait_object_safe() {
        // Verify ScittClient can be used as Arc<dyn ScittClient>
        let client: std::sync::Arc<dyn ScittClient> = std::sync::Arc::new(MockScittClient::new());
        let _ = client;
    }
}
