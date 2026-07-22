//! ANS Registry API client.
//!
//! The client provides methods for agent registration, certificate management,
//! and agent discovery operations.
//!
//! # Example
//!
//! ```rust,no_run
//! use ans_client::{AnsClient, models::*};
//!
//! #[tokio::main]
//! async fn main() -> ans_client::Result<()> {
//!     let client = AnsClient::builder()
//!         .base_url("https://api.godaddy.com")
//!         .jwt("your-jwt-token")
//!         .build()?;
//!
//!     let endpoint = AgentEndpoint::new("https://agent.example.com/mcp", Protocol::Mcp)
//!         .with_transports(vec![Transport::StreamableHttp]);
//!
//!     let request = AgentRegistrationRequest::new(
//!         "my-agent",
//!         "agent.example.com",
//!         "1.0.0",
//!         "-----BEGIN CERTIFICATE REQUEST-----...",
//!         vec![endpoint],
//!     )
//!     .with_description("My AI agent")
//!     .with_server_csr_pem("-----BEGIN CERTIFICATE REQUEST-----...");
//!
//!     let pending = client.register_agent(&request).await?;
//!     println!("Registered: {}", pending.ans_name);
//!
//!     Ok(())
//! }
//! ```

use std::fmt;
use std::time::Duration;

use reqwest::Client;
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, instrument};
use url::Url;

use crate::error::{ClientError, HttpError, Result};
use crate::models::{
    AgentDetails, AgentRegistrationRequest, AgentResolutionRequest, AgentResolutionResponse,
    AgentRevocationRequest, AgentRevocationResponse, AgentSearchResponse, AgentStatus,
    CertificateResponse, CsrStatusResponse, CsrSubmissionRequest, CsrSubmissionResponse,
    EventPageResponse, RegistrationPending, RevocationReason, SearchCriteria,
};

/// Default request timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Authentication method for the ANS API.
///
/// Secrets are stored using [`SecretString`] which provides:
/// - Zeroization on drop (secret bytes overwritten in memory)
/// - Debug output prints `[REDACTED]` instead of the secret value
/// - Explicit `.expose_secret()` required to access the value
#[derive(Clone)]
#[non_exhaustive]
pub enum Auth {
    /// JWT authentication for internal endpoints.
    Jwt(SecretString),
    /// API key authentication for public gateway.
    ApiKey {
        /// The API key identifier.
        key: String,
        /// The API key secret.
        secret: SecretString,
    },
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jwt(_) => f.debug_tuple("Jwt").field(&"[REDACTED]").finish(),
            Self::ApiKey { key, .. } => f
                .debug_struct("ApiKey")
                .field("key", key)
                .field("secret", &"[REDACTED]")
                .finish(),
        }
    }
}

impl Auth {
    fn header_value(&self) -> SecretString {
        match self {
            Self::Jwt(token) => SecretString::from(format!("sso-jwt {}", token.expose_secret())),
            Self::ApiKey { key, secret } => {
                SecretString::from(format!("sso-key {key}:{}", secret.expose_secret()))
            }
        }
    }
}

/// Registration Authority API lane targeted by the agent-lifecycle and
/// certificate methods.
///
/// The two lanes expose the same request/response shapes for the routes
/// this client maps; they differ in path (`/v1/agents/...` vs
/// `/v2/ans/agents/...`) and in which features the server enables:
/// DNS discovery profiles
/// ([`AgentRegistrationRequest::discovery_profiles`](crate::models::AgentRegistrationRequest))
/// only take effect on the V2 lane, where the server default is the
/// DNS-AID SVCB family ([`DiscoveryProfile::AnsDnsaid`](crate::models::DiscoveryProfile));
/// the V1 lane is pinned server-side to the legacy `_ans` TXT family.
///
/// Routes that only exist on the V1 surface —
/// [`search_agents`](AnsClient::search_agents),
/// [`resolve_agent`](AnsClient::resolve_agent), and
/// [`get_events`](AnsClient::get_events) — keep their paths
/// regardless of this setting, so selecting [`ApiVersion::V2`] never
/// changes the behavior of a route without a V2 twin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApiVersion {
    /// The original `/v1/agents` lane (default).
    #[default]
    V1,
    /// The `/v2/ans/agents` lane.
    V2,
}

/// Builder for constructing an [`AnsClient`].
#[derive(Debug)]
pub struct AnsClientBuilder {
    base_url: Option<String>,
    auth: Option<Auth>,
    timeout: Duration,
    extra_headers: Vec<(String, String)>,
    allow_insecure: bool,
    api_version: ApiVersion,
}

impl Default for AnsClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AnsClientBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            base_url: None,
            auth: None,
            timeout: DEFAULT_TIMEOUT,
            extra_headers: Vec::new(),
            allow_insecure: false,
            api_version: ApiVersion::default(),
        }
    }

    /// Select the RA API lane for agent-lifecycle and certificate routes.
    ///
    /// Defaults to [`ApiVersion::V1`]. Select [`ApiVersion::V2`] to
    /// register with DNS discovery profiles — see [`ApiVersion`] for the
    /// lane semantics.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ans_client::{AnsClient, ApiVersion};
    ///
    /// let client = AnsClient::builder()
    ///     .base_url("https://api.godaddy.com")
    ///     .api_version(ApiVersion::V2)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn api_version(mut self, version: ApiVersion) -> Self {
        self.api_version = version;
        self
    }

    /// Set the base URL for API requests.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ans_client::AnsClient;
    ///
    /// let client = AnsClient::builder()
    ///     .base_url("https://api.godaddy.com")
    ///     .build();
    /// ```
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set JWT authentication (for internal endpoints).
    ///
    /// Use this when connecting to internal RA endpoints like
    /// `api.{env}-godaddy.com`.
    pub fn jwt(mut self, token: impl Into<String>) -> Self {
        self.auth = Some(Auth::Jwt(SecretString::from(token.into())));
        self
    }

    /// Set API key authentication (for public gateway).
    ///
    /// Use this when connecting to public API gateway endpoints like
    /// `api.godaddy.com`.
    pub fn api_key(mut self, key: impl Into<String>, secret: impl Into<String>) -> Self {
        self.auth = Some(Auth::ApiKey {
            key: key.into(),
            secret: SecretString::from(secret.into()),
        });
        self
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add a custom header to include with every request.
    ///
    /// Header names and values are validated when [`build()`](Self::build) is called.
    /// Use this for API gateway headers, correlation IDs, or other
    /// headers required by your environment.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple custom headers to include with every request.
    ///
    /// Header names and values are validated when [`build()`](Self::build) is called.
    pub fn headers(
        mut self,
        headers: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.extra_headers
            .extend(headers.into_iter().map(|(n, v)| (n.into(), v.into())));
        self
    }

    /// Allow insecure (non-HTTPS) base URLs.
    ///
    /// By default, the builder rejects `http://` base URLs because this SDK
    /// sends authentication credentials (JWT tokens, API key secrets) in the
    /// `Authorization` header on every request. Sending credentials over
    /// plaintext HTTP is a security risk.
    ///
    /// Only use this for local development or testing against mock servers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ans_client::AnsClient;
    ///
    /// let client = AnsClient::builder()
    ///     .base_url("http://localhost:8080")
    ///     .allow_insecure()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn allow_insecure(mut self) -> Self {
        self.allow_insecure = true;
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// Returns an error if the base URL is invalid, uses a non-HTTPS scheme
    /// (unless [`allow_insecure`](Self::allow_insecure) is set), or if any
    /// custom header names or values are invalid.
    pub fn build(self) -> Result<AnsClient> {
        let base_url = self
            .base_url
            .unwrap_or_else(|| "https://api.godaddy.com".to_string());

        let base_url = Url::parse(&base_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;

        if !self.allow_insecure && base_url.scheme() != "https" {
            return Err(ClientError::Configuration(format!(
                "base URL must use HTTPS (got \"{}\"). \
                 Use .allow_insecure() to permit non-HTTPS URLs for local development.",
                base_url.scheme()
            )));
        }

        let http_client = Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| ClientError::Configuration(format!("failed to build HTTP client: {e}")))?;

        let mut extra_headers = HeaderMap::new();
        for (name, value) in self.extra_headers {
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                ClientError::Configuration(format!("invalid header name '{name}': {e}"))
            })?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                ClientError::Configuration(format!("invalid header value for '{name}': {e}"))
            })?;
            extra_headers.insert(header_name, header_value);
        }

        Ok(AnsClient {
            base_url,
            auth: self.auth,
            http_client,
            extra_headers,
            api_version: self.api_version,
        })
    }
}

/// ANS Registry API client.
///
/// Provides methods for agent registration, certificate management,
/// and agent discovery operations.
#[derive(Debug, Clone)]
pub struct AnsClient {
    base_url: Url,
    auth: Option<Auth>,
    http_client: Client,
    extra_headers: HeaderMap,
    api_version: ApiVersion,
}

impl AnsClient {
    /// Create a new builder for constructing a client.
    pub fn builder() -> AnsClientBuilder {
        AnsClientBuilder::new()
    }

    /// Create a client with default settings.
    ///
    /// Uses `https://api.godaddy.com` as the base URL with no authentication.
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    /// Build the URL for a path.
    fn url(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .map_err(|e| ClientError::InvalidUrl(e.to_string()))
    }

    /// Lane-specific agents collection path.
    fn agents_collection_path(&self) -> &'static str {
        match self.api_version {
            ApiVersion::V1 => "/v1/agents",
            ApiVersion::V2 => "/v2/ans/agents",
        }
    }

    /// Lane-specific registration route: the V1 lane registers at
    /// `POST /v1/agents/register`, the V2 lane at the collection itself
    /// (`POST /v2/ans/agents`).
    fn register_path(&self) -> &'static str {
        match self.api_version {
            ApiVersion::V1 => "/v1/agents/register",
            ApiVersion::V2 => "/v2/ans/agents",
        }
    }

    /// Lane-specific path for one agent with an optional trailing
    /// suffix. The agent ID is URL-encoded here; callers encode any
    /// suffix segment carrying user input (e.g. a CSR ID).
    fn agent_path(&self, agent_id: &str, suffix: &str) -> String {
        let base = self.agents_collection_path();
        let id = urlencoding::encode(agent_id);
        if suffix.is_empty() {
            format!("{base}/{id}")
        } else {
            format!("{base}/{id}/{suffix}")
        }
    }

    /// Build a request with common headers and authentication.
    fn build_request(&self, method: &str, path: &str) -> Result<reqwest::RequestBuilder> {
        let url = self.url(path)?;

        let mut req = match method {
            "GET" => self.http_client.get(url),
            "POST" => self.http_client.post(url),
            "PUT" => self.http_client.put(url),
            "DELETE" => self.http_client.delete(url),
            _ => {
                return Err(ClientError::Configuration(format!(
                    "unsupported method: {method}"
                )));
            }
        };

        req = req.header(header::ACCEPT, "application/json").header(
            header::USER_AGENT,
            format!("ans-client/{}", env!("CARGO_PKG_VERSION")),
        );

        if let Some(auth) = &self.auth {
            req = req.header(header::AUTHORIZATION, auth.header_value().expose_secret());
        }

        for (name, value) in &self.extra_headers {
            req = req.header(name, value);
        }

        Ok(req)
    }

    /// Send a request and deserialize the JSON response.
    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T> {
        let response = req.send().await.map_err(HttpError::from)?;
        let status = response.status();

        if status.is_success() {
            let body_text = response.text().await.map_err(HttpError::from)?;
            serde_json::from_str(&body_text).map_err(|e| {
                debug!(error = %e, body = %&body_text[..body_text.len().min(200)], "JSON deserialization failed");
                ClientError::Json(e)
            })
        } else {
            let body = response.text().await.map_err(HttpError::from)?;
            Err(ClientError::from_response(status.as_u16(), &body))
        }
    }

    /// Execute a request and deserialize the response.
    #[instrument(skip(self, body), fields(method = %method, path = %path))]
    async fn request<T, B>(&self, method: &str, path: &str, body: Option<&B>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: serde::Serialize,
    {
        let mut req = self.build_request(method, path)?;
        if let Some(body) = body {
            req = req
                .header(header::CONTENT_TYPE, "application/json")
                .json(body);
        } else if method == "POST" || method == "PUT" || method == "PATCH" {
            req = req.header(header::CONTENT_LENGTH, "0");
        }
        self.send(req).await
    }

    // =========================================================================
    // Registration Operations
    // =========================================================================

    /// Register a new agent.
    ///
    /// Returns the pending registration details including required next steps
    /// for completing registration (DNS configuration, domain validation, etc.).
    ///
    /// On the V2 lane ([`ApiVersion::V2`]) the request's
    /// [`discovery_profiles`](AgentRegistrationRequest::discovery_profiles)
    /// select which DNS record families the RA asks the operator to
    /// publish (omitted → the server default,
    /// [`DiscoveryProfile::AnsDnsaid`](crate::models::DiscoveryProfile)).
    /// A non-empty set on the default V1 lane is rejected client-side:
    /// the V1 lane ignores the field server-side and always emits the
    /// `_ans` TXT family, so forwarding it would silently drop an
    /// explicit choice — the registration would succeed with TXT
    /// records and no signal anywhere.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Configuration`] if `discovery_profiles` is set
    ///   without [`ApiVersion::V2`]
    /// - [`ClientError::Conflict`] if the agent is already registered
    /// - [`ClientError::InvalidRequest`] if the request is invalid
    #[instrument(skip(self, request), fields(agent_host = %request.agent_host))]
    pub async fn register_agent(
        &self,
        request: &AgentRegistrationRequest,
    ) -> Result<RegistrationPending> {
        if self.api_version != ApiVersion::V2 && !request.discovery_profiles.is_empty() {
            return Err(ClientError::Configuration(
                "discovery_profiles requires ApiVersion::V2; the V1 lane ignores the field"
                    .to_string(),
            ));
        }
        self.request("POST", self.register_path(), Some(request))
            .await
    }

    /// Get agent details by ID.
    ///
    /// # Errors
    ///
    /// - [`ClientError::NotFound`] if the agent doesn't exist
    #[instrument(skip(self))]
    pub async fn get_agent(&self, agent_id: &str) -> Result<AgentDetails> {
        let path = self.agent_path(agent_id, "");
        self.request("GET", &path, None::<&()>).await
    }

    /// Search for agents.
    ///
    /// This search surface (its filter set and response shape) only
    /// exists on the V1 lane, so the path is not affected by
    /// [`ApiVersion`].
    ///
    /// # Arguments
    ///
    /// * `criteria` - Search criteria (display name, host, version, protocol)
    /// * `limit` - Maximum results to return (1-100, default 20)
    /// * `offset` - Number of results to skip for pagination
    #[instrument(skip(self))]
    pub async fn search_agents(
        &self,
        criteria: &SearchCriteria,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<AgentSearchResponse> {
        let mut query: Vec<(&str, String)> = Vec::new();

        if let Some(name) = &criteria.agent_display_name {
            query.push(("agentDisplayName", name.clone()));
        }
        if let Some(host) = &criteria.agent_host {
            query.push(("agentHost", host.clone()));
        }
        if let Some(version) = &criteria.version {
            query.push(("version", version.clone()));
        }
        if let Some(protocol) = &criteria.protocol {
            query.push(("protocol", protocol.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        if let Some(offset) = offset {
            query.push(("offset", offset.to_string()));
        }

        let req = self.build_request("GET", "/v1/agents")?.query(&query);
        self.send(req).await
    }

    /// Resolve an ANS name to agent details.
    ///
    /// This route only exists on the V1 surface, so the path is not
    /// affected by [`ApiVersion`].
    ///
    /// # Arguments
    ///
    /// * `agent_host` - The agent's host domain
    /// * `version` - Version pattern ("*" for any, or semver range like "^1.0.0")
    #[instrument(skip(self))]
    pub async fn resolve_agent(
        &self,
        agent_host: &str,
        version: &str,
    ) -> Result<AgentResolutionResponse> {
        let request = AgentResolutionRequest {
            agent_host: agent_host.to_string(),
            version: version.to_string(),
        };
        self.request("POST", "/v1/agents/resolution", Some(&request))
            .await
    }

    // =========================================================================
    // Validation Operations
    // =========================================================================

    /// Trigger ACME domain validation.
    ///
    /// Call this after configuring the ACME challenge (DNS or HTTP).
    ///
    /// # Errors
    ///
    /// - [`ClientError::NotFound`] if the agent doesn't exist
    /// - [`ClientError::InvalidRequest`] if validation fails
    #[instrument(skip(self))]
    pub async fn verify_acme(&self, agent_id: &str) -> Result<AgentStatus> {
        let path = self.agent_path(agent_id, "verify-acme");
        self.request("POST", &path, None::<&()>).await
    }

    /// Verify DNS records are configured correctly.
    ///
    /// Call this after configuring all required DNS records.
    ///
    /// # Errors
    ///
    /// - [`ClientError::NotFound`] if the agent doesn't exist
    /// - [`ClientError::InvalidRequest`] if DNS verification fails
    #[instrument(skip(self))]
    pub async fn verify_dns(&self, agent_id: &str) -> Result<AgentStatus> {
        let path = self.agent_path(agent_id, "verify-dns");
        self.request("POST", &path, None::<&()>).await
    }

    // =========================================================================
    // Certificate Operations
    // =========================================================================

    /// Get server certificates for an agent.
    #[instrument(skip(self))]
    pub async fn get_server_certificates(
        &self,
        agent_id: &str,
    ) -> Result<Vec<CertificateResponse>> {
        let path = self.agent_path(agent_id, "certificates/server");
        self.request("GET", &path, None::<&()>).await
    }

    /// Get identity certificates for an agent.
    #[instrument(skip(self))]
    pub async fn get_identity_certificates(
        &self,
        agent_id: &str,
    ) -> Result<Vec<CertificateResponse>> {
        let path = self.agent_path(agent_id, "certificates/identity");
        self.request("GET", &path, None::<&()>).await
    }

    /// Submit a server certificate CSR.
    #[instrument(skip(self, csr_pem))]
    pub async fn submit_server_csr(
        &self,
        agent_id: &str,
        csr_pem: &str,
    ) -> Result<CsrSubmissionResponse> {
        let path = self.agent_path(agent_id, "certificates/server");
        let request = CsrSubmissionRequest {
            csr_pem: csr_pem.to_string(),
        };
        self.request("POST", &path, Some(&request)).await
    }

    /// Submit an identity certificate CSR.
    #[instrument(skip(self, csr_pem))]
    pub async fn submit_identity_csr(
        &self,
        agent_id: &str,
        csr_pem: &str,
    ) -> Result<CsrSubmissionResponse> {
        let path = self.agent_path(agent_id, "certificates/identity");
        let request = CsrSubmissionRequest {
            csr_pem: csr_pem.to_string(),
        };
        self.request("POST", &path, Some(&request)).await
    }

    /// Get CSR status.
    #[instrument(skip(self))]
    pub async fn get_csr_status(&self, agent_id: &str, csr_id: &str) -> Result<CsrStatusResponse> {
        let suffix = format!("csrs/{}/status", urlencoding::encode(csr_id));
        let path = self.agent_path(agent_id, &suffix);
        self.request("GET", &path, None::<&()>).await
    }

    // =========================================================================
    // Revocation Operations
    // =========================================================================

    /// Revoke an agent.
    ///
    /// This permanently revokes the agent's certificates and marks the
    /// registration as revoked.
    ///
    /// # Errors
    ///
    /// - [`ClientError::NotFound`] if the agent doesn't exist
    #[instrument(skip(self))]
    pub async fn revoke_agent(
        &self,
        agent_id: &str,
        reason: RevocationReason,
        comments: Option<&str>,
    ) -> Result<AgentRevocationResponse> {
        let path = self.agent_path(agent_id, "revoke");
        let request = AgentRevocationRequest {
            reason,
            comments: comments.map(String::from),
        };
        self.request("POST", &path, Some(&request)).await
    }

    // =========================================================================
    // Event Operations
    // =========================================================================

    /// Get paginated agent events.
    ///
    /// This endpoint is used by Agent Host Providers (AHPs) to track agent
    /// registration events across the system. The events feed is a
    /// lane-neutral route served at `/v1/agents/events` regardless of
    /// [`ApiVersion`].
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum events to return (1-100)
    /// * `provider_id` - Filter by provider ID (optional)
    /// * `last_log_id` - Continuation token from previous response (for pagination)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use ans_client::AnsClient;
    ///
    /// # async fn example() -> ans_client::Result<()> {
    /// let client = AnsClient::builder()
    ///     .base_url("https://api.godaddy.com")
    ///     .api_key("key", "secret")
    ///     .build()?;
    ///
    /// // Get first page
    /// let page1 = client.get_events(Some(50), None, None).await?;
    /// for event in &page1.items {
    ///     println!("{}: {} - {}", event.event_type, event.ans_name, event.agent_host);
    /// }
    ///
    /// // Get next page if available
    /// if let Some(last_id) = page1.last_log_id {
    ///     let page2 = client.get_events(Some(50), None, Some(&last_id)).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self))]
    pub async fn get_events(
        &self,
        limit: Option<u32>,
        provider_id: Option<&str>,
        last_log_id: Option<&str>,
    ) -> Result<EventPageResponse> {
        let mut query: Vec<(&str, String)> = Vec::new();

        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        if let Some(provider_id) = provider_id {
            query.push(("providerId", provider_id.to_string()));
        }
        if let Some(last_log_id) = last_log_id {
            query.push(("lastLogId", last_log_id.to_string()));
        }

        let req = self
            .build_request("GET", "/v1/agents/events")?
            .query(&query);
        self.send(req).await
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_header() {
        let jwt = Auth::Jwt(SecretString::from("token123"));
        assert_eq!(jwt.header_value().expose_secret(), "sso-jwt token123");

        let api_key = Auth::ApiKey {
            key: "mykey".into(),
            secret: SecretString::from("mysecret"),
        };
        assert_eq!(
            api_key.header_value().expose_secret(),
            "sso-key mykey:mysecret"
        );
    }

    #[test]
    fn test_auth_debug_redacts_secrets() {
        let jwt = Auth::Jwt(SecretString::from("super-secret-token"));
        let debug_output = format!("{:?}", jwt);
        assert!(
            !debug_output.contains("super-secret-token"),
            "JWT token must not appear in Debug output"
        );
        assert!(debug_output.contains("[REDACTED]"));

        let api_key = Auth::ApiKey {
            key: "mykey".into(),
            secret: SecretString::from("top-secret"),
        };
        let debug_output = format!("{:?}", api_key);
        assert!(
            !debug_output.contains("top-secret"),
            "API secret must not appear in Debug output"
        );
        assert!(
            debug_output.contains("mykey"),
            "API key (non-secret) should appear in Debug output"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_builder_defaults() {
        let client = AnsClient::builder().build().unwrap();
        assert_eq!(client.base_url.as_str(), "https://api.godaddy.com/");
        assert!(client.auth.is_none());
    }

    #[test]
    fn test_builder_custom_url() {
        let client = AnsClient::builder()
            .base_url("https://api.godaddy.com")
            .jwt("mytoken")
            .build()
            .unwrap();

        assert_eq!(client.base_url.as_str(), "https://api.godaddy.com/");
        assert!(matches!(client.auth, Some(Auth::Jwt(_))));
    }

    #[test]
    fn test_builder_api_key() {
        let client = AnsClient::builder()
            .api_key("mykey", "mysecret")
            .build()
            .unwrap();

        match &client.auth {
            Some(Auth::ApiKey { key, secret }) => {
                assert_eq!(key, "mykey");
                assert_eq!(secret.expose_secret(), "mysecret");
            }
            _ => panic!("Expected Auth::ApiKey"),
        }
    }

    #[test]
    fn test_event_type_display() {
        use crate::models::EventType;

        assert_eq!(EventType::AgentRegistered.to_string(), "AGENT_REGISTERED");
        assert_eq!(EventType::AgentRenewed.to_string(), "AGENT_RENEWED");
        assert_eq!(EventType::AgentRevoked.to_string(), "AGENT_REVOKED");
        assert_eq!(
            EventType::AgentVersionUpdated.to_string(),
            "AGENT_VERSION_UPDATED"
        );
    }

    #[test]
    fn test_builder_timeout() {
        let client = AnsClient::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Client builds successfully with custom timeout
        assert_eq!(client.base_url.as_str(), "https://api.godaddy.com/");
    }

    #[test]
    fn test_builder_custom_header() {
        let client = AnsClient::builder()
            .header("x-request-id", "test-123")
            .build()
            .unwrap();

        assert_eq!(
            client.extra_headers.get("x-request-id").unwrap(),
            "test-123"
        );
    }

    #[test]
    fn test_builder_multiple_headers() {
        let client = AnsClient::builder()
            .headers([("x-correlation-id", "corr-456"), ("x-source", "test")])
            .build()
            .unwrap();

        assert_eq!(
            client.extra_headers.get("x-correlation-id").unwrap(),
            "corr-456"
        );
        assert_eq!(client.extra_headers.get("x-source").unwrap(), "test");
    }

    #[test]
    fn test_builder_invalid_header_name() {
        let result = AnsClient::builder()
            .header("invalid header\0name", "value")
            .build();

        assert!(matches!(result, Err(ClientError::Configuration(_))));
    }

    #[test]
    fn test_builder_invalid_url() {
        let result = AnsClient::builder().base_url("not a valid url").build();

        assert!(result.is_err());
    }

    #[test]
    fn test_new_default_client() {
        let client = AnsClient::new().unwrap();
        assert_eq!(client.base_url.as_str(), "https://api.godaddy.com/");
        assert!(client.auth.is_none());
    }

    #[test]
    fn test_builder_rejects_http_url() {
        let result = AnsClient::builder()
            .base_url("http://api.example.com")
            .build();

        match result {
            Err(ClientError::Configuration(msg)) => {
                assert!(msg.contains("HTTPS"), "error should mention HTTPS: {msg}");
            }
            other => panic!("expected Configuration error, got: {other:?}"),
        }
    }

    #[test]
    fn test_builder_allow_insecure_permits_http() {
        let client = AnsClient::builder()
            .base_url("http://localhost:8080")
            .allow_insecure()
            .build()
            .unwrap();

        assert_eq!(client.base_url.scheme(), "http");
    }

    #[test]
    fn test_builder_https_url_always_accepted() {
        let client = AnsClient::builder()
            .base_url("https://api.example.com")
            .build()
            .unwrap();

        assert_eq!(client.base_url.scheme(), "https");
    }
}
