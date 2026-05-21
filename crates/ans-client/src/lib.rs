#![warn(missing_docs)]

//! # ANS API Client
//!
//! This crate provides a client for interacting with the ANS (Agent Name Service) API
//! for agent registration, certificate management, and discovery operations.
//!
//! ## Features
//!
//! - Agent registration and renewal
//! - Certificate signing request generation ([`csr::AnsCsrBuilder`])
//! - Certificate signing request submission
//! - Agent search and resolution
//! - Domain validation (ACME, DNS)
//! - Agent revocation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ans_client::{AnsClient, models::*};
//!
//! #[tokio::main]
//! async fn main() -> ans_client::Result<()> {
//!     // Create a client with JWT authentication
//!     let client = AnsClient::builder()
//!         .base_url("https://api.godaddy.com")
//!         .jwt("your-jwt-token")
//!         .build()?;
//!
//!     // Search for agents
//!     let mut criteria = SearchCriteria::default();
//!     criteria.agent_host = Some("example.com".into());
//!     let results = client.search_agents(&criteria, Some(10), None).await?;
//!
//!     for agent in results.agents {
//!         println!("{}: {}", agent.ans_name, agent.agent_display_name);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Authentication
//!
//! The ANS API supports two authentication methods:
//!
//! - **JWT**: For endpoints at `api.{env}-godaddy.com`
//!   ```rust
//!   # use ans_client::AnsClient;
//!   let client = AnsClient::builder()
//!       .jwt("your-jwt-token")
//!       .build();
//!   ```
//!
//! - **API Key**: For public gateway (`api.godaddy.com`)
//!   ```rust
//!   # use ans_client::AnsClient;
//!   let client = AnsClient::builder()
//!       .api_key("your-key", "your-secret")
//!       .build();
//!   ```
//!
//! ## Registration Flow
//!
//! Agent registration is a multi-step process:
//!
//! 1. Submit registration request with CSRs
//! 2. Configure ACME challenge (DNS-01 or HTTP-01)
//! 3. Call `verify_acme()` to validate domain ownership
//! 4. Configure required DNS records
//! 5. Call `verify_dns()` to complete registration
//!
//! ```rust,no_run
//! # use ans_client::{AnsClient, AnsCsrBuilder, models::*};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = AnsClient::builder()
//!     .base_url("https://api.godaddy.com")
//!     .jwt("token")
//!     .build()?;
//!
//! // Step 1: Generate CSRs with correct extensions and RSA-2048 keys
//! let server = AnsCsrBuilder::server("agent.example.com", "1.0.0").build()?;
//! let identity = AnsCsrBuilder::identity("agent.example.com", "1.0.0").build()?;
//! // store server.private_key_pem and identity.private_key_pem securely
//!
//! // Step 2: Register
//! let endpoint = AgentEndpoint::new("https://agent.example.com/mcp", Protocol::Mcp)
//!     .with_transports(vec![Transport::StreamableHttp]);
//!
//! let request = AgentRegistrationRequest::new(
//!     "my-agent",
//!     "agent.example.com",
//!     "1.0.0",
//!     &identity.csr_pem,
//!     vec![endpoint],
//! )
//! .with_server_csr_pem(&server.csr_pem);
//!
//! let pending = client.register_agent(&request).await?;
//! let agent_id = pending.agent_id.expect("agent_id");
//!
//! // Step 3: Configure ACME challenge, then verify
//! // ... add _acme-challenge DNS TXT record from pending.dns_records ...
//! let _status = client.verify_acme(&agent_id).await?;
//!
//! // Step 4: Configure DNS records, then verify
//! // ... configure DNS records from pending.dns_records ...
//! let _status = client.verify_dns(&agent_id).await?;
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod csr;
pub mod error;
pub mod models;

pub use client::{AnsClient, AnsClientBuilder, Auth};
pub use csr::{AnsCsrBuilder, CsrOutput};
pub use error::{ClientError, HttpError, Result};

// Re-export types from ans-types for convenience
pub use ans_types::{Fqdn, Version};
