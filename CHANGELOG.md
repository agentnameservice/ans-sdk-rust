# Changelog

## [0.1.5](https://github.com/agentnameservice/ans-sdk-rust/compare/ans-sdk-v0.1.4...ans-sdk-v0.1.5) (2026-06-23)


### Features

* Add release workflow, cargo-deny, and coverage reporting ([#5](https://github.com/agentnameservice/ans-sdk-rust/issues/5)) ([097d5e6](https://github.com/agentnameservice/ans-sdk-rust/commit/097d5e63f31081bad8a18b80ad3c8e29d0b5b64b))
* add SCITT verification for offline-capable trust verification ([#29](https://github.com/agentnameservice/ans-sdk-rust/issues/29)) ([f03f977](https://github.com/agentnameservice/ans-sdk-rust/commit/f03f977fe78d00fe38ad564ec0b7014935d0162b))


### Bug Fixes

* add version to workspace deps and configure release-please to update them ([#12](https://github.com/agentnameservice/ans-sdk-rust/issues/12)) ([410fd1f](https://github.com/agentnameservice/ans-sdk-rust/commit/410fd1f6388f1ffaccf9641e1296f71e25d27661))
* **deps:** upgrade hickory-resolver 0.25 → 0.26 to fix RUSTSEC-2026-0118/0119 ([#53](https://github.com/agentnameservice/ans-sdk-rust/issues/53)) ([c46e99e](https://github.com/agentnameservice/ans-sdk-rust/commit/c46e99e15fcde00613035aca53701dc71b8a280b))
* let release-please always run, simplify publish conditionals ([#11](https://github.com/agentnameservice/ans-sdk-rust/issues/11)) ([7ffcdc7](https://github.com/agentnameservice/ans-sdk-rust/commit/7ffcdc70dee0e9a7b246145a6bbc69f4223daa06))
* **release:** Update release-please-config with changelog sections ([#21](https://github.com/agentnameservice/ans-sdk-rust/issues/21)) ([0e411d1](https://github.com/agentnameservice/ans-sdk-rust/commit/0e411d14d8303e44fe8ec5ce2abbe38f7366e828))
* remove crate Cargo.toml from release-please extra-files ([#6](https://github.com/agentnameservice/ans-sdk-rust/issues/6)) ([44e45b2](https://github.com/agentnameservice/ans-sdk-rust/commit/44e45b219a5069059d59e6ed8c3652115e3ba537))
* remove publish dry-run step from release workflow ([#13](https://github.com/agentnameservice/ans-sdk-rust/issues/13)) ([8ed8a35](https://github.com/agentnameservice/ans-sdk-rust/commit/8ed8a35e0773613746040b8f134b7722cf5e7a37))
* simplify release-please config for independent crate versioning ([#14](https://github.com/agentnameservice/ans-sdk-rust/issues/14)) ([a69d1f1](https://github.com/agentnameservice/ans-sdk-rust/commit/a69d1f144d5f332be59d612e608d8d4e1f3adec1))
* update ans crate versions to 0.1.3 and enhance release configuration ([#43](https://github.com/agentnameservice/ans-sdk-rust/issues/43)) ([076812a](https://github.com/agentnameservice/ans-sdk-rust/commit/076812a665bed338e814ab00aea827bcf87e3e0e))
* use explicit crate versions for release-please compatibility ([#7](https://github.com/agentnameservice/ans-sdk-rust/issues/7)) ([e32aa42](https://github.com/agentnameservice/ans-sdk-rust/commit/e32aa42e1e170d88460839bd6a124b3c7abf78a9))
* use releases_created (plural) for per-crate release-please output ([#10](https://github.com/agentnameservice/ans-sdk-rust/issues/10)) ([4789795](https://github.com/agentnameservice/ans-sdk-rust/commit/478979568a7978670b404b31be04622cb0a9713b))


### Miscellaneous

* org rename to agentnameservice + dependency/security update (LF donation prep) ([#74](https://github.com/agentnameservice/ans-sdk-rust/issues/74)) ([af5f7fa](https://github.com/agentnameservice/ans-sdk-rust/commit/af5f7fab16efeecf7ec594211942153b70946e5c))
* release main ([#15](https://github.com/agentnameservice/ans-sdk-rust/issues/15)) ([e4d88cf](https://github.com/agentnameservice/ans-sdk-rust/commit/e4d88cfbc712ee6ef14061b6aeeccdaff64d9c6a))
* release main ([#22](https://github.com/agentnameservice/ans-sdk-rust/issues/22)) ([9d8d006](https://github.com/agentnameservice/ans-sdk-rust/commit/9d8d00653c9a2f22029ff98844ff59aeea2063b5))
* release main ([#46](https://github.com/agentnameservice/ans-sdk-rust/issues/46)) ([8b3e37a](https://github.com/agentnameservice/ans-sdk-rust/commit/8b3e37a0a14463f2d483cea35b4c45c305f6d142))
* release main ([#8](https://github.com/agentnameservice/ans-sdk-rust/issues/8)) ([f1bce3f](https://github.com/agentnameservice/ans-sdk-rust/commit/f1bce3f71222d42d16edb8583a9c0ead360412fa))
* reorganize release configuration for ans-sdk components ([#45](https://github.com/agentnameservice/ans-sdk-rust/issues/45)) ([9820f54](https://github.com/agentnameservice/ans-sdk-rust/commit/9820f549d74fa7697512fb6f28a688a864a3424e))
* update release configuration for ans-sdk and add version file ([#44](https://github.com/agentnameservice/ans-sdk-rust/issues/44)) ([aeea958](https://github.com/agentnameservice/ans-sdk-rust/commit/aeea9583ddd14a2d9c939b6d804b87d97e8d0c20))


### Build System

* **deps:** Bump actions/cache from 5.0.3 to 5.0.5 ([#38](https://github.com/agentnameservice/ans-sdk-rust/issues/38)) ([6b5c320](https://github.com/agentnameservice/ans-sdk-rust/commit/6b5c320cdf4f72237a28d0715c5ef2707f26ad24))
* **deps:** Bump actions/upload-artifact from 4.6.2 to 7.0.0 ([#16](https://github.com/agentnameservice/ans-sdk-rust/issues/16)) ([125bf71](https://github.com/agentnameservice/ans-sdk-rust/commit/125bf71ff1a5821a4193846e05d5fdf4a51c78b2))
* **deps:** Bump dtolnay/rust-toolchain ([#30](https://github.com/agentnameservice/ans-sdk-rust/issues/30)) ([9ed6b19](https://github.com/agentnameservice/ans-sdk-rust/commit/9ed6b1929a5ce0850a4a4ba5c1fe2aca1b27052e))
* **deps:** Bump EmbarkStudios/cargo-deny-action from 2.0.15 to 2.0.16 ([#36](https://github.com/agentnameservice/ans-sdk-rust/issues/36)) ([8a035c9](https://github.com/agentnameservice/ans-sdk-rust/commit/8a035c9a9b28163eeea072991cad92885e0c68c8))
* **deps:** Bump EmbarkStudios/cargo-deny-action from 2.0.16 to 2.0.19 ([#63](https://github.com/agentnameservice/ans-sdk-rust/issues/63)) ([2f5e189](https://github.com/agentnameservice/ans-sdk-rust/commit/2f5e189227e38449f41b5de38ff0f53d731ad9fb))
* **deps:** Bump googleapis/release-please-action from 4.4.0 to 4.4.1 ([#37](https://github.com/agentnameservice/ans-sdk-rust/issues/37)) ([7e0a852](https://github.com/agentnameservice/ans-sdk-rust/commit/7e0a85223c439ef4b4aacc3a7c8cdfa54f547590))
* **deps:** Bump quinn-proto from 0.11.13 to 0.11.14 ([#19](https://github.com/agentnameservice/ans-sdk-rust/issues/19)) ([baa6a57](https://github.com/agentnameservice/ans-sdk-rust/commit/baa6a57abd93d643b7fd94587777af4b3ff752d1))
* **deps:** Bump rustls-webpki from 0.103.12 to 0.103.13 ([#49](https://github.com/agentnameservice/ans-sdk-rust/issues/49)) ([74f303c](https://github.com/agentnameservice/ans-sdk-rust/commit/74f303c8d84ef15fda8499ddfb68d155647f50cf))
* **deps:** Bump taiki-e/install-action from 2.68.16 to 2.68.25 ([#17](https://github.com/agentnameservice/ans-sdk-rust/issues/17)) ([c61f01f](https://github.com/agentnameservice/ans-sdk-rust/commit/c61f01f17f3cb2b57e84ee510f74b95559974c16))
* **deps:** Bump taiki-e/install-action from 2.68.25 to 2.75.10 ([#35](https://github.com/agentnameservice/ans-sdk-rust/issues/35)) ([443dc55](https://github.com/agentnameservice/ans-sdk-rust/commit/443dc5569a62fc78c194fb55bc8a47ccd4a2a3ec))
* **deps:** Bump taiki-e/install-action from 2.75.10 to 2.79.7 ([#64](https://github.com/agentnameservice/ans-sdk-rust/issues/64)) ([6c218b5](https://github.com/agentnameservice/ans-sdk-rust/commit/6c218b52b065007c5dcd5f5d91b705709d6cf33b))
* **deps:** Bump the rust-dependencies group across 1 directory with 10 updates ([#62](https://github.com/agentnameservice/ans-sdk-rust/issues/62)) ([3d53b5d](https://github.com/agentnameservice/ans-sdk-rust/commit/3d53b5dd7f78b39d40c6ad3ad7c6969013374ffb))
* **deps:** Bump the rust-dependencies group across 1 directory with 13 updates ([#9](https://github.com/agentnameservice/ans-sdk-rust/issues/9)) ([012449a](https://github.com/agentnameservice/ans-sdk-rust/commit/012449aa4c00b1b6f5c3500ba45760b892c7b992))
* **deps:** Bump the rust-dependencies group with 2 updates ([#65](https://github.com/agentnameservice/ans-sdk-rust/issues/65)) ([2b1e344](https://github.com/agentnameservice/ans-sdk-rust/commit/2b1e3448849aa5e206239e33a89fe1989ccde122))
* **deps:** Bump the rust-dependencies group with 3 updates ([#18](https://github.com/agentnameservice/ans-sdk-rust/issues/18)) ([2517be2](https://github.com/agentnameservice/ans-sdk-rust/commit/2517be25d6da834ff47d10c52d8310354528efdb))

## [0.1.4](https://github.com/godaddy/ans-sdk-rust/compare/ans-sdk-v0.1.3...ans-sdk-v0.1.4) (2026-04-15)


### Features

* Add release workflow, cargo-deny, and coverage reporting ([#5](https://github.com/godaddy/ans-sdk-rust/issues/5)) ([097d5e6](https://github.com/godaddy/ans-sdk-rust/commit/097d5e63f31081bad8a18b80ad3c8e29d0b5b64b))
* add SCITT verification for offline-capable trust verification ([#29](https://github.com/godaddy/ans-sdk-rust/issues/29)) ([f03f977](https://github.com/godaddy/ans-sdk-rust/commit/f03f977fe78d00fe38ad564ec0b7014935d0162b))


### Bug Fixes

* add version to workspace deps and configure release-please to update them ([#12](https://github.com/godaddy/ans-sdk-rust/issues/12)) ([410fd1f](https://github.com/godaddy/ans-sdk-rust/commit/410fd1f6388f1ffaccf9641e1296f71e25d27661))
* let release-please always run, simplify publish conditionals ([#11](https://github.com/godaddy/ans-sdk-rust/issues/11)) ([7ffcdc7](https://github.com/godaddy/ans-sdk-rust/commit/7ffcdc70dee0e9a7b246145a6bbc69f4223daa06))
* **release:** Update release-please-config with changelog sections ([#21](https://github.com/godaddy/ans-sdk-rust/issues/21)) ([0e411d1](https://github.com/godaddy/ans-sdk-rust/commit/0e411d14d8303e44fe8ec5ce2abbe38f7366e828))
* remove crate Cargo.toml from release-please extra-files ([#6](https://github.com/godaddy/ans-sdk-rust/issues/6)) ([44e45b2](https://github.com/godaddy/ans-sdk-rust/commit/44e45b219a5069059d59e6ed8c3652115e3ba537))
* remove publish dry-run step from release workflow ([#13](https://github.com/godaddy/ans-sdk-rust/issues/13)) ([8ed8a35](https://github.com/godaddy/ans-sdk-rust/commit/8ed8a35e0773613746040b8f134b7722cf5e7a37))
* simplify release-please config for independent crate versioning ([#14](https://github.com/godaddy/ans-sdk-rust/issues/14)) ([a69d1f1](https://github.com/godaddy/ans-sdk-rust/commit/a69d1f144d5f332be59d612e608d8d4e1f3adec1))
* update ans crate versions to 0.1.3 and enhance release configuration ([#43](https://github.com/godaddy/ans-sdk-rust/issues/43)) ([076812a](https://github.com/godaddy/ans-sdk-rust/commit/076812a665bed338e814ab00aea827bcf87e3e0e))
* use explicit crate versions for release-please compatibility ([#7](https://github.com/godaddy/ans-sdk-rust/issues/7)) ([e32aa42](https://github.com/godaddy/ans-sdk-rust/commit/e32aa42e1e170d88460839bd6a124b3c7abf78a9))
* use releases_created (plural) for per-crate release-please output ([#10](https://github.com/godaddy/ans-sdk-rust/issues/10)) ([4789795](https://github.com/godaddy/ans-sdk-rust/commit/478979568a7978670b404b31be04622cb0a9713b))


### Miscellaneous

* release main ([#15](https://github.com/godaddy/ans-sdk-rust/issues/15)) ([e4d88cf](https://github.com/godaddy/ans-sdk-rust/commit/e4d88cfbc712ee6ef14061b6aeeccdaff64d9c6a))
* release main ([#22](https://github.com/godaddy/ans-sdk-rust/issues/22)) ([9d8d006](https://github.com/godaddy/ans-sdk-rust/commit/9d8d00653c9a2f22029ff98844ff59aeea2063b5))
* release main ([#8](https://github.com/godaddy/ans-sdk-rust/issues/8)) ([f1bce3f](https://github.com/godaddy/ans-sdk-rust/commit/f1bce3f71222d42d16edb8583a9c0ead360412fa))
* reorganize release configuration for ans-sdk components ([#45](https://github.com/godaddy/ans-sdk-rust/issues/45)) ([9820f54](https://github.com/godaddy/ans-sdk-rust/commit/9820f549d74fa7697512fb6f28a688a864a3424e))
* update release configuration for ans-sdk and add version file ([#44](https://github.com/godaddy/ans-sdk-rust/issues/44)) ([aeea958](https://github.com/godaddy/ans-sdk-rust/commit/aeea9583ddd14a2d9c939b6d804b87d97e8d0c20))


### Build System

* **deps:** Bump actions/upload-artifact from 4.6.2 to 7.0.0 ([#16](https://github.com/godaddy/ans-sdk-rust/issues/16)) ([125bf71](https://github.com/godaddy/ans-sdk-rust/commit/125bf71ff1a5821a4193846e05d5fdf4a51c78b2))
* **deps:** Bump quinn-proto from 0.11.13 to 0.11.14 ([#19](https://github.com/godaddy/ans-sdk-rust/issues/19)) ([baa6a57](https://github.com/godaddy/ans-sdk-rust/commit/baa6a57abd93d643b7fd94587777af4b3ff752d1))
* **deps:** Bump taiki-e/install-action from 2.68.16 to 2.68.25 ([#17](https://github.com/godaddy/ans-sdk-rust/issues/17)) ([c61f01f](https://github.com/godaddy/ans-sdk-rust/commit/c61f01f17f3cb2b57e84ee510f74b95559974c16))
* **deps:** Bump the rust-dependencies group across 1 directory with 13 updates ([#9](https://github.com/godaddy/ans-sdk-rust/issues/9)) ([012449a](https://github.com/godaddy/ans-sdk-rust/commit/012449aa4c00b1b6f5c3500ba45760b892c7b992))
* **deps:** Bump the rust-dependencies group with 3 updates ([#18](https://github.com/godaddy/ans-sdk-rust/issues/18)) ([2517be2](https://github.com/godaddy/ans-sdk-rust/commit/2517be25d6da834ff47d10c52d8310354528efdb))

## [0.1.0](https://github.com/godaddy/ans-sdk-rust/releases/tag/v0.1.0) (Unreleased)

### Added

- **ans-types**: Shared domain types — `Fqdn`, `AnsName`, `Version`, `Badge`, `CertFingerprint`
- **ans-verify**: Trust verification with DNS and transparency log integration
  - `ServerVerifier` for client-side TLS verification
  - `ClientVerifier` for server-side mTLS verification
  - `AnsVerifier` high-level facade combining both
  - `HickoryDnsResolver` for `_ans-badge` / `_ra-badge` TXT record lookup
  - `HttpTransparencyLogClient` for badge API access
  - `BadgeCache` with TTL-based caching via moka
  - DANE/TLSA verification support
  - rustls integration (`AnsServerCertVerifier`, `AnsClientCertVerifier`) behind `rustls` feature flag
  - Mock implementations behind `test-support` feature flag
- **ans-client**: ANS Registry API client
  - Agent registration, discovery, and resolution
  - Certificate management (server and identity CSRs)
  - Agent revocation with RFC 5280 reason codes
  - Event pagination for Agent Host Providers
  - JWT and API key authentication with `secrecy::SecretString`
  - HTTPS-only enforcement by default (`.allow_insecure()` opt-out)

### Security

- All public types annotated with `#[non_exhaustive]` for semver-safe evolution
- Authentication secrets wrapped in `secrecy::SecretString` (zeroized on drop)
- `reqwest` types hidden behind SDK-owned wrappers to decouple semver
- `unsafe_code` forbidden at workspace level
- Panic-prevention lints (`unwrap_used`, `expect_used`, `panic`) denied in production code
- Constant-time certificate fingerprint comparison via `subtle::ConstantTimeEq`
- HTTPS enforced on `AnsClientBuilder` base URL by default
