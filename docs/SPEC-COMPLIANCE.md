# Merged-spec SDK coverage

The SDK supports the following contracts from
[`agentnameservice/ans-registry` at `f2373f164d562edcb239dd9cd1f77b45797da682`](https://github.com/agentnameservice/ans-registry/tree/f2373f164d562edcb239dd9cd1f77b45797da682).
This describes SDK contract and verification coverage, not certification of a
particular RA, DNS deployment, or transparency log.

| Requirement / surface | SDK behavior | Regression evidence |
| --- | --- | --- |
| ANS-2 naming | Shared FQDN construction/deserialization and strict numeric version components | `ans-types` boundary tests; CSR tests |
| ANS-0/1 registration | Optional identity CSR; endpoint metadata hashes; DEPRECATED lifecycle; identity associations | `v2_lifecycle`, `identity_management` and shared model tests |
| V2 owner collection | Repeated status filters, host filter, bounded page size, opaque cursor | `v2_lifecycle` HTTP tests |
| V2 server renewal | CSR/BYOC submit, poll, ACME verify, cancel with empty 204 | `v2_lifecycle` HTTP tests |
| ANS-0 identity management | All eight owner API operations, atomic proof/link batches, error propagation | `identity_management` HTTP tests |
| ANS-0 proof preparation | Exact served payload, trusted RA/identity/nonce binding, eligible kid, external signer support | `identity_management` preparation tests |
| ANS-0 public TL reads | Badge, audit, receipt, linked agents, agent identities, agent identity history; checkpoint-pending response | `tlog::identities::tests` |
| ANS-0 did:web / did:key proofs | Sealed authoritative JWK/Multikey, Ed25519/P-256/RSA signatures, exact JCS input, common round, unique methods | `identities::tests` real-signature tests |
| ANS-0 current identity state | Separate historical proof and current badge, exact keysLogId/method binding, terminal revocation | `identities::tests` state and receipt tests; `verify_identity` public workflow example/tests |
| ANS-3 DANE | Only DNSSEC-secure TLSA records are eligible | DNS proof-state tests |
| ANS-6 caller version | Exact versioned badge before legacy versionless fallback; no newest-version substitution | Verification scenario tests |
| ANS-4/6 trusted TL origin | HTTPS root-key retrieval and no redirects | SCITT HTTP tests |
| ANS-4/6 regular SCITT tier | Complete receipt/token pair for RequireScitt; partial evidence validated and bound before allowed fallback | SCITT scenario tests |
| ANS-4 receipt processing | Original COSE signature before issuer checks, exact RFC8785 JCS payload before leaf hashing | Receipt canonicalization/signature tests |
| ANS-6 request path | Cache-only current_headers; explicit bounded initialize and background refresh | Supplier tests |

## Supported identity workflow

1. Register or rotate through a V2 `AnsClient` to obtain the challenge round.
2. Prepare each eligible key's proof with the configured RA identifier. Sign the
   exposed bytes with the chosen local/KMS signer, then attach the signature.
3. Submit all proofs in one `verify_identity_control` request. The RA owns
   authoritative DID resolution, owner authorization, nonce consumption, and
   persistence. The SDK does not simulate those server responsibilities.
4. Link verified identities to owned agents through the management API.
5. Read the current identity badge from a configured trusted HTTPS TL. Fetch
   the proof event referenced by `keysLogId` from the identity audit. Audit pages
   are newest first: process oldest to newest when selecting the latest proof.
6. Authenticate proof evidence with `observe_receipt`, or use
   `observe_trusted_entry` when relying on the configured trusted fetch channel.
   A receipt for a later link-only event does not contain the prior proof.
7. Call `verify_badge` with the current trusted badge. A valid historical proof
   alone never establishes current VERIFIED status. Revocation cannot be undone
   by later proof/link events or stale badges.

A missing sealed `raId` makes offline proof reconstruction incomplete. Header
JWKs never replace the sealed verification method. Additional method members are
preserved and checked when matching the current badge. LEI and ENS remain
recognized wire kinds, but their control-proof profiles are postponed in the
pinned spec and return unsupported when offline verification is attempted.

Method B's configured receipt waiver and existing V1 badge reading remain
supported. No audit-completeness, independent detached-JSON-signature, or live
service conformance claim is implied. See [MIGRATING.md](../MIGRATING.md) for API
changes and initialization requirements.

Agent badge `identities` preserves omission separately from an empty list, and
`identities_unavailable` preserves the TL's failure marker. An unavailable join
must not be treated as no visible identities. DANE binds records to the queried
service name and requires every CNAME hop and the terminal TLSA RRset to be
DNSSEC-secure; unrelated signed answers and unproven alias paths are ignored.
