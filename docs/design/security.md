# Security

::: tip Canonical source
This is an overview. The authoritative, maintained design lives in [`SECURITY.md`](https://github.com/jakobmoellerdev/roci/blob/main/SECURITY.md) at the repo root — it is the source of truth.
:::

roci's security posture is reverse-engineered from [zot](https://zotregistry.dev)'s published [security posture](https://zotregistry.dev/v2.1.21/articles/security-posture/) and adapted to Rust.

## Build-time hardening

- Every crate carries `#![forbid(unsafe_code)]` unless it is an audited zero-copy module explicitly exempted (security invariant 7).
- Supply-chain gating via `cargo deny`; pinned toolchain; static musl builds.

## Runtime hardening

- Rootless by default; the container image runs as a nonroot UID on a `scratch` base with a read-only root filesystem and only the storage volume writable.

## Authentication & authorization

**[implemented — Phase 6]** roci supports the full authn/authz matrix: HTTP Basic (local htpasswd with bcrypt; LDAP bind via the opt-in `ldap` feature, not in `full`), external Bearer token verification (ES256/RS256 over `ring`), mTLS client-certificate authentication with optional CA/leaf-fingerprint pinning, and Identity-Based Access Control (IBAC) with glob-pattern policies, specificity-based rule matching, admin/group support, and live-reloadable authorization. Auth is opt-in; without configuration the registry behaves identically to a no-auth build. Bearer token principals are authorized by their token's `access` claims only (IBAC not consulted). The `/metrics` endpoint stays unauthenticated. See [`SECURITY.md`](https://github.com/jakobmoellerdev/roci/blob/main/SECURITY.md) for the full authn order, decision→response matrix, challenge header rules, and credential-cache design.

## Content trust & integrity

SHA-512 default digests (SHA-256 accepted) with constant-time verification; cosign and notation signatures; verified streaming for per-`Range`-chunk integrity. 307 redirect SSRF containment via a derived host allowlist and internal-host rejection. 0-RTT hardening: `425 Too Early` for proxy-forwarded early data on non-idempotent methods (RFC 8470 §5.1).

## Request- & storage-boundary controls

Path-traversal-safe validation, a wire digest allowlist, bounded inputs (config-driven size / `n` caps, JSON depth), header-read + idle timeouts, per-HTTP-method rate limits (`429 TOOMANYREQUESTS`), TLS 0-RTT hardening, repository isolation (no cross-repo presence or content oracle), cross-repo mount double-authorization, and SSRF containment (no client-URL fetch; host-allowlisted, repo-gated redirects). On the storage side: storage quotas and a concurrent upload-session cap against exhaustion, GC that can never delete a blob a push is about to reference, a manifest and its derived links committed as one metadata record, scrub quarantine of blobs that no longer match their digest, and optional HMAC authentication of the metadata log and snapshot against a tampered storage volume.

## Security invariants & CVE regression suite

The canonical doc enumerates security invariants that must never regress, plus a tracked set of prior-art CVE classes exercised as a regression suite in CI. Changing an invariant requires updating `SECURITY.md` and flagging the change.

::: info Reporting
Report security issues per the process in [`SECURITY.md`](https://github.com/jakobmoellerdev/roci/blob/main/SECURITY.md) — do not open a public issue for a vulnerability.
:::
