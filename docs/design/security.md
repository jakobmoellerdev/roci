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

roci targets the full authn/authz matrix: TLS 1.3 (with mutual auth), HTTP Basic (htpasswd + LDAP), HTTP Bearer tokens with per-request scope binding, and Identity-Based Access Control with live-reloadable authorization.

## Content trust & integrity

SHA-512 default digests (SHA-256 accepted) with constant-time verification; cosign and notation signatures; verified streaming for per-`Range`-chunk integrity.

## Request- & storage-boundary controls

Path-traversal-safe validation, a wire digest allowlist, bounded inputs (config-driven size / `n` caps, JSON depth), header-read + idle timeouts, per-HTTP-method rate limits (`429 TOOMANYREQUESTS`), TLS 0-RTT refused (1-RTT ticket resumption only), repository isolation (no cross-repo presence or content oracle), and SSRF containment (no client-URL fetch; host-allowlisted, repo-gated redirects).

## Security invariants & CVE regression suite

The canonical doc enumerates security invariants that must never regress, plus a tracked set of prior-art CVE classes exercised as a regression suite in CI. Changing an invariant requires updating `SECURITY.md` and flagging the change.

::: info Reporting
Report security issues per the process in [`SECURITY.md`](https://github.com/jakobmoellerdev/roci/blob/main/SECURITY.md) — do not open a public issue for a vulnerability.
:::
