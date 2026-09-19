# roci — Security Design

Security design for **roci**, a Rust OCI Distribution registry. This document defines roci's defense-in-depth posture across build-time hardening, runtime hardening, authentication, authorization, and content trust.

## Design lineage

roci's security posture is reverse-engineered from [zot](https://zotregistry.dev)'s and adapted to Rust. Design sources (zot docs, v2.1.21):

- [zot — Security Posture](https://zotregistry.dev/v2.1.21/articles/security-posture/) — build-time and runtime hardening, conditional builds, non-root deployment, authn/authz options, HTTP timeouts.
- [zot — Architecture](https://zotregistry.dev/v2.1.21/general/architecture) — the "authn/authz enforced before storage access" model and the minimal/extension separation that bounds attack surface.
- [zot — Storage Planning](https://zotregistry.dev/v2.1.21/articles/storage/) — repository-boundary and data-integrity properties relevant to security (repo-local reads, scrub).

Companion: [`ARCHITECTURE.md`](ARCHITECTURE.md). Spec/auth reference: [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md) (de-facto bearer-token flow).

roci adopts zot's **defense-in-depth** philosophy: layered, industry-standard controls at build and deploy time, with flexibility where hardening and features conflict. **[roci divergence]** notes where Rust changes or strengthens the posture.

## Threat model (scope)

- **Assets:** stored blobs/manifests (integrity + confidentiality per access policy), signing/token keys, backend credentials, availability of the service.
- **Adversaries:** unauthenticated network clients; authenticated-but-unauthorized users attempting cross-repo access; malicious content pushers; slow/abusive connections (DoS); attackers exploiting memory-safety or dependency vulnerabilities.
- **Out of scope:** host OS hardening, network perimeter, physical security, compromised admin.

## Build-time hardening

### Memory safety (roci's strongest divergence)

**[roci divergence]** roci is written in safe Rust. The largest single class of registry CVEs — memory-corruption in a long-running network service parsing untrusted input (manifests, digests, ranges) — is eliminated by construction. `unsafe` is forbidden outside audited, isolated modules (zero-copy I/O) and gated by CI lint (`#![forbid(unsafe_code)]` in every crate that can afford it).

### Hardened binaries

Adopt zot's binary hardening intent:

- **PIE / ASLR.** Build position-independent executables so ASLR randomizes memory layout, preventing generic address-dependent exploits reused across deployments. (zot: PIE build-mode.)
- **Stripped, static release builds** with overflow checks retained where cheap; fuzzed parsers at the untrusted boundary (manifest/digest/reference — see [`PLAN.md`](PLAN.md) cross-cutting).

### Conditional builds (attack-surface control)

Directly from zot: functionality splits into a **core** Distribution Spec implementation and **extensions**, so dependency count and attack surface are controllable.

- **`roci-minimal`** — core only, fewest dependencies/libraries; for the security-minded.
- **`roci-full`** — minimal + all extensions; larger attack surface, more features.
- **Custom** — pick individual extensions (`cargo build --features search`) to sit anywhere on the minimal↔full spectrum.

Every extension is a cargo feature → excluded code is not compiled into the binary at all, not merely disabled at runtime. This is the primary attack-surface lever.

### Supply chain & CI/CD

Aligns with zot's OSSF best-practices intent:

- All PRs reviewed by code owners; CI blocks unreviewed commits to protected branches.
- CI gate: unit + functional + integration tests, OCI conformance suite, lint/style, performance-regression checks.
- **[roci divergence] Rust supply-chain tooling:** `cargo audit` / `cargo deny` for advisory + license + duplicate-dependency gating; `cargo vet` for trusted dependency provenance; reproducible builds; SBOM emitted per release. Released binaries scanned for known vulns before publish.

## Runtime hardening

### Unprivileged process

roci requires **no root privileges** (zot design). Recommended deployment: a dedicated, unprivileged user/group ID, no capabilities, read-only container root FS with the storage volume the only writable mount. No privileged ports by default.

### Enforcement point

**AuthN/AuthZ is enforced before any access into the storage layer** (zot architecture). No handler touches the `Storage` trait before the request identity is authenticated and the action authorized. This is an architectural invariant (see [`ARCHITECTURE.md`](ARCHITECTURE.md)).

### HTTP read/write timeouts

Adopt zot's configurable read/write timeouts (default `60s`) on both the API server and the metrics exporter, to bound slow-client and stalled-connection resource exhaustion.

- Larger values for large pushes/pulls over slow links.
- `0` disables (infinite) — flagged in docs as increasing exposure to stalled/abusive connections.

**[roci divergence]** timeouts pair with per-method rate limiting and bounded upload-session memory (streaming, never buffering a full blob) so a flood of concurrent uploads cannot exhaust RAM.

## Authentication

All interaction is over HTTP APIs; roci supports the full zot authn matrix (see [`PLAN.md`](PLAN.md) Phase 6). Operators are strongly advised to enable a mechanism suited to their deployment to prevent unauthorized access.

| Mechanism | Notes |
| --- | --- |
| **HTTP Basic — local htpasswd** | bcrypt-hashed credentials in an htpasswd file. |
| **HTTP Basic — LDAP** | Bind against a directory; credentials never stored locally. |
| **HTTP Bearer token** | Docker V2 token scheme: `WWW-Authenticate` challenge → repo-scoped bearer token. Auth reference: [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md). |
| **TLS mutual authentication (mTLS)** | Client-certificate verification; identity derived from the cert. |

TLS is supported for transport confidentiality; mTLS additionally authenticates the client. Anonymous access (e.g. public pull) is a policy choice, not a default.

## Authorization (access control)

After authentication, roci allows or denies a specific **action** by a **user/identity** on a specific **repository** — Identity-Based Access Control (IBAC).

- Policies map identity → repository (glob/prefix) → permitted actions (pull, push, delete, …).
- Default-deny where a policy is configured; explicit anonymous-pull opt-in.
- **Live authorization reload:** authz policy can be modified in the running config and reload without restart or dropping connections (zot supports live modification of authorization config). Only authorization is live-reloadable; other config changes require restart.

## Content trust & integrity

- **Digest verification everywhere.** Every blob is verified against its digest on write (hash-on-write during upload finalize) and its identity is its content address on read. Constant-time digest comparison. A digest mismatch is `DIGEST_INVALID`.
- **Repository boundaries.** Repo-local-by-default blob reads (zot v2.1.21 `hydrateBlobOnRead=false`): a digest present only in the cross-repo dedupe cache is **not** served from another repo — returns `404` until explicitly mounted (`end-11`) or uploaded. Prevents cross-repo content leakage via shared dedupe.
- **Data scrubbing.** The scrub extension re-hashes blobs periodically to detect bit-rot/tampering on disk and report it early.
- **Image signatures (extensions).** cosign and notation signatures stored/served via the referrers API; verification hooks let policy require valid signatures.
- **Vulnerability scanning (extension).** Trivy integration scans stored images; the vuln DB is refreshed on a configurable interval by the background scheduler. The scanner implementation is abstracted so it can change without user-facing impact.

## Secrets handling

- Sensitive config (backend credentials, LDAP bind password, token signing keys) MAY live in separate referenced files with stricter filesystem permissions, and mount as Kubernetes Secrets (zot config model).
- Cloud credentials resolvable via environment / instance IAM roles rather than inline config (avoid secrets at rest in the main config).
- Signing/token keys never logged; telemetry redacts credential-bearing fields.

## Security invariants (must never regress)

1. No `Storage` access before authentication + authorization of the request.
2. Excluded extensions are not compiled into the binary (attack surface = enabled features only).
3. Every blob write is digest-verified; every read is content-addressed.
4. Cross-repo dedupe never leaks content across repository boundaries on read.
5. No blob is fully buffered in memory; upload/download memory is bounded regardless of client behavior.
6. `roci-minimal` carries the minimum dependency set required for a conformant registry.
7. `unsafe` code is confined to audited modules and CI-gated.

## Reporting security issues

A `SECURITY.md`-style responsible-disclosure policy (contact, embargo, coordinated disclosure) will govern reported vulnerabilities, following the zot precedent. TBD before first release.
