# Roadmap

::: tip Kept in sync with the README
This page mirrors the feature roadmap in the repo-root [`README.md`](https://github.com/jakobmoellerdev/roci/blob/main/README.md). When a capability's status changes, update both in the same change (see `AGENTS.md`).
:::

Legend: `[ ]` planned · `[~]` in progress · `[x]` done.

## Core distribution

- [x] Conforms to OCI Distribution Spec APIs (v1.1.1)
- [x] Uses OCI image layout for image storage
- [x] Can serve any OCI image layout as a registry
- [~] Single binary for all features
- [x] Runs without root privileges
- [~] Clear separation between core dist-spec and roci-specific extensions
- [x] Behavior controlled entirely via configuration
- [x] Binaries released for multiple operating systems and architectures
- [x] Image deletion by tag
- [ ] Compatible with ecosystem tools (skopeo, cri-o)
- [ ] Suitable for on-premises deployments (e.g. colocated with Kubernetes)
- [~] HTTP/2 multiplexing + keep-alive; TLS 1.3 with optional kTLS zero-copy
- [~] SHA-512 default digests (SHA-256 accepted); constant-time verification
- [ ] Immutable-by-digest response caching (`ETag`/`If-None-Match` → `304`), correct tag-vs-digest cache-control
- [ ] Foreign media types & `tar+zstd` layers stored/served as opaque blobs (Nydus, eStargz, SBOM, signatures)

## Content & ecosystem

- [ ] Container image signatures — cosign
- [ ] Container image signatures — notation
- [ ] Helm chart support
- [ ] Lazy-pull origin (eStargz / SOCI / Nydus) via Range + referrer-carried metadata
- [ ] BLAKE3 Bao verified streaming — per-`Range`-chunk integrity, stored as a referrer

## Query & search

- [ ] Advanced image queries via search extension
- [ ] Vulnerability scanning of images (Trivy) with SBOMs (SPDX/CycloneDX) as referrers

## Security & access control

- [x] TLS support (TLS 1.3, 0-RTT hardening via `425 Too Early`)
- [x] TLS mutual authentication (client cert, optional CA/leaf-fingerprint pinning)
- [x] HTTP Basic authentication — local htpasswd (bcrypt)
- [x] HTTP Basic authentication — LDAP (opt-in cargo feature `ldap`, not in `full`)
- [x] HTTP Bearer token authentication (external token server; ES256/RS256 verification, per-request scope binding)
- [x] Identity-Based Access Control (glob patterns, specificity matching, admin/group support)
- [x] Live modification of authorization configuration while running
- [~] Boundary hardening — path-traversal-safe validation, wire digest allowlist, bounded inputs (size/`n`/depth)
- [x] Repository isolation — no cross-repo presence/content oracle; cross-repo mount double-authorized
- [x] SSRF containment — no client-URL fetch; host-allowlisted, repo-gated redirects; config-load rejection of internal endpoints
- [ ] Prior-art CVE-class regression suite in CI

## Storage

- [x] Online, O(garbage) garbage collection (grace-period, backref index, startup backref rebuild; never offline)
- [x] Copy-on-write (reflink `FICLONE`) deduplication across repos — mounts and uploads — hard-link then streaming-copy fallback
- [x] Data scrubbing (CRC32C staggered + adaptive, FS-scrub offload, digest re-hash escalation, quarantine)
- [x] Serve multiple storage paths (and backends, incl. S3-compatible object storage) from a single server
- [x] Per-repo / per-total storage quotas and a concurrent upload-session cap
- [ ] In-memory small-blob content cache; 2-level fanout at scale
- [x] Embedded metadata index — append-log + in-RAM maps default (compaction, rkyv mmap snapshot, optional HMAC), redb B-tree KV upgrade

## Replication

- [ ] Pull and synchronize from other dist-spec conformant registries

## Scaling

- [ ] Vertical scale — efficient scale-up on a single node (streaming, zero-copy, bounded memory)
- [ ] Horizontal scale-out — clustered instances, repo sharding via consistent hashing (HRW + bounded-load), peer proxy
- [ ] RSS scales with reference count, not stored bytes (mmap-offloadable metadata; runs on a Raspberry Pi)

## Operability

- [x] Rate limiting, including per-HTTP-method limits
- [x] Prometheus metrics
- [x] OpenTelemetry observability (OTLP traces, metrics, and logs)
- [ ] Node exporter for minimal builds
- [ ] Swagger-based API documentation
- [~] O(1) cold start (rkyv mmap snapshot / fast-restart) and low-fragmentation allocator
