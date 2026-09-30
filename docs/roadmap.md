---
aside: false
outline: false
# Roadmap data. Mirrors the "Feature roadmap" in the repo-root README.md:
# change a capability's status in both files in one change.
# status: done | wip | planned | blocked
areas:
  - id: core
    title: Core distribution
    tagline: The OCI Distribution Spec, served from a plain OCI image layout.
    items:
      - { status: done, title: OCI Distribution Spec v1.1.1, detail: "Passes the upstream conformance suite." }
      - { status: done, title: OCI image layout storage, detail: "Any layout on disk can be served as a registry." }
      - { status: done, title: Rootless, detail: "Runs without root privileges." }
      - { status: done, title: Config-driven, detail: "Behavior controlled entirely via configuration." }
      - { status: done, title: Multi-platform releases, detail: "Binaries for multiple operating systems and architectures." }
      - { status: done, title: Delete by tag }
      - { status: done, title: On-premises ready, detail: "e.g. colocated with Kubernetes." }
      - { status: wip, title: Single binary, detail: "One binary for all features." }
      - { status: wip, title: Core / extension split, detail: "Dist-spec core cleanly separated from roci extensions." }
      - { status: wip, title: HTTP/2 and TLS 1.3, detail: "Multiplexing and keep-alive; optional kTLS zero-copy." }
      - { status: wip, title: SHA-512 digests, detail: "SHA-512 by default, SHA-256 accepted; constant-time verification." }
      - { status: planned, title: Ecosystem compatibility, detail: "skopeo, cri-o." }
      - { status: planned, title: Digest response caching, detail: "`ETag` / `If-None-Match` → `304`; correct tag-vs-digest cache-control." }
      - { status: planned, title: Foreign media types, detail: "Nydus, eStargz, SBOMs, signatures and `tar+zstd` layers served as opaque blobs." }

  - id: security
    title: Security & access control
    tagline: Authenticated, authorized, and hard to misuse.
    items:
      - { status: done, title: TLS 1.3, detail: "0-RTT hardening via `425 Too Early`." }
      - { status: done, title: Mutual TLS, detail: "Client certificates with optional CA or leaf-fingerprint pinning." }
      - { status: done, title: Basic auth — htpasswd, detail: "bcrypt only." }
      - { status: done, title: Basic auth — LDAP, detail: "Opt-in cargo feature `ldap`, not in `full`." }
      - { status: done, title: Bearer tokens, detail: "External token server; ES256/RS256, per-request scope binding." }
      - { status: done, title: Identity-based access control, detail: "Glob patterns, specificity matching, admins and groups." }
      - { status: done, title: Live authorization reload, detail: "Change access rules without a restart." }
      - { status: done, title: Repository isolation, detail: "No cross-repo presence oracle; cross-repo mounts authorized twice." }
      - { status: done, title: SSRF containment, detail: "No client-supplied URL fetches; allowlisted, repo-gated redirects." }
      - { status: wip, title: Boundary hardening, detail: "Path-traversal-safe validation, digest allowlist, bounded inputs." }
      - { status: planned, title: CVE-class regression suite, detail: "Prior-art registry CVEs replayed in CI." }

  - id: storage
    title: Storage
    tagline: Content-addressed, deduplicated, self-healing.
    items:
      - { status: done, title: Online garbage collection, detail: "O(garbage) with a grace period and backref index; never offline." }
      - { status: done, title: Copy-on-write dedup, detail: "Reflink (`FICLONE`) across repos, with hard-link and copy fallbacks." }
      - { status: done, title: Data scrubbing, detail: "CRC32C checks, digest re-hash on mismatch, quarantine." }
      - { status: done, title: Multiple storage paths, detail: "Mix local paths and S3-compatible object storage in one server." }
      - { status: done, title: Quotas, detail: "Per-repo and total quotas, plus a cap on concurrent uploads." }
      - { status: done, title: Small-blob cache, detail: "Byte-capped in-memory LRU for manifests and configs." }
      - { status: done, title: Metadata engines, detail: "In-memory log (default, optional HMAC) or LMDB on disk." }
      - { status: done, title: Lossless engine switching, detail: "log ↔ lmdb with a verified migration at startup." }

  - id: operability
    title: Operability
    tagline: Observable, deployable, boring to run.
    items:
      - { status: done, title: Rate limiting, detail: "Per HTTP method and per client." }
      - { status: done, title: Prometheus metrics }
      - { status: done, title: OpenTelemetry, detail: "OTLP traces, metrics and logs." }
      - { status: done, title: Fast cold start, detail: "Opt-in `fast_restart` stamp and a low-fragmentation allocator." }
      - { status: done, title: Hardened Helm chart, detail: "PSS restricted, NetworkPolicies, optional HA S3 on RustFS; attested OCI artifact at `oci://ghcr.io/jakobmoellerdev/charts/roci`." }
      - { status: done, title: Health endpoints, detail: "`/readyz` and `/livez`, unauthenticated and rate-limit-free." }
      - { status: done, title: S3 bucket auto-creation, detail: "`create_bucket`, plus private-CA trust via `ca_file`." }
      - { status: planned, title: Node exporter for minimal builds }
      - { status: planned, title: OpenAPI documentation }
      - { status: blocked, title: RustFS client-cert mTLS, detail: "`object_store` has no client-cert API; the RustFS chart has no server-TLS-only mode." }

  - id: content
    title: Content & ecosystem
    tagline: Signatures, charts and lazy pulls.
    items:
      - { status: planned, title: cosign signatures }
      - { status: planned, title: notation signatures }
      - { status: planned, title: Helm charts as artifacts }
      - { status: planned, title: Lazy-pull origin, detail: "eStargz, SOCI and Nydus via Range requests and referrer metadata." }
      - { status: planned, title: BLAKE3 verified streaming, detail: "Per-`Range`-chunk integrity, stored as a referrer." }

  - id: search
    title: Query & search
    tagline: Find images and what is inside them.
    items:
      - { status: planned, title: Search extension, detail: "Advanced image queries." }
      - { status: planned, title: Vulnerability scanning, detail: "Trivy, with SPDX/CycloneDX SBOMs as referrers." }

  - id: scaling
    title: Scaling
    tagline: From a Raspberry Pi to a cluster.
    items:
      - { status: planned, title: Vertical scale, detail: "Streaming, zero-copy, bounded memory on one node." }
      - { status: planned, title: Horizontal scale-out, detail: "Repo sharding via consistent hashing with a peer proxy." }
      - { status: planned, title: Memory follows references, detail: "RSS scales with reference count, not stored bytes." }

  - id: replication
    title: Replication
    tagline: Mirror other registries.
    items:
      - { status: planned, title: Registry sync, detail: "Pull and synchronize from any dist-spec conformant registry." }
---

# Roadmap

What roci does today, what is being built, and what comes next.

<Roadmap />
