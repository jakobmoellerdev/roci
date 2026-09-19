<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="roci" width="360">
  </picture>
</p>

# roci

![coverage](https://img.shields.io/badge/coverage-100.00%25-brightgreen)

**roci** is a Rust implementation of the [OCI Distribution Specification](spec/distribution-spec/spec.md) — an OCI container registry.

roci is built around three goals:

- **Minimal runtime overhead / small footprint** — a single static binary with a tiny memory and CPU baseline, no runtime dependencies, no daemon sprawl. Suitable for edge, CI, and colocated Kubernetes deployments.
- **Extremely fast and efficient queries** — an index designed for low-latency tag, manifest, referrer, and search lookups; zero-copy blob serving where the OS allows it.
- **Fast and easy configuration** — start with zero config and sane defaults; grow into a single declarative config file. No external database required to run.

roci targets full conformance with the OCI Distribution Spec v1.1.1 and feature parity with [zot](https://github.com/project-zot/zot), while keeping a clear separation between the core distribution API and optional extensions.

## Design principles

- **Content-addressable storage.** Blobs and manifests live in a filesystem-backed content-addressable store (per-repo `blobs/`, `manifests/`, `tags/`) with streamed hash-on-write. Serving a standard [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) directly is a roadmap goal (see below), not yet the on-disk format.
- **Core vs. extensions.** The dist-spec surface is a stable core; signatures, search, sync, scanning, and metrics are cleanly separated extensions that can be compiled and configured independently.
- **Config-driven behavior.** All behavior is controlled from configuration, not code paths baked at build time.
- **Rootless by default.** No root privileges required to run.

## Design & specs

Design documents:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component model, storage subsystem, extension model.
- [`SECURITY.md`](SECURITY.md) — build/runtime hardening, authn/authz, content trust.
- [`PLAN.md`](PLAN.md) — phased master build plan.
- [`RESEARCH.md`](RESEARCH.md) — academic + industry evidence backing the storage and scale-out design.

The design docs are reverse-engineered from [zot](https://zotregistry.dev)'s published architecture, storage, security-posture, and scale-out articles (cited within) and adapted to Rust.

A rendered documentation site (VitePress) is published to GitHub Pages from [`docs/`](docs/): <https://jakobmoellerdev.github.io/roci/>. Build it locally with `cd docs && npm install && npm run docs:dev`.

Specs are vendored under `spec/` — OCI Distribution + Image specs as submodules pinned to `v1.1.1`, plus a snapshot of the Docker Registry V2 API reference:

```
spec/distribution-spec/spec.md    # OCI Distribution Spec (registry API)
spec/image-spec/spec.md           # OCI Image Spec
spec/image-spec/image-layout.md   # OCI Image Layout (on-disk format)
spec/docker-registry-api-v2.md    # Docker Registry V2 (de-facto bearer-token auth)
```

Populate the submodules after clone with:

```sh
git submodule update --init --depth 1
```

## Developing locally

### Prerequisites

- **Rust** via [`rustup`](https://rustup.rs) — the pinned toolchain in `rust-toolchain.toml` installs automatically on the first `cargo` invocation.
- [`just`](https://github.com/casey/just) — the task runner.
- [`cargo-nextest`](https://nexte.st) — test runner used by CI.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) — supply-chain gate.
- [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) — coverage gate (`rustup component add llvm-tools-preview` too).
- **Go 1.17+** — only for the OCI conformance suite.
- [`actionlint`](https://github.com/rhysd/actionlint) and [`zizmor`](https://github.com/zizmorcore/zizmor) — only for linting/auditing the GitHub Actions workflows (`just lint-workflows`, `just zizmor`).

Install the cargo tools in one line:

```sh
cargo install just cargo-nextest cargo-deny cargo-llvm-cov
```

### First-time setup

Fetch the pinned OCI spec submodules:

```sh
git submodule update --init --depth 1   # or: just init
```

Install the git pre-commit hook (runs fmt, clippy, workflow lint, and the 100%
coverage gate, and refreshes [`COVERAGE.md`](COVERAGE.md) + the badge on every commit):

```sh
just hooks   # or, with the pre-commit framework: pre-commit install
```

### Tasks

Every recipe mirrors a CI gate, so passing locally means passing the required CI checks.

| Command | What it does |
| --- | --- |
| `just` | List all recipes |
| `just init` | Fetch pinned spec submodules |
| `just fmt` / `just fmt-fix` | Check / apply formatting |
| `just clippy` | Lint both build flavors, warnings = errors |
| `just test` | Run tests (nextest) + doctests |
| `just build` | Build minimal and full flavors |
| `just deps-guard` | Assert no extension crate leaks into the minimal build |
| `just lint-workflows` | Lint the GitHub Actions workflows (actionlint) |
| `just zizmor` | Security-audit the workflows (zizmor) |
| `just audit` | `cargo deny` supply-chain check |
| `just coverage` | Enforce 100% line coverage (cargo-llvm-cov) |
| `just coverage-report` | Show uncovered lines (developer aid) |
| `just ci` | Run the full local gate before pushing (actionlint + fmt + clippy + test + build + deps-guard + coverage) |
| `just conformance` | Run the OCI dist-spec conformance suite against a local roci |
| `just container` | Build the hardened scratch image and smoke-test it |
| `just container-multiarch` | Build the multi-arch image (linux/amd64, linux/arm64) |

### Run it locally

`cargo run -p roci-cli` starts a zero-config registry on `127.0.0.1:5000` by default; point `skopeo`, `crane`, or `oras` at it. See `cargo run -p roci-cli -- --help` for flags (`--listen`, `--storage-root`).

**CI parity:** `just ci` runs the same checks GitHub Actions requires — if it passes locally, the required CI checks pass.

### Container image

[`Containerfile`](Containerfile) builds a **hardened, fully static** image: a
musl-static binary on a `scratch` base (no shell, no libc, no package manager),
running as an unprivileged nonroot UID with the storage directory as the only
writable path (mount the root FS read-only).

```sh
just container          # build + smoke-test the running container
docker run --read-only -v roci-data:/var/lib/roci -p 5000:5000 ghcr.io/jakobmoellerdev/roci
```

The `container` CI workflow builds and smoke-tests the image on **native
per-arch runners** (no QEMU emulation): pull requests build only `linux/arm64`
(on an `ubuntu-24.04-arm` runner) to save time, while `main` builds both
`linux/amd64` and `linux/arm64`, assembles a multi-arch manifest, and pushes it
to GHCR with a signed
[build-provenance attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations)
plus an embedded SBOM and SLSA provenance. Verify a pulled image with:

```sh
gh attestation verify oci://ghcr.io/jakobmoellerdev/roci:latest --owner jakobmoellerdev
```

Alongside the image, the workflow builds a standalone static `roci` binary for
each Linux arch on its native runner and attests it. Container images are
Linux-only (OCI/Docker has no darwin runtime); `darwin/amd64` and
`darwin/arm64` binaries build cleanly from the same workspace and are
**planned** to ship as cross-compiled release binaries (macOS runners), not as
container platforms — that release pipeline is not wired up yet.

### Security scanning

Beyond the required gate, CI runs three security/static-analysis workflows: `actionlint` (workflow linting, part of the `CI` workflow), `zizmor` (GitHub Actions security audit), and `codeql` (CodeQL SAST for Rust). `zizmor` and `codeql` publish results to the repository's code-scanning dashboard.

## Feature roadmap

Legend: `[ ]` planned · `[~]` in progress · `[x]` done.

### Core distribution

- [ ] Conforms to OCI Distribution Spec APIs (v1.1.1)
- [ ] Uses OCI image layout for image storage
- [ ] Can serve any OCI image layout as a registry
- [ ] Single binary for all features
- [ ] Runs without root privileges
- [ ] Clear separation between core dist-spec and roci-specific extensions
- [ ] Behavior controlled entirely via configuration
- [ ] Binaries released for multiple operating systems and architectures
- [ ] Image deletion by tag
- [ ] Compatible with ecosystem tools (skopeo, cri-o)
- [ ] Suitable for on-premises deployments (e.g. colocated with Kubernetes)
- [ ] HTTP/2 multiplexing + keep-alive; TLS 1.3 with optional kTLS zero-copy
- [ ] SHA-512 default digests (SHA-256 accepted); constant-time verification
- [ ] Immutable-by-digest response caching (`ETag`/`If-None-Match` → `304`), correct tag-vs-digest cache-control
- [ ] Foreign media types & `tar+zstd` layers stored/served as opaque blobs (Nydus, eStargz, SBOM, signatures)

### Content & ecosystem

- [ ] Container image signatures — cosign
- [ ] Container image signatures — notation
- [ ] Helm chart support
- [ ] Lazy-pull origin (eStargz / SOCI / Nydus) via Range + referrer-carried metadata
- [ ] BLAKE3 Bao verified streaming — per-`Range`-chunk integrity, stored as a referrer

### Query & search

- [ ] Advanced image queries via search extension
- [ ] Vulnerability scanning of images (Trivy) with SBOMs (SPDX/CycloneDX) as referrers

### Security & access control

- [ ] TLS support (TLS 1.3, 0-RTT resumption)
- [ ] TLS mutual authentication
- [ ] HTTP Basic authentication — local htpasswd
- [ ] HTTP Basic authentication — LDAP
- [ ] HTTP Bearer token authentication (per-request scope binding)
- [ ] Identity-Based Access Control
- [ ] Live modification of authorization configuration while running
- [ ] Boundary hardening — path-traversal-safe validation, wire digest allowlist, bounded inputs (size/`n`/depth)
- [ ] Repository isolation — no cross-repo presence/content oracle; cross-repo mount double-authorized
- [ ] SSRF containment — no client-URL fetch; host-allowlisted, repo-gated redirects
- [ ] Prior-art CVE-class regression suite in CI

### Storage

- [ ] Online, O(garbage) garbage collection (grace-period, backref index; never offline)
- [ ] Copy-on-write (reflink) deduplication across repos, hard-link fallback
- [ ] Data scrubbing (CRC32C staggered, FS-scrub offload, BLAKE3 escalation)
- [ ] Serve multiple storage paths (and backends) from a single server
- [ ] Per-repo / per-total storage quotas
- [ ] In-memory small-blob content cache; 2-level fanout at scale
- [ ] Embedded metadata index — append-log + in-RAM maps default, B-tree KV upgrade

### Replication

- [ ] Pull and synchronize from other dist-spec conformant registries

### Scaling

- [ ] Vertical scale — efficient scale-up on a single node (streaming, zero-copy, bounded memory)
- [ ] Horizontal scale-out — clustered instances, repo sharding via consistent hashing (HRW + bounded-load), peer proxy
- [ ] RSS scales with reference count, not stored bytes (mmap-offloadable metadata; runs on a Raspberry Pi)

### Operability

- [ ] Rate limiting, including per-HTTP-method limits
- [ ] Prometheus metrics
- [ ] OpenTelemetry observability (OTLP traces, metrics, and logs)
- [ ] Node exporter for minimal builds
- [ ] Swagger-based API documentation
- [ ] O(1) cold start (rkyv mmap snapshot / fast-restart) and low-fragmentation allocator

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
