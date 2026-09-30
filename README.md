<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="roci" width="360">
  </picture>
</p>

# roci

![coverage](https://img.shields.io/badge/coverage-96.98%25-brightgreen)

**roci** is a Rust implementation of the [OCI Distribution Specification](spec/distribution-spec/spec.md) — an OCI container registry.

roci is built around three goals:

- **Minimal runtime overhead / small footprint** — a single static binary with a tiny memory and CPU baseline, no runtime dependencies, no daemon sprawl. Suitable for edge, CI, and colocated Kubernetes deployments.
- **Extremely fast and efficient queries** — an index designed for low-latency tag, manifest, referrer, and search lookups; zero-copy blob serving where the OS allows it.
- **Fast and easy configuration** — start with zero config and sane defaults; grow into a single declarative config file. No external database required to run.

roci targets full conformance with the OCI Distribution Spec v1.1.1 and feature parity with [zot](https://github.com/project-zot/zot), while keeping a clear separation between the core distribution API and optional extensions.

## Quick start

```sh
docker run -d --read-only -v roci-data:/var/lib/roci -p 5000:5000 ghcr.io/jakobmoellerdev/roci:latest
skopeo copy --all --dest-tls-verify=false docker://alpine:latest docker://localhost:5000/alpine:latest
```

Static Linux/macOS binaries (amd64/arm64) are attached to every [release](https://github.com/jakobmoellerdev/roci/releases). The [Getting started guide](https://jakobmoellerdev.github.io/roci/guide/getting-started) covers the binary, container, and source install paths, plus the macOS port-5000 (AirPlay) caveat.

## Design principles

- **OCI image layout on disk.** Storage is a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md), so any OCI layout can be served directly as a registry and inspected with standard tooling.
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
- [`helm`](https://helm.sh) — only for chart linting (`just helm-lint`).

Install the cargo tools in one line:

```sh
cargo install just cargo-nextest cargo-deny cargo-llvm-cov
```

### First-time setup

Fetch the pinned OCI spec submodules:

```sh
git submodule update --init --depth 1   # or: just init
```

Install the git pre-commit hook (when Rust sources are staged, runs fmt,
clippy, the coverage gate, and the full OCI conformance suite; refreshes
[`COVERAGE.md`](COVERAGE.md) + the badge on every commit):

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
| `just clippy` | Lint both flavors, warnings = errors — the sole gate compiling the minimal flavor |
| `just test` | Run tests (nextest) + doctests |
| `just build` | Build minimal and full flavors (dev convenience; the minimal-flavor CI compile is the clippy job) |
| `just deps-guard` | Assert no extension crate leaks into the minimal build |
| `just lint-workflows` | Lint the GitHub Actions workflows (actionlint) |
| `just zizmor` | Security-audit the workflows (zizmor) |
| `just audit` | `cargo deny` supply-chain check |
| `just coverage` | Enforce the line-coverage floor (95%, cargo-llvm-cov) |
| `just coverage-report` | Show uncovered lines (developer aid) |
| `just coverage-linux` | Reproduce the CI Linux coverage gate in a container (macOS devs; the only way to exercise the Linux-only fast paths) |
| `just codeql-local` | Reproduce the CI CodeQL rust path-injection analysis in a container (macOS devs; fails if any alert remains) |
| `just test-filesystems` | Run the storage suite on real ext4/btrfs/XFS loopback filesystems (privileged container) — exercises the actual reflink/hard-link/O_TMPFILE/copy behavior per FS, not the `FORCE_*` simulation |
| `just ci` | Run the full local gate before pushing (actionlint + fmt + clippy + test + build + deps-guard + helm-lint + coverage + conformance) |
| `just conformance` | Run the OCI dist-spec conformance suite against a local roci |
| `just container` | Build the hardened scratch image and smoke-test it |
| `just container-multiarch` | Build the multi-arch image (linux/amd64, linux/arm64) |
| `just bench` | Benchmark roci vs distribution vs zot in pinned containers (`quick` smoke / `full` 5-rep) — see docs/guide/benchmarks.md |
| `just bench-perf` | Profile roci (flamegraphs, syscalls, per-route latency, gaps vs a prior `just bench` run) |
| `just helm-lint` | Lint the Helm chart and assert its render-time security guards (needs `helm`) |

### Run it locally

`cargo run -p roci-cli` starts a zero-config registry on `127.0.0.1:5000` by default; point `skopeo`, `crane`, or `oras` at it. See `cargo run -p roci-cli -- --help` for flags (`--config <file.toml>`, `--listen`, `--storage-root`); the config file is documented in `docs/guide/configuration.md`.

**CI parity:** `just ci` runs the same checks GitHub Actions requires — if it passes locally, the required CI checks pass.

### Container image

[`Containerfile`](Containerfile) builds a **hardened, fully static** image: a
musl-static binary on a `scratch` base (no shell, no libc, no package manager),
running as an unprivileged nonroot UID with the storage directory as the only
writable path (mount the root FS read-only).

```sh
just container          # build + smoke-test the running container
docker run --read-only -v roci-data:/var/lib/roci -p 5000:5000 ghcr.io/jakobmoellerdev/roci:latest
```

Images carry the full set of OCI `org.opencontainers.image.*` annotations (labels, per-arch manifest, index), generated by [`scripts/oci-meta.sh`](scripts/oci-meta.sh). Image tags: `latest` (newest release), `X.Y.Z` / `X.Y` (pinned releases), `main` (rolling `main` build), `<commit-sha>` (immutable).

The `container` CI workflow builds and smoke-tests the image on **native
per-arch runners** (no QEMU emulation): pull requests build only `linux/arm64`
(on an `ubuntu-24.04-arm` runner) to save time, while `main` and `v*` release
tags build both `linux/amd64` and `linux/arm64`, assemble a multi-arch manifest,
and push it
to GHCR with a signed
[build-provenance attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations)
plus an embedded SBOM and SLSA provenance. Verify a pulled image with:

```sh
gh attestation verify oci://ghcr.io/jakobmoellerdev/roci:latest --owner jakobmoellerdev
```

Alongside the image, the workflow builds a standalone static `roci` binary for
each Linux arch on its native runner and attests it. Container images are
Linux-only (OCI/Docker has no darwin runtime). Versioned release tarballs
(static `linux-musl` + `apple-darwin`, amd64/arm64, sha256 + attestation) are
built by [`release.yml`](.github/workflows/release.yml) on `v*` tags.

### Kubernetes (Helm)

A hardened Helm chart is provided at `charts/roci/`. Every `v*` release publishes
it to GHCR as an OCI artifact, version-locked to the release (chart `X.Y.Z`
deploys image `roci:X.Y.Z`), with a build-provenance attestation. Install with:

```sh
kubectl create namespace roci
kubectl label namespace roci pod-security.kubernetes.io/enforce=restricted
helm install roci oci://ghcr.io/jakobmoellerdev/charts/roci --version <X.Y.Z> \
  -n roci --set auth.allowAnonymous=true
gh attestation verify oci://ghcr.io/jakobmoellerdev/charts/roci:<X.Y.Z> --owner jakobmoellerdev
```

To install from a checkout instead: `helm repo add rustfs https://charts.rustfs.com && helm dependency build charts/roci`, then `helm install roci charts/roci …`.

The chart enforces Pod Security Standards restricted, per-workload NetworkPolicies, a secure-by-default auth guard, and supports optional HA S3 storage on RustFS. See the [Kubernetes guide](https://jakobmoellerdev.github.io/roci/guide/kubernetes) for the full configuration reference.

### Security scanning

Beyond the required gate, CI runs three security/static-analysis workflows: `actionlint` (workflow linting, part of the `CI` workflow), `zizmor` (GitHub Actions security audit), and `codeql` (CodeQL SAST for Rust). `zizmor` and `codeql` publish results to the repository's code-scanning dashboard.

## Feature roadmap

**31 shipped · 5 in progress · 17 planned · 1 blocked** — ● shipped · ◐ in progress · ○ planned · ⊘ blocked. The docs site renders the same data as an interactive page ([`docs/roadmap.md`](docs/roadmap.md)).

| Area | Progress | |
|---|---|---|
| Core distribution | `█████░░░░░` | 7 / 14 |
| Security & access control | `████████░░` | 9 / 11 |
| Storage | `██████████` | 8 / 8 |
| Operability | `███████░░░` | 7 / 10 |
| Content & ecosystem | `░░░░░░░░░░` | 0 / 5 |
| Query & search | `░░░░░░░░░░` | 0 / 2 |
| Scaling | `░░░░░░░░░░` | 0 / 3 |
| Replication | `░░░░░░░░░░` | 0 / 1 |

### Core distribution

| | Capability | |
|---|---|---|
| ● | OCI Distribution Spec v1.1.1 | Passes the upstream conformance suite |
| ● | OCI image layout storage | Any layout on disk can be served as a registry |
| ● | Rootless | Runs without root privileges |
| ● | Config-driven | Behavior controlled entirely via configuration |
| ● | Multi-platform releases | Binaries for multiple operating systems and architectures |
| ● | Delete by tag | |
| ● | On-premises ready | e.g. colocated with Kubernetes |
| ◐ | Single binary | One binary for all features |
| ◐ | Core / extension split | Dist-spec core cleanly separated from roci extensions |
| ◐ | HTTP/2 and TLS 1.3 | Multiplexing and keep-alive; optional kTLS zero-copy |
| ◐ | SHA-512 digests | SHA-512 by default, SHA-256 accepted; constant-time verification |
| ○ | Ecosystem compatibility | skopeo, cri-o |
| ○ | Digest response caching | `ETag` / `If-None-Match` → `304`; correct tag-vs-digest cache-control |
| ○ | Foreign media types | Nydus, eStargz, SBOMs, signatures and `tar+zstd` layers served as opaque blobs |

### Security & access control

| | Capability | |
|---|---|---|
| ● | TLS 1.3 | 0-RTT hardening via `425 Too Early` |
| ● | Mutual TLS | Client certificates with optional CA or leaf-fingerprint pinning |
| ● | Basic auth — htpasswd | bcrypt only |
| ● | Basic auth — LDAP | Opt-in cargo feature `ldap`, not in `full` |
| ● | Bearer tokens | External token server; ES256/RS256, per-request scope binding |
| ● | Identity-based access control | Glob patterns, specificity matching, admins and groups |
| ● | Live authorization reload | Change access rules without a restart |
| ● | Repository isolation | No cross-repo presence oracle; cross-repo mounts authorized twice |
| ● | SSRF containment | No client-supplied URL fetches; allowlisted, repo-gated redirects |
| ◐ | Boundary hardening | Path-traversal-safe validation, digest allowlist, bounded inputs |
| ○ | CVE-class regression suite | Prior-art registry CVEs replayed in CI |

### Storage

| | Capability | |
|---|---|---|
| ● | Online garbage collection | O(garbage) with a grace period and backref index; never offline |
| ● | Copy-on-write dedup | Reflink (`FICLONE`) across repos, with hard-link and copy fallbacks |
| ● | Data scrubbing | CRC32C checks, digest re-hash on mismatch, quarantine |
| ● | Multiple storage paths | Mix local paths and S3-compatible object storage in one server |
| ● | Quotas | Per-repo and total quotas, plus a cap on concurrent uploads |
| ● | Small-blob cache | Byte-capped in-memory LRU for manifests and configs |
| ● | Metadata engines | In-memory log (default, optional HMAC) or LMDB on disk |
| ● | Lossless engine switching | log ↔ lmdb with a verified migration at startup |

### Operability

| | Capability | |
|---|---|---|
| ● | Rate limiting | Per HTTP method and per client |
| ● | Prometheus metrics | |
| ● | OpenTelemetry | OTLP traces, metrics and logs |
| ● | Fast cold start | Opt-in `fast_restart` stamp and a low-fragmentation allocator |
| ● | Hardened Helm chart | PSS restricted, NetworkPolicies, optional HA S3 on RustFS; attested OCI artifact at `oci://ghcr.io/jakobmoellerdev/charts/roci` |
| ● | Health endpoints | `/readyz` and `/livez`, unauthenticated and rate-limit-free |
| ● | S3 bucket auto-creation | `create_bucket`, plus private-CA trust via `ca_file` |
| ○ | Node exporter for minimal builds | |
| ○ | OpenAPI documentation | |
| ⊘ | RustFS client-cert mTLS | `object_store` has no client-cert API; the RustFS chart has no server-TLS-only mode |

### Content & ecosystem

| | Capability | |
|---|---|---|
| ○ | cosign signatures | |
| ○ | notation signatures | |
| ○ | Helm charts as artifacts | |
| ○ | Lazy-pull origin | eStargz, SOCI and Nydus via Range requests and referrer metadata |
| ○ | BLAKE3 verified streaming | Per-`Range`-chunk integrity, stored as a referrer |

### Query & search

| | Capability | |
|---|---|---|
| ○ | Search extension | Advanced image queries |
| ○ | Vulnerability scanning | Trivy, with SPDX/CycloneDX SBOMs as referrers |

### Scaling

| | Capability | |
|---|---|---|
| ○ | Vertical scale | Streaming, zero-copy, bounded memory on one node |
| ○ | Horizontal scale-out | Repo sharding via consistent hashing with a peer proxy |
| ○ | Memory follows references | RSS scales with reference count, not stored bytes |

### Replication

| | Capability | |
|---|---|---|
| ○ | Registry sync | Pull and synchronize from any dist-spec conformant registry |

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
