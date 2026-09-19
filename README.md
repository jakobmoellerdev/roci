# roci

**roci** is a Rust implementation of the [OCI Distribution Specification](spec/distribution-spec/spec.md) — an OCI container registry.

roci is built around three goals:

- **Minimal runtime overhead / small footprint** — a single static binary with a tiny memory and CPU baseline, no runtime dependencies, no daemon sprawl. Suitable for edge, CI, and colocated Kubernetes deployments.
- **Extremely fast and efficient queries** — an index designed for low-latency tag, manifest, referrer, and search lookups; zero-copy blob serving where the OS allows it.
- **Fast and easy configuration** — start with zero config and sane defaults; grow into a single declarative config file. No external database required to run.

roci targets full conformance with the OCI Distribution Spec v1.1.1 and feature parity with [zot](https://github.com/project-zot/zot), while keeping a clear separation between the core distribution API and optional extensions.

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
- **Go 1.17+** — only for the OCI conformance suite.
- [`actionlint`](https://github.com/rhysd/actionlint) and [`zizmor`](https://github.com/zizmorcore/zizmor) — only for linting/auditing the GitHub Actions workflows (`just lint-workflows`, `just zizmor`).

Install the cargo tools in one line:

```sh
cargo install just cargo-nextest cargo-deny
```

### First-time setup

Fetch the pinned OCI spec submodules:

```sh
git submodule update --init --depth 1   # or: just init
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
| `just ci` | Run the full local gate before pushing (actionlint + fmt + clippy + test + build + deps-guard) |
| `just conformance` | Run the OCI dist-spec conformance suite against a local roci |

### Run it locally

Once `roci-cli` exists, `cargo run -p roci-cli` starts a zero-config registry; point `skopeo`, `crane`, or `oras` at it. For the listen address and flags, see `roci --help`.

**CI parity:** `just ci` runs the same checks GitHub Actions requires — if it passes locally, the required CI checks pass.

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

### Content & ecosystem

- [ ] Container image signatures — cosign
- [ ] Container image signatures — notation
- [ ] Helm chart support

### Query & search

- [ ] Advanced image queries via search extension
- [ ] Vulnerability scanning of images

### Security & access control

- [ ] TLS support
- [ ] TLS mutual authentication
- [ ] HTTP Basic authentication — local htpasswd
- [ ] HTTP Basic authentication — LDAP
- [ ] HTTP Bearer token authentication
- [ ] Identity-Based Access Control
- [ ] Live modification of authorization configuration while running

### Storage

- [ ] Automatic garbage collection of orphaned blobs
- [ ] Layer deduplication using hard links for identical content
- [ ] Data scrubbing
- [ ] Serve multiple storage paths (and backends) from a single server

### Replication

- [ ] Pull and synchronize from other dist-spec conformant registries

### Scaling

- [ ] Vertical scale — efficient scale-up on a single node (streaming, zero-copy, bounded memory)
- [ ] Horizontal scale-out — clustered instances, repo sharding via consistent hashing, peer proxy

### Operability

- [ ] Rate limiting, including per-HTTP-method limits
- [ ] Prometheus metrics
- [ ] OpenTelemetry observability (OTLP traces, metrics, and logs)
- [ ] Node exporter for minimal builds
- [ ] Swagger-based API documentation

## License

TBD.
