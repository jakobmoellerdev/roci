# Introduction

**roci** is a Rust implementation of the [OCI Distribution Specification](https://specs.opencontainers.org/distribution-spec/) — an OCI container registry.

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

## Where to go next

- [Getting started](/guide/getting-started) — run a registry locally in one command.
- [Configuration](/guide/configuration) — flags and the declarative config file.
- [Architecture](/design/architecture) — the component and storage model.
- [Roadmap](/roadmap) — the phased feature plan.

## Prior art

roci's design is reverse-engineered from [zot](https://zotregistry.dev)'s published architecture, storage, security-posture, and scale-out articles and adapted to Rust. The design documents cite zot throughout and mark **[roci divergence]** where roci intentionally differs.
