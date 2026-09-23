# Configuration

roci follows a **config-driven** design: all behavior is controlled from configuration rather than build-time code paths. It starts with zero config and sane defaults, and grows into a single declarative config file — no external database is required to run.

::: info Status
Configuration is being built out across the phased [build plan](https://github.com/jakobmoellerdev/roci/blob/main/PLAN.md). This page tracks the intended surface; consult `cargo run -p roci-cli -- --help` for the flags available in your build.
:::

## Zero-config defaults

With no configuration, roci:

- Listens on `127.0.0.1:5000`.
- Stores content as an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) under a local storage root.
- Enables only the core distribution API — no extensions.

## Command-line flags

| Flag | Purpose |
| --- | --- |
| `--listen` | Address to bind (default `127.0.0.1:5000`). |
| `--storage-root` | Directory for the on-disk OCI image layout. |

## Configuration schema

The configuration schema (`roci-config`) currently has these fields. All are optional; omitted fields take the defaults above.

| Field | Default | Purpose |
| --- | --- | --- |
| `listen` | `127.0.0.1:5000` | Address to bind. |
| `storage_root` | `./roci-data` | Directory for the on-disk OCI image layout. |
| `delete.enabled` | `true` | Allow manifest/blob deletion. When `false`, every delete endpoint returns `405 UNSUPPORTED` through a single shared guard (CVE-2026-41888 class). |

Loading a config file lands in Phase 4 (see [`PLAN.md`](https://github.com/jakobmoellerdev/roci/blob/main/PLAN.md)). Until then, the fields are set programmatically.

## Build flavors

roci compiles in two flavors (see [Architecture](/design/architecture)):

- **minimal** — the core distribution API only, with the smallest possible dependency graph.
- **full** — the core plus the optional extensions (`roci-ext-*`) for signatures, search, sync, and scanning.

Every extension is reachable from the CLI **only** behind a cargo feature, never as an unconditional dependency. Behavior is then selected at runtime through configuration.
