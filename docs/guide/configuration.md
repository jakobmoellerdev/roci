# Configuration

roci follows a **config-driven** design: all behavior is controlled from configuration rather than build-time code paths. It starts with zero config and sane defaults, and grows into a single declarative config file — no external database is required to run.

::: info Status
Configuration is being built out across the phased [build plan](/design/plan). This page tracks the intended surface; consult `cargo run -p roci-cli -- --help` for the flags available in your build.
:::

## Zero-config defaults

With no configuration, roci:

- Listens on `127.0.0.1:5000`.
- Stores content in a filesystem-backed content-addressable store (per-repo `blobs/`, `manifests/`, `tags/`) under a local storage root.
- Enables only the core distribution API — no extensions.

## Command-line flags

| Flag | Purpose |
| --- | --- |
| `--listen` | Address to bind (default `127.0.0.1:5000`). |
| `--storage-root` | Directory for the on-disk content-addressable store. |

## Build flavors

roci compiles in two flavors (see [Architecture](/design/architecture)):

- **minimal** — the core distribution API only, with the smallest possible dependency graph.
- **full** — the core plus the optional extensions (`roci-ext-*`) for signatures, search, sync, and scanning.

Every extension is reachable from the CLI **only** behind a cargo feature, never as an unconditional dependency. Behavior is then selected at runtime through configuration.
