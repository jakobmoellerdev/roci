# Architecture

::: tip Canonical source
This is an overview. The authoritative, maintained design lives in [`ARCHITECTURE.md`](https://github.com/jakobmoellerdev/roci/blob/main/ARCHITECTURE.md) at the repo root — it is the source of truth and is kept current under the [maintenance contract](https://github.com/jakobmoellerdev/roci/blob/main/PLAN.md).
:::

roci's architecture is reverse-engineered from [zot](https://zotregistry.dev)'s published [architecture](https://zotregistry.dev/v2.1.21/general/architecture) and adapted to Rust, marking **[roci divergence]** where it intentionally differs.

## Build flavors

roci compiles in two flavors, an architectural invariant:

- **minimal** — the core distribution API only, with the smallest possible dependency graph.
- **full** — the core plus optional extensions.

Every extension crate is named `roci-ext-*` (or `roci-cluster`) and is reachable from `roci-cli` **only** behind a cargo feature, never as an unconditional dependency. `just deps-guard` (and the `minimal-deps-guard` CI job) enforces this.

## Component & crate model

The workspace separates the stable dist-spec core from cleanly isolated extensions:

- `roci-core` — the OCI Distribution API surface.
- `roci-storage` / `roci-storage-s3` — the storage subsystem (OCI image layout on disk, plus backends).
- `roci-config` — the declarative configuration model.
- `roci-telemetry` — metrics, traces, and structured errors.
- `roci-ext-sig` / `roci-ext-search` / `roci-ext-sync` / `roci-ext-scan` — optional extensions (signatures, search, replication, scanning).
- `roci-cluster` — horizontal scale-out.
- `roci-cli` — the binary that wires it together behind cargo features.

## Storage subsystem

Storage is a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) on disk. Highlights (see the canonical doc for the full design): content-addressable dedup across repositories (reflink → hard link, including on upload), online O(garbage) garbage collection with a grace period and a startup backref rebuild, CRC32C scrubbing with quarantine, per-repository / registry-wide / upload-session quotas, multiple storage paths and an S3-compatible backend behind one `Storage` trait, an embedded metadata index (append-log + in-RAM maps with compaction, an optional rkyv mmap snapshot and HMAC authentication, or a redb B-tree KV) with coalescing write-behind of the spec-visible `index.json` (reconciled at startup), and zero-copy blob serving. One background scheduler per storage path runs GC, scrub and metadata upkeep.

## Configuration & observability

One TOML file (`roci --config`) with `http`, `storage` (incl. `gc`, `scrub`, `quota`, `metadata`, `subpaths`, `s3`), `limits`, `delete`, `log`, and `telemetry` sections, validated on load; zero-config defaults need no file. The `otel` build exports traces, metrics, and logs over OTLP and serves a Prometheus scrape view of the same meters; metric labels are bounded by construction, and tail-based sampling is delegated to the OTel Collector.

## Scaling

- **Vertical** — streaming, zero-copy, bounded memory; RSS scales with reference count, not stored bytes.
- **Horizontal** — clustered instances with repo sharding via consistent hashing (HRW + bounded-load) and a peer proxy.

## Architectural invariants

The canonical doc enumerates invariants that must never regress (build-flavor isolation, extension-crate naming, storage-format stability, and more). Changing an invariant requires updating `ARCHITECTURE.md` and flagging the change.

See also: [Security](/design/security) · [Storage](/design/storage) · [Research](/design/research).
