# Storage

::: tip Canonical source
This is an overview. The authoritative storage design lives in the *Storage subsystem* section of [`ARCHITECTURE.md`](https://github.com/jakobmoellerdev/roci/blob/main/ARCHITECTURE.md), with the evidence backing it in [`RESEARCH.md`](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md).
:::

roci's storage design is reverse-engineered from [zot](https://zotregistry.dev)'s published [storage article](https://zotregistry.dev/v2.1.21/articles/storage/) and adapted to Rust, marking **[roci divergence]** where it differs.

## OCI image layout on disk

Storage is a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md): any OCI layout can be served directly as a registry, and the storage root can be inspected with standard OCI tooling.

## Content-addressable storage & dedup

Blobs are stored by digest. Deduplication uses copy-on-write (reflink) across repos with a hard-link fallback. RSS scales with reference count, not stored bytes.

## Garbage collection

Online, O(garbage) garbage collection — never offline — using a grace period and a backref index, so a running registry reclaims only unreferenced content without blocking serving.

## Metadata index

An embedded metadata index designed for a footprint budget: append-log + in-RAM maps by default, upgradeable to a B-tree KV store, with mmap-offloadable metadata so the index can run on a Raspberry Pi. Tags and referrers live in ordered maps, so every `tags/list` and referrers page (including `artifactType`-filtered pages) is a seek past the cursor: per-request work is bounded by the page size, not by how many tags or referrers a repository holds.

The spec-visible `index.json` is maintained by **coalescing write-behind**: a mutation is authoritative in the metadata log immediately, and a background task rewrites `index.json` atomically (no-follow beneath the storage root), preserving descriptors written by other tools. At startup roci reconciles `index.json` against the replayed log, so a crash between the two never leaves the layout behind. See the canonical [Architecture](https://github.com/jakobmoellerdev/roci/blob/main/ARCHITECTURE.md) invariant 12.

## Multi-store & quotas

Serve multiple storage paths (and backends, e.g. S3 via `roci-storage-s3`) from a single server, with per-repo and per-total storage quotas, an in-memory small-blob content cache, and a 2-level fanout at scale.

## Integrity & scrubbing

Data scrubbing (CRC32C staggered, FS-scrub offload, BLAKE3 escalation) detects and surfaces on-disk corruption.

See also: [Architecture](/design/architecture) · [Research](/design/research).
