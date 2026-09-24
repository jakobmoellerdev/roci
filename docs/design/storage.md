# Storage

::: tip Canonical source
This is an overview. The authoritative storage design lives in the *Storage subsystem* section of [`ARCHITECTURE.md`](https://github.com/jakobmoellerdev/roci/blob/main/ARCHITECTURE.md), with the evidence backing it in [`RESEARCH.md`](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md).
:::

roci's storage design is reverse-engineered from [zot](https://zotregistry.dev)'s published [storage article](https://zotregistry.dev/v2.1.21/articles/storage/) and adapted to Rust, marking **[roci divergence]** where it differs.

## OCI image layout on disk

Storage is a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md): any OCI layout can be served directly as a registry, and the storage root can be inspected with standard OCI tooling. Layers are opaque bytes, so `tar+zstd` (and any other media type) is stored and served exactly as pushed.

## Content-addressable storage & dedup

Blobs are stored by digest. A cross-repo mount — and, with `storage.dedupe` (default on), an upload of a blob another repository already holds — links the existing copy: copy-on-write reflink first, hard link as the logged fallback, never a second byte copy. A repository still serves only blobs it holds itself. RSS scales with reference count, not stored bytes.

## Garbage collection

Online and O(garbage): roci tracks only the blobs that are currently unreferenced and reclaims one once it has stayed unreferenced *and* untouched for the grace period (`storage.gc.delay_secs`, 1 h by default). A client's existence check or `HEAD` refreshes that clock, so a push in flight never loses a layer. Before the first sweep a background consistency check rebuilds every backref edge from the layout, so a pre-existing or externally written layout is never collected by mistake; the registry keeps serving throughout.

## Metadata index

The metadata index is a cache of the layout behind one engine-neutral interface:

- **Log engine (default):** in-RAM maps mirrored to an append-only, CRC32C-framed write-ahead log with group commit. The log is compacted in the background; optionally the state is served from an rkyv `mmap` snapshot plus the log tail (fast cold start, demand-paged memory), and every record and snapshot can be HMAC-authenticated with a per-deployment key.
- **redb engine (`redb` build):** an embedded pure-Rust B-tree KV for metadata that outgrows RAM.

Tags and referrers are ordered, so every `tags/list` and referrers page (including `artifactType`-filtered pages) is a seek past the cursor. A manifest, its tag, its backref edges and its referrer registration are committed as one record, so a crash can never leave a stored manifest whose blobs look unreferenced.

The spec-visible `index.json` is maintained by **coalescing write-behind**: a mutation is authoritative in the metadata log immediately, and a background task rewrites `index.json` atomically (no-follow beneath the storage root), preserving descriptors written by other tools. At startup roci reconciles `index.json` against the replayed log. See the canonical [Architecture](https://github.com/jakobmoellerdev/roci/blob/main/ARCHITECTURE.md) invariants 12 and 15.

## Storage paths, backends & quotas

`storage.subpaths` routes repository prefixes to their own storage path or backend — another local directory or an S3-compatible bucket (`s3` build) — presented as one registry. The S3 backend keeps one OCI layout per repository in the bucket, redirects large blob pulls to short-lived signed URLs and proxies small ones, and copies server-side for mounts. Quotas cap bytes per repository (`413`), bytes registry-wide across every path (`507`), and concurrent upload sessions (`429`).

## Integrity & scrubbing

An optional background scrub verifies each blob against the CRC32C recorded when it was written, visiting the store in a staggered order under a bandwidth cap, and re-hashes with the full digest only on a mismatch. A blob that no longer matches its digest is quarantined so it reads as absent and can be pushed again. On btrfs and ZFS the filesystem's own scrub is used instead.

See also: [Architecture](/design/architecture) · [Research](/design/research) · [Configuration](/guide/configuration).
