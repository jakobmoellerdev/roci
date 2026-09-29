# Metadata engines

roci keeps the blobs and `index.json` of every repository as a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md). On top of that it maintains a **metadata index** (tags, media types, referrers, blob backrefs for garbage collection, and per-blob checksums for scrub) so that every request is answered without walking the layout. The index is always rebuildable from the layout. Two engines can hold it:

- **`log` (default):** in-memory maps, mirrored to an append-only log on disk.
- **`lmdb`:** an embedded B-tree database on disk (LMDB via [heed](https://github.com/meilisearch/heed)), read through memory mapping.

Both hold the same data and answer the same queries. They differ in where the data lives, and therefore in memory, write speed and restart time.

```toml
[storage.metadata]
engine = "log"   # or "lmdb"
```

## Comparison

| | `log` (default) | `lmdb` |
|---|---|---|
| Where metadata lives | In-memory maps, rebuilt from an append-only log at startup | LMDB B-tree file on disk, read through memory mapping |
| Memory | Fixed heap, about 1.5 KB per image (tag, backrefs, checksums); grows with the corpus and cannot be paged out | Small heap; data sits in page cache the OS can reclaim, so resident memory follows the hot working set |
| Heap after reads, 100k images¹ | 326 MiB | 174 MiB |
| Tag lookup, median / slowest 1%¹ | ~0.25 ms / ~1–4 ms | ~0.25 ms / ~1 ms |
| Push throughput¹ | ~3,600–3,900 images/s | ~2,100–2,300 images/s |
| Write path | One log append per change; concurrent pushes share one sync to disk | One write transaction per change, then a sync; slower per write |
| Restart | Replays the log; grows with the log size | Opens the file; roughly constant |
| Metadata on disk, 100k images¹ | ~89 MB | ~215 MB |
| Background upkeep | Compacts the log when it has grown past `compact_threshold_bytes` (writes pause during the rewrite) | None; the file reuses freed pages but never shrinks |
| Tamper protection | Optional HMAC on every log record (`hmac_key_file`) | None built in; use volume encryption (LUKS/dm-crypt, encrypted cloud volumes) |
| Build | Every build, pure Rust | `full` build (cargo feature `lmdb`); release binaries and the container image include it |

¹ First-party benchmark, 10 repositories × 10,000 small images, Docker Desktop, one run; indicative only. See [Benchmarks](./benchmarks) and [RESEARCH §9.9](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md).

## Which one to use

Start with **`log`**. It is the default, has no extra dependencies and pushes fastest. Its cost is heap: roughly **0.35–0.7 million images per 0.5–1 GB** of RAM (images with a few small blobs each).

Switch to **`lmdb`** when any of these apply:

- the metadata no longer fits comfortably in the memory you want roci to use, for example a pod with a hard memory limit;
- you want flat memory regardless of how many repositories and tags are stored, since cold repositories cost only disk;
- restart time matters and the log has grown large;
- the workload is read-heavy and tail latency matters more than push throughput.

Stay on **`log`** when pushes dominate, the corpus is small to medium, or you want HMAC-authenticated metadata.

## Switching engines

Switching is a configuration change plus a restart, in either direction, without losing data:

1. Set `storage.metadata.engine` to the new engine (Helm: `config.storage.metadata.engine`).
2. Restart roci.

On startup roci sees that the configured engine differs from the active one and migrates before serving:

1. It exports the full state from the active engine and writes it into the new engine in a temporary location (`roci-meta.lmdb.migrating/` or `roci-meta.log.migrating`).
2. It verifies that repositories, manifests, tags and referrers match between the two. On any mismatch it discards the copy, keeps the old engine and aborts startup with an error, so roci never serves from a partial copy.
3. It moves the copy into place and records the new engine in `roci-meta.engine`. This marker write is the commit point: a crash before it leaves the old engine active, and the migration runs again on the next start.
4. It renames the old engine's files to `*.migrated-<timestamp>`. They are never deleted; remove them once you have checked the switch.

The migration takes one pass over the metadata; progress and duration are logged. With `hmac_key_file` configured, the key is used to read an authenticated log and to write one when switching back to `log`. Change the key and the engine in **separate** restarts: a log that cannot be authenticated with the configured key is treated as untrusted and rebuilt from the layout instead of migrated.

The removed `redb` engine cannot be migrated from. Configuring `engine = "redb"` stops startup with a message pointing to `lmdb`, and an LMDB store started next to an old `roci-meta.redb` rebuilds from the layout. Only what the layout's `index.json` already holds carries over, so let pushes settle before stopping the old build.

## Engine settings

| Setting | Engine | Meaning |
|---|---|---|
| `storage.metadata.engine` | both | `log` (default) or `lmdb` |
| `storage.metadata.compact_threshold_bytes` | `log` | Compact the log once it has grown this much past its last image (default 64 MiB) |
| `storage.metadata.hmac_key_file` | `log` | File with a ≥ 32-byte key; every log record is HMAC-authenticated. Also used during a switch |
| `storage.metadata.map_size_bytes` | `lmdb` | Address space LMDB reserves for its file (default 64 GiB, sparse); the store fails with an error naming this setting when full |

See [Configuration](./configuration) for the full `[storage.metadata]` section and [Storage design](../design/storage) for how the index relates to the layout.
