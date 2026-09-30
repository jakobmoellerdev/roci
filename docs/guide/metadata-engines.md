# Metadata engines

roci stores blobs and `index.json` as a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md). A **metadata index** (tags, media types, referrers, GC backrefs, scrub checksums) sits on top so requests never walk the layout; it can always be rebuilt from the layout. Two engines hold it:

```toml
[storage.metadata]
engine = "log"   # default; or "lmdb"
```

## Comparison

Measured with 100k images (10 repos × 10k small images), median of 5 reps¹:

| | `log` (default) | `lmdb` |
|---|---|---|
| How it works | In-memory maps + append-only log on disk | LMDB B-tree file, memory-mapped |
| Heap after reads | 316 MiB (~3 KB per image, grows with the corpus) | 147 MiB (the rest is reclaimable page cache) |
| Tag lookup p50 / p99 | 0.17 / 0.5 ms | 0.17 / 0.5 ms |
| Push throughput | ~1,170 images/s | ~560 images/s |
| Restart with the corpus | 2.6 s (replays the log) | 2.2 s (opens the file) |
| Metadata on disk | 129 MB | 234 MB |
| Upkeep | Log compaction past `compact_threshold_bytes` | None; file never shrinks |
| Tamper protection | Optional HMAC per record (`hmac_key_file`) | None; use volume encryption |
| Build | Every build | `full` build (release binaries and image include it) |

¹ Shared GitHub arm64 CI runner, 2 registry CPUs — compare the two columns, not absolute numbers. See [Benchmarks](./benchmarks).

## Which one to use

Use **`log`** by default: it pushes about twice as fast and supports HMAC. Budget roughly **3 KB of heap per image** (~300k images per GiB).

Use **`lmdb`** when the heap is the constraint — a pod with a hard memory limit, or a large corpus with many cold repositories. Its resident memory follows the hot working set; lookup latency is the same.

## Switching engines

Change `storage.metadata.engine` (Helm: `config.storage.metadata.engine`) and restart. roci migrates before serving, in either direction:

1. Copies the full state into the new engine in a temporary location.
2. Verifies repositories, manifests, tags and referrers match; on mismatch it keeps the old engine and aborts startup.
3. Records the new engine in `roci-meta.engine` (the commit point — a crash before it re-runs the migration).
4. Renames the old files to `*.migrated-<timestamp>`; delete them once satisfied.

With `hmac_key_file`, change the key and the engine in **separate** restarts: a log that fails authentication is rebuilt from the layout, not migrated.

The removed `redb` engine cannot be migrated: `engine = "redb"` fails startup, and LMDB rebuilds from the layout's `index.json`.

## Settings

| Setting | Engine | Meaning |
|---|---|---|
| `storage.metadata.engine` | both | `log` (default) or `lmdb` |
| `storage.metadata.compact_threshold_bytes` | `log` | Compact once the log grows this far past its live data (default 64 MiB) |
| `storage.metadata.hmac_key_file` | `log` | ≥ 32-byte key; HMAC on every log record |
| `storage.metadata.map_size_bytes` | `lmdb` | Reserved address space (default 64 GiB, sparse); writes fail naming this setting when full |

See [Configuration](./configuration) and [Storage design](../design/storage).
