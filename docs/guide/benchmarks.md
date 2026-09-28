# Benchmarks

`just bench` compares multiple roci metadata-engine configurations with [CNCF distribution](https://github.com/distribution/distribution) 3.1.2 and [zot](https://zotregistry.dev) 2.1.21 using established third-party load tools — zot's own `zb`, `vegeta`, `crane` — plus a small stdlib-only Go push-storm tool (`bench/loadgen`). A Python orchestrator (`bench/harness`, stdlib only) drives everything inside a pinned runner container, so the host needs only rootful Docker.

## Registry variants

roci is benchmarked under two metadata-engine configurations, each running as a separate named container:

| name | engine | notes |
|------|--------|-------|
| `roci-log` | log (default in-memory maps + append-only WAL) | baseline; equivalent to the previous bare `roci` entry |
| `roci-lmdb` | LMDB (heed) | out-of-RAM B+ tree; needs the `full` (lmdb) build feature |

External registries (`zot`, `distribution`) run their default configurations as before.

All roci variants share the same release image (built with `--features full`); only the TOML config file in `bench/registries/` differs.

## What is measured

| phase | tool | metric keys |
|---|---|---|
| Startup, empty store | poll `GET /v2/` every 5 ms | `startup.empty_ms`, `memory.idle_anon_mib`, `memory.idle_file_mib` |
| Push storm + corpus seed (7-request client flow per image) | `loadgen` | `storm.images_per_s`, `storm.p99_ms`, `memory.corpus_anon_mib`, `memory.corpus_file_mib` |
| Hot path latency ladder (manifest GET, blob HEAD, missing-blob HEAD, tags list) | `vegeta` | `hot.<ep>.max_sustained_rps`, `hot.<ep>.p50_ms`, `hot.<ep>.p99_ms` |
| Startup, populated store | restart + poll | `startup.populated_ms`, `startup.populated_first_manifest_ms` |
| Real client (85 MiB 6-layer image) | `crane` | `crane.push_s`, `crane.push_second_repo_s`, `crane.pull_cold_s`, `crane.pull_warm_s`, `crane.fleet_pull_s` |
| Throughput matrix (push monolith / chunked, pull, 75/25 mix × size × concurrency) | `zb` | `zb.<test>.c<c>.{rps,p50_ms,p99_ms,mib_per_s}`, `cpu.zb_cpu_s_per_gib` |
| Metadata scale (many small manifests) | `loadgen` + `vegeta` | `scale.*` (see below) |
| Disk | `du` of the data volume | `disk.bytes`, `disk.meta_bytes`, `memory.peak_anon_mib`, `memory.peak_file_mib` |

A hot-path step **passes** when every response has the expected status (404 for missing-blob HEAD, 200 otherwise), p99 ≤ 20 ms, and the achieved rate is ≥ 95% of the target; a step failing only the rate check is `client_bound` (reported as a lower bound).

### Metadata-scale scenario

The `scale` phase pushes many small images through `loadgen seed` to stress metadata indexing at volume: each image has its own 4 KiB layer, config and manifest (three small blobs per tag). The `quick` profile pushes ~100 k tags (10 repos × 10 000 tags, ~300 k blobs); `full` pushes 1 M tags (100 repos × 10 000 tags). After the push:

| measurement | metric key |
|---|---|
| Push throughput and p99 | `scale.push_images_per_s`, `scale.push_p99_ms` |
| Tag-resolve latency (manifest GET by tag) under concurrency | `scale.resolve_p50_ms`, `scale.resolve_p99_ms`, `scale.resolve_rps` |
| `tags/list` paging (all pages for one repo) | `scale.tags_list_ms`, `scale.tags_list_count` |
| Referrers listing | `scale.referrers_ms` |
| Anonymous RSS + page cache after push and after reads | `scale.anon_mib_after_push`, `scale.file_mib_after_push`, `scale.anon_mib_after_read`, `scale.file_mib_after_read` |
| Startup time with the full scale corpus | `scale.startup_populated_ms` |
| Metadata on-disk size (roci variants only) | `scale.meta_bytes` |

The scale parameters are configured per profile in `bench/config.toml` under `[profiles.<name>.scale]`.

#### Reference run (100k tags)

> **NON-AUTHORITATIVE: Docker Desktop VM (Apple M-series, 6 CPUs), `quick`, 1 rep.** zot saturated at ~435 rps under the 3,200 rps tag-resolve load, so its latency there is queueing.

| 100k tags | roci-log | roci-lmdb | zot |
|---|---|---|---|
| scale push (images/s) | 2845 | 2109 | 74 |
| tag resolve p50 / p99 (ms) | 0.24 / 11.8 | 0.21 / 1.1 | 2793 / 7030 |
| anon RSS after reads (MiB), before → after the heap fixes | 664 → 326 | 480 → 174 | 129 |
| restart with the corpus (ms) | 8093 | 973 | 112 |
| metadata on disk (MB) | 89 | 215 | — |

LMDB has the flattest tail latency and the fastest restart; the log engine is the fastest pusher. The heap row shows the fixes from RESEARCH §9.9 (read-driven small-blob cache with honest budget accounting, clone-free log compaction, per-repo log state); the other rows are from the first run. The `roci-snapshot` variant was removed based on these measurements (see RESEARCH §9.9). Analysis and follow-ups: [RESEARCH §9.9](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md).

## Fairness & parity

- **Pinned inputs:** image digests per arch in `bench/config.toml`, pinned tool versions in `bench/Containerfile.runner` (zb checksum-verified).
- **Defaults everywhere**, except: logging lowered to `warn` (per-request info logging is a config choice, not engine cost) and distribution's upload purging disabled (no background timer during a run). All run plain HTTP, no auth, local filesystem backend. roci runs its release `Containerfile` with `--features full` and no config file except the variant TOML — including its default `storage.commit = false`, which matches zot's `commit` default (blob data not fsynced before acknowledging).
- **Isolation:** registry and runner get disjoint `--cpuset-cpus` (half the Docker CPUs each, ≤ 4); the registry gets a 4 GiB memory limit.
- **Memory:** `anon` (anonymous RSS) and `file` (page cache) are reported separately from cgroup v2 `memory.stat`. Page cache is demand-paged for mmap-backed engines (LMDB) so comparing only anon RSS would undercount their working set.
- **Order:** each rep shuffles the registry order (seeded), and every registry starts from an empty volume.
- **zb is zot's own tool.** zb cannot drive distribution: it keeps only the path of an upload `Location` and drops distribution's mandatory `_state` query, so every push fails; those cells show `n/a`.

## Statistics

Cells are `median [min–max]` over reps; `vs roci-log` = other median / roci-log median, prefixed `≈` when the ranges overlap; `⚠ unstable` marks CV > 10%. `quick` is one rep (a smoke test); `full` is 5 interleaved reps.

## Reproduce

```sh
just bench quick                            # roci-log, roci-lmdb, zot (add distribution via the registries argument)
just bench full                             # 5 reps; authoritative only on a dedicated Linux host
just bench quick "roci-log,roci-lmdb,zot"   # subset of registries
```

To benchmark a published image instead of building one, set `BENCH_ROCI_PREBUILT=<ref>` (e.g. `ghcr.io/jakobmoellerdev/roci:<commit-sha>` — every `main` commit is published); `BENCH_RUNNER_PREBUILT=1` skips building the runner image when `roci-bench/runner:local` is already loaded. The manual `bench` workflow does both: it pulls the GHCR image of the dispatched commit (or the `roci_image` input) and builds the runner image with a GitHub Actions layer cache. Its `registries` input selects the registries like the local argument (e.g. `roci-log,roci-lmdb,zot,distribution`; empty runs the default `roci-log,roci-lmdb,zot`). The published image is built with `full`, so `roci-lmdb` works out of the box.

Prerequisites: rootful Docker, ≥ 4 CPUs visible to Docker, ≥ 20 GB free disk for `full`. Results land in `bench/results/<run-id>/` (`report.md`, `summary.json`, `env.json`, and `raw/<rep>/<registry>/` with every tool's output, stderr of failed phases, the cgroup time series and container logs). Only a dedicated Linux host is authoritative; **Docker Desktop results are non-authoritative** — Docker Desktop runs a Linux VM with shared resources, variable memory pressure, and a different I/O stack, so absolute numbers and even relative rankings can shift between runs. Such runs are labelled `NON-AUTHORITATIVE: Docker Desktop VM` in the report. The manual `bench` GitHub workflow runs either mode on a shared arm64 runner — compare ratios within one run only.

## Profiling roci

```sh
just bench-perf quick                                # roci-log only, symbolized build
just bench-perf quick bench/results/<compare-run>    # + "gaps vs competitors"
```

`bench-perf` builds `bench/Containerfile.roci-perf` (release optimizations plus line tables and frame pointers, not stripped) and runs the same phases against roci-log alone. For the storm, hot, crane and zb phases it records a CPU profile (`perf record`, rendered as `profile/<phase>.svg` flamegraphs), a syscall summary (`perf trace -s`, falling back to `strace -c`), and roci's own per-route latency from its Prometheus `http.server.request.duration` histogram.

Read `profile_report.md` top-down: **Findings** (threshold-based hints such as "hashing is 30% of CPU"), then **Gaps vs competitors** (every metric where the best competitor beats roci by > 10%, mapped to the phase whose profile explains it), then per-phase detail (CPU categories, top self and inclusive frames, syscalls, server-side routes). Profiler-overhead frames are stripped and their share reported. The run temporarily sets `kernel.perf_event_paranoid=-1` and `kptr_restrict=0` and restores them afterwards. Flamegraphs need a Linux kernel with perf events.

## Limitations

Plain HTTP only (no TLS, no auth), a single node, the local filesystem backend, and synthetic content (random layers; a fixed-shape many-tag corpus). Docker Desktop results are non-authoritative (see Reproduce above).

## Index-engine bake-off (heed/LMDB vs redb)

`just bench-index` runs a standalone benchmark comparing heed (LMDB) and redb on roci's real metadata access pattern — tag point lookups, referrer range-scans, existence checks, and write throughput. The benchmark lives in `bench/index-engines/` with its own `Cargo.toml` and `[workspace]` table so heed's C FFI dependency never enters the product dependency graph.

### Reproduce

```sh
just bench-index                     # default: 100K + 1M refs (~5 min)
just bench-index 100000,1000000,5000000   # include 5M (longer, more disk)
```

The benchmark binary is built with `--release` and LTO (fat). Pass `--smoke` for a quick 10K-ref validation.

### What is measured

| workload | description |
|----------|-------------|
| Tag point lookup | `(repo, tag) → (digest, media_type)` random hot read |
| Existence check (hit/miss) | `(repo, digest)` presence in media_types table |
| Referrer range-scan | First 100 referrers for a random subject via prefix range |
| Write throughput | Batched inserts (batch 1000) across tags + media_types + referrers |

All keys use roci's repo-qualified ~276 B/ref format ([RESEARCH §9.6](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md)). Both engines use identical durability settings (NoSync for reads and writes, equal batch sizes). Multi-threaded read scaling is measured at 1 and 8 threads.

### Reference run

> **NON-AUTHORITATIVE: Apple Silicon macOS (M-series), APFS/NVMe, single host.**

| N refs | workload | redb p50/p99 (ns) | heed p50/p99 (ns) | redb/heed p50 |
|--------|----------|-------------------|-------------------|---------------|
| 100K | tag lookup | 1125/1625 | 875/1917 | 1.3× |
| 100K | existence (hit) | 1125/1708 | 875/1958 | 1.3× |
| 1M | tag lookup | 2750/4666 | 1708/3542 | 1.6× |
| 1M | referrer scan (p100) | 8916/21375 | 2208/4584 | 4.0× |

At 8 threads: redb degrades to 5–7 µs p50 (write-lock contention); heed stays near single-thread latency (LMDB MVCC readers).

| N refs | redb disk | heed disk | redb write ops/s | heed write ops/s |
|--------|-----------|-----------|-----------------|-----------------|
| 100K | 514 MB | 429 MB | 154,070 | 50,652 |
| 1M | 4.02 GB | 2.97 GB | 141,146 | 22,870 |

**Verdict: [changed — heed migration]** heed/LMDB wins reads (1.3–4× single-thread, up to 7× multi-thread) and disk size (17–26% smaller); redb wins writes (3–6×). roci ships heed/LMDB (stable `mdb.master`) as the upgrade engine because the multi-thread read advantage (4–7×, p99 ~48 µs→~3 µs) dominates the read-heavy workload in the out-of-RAM regime. LMDB encryption at rest was dropped: heed3's encrypted environment returned corrupt data under concurrent readers (RESEARCH §9.8), so at-rest confidentiality is left to volume encryption. This macOS benchmark is non-authoritative — a Linux `just bench-index` rerun is required. See [RESEARCH §8.6 / §9.8](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md) for the full analysis.
