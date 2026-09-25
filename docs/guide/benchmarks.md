# Benchmarks

`just bench` compares roci with [CNCF distribution](https://github.com/distribution/distribution) 3.1.2 and [zot](https://zotregistry.dev) 2.1.21 using established third-party load tools — zot's own `zb`, `vegeta`, `crane` — plus a small stdlib-only Go push-storm tool (`bench/loadgen`). A Python orchestrator (`bench/harness`, stdlib only) drives everything inside a pinned runner container, so the host needs only rootful Docker.

## What is measured

| phase | tool | metric keys |
|---|---|---|
| Startup, empty store | poll `GET /v2/` every 5 ms | `startup.empty_ms`, `memory.idle_anon_mib` |
| Push storm + corpus seed (7-request client flow per image) | `loadgen` | `storm.images_per_s`, `storm.p99_ms`, `memory.corpus_anon_mib` |
| Hot path latency ladder (manifest GET, blob HEAD, missing-blob HEAD, tags list) | `vegeta` | `hot.<ep>.max_sustained_rps`, `hot.<ep>.p50_ms`, `hot.<ep>.p99_ms` |
| Startup, populated store | restart + poll | `startup.populated_ms`, `startup.populated_first_manifest_ms` |
| Real client (85 MiB 6-layer image) | `crane` | `crane.push_s`, `crane.push_second_repo_s`, `crane.pull_cold_s`, `crane.pull_warm_s`, `crane.fleet_pull_s` |
| Throughput matrix (push monolith / chunked, pull, 75/25 mix × size × concurrency) | `zb` | `zb.<test>.c<c>.{rps,p50_ms,p99_ms,mib_per_s}`, `cpu.zb_cpu_s_per_gib` |
| Disk | `du` of the data volume | `disk.bytes`, `memory.peak_anon_mib` |

A hot-path step **passes** when every response has the expected status (404 for missing-blob HEAD, 200 otherwise), p99 ≤ 20 ms, and the achieved rate is ≥ 95% of the target; a step failing only the rate check is `client_bound` (reported as a lower bound).

## Fairness & parity

- **Pinned inputs:** image digests per arch in `bench/config.toml`, pinned tool versions in `bench/Containerfile.runner` (zb checksum-verified).
- **Defaults everywhere**, except: logging lowered to `warn` (per-request info logging is a config choice, not engine cost) and distribution's upload purging disabled (no background timer during a run). All run plain HTTP, no auth, local filesystem backend. roci runs its release `Containerfile` with no config file — including its default `storage.commit = false`, which matches zot's `commit` default (blob data not fsynced before acknowledging).
- **Isolation:** registry and runner get disjoint `--cpuset-cpus` (half the Docker CPUs each, ≤ 4); the registry gets a 4 GiB memory limit.
- **Memory = anonymous RSS** from cgroup v2 `memory.stat` (`memory.current` includes page cache, which is filesystem noise for a blob server).
- **Order:** each rep shuffles the registry order (seeded), and every registry starts from an empty volume.
- **zb is zot's own tool.** zb cannot drive distribution: it keeps only the path of an upload `Location` and drops distribution's mandatory `_state` query, so every push fails; those cells show `n/a`.

## Statistics

Cells are `median [min–max]` over reps; `vs roci` = other median / roci median, prefixed `≈` when the ranges overlap; `⚠ unstable` marks CV > 10%. `quick` is one rep (a smoke test); `full` is 5 interleaved reps.

## Reproduce

```sh
just bench quick   # ~10 min smoke
just bench full    # 5 reps; authoritative only on a dedicated Linux host
```

To benchmark a published image instead of building one, set `BENCH_ROCI_PREBUILT=<ref>` (e.g. `ghcr.io/jakobmoellerdev/roci:<commit-sha>` — every `main` commit is published); `BENCH_RUNNER_PREBUILT=1` skips building the runner image when `roci-bench/runner:local` is already loaded. The manual `bench` workflow does both: it pulls the GHCR image of the dispatched commit (or the `roci_image` input) and builds the runner image with a GitHub Actions layer cache.

Prerequisites: rootful Docker, ≥ 4 CPUs visible to Docker, ≥ 20 GB free disk for `full`. Results land in `bench/results/<run-id>/` (`report.md`, `summary.json`, `env.json`, and `raw/<rep>/<registry>/` with every tool's output, stderr of failed phases, the cgroup time series and container logs). Only a dedicated Linux host is authoritative; a Docker Desktop run is labelled `NON-AUTHORITATIVE`. The manual `bench` GitHub workflow runs either mode on a shared arm64 runner — compare ratios within one run only.

## Profiling roci

```sh
just bench-perf quick                                # roci only, symbolized build
just bench-perf quick bench/results/<compare-run>    # + "gaps vs competitors"
```

`bench-perf` builds `bench/Containerfile.roci-perf` (release optimizations plus line tables and frame pointers, not stripped) and runs the same phases against roci alone. For the storm, hot, crane and zb phases it records a CPU profile (`perf record`, rendered as `profile/<phase>.svg` flamegraphs), a syscall summary (`perf trace -s`, falling back to `strace -c`), and roci's own per-route latency from its Prometheus `http.server.request.duration` histogram.

Read `profile_report.md` top-down: **Findings** (threshold-based hints such as "hashing is 30% of CPU"), then **Gaps vs competitors** (every metric where the best competitor beats roci by > 10%, mapped to the phase whose profile explains it), then per-phase detail (CPU categories, top self and inclusive frames, syscalls, server-side routes). Profiler-overhead frames are stripped and their share reported. The run temporarily sets `kernel.perf_event_paranoid=-1` and `kptr_restrict=0` and restores them afterwards. Flamegraphs need a Linux kernel with perf events.

## Reference run

> **NON-AUTHORITATIVE: Docker Desktop VM, `quick` profile (1 rep).** Apple M-series, 6 CPUs to Docker (server `0-2`, client `3-5`), kernel 7.0.12-linuxkit, ext4 volume, roci at `7834d351`. Authoritative numbers need `just bench full` on a dedicated Linux host.

| metric | roci | distribution | zot |
|---|---|---|---|
| Startup, empty store (ms) | **66** | 123 | 187 |
| Idle anon RSS (MiB) | **1.9** | 14.4 | 49.8 |
| Anon RSS after corpus seed (MiB) | **14.7** | 26.6 | 65.6 |
| Peak anon RSS (MiB) | 79.7 | **53.4** | 70.2 |
| Push storm (images/s) | **1398** | 295 | 334 |
| Push storm p99 per image (ms) | **19.7** | 74.4 | 58.4 |
| Hot path, all 4 endpoints: max sustained rps (quick ladder tops at 4000) | 4000 | 4000 | 4000 |
| manifest GET p50 / p99 @ 1000 rps (ms) | 0.31 / 8.3 | **0.28 / 1.2** | 0.33 / 4.1 |
| crane push / pull warm / fleet pull (s) | 0.104 / 0.047 / **0.069** | 0.107 / 0.057 / 0.113 | **0.079 / 0.045** / 0.078 |
| zb pull 10 MB, c=8 (MiB/s) | **2752** | n/a | 2451 |
| zb push monolith 10 MB, c=8 (MiB/s) | **1914** | n/a | 1511 |
| Server CPU per GiB moved (CPU-s/GiB) | **1.12** | n/a | 1.66 |
| Disk used (bytes) | **129.7 M** | 130.2 M | 136.8 M |

**Known gap:** roci's hot-path p99 at 1000 rps is ~2× zot's while its p50 is equal or better. Isolated A/B runs ruled out handler time (5–7 µs server-side), the tokio scheduler flavour, allocator page purging and hyper-util's protocol auto-detection; on Docker Desktop the same build's p99 swings 2–10 ms between runs, so the remaining diagnosis (off-CPU / scheduler-wakeup tracing) needs a quiet Linux host. See [RESEARCH §9.7](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md) for what the benchmark changed in roci.

## Limitations

Plain HTTP only (no TLS, no auth), a single node, the local filesystem backend, and synthetic content (random layers; a fixed-shape many-tag corpus).

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

**Verdict:** heed/LMDB wins reads (1.3–4× single-thread, up to 7× multi-thread) and disk size (17–26% smaller); redb wins writes (3–6×). roci ships redb because (1) the in-RAM backend is the hot path for most deployments, (2) redb's write speed matches push-storm profiles, and (3) heed's C FFI would break the static-musl/`forbid(unsafe_code)` release story. The `MetadataStore` trait is ready for heed if future deployments need it. See [RESEARCH §8.6 / §9.8](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md) for the full analysis.
