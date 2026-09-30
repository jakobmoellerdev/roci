# Benchmarks

`just bench` runs roci (both [metadata engines](./metadata-engines)) against [zot](https://zotregistry.dev) 2.1.21 and, optionally, [CNCF distribution](https://github.com/distribution/distribution) 3.1.2, in pinned containers with third-party load tools (`zb`, `vegeta`, `crane`) plus a small push-storm tool (`bench/loadgen`).

## Latest results

> Manual `bench` workflow, `full` profile (5 reps, medians), commit `e07f8627e69d`, 2026-09-29. Shared GitHub arm64 runner: registry on 2 CPUs / 4 GiB, client on the other 2. **Compare columns within the run, not absolute numbers.**

| | roci-log | roci-lmdb | zot |
|---|---|---|---|
| Idle memory (anon RSS) | 2.1 MiB | 2.1 MiB | 43 MiB |
| Push storm (images/s) | 1192 | 776 | 144 |
| Manifest GET, max sustained rps | 32,000 | 32,000 | 2,000 |
| Blob pull 10 MiB, 1 client (MiB/s) | 2247 | 2143 | 1236 |
| Blob push 1 MiB, 16 clients (MiB/s) | 437 | 392 | 116 |
| Server CPU per GiB moved | 1.41 s | 1.45 s | 2.07 s |
| crane push / pull, 85 MiB image | within noise | within noise | within noise |

**Metadata at scale** — 100k small images (10 repos × 10k):

| | roci-log | roci-lmdb | zot |
|---|---|---|---|
| Push (images/s) | 1167 | 561 | 105 |
| Tag lookup p50 / p99 | 0.17 / 0.53 ms | 0.17 / 0.51 ms | 1.3 / 3.2 s ¹ |
| Referrers listing | 3.8 ms | 3.8 ms | 16 ms |
| Heap after reads | 316 MiB | 147 MiB | 169 MiB |
| Restart with the corpus | 2.6 s | 2.2 s | 0.4 s |
| Metadata on disk | 129 MB | 234 MB | — |

¹ zot saturates at ~1,040 rps under the 6,400 rps lookup load, so its latency is queueing.

Takeaways: roci pushes 5–10× faster than zot and serves reads with far lower latency and CPU. Between the engines, `log` pushes about twice as fast; `lmdb` uses half the heap. zot restarts fastest.

## Method

Phases: startup (empty and populated), push storm, hot-path latency ladder (manifest GET, blob HEAD, missing-blob HEAD, tags list), real client (`crane`), throughput matrix (`zb`: push/pull/mixed × 1–100 MiB × 1/16 clients), metadata scale, disk. The `report.md` of each run lists every metric as `median [min–max]`, flags CV > 10% as unstable, and marks overlapping ranges with `≈`.

Fairness: pinned image digests and tool versions; default configs everywhere except `warn` logging and distribution's upload purging disabled; plain HTTP, no auth, local filesystem; disjoint CPU sets for registry and client; registry order shuffled per rep, each on an empty volume. roci runs with its default `storage.commit = false`, matching zot. `zb` cannot drive distribution (it drops the upload `_state` parameter), so those cells are `n/a`.

Limitations: single node, no TLS/auth, synthetic content. Only a dedicated Linux host is authoritative; Docker Desktop and shared CI runners are for relative comparison.

## Reproduce

```sh
just bench quick                              # ~10 min smoke, 1 rep: roci-log, roci-lmdb, zot
just bench full                               # 5 interleaved reps
just bench quick "roci-log,roci-lmdb,zot,distribution"
```

Needs rootful Docker, ≥ 4 CPUs and ≥ 20 GB free disk (`full`). Results go to `bench/results/<run-id>/` (`report.md`, `summary.json`, raw tool output and container logs).

- `BENCH_ROCI_PREBUILT=<ref>` benchmarks a published image (every `main` commit is at `ghcr.io/jakobmoellerdev/roci:<sha>`); `BENCH_RUNNER_PREBUILT=1` reuses a loaded runner image.
- `BENCH_SCALE_TAGS_PER_REPO` shrinks the scale phase; the `bench` workflow defaults it to `1000` because zot needs over an hour for 100k images on a 4-vCPU runner.
- The manual `bench` workflow pulls the image of the dispatched commit and accepts `mode`, `registries` and `scale_tags_per_repo` inputs.

## Profiling roci

```sh
just bench-perf quick                               # roci-log, symbolized build
just bench-perf quick bench/results/<compare-run>   # + gaps vs competitors
```

Records flamegraphs (`perf record`), syscall summaries and roci's per-route latency for the storm, hot, crane and zb phases. `profile_report.md` starts with findings and every metric where a competitor beats roci by > 10%. Needs a Linux kernel with perf events.

## Index-engine bake-off (LMDB vs redb)

`just bench-index` (in `bench/index-engines/`, outside the product workspace) compares heed/LMDB and redb on roci's metadata access pattern. On macOS (non-authoritative), LMDB was 1.3–4× faster on reads single-threaded, up to 7× at 8 threads, and 17–26% smaller on disk; redb was 3–6× faster on writes. roci ships LMDB because reads dominate.
