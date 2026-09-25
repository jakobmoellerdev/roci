# roci — Design Research: Low-Overhead Storage & Hyperscale Scale-Out

Evidence backing roci's two load-bearing invariants — **minimal footprint / local-minimal-first** and **a credible path to hyperscale** — from peer-reviewed systems literature and production engineering at scale. Each finding is tied to a concrete roci design decision, with contradicting evidence flagged.

Companion docs: [`ARCHITECTURE.md`](ARCHITECTURE.md), [`SECURITY.md`](SECURITY.md), [`PLAN.md`](PLAN.md). Design lineage (zot articles) is cited in those.

**Guiding thesis (what the evidence supports):** roci should be an *excellent, low-overhead single-node origin* — content-addressed OCI-layout storage, inline GC/dedup, fast zero-copy ranged reads, cheap referrer metadata — and reach hyperscale by (a) repo-sharded horizontal scale-out for the registry tier and (b) *integrating with*, not reimplementing, external P2P distribution fabrics. Nearly every hyperscale technique (lazy pull, P2P) turns out to need **nothing new on the registry protocol surface** beyond Range serving + referrers, both already in roci's Phase 1–3 plan.

---

## 1. Content-addressable storage, dedup & the "local minimal" core

### 1.1 Content addressing is dedup, integrity, and cache-coherence by construction

**Venti** (Quinlan & Dorward, *USENIX FAST 2002*) is the canonical design roci's on-disk model reimplements: a block is addressed by the cryptographic hash of its contents ("fingerprint"), giving four properties for free:

- **Write-once / immutable.** Content cannot change without changing its address.
- **Idempotent, coalescing writes** → duplicate writes consume no extra space (dedup by construction, independent of client behavior).
- **Integrity checking at every read** — client and server both recompute the fingerprint; a mirror/cache can never hold a stale block.
- **Universal namespace** shared across clients without coordination.

Concrete numbers: SHA-1 (160-bit) fingerprints; at an exabyte stored as 8 KB blocks (~10¹⁴ blocks) the collision probability is **< 10⁻²⁰** — treated as unique. Implementation = **append-only data log ("arenas") + a separate hash-table index that maps fingerprint→log location and is rebuildable from the log**, so the index carries weaker reliability constraints than the data. One disk access locates a block in almost all cases.

→ **roci mapping:** the OCI image layout `blobs/<alg>/<hex>` CAS *is* Venti's model at file granularity. Digest = content address → O(1) open, dedup-for-free within a store, integrity on read, safe caching/mirroring (relevant to scale-out proxying). roci uses SHA-256/SHA-512 (OCI-mandated) — strictly stronger than Venti's SHA-1. Venti's "rebuildable index separate from the write-once log" validates roci's plan to keep tag/referrer indexes as *derived* state reconstructable from the layout (matches zot `fastRestart`).

### 1.2 Chunking & sub-file dedup — a bounded, deferred option, not the baseline

- **LBFS** (Muthitacharoen, Chen, Mazières, *SOSP 2001*) introduced **content-defined chunking** (Rabin-fingerprint boundaries) so dedup survives insertions/shifts; cut network traffic by up to **~90%** on a low-bandwidth link.
- **Data Domain** (Zhu, Li, Patterson, *USENIX FAST 2008*) is the scaling lesson: the fingerprint index does not fit in RAM, so naïve dedup is disk-index-bound. Their fix — a **Bloom filter ("summary vector")** to answer "definitely new" without a disk lookup, plus a **locality-preserving cache** exploiting stream locality — removed **~99% of index disk reads** and hit ~100 MB/s dedup throughput on then-current hardware.
- **Primary Data Deduplication** (Microsoft, *USENIX ATC 2012*) confirmed chunk-dedup at primary-storage scale with low RAM/CPU budgets (larger average chunks + selective dedup to cap index cost).

→ **roci mapping:** OCI dedup is naturally at **blob (layer) granularity** — that is roci's baseline and it is free. Sub-blob **chunk dedup is out of scope for the minimal core**; it belongs in a future storage/scrub extension (and the closest container-world instance is Nydus RAFS chunking — §4). The load-bearing takeaway is **Data Domain's Bloom-filter existence check**: roci's "does this blob/manifest already exist?" hot path (blob HEAD, push-time skip, mount) should be answered by an **in-memory approximate filter before touching disk** — see §3.2.

### 1.3 Cheap CAS without heavyweight infrastructure

**Foundation** (Rhea, Cox, Pesterev, *USENIX ATC 2008*) built fast, inexpensive CAS on commodity hardware, showing a Bloom filter over stored fingerprints avoids most disk index lookups for the "is this new?" test — the same lever as Data Domain, in a lighter deployment. → Reinforces that roci's **single-binary, no-external-DB** posture is compatible with efficient CAS: the existence-check filter is a few MB of RAM, not a database.

### 1.4 Zero-copy serving

`sendfile`-style zero-copy (kernel path from file → socket, no user-space buffer) is the standard mechanism behind high-throughput static-file/HTTP serving. → **roci mapping:** blob GET should stream via `sendfile`/`mmap` where the OS permits (Architecture invariant 4: no full-blob buffering). This is the single biggest lever for the "extremely fast" claim on the pull path and is directly exercised by lazy-pull Range traffic (§4).

---

## 2. Safe online garbage collection (the non-transactional-lifecycle problem)

The hard correctness problem, called out in zot's storage article and roci's PLAN: **OCI blob and manifest lifecycles are not transactional**, so GC can race a concurrent push and delete a blob about to be referenced.

Evidence and prior art:

- **Docker/CNCF `distribution` registry** GC is **stop-the-world**: the docs require the **registry to be read-only or offline** during mark-and-sweep, precisely because a blob uploaded after the mark phase but referenced by a manifest written during sweep would be wrongly collected. This is the anti-pattern roci (like zot) must beat.
- **Harbor** (which wraps `distribution`) has a documented history of **online-GC race issues** deleting blobs of in-flight/just-pushed images — empirical proof the race is real and costly in production.
- **zot** solves it with **inline GC** + a tunable **grace period** (`gcDelay`, default 1h): newly-orphaned blobs are only collected after the delay, so a blob mid-push (or a manifest about to reference it) is never swept. Optional `gcTimeWindow` restricts sweeps to off-peak UTC hours.
- **Distributed CAS GC literature** (e.g. concurrent deletion with global dedup, *USENIX FAST 2013*; dedup-fs GC, *FAST 2017*) formalizes the safe approaches: **grace-period / generation-based mark-and-sweep** and **reference counting**, with the consistent lesson that under global dedup, deletion must be conservative (never delete a block that *could* become referenced during the sweep).

→ **roci mapping (PLAN Phase 5):** adopt **inline, online mark-and-sweep with a grace period** — GC roots = tags + manifests + referrers; a blob is collectable only if unreferenced *and* older than `gcDelay`. Never require offline/read-only mode. Coordinate GC with the upload-session manager so an in-flight push pins its staged blobs (Architecture invariant 5). Prefer grace-period generations over pure refcounting to avoid refcount-correctness bugs under concurrent dedup. This is a hard-evidence differentiator vs. Go `distribution`.

---

## 3. Index & query structures under a footprint budget

### 3.1 The fundamental tradeoff to name explicitly

**The RUM Conjecture** (Athanassoulis et al., *EDBT 2016*): any access method optimizes at most two of **R**ead / **U**pdate / **M**emory (space) amplification at the expense of the third. **LSM-trees** (O'Neil et al., *Acta Informatica 1996*; RocksDB, *SIGMOD 2020*) minimize write amplification (great for high-ingest) at the cost of read/space amplification and compaction CPU; **B-trees** favor reads at the cost of write amplification.

→ **roci mapping:** roci's index workload is **read-heavy, modest-write** (tag resolve, referrer lookup, existence checks; writes only on push/delete) and the footprint budget is tight. That points to a **B-tree-family embedded store, not an LSM**, and specifically a **single-file, zero-background-thread embedded KV** so the "no auxiliary services / small footprint" invariant holds. In Rust that is **redb** (single-file, copy-on-write B-tree, no compaction threads) over **sled** (LSM-ish, background flush) for this read-dominated profile. **Notable finding:** zot's own metadata backend is **bbolt/BoltDB** (a single-file B-tree), *not* SQLite — independent confirmation that a B-tree single-file store is the right class for a registry index. RocksDB/LSM would conflict with the low-footprint goal (compaction CPU + space amp + thread pool) and should be avoided in the minimal build.

### 3.2 Existence checks → approximate membership filters

For the very hot "is this blob/manifest present?" test (blob HEAD, push-time dedup skip, cross-repo mount, GC marking), an in-memory approximate filter avoids index/disk hits (the Data Domain lever, §1.2):

- **Bloom filter** — classic, but no deletes, ~10 bits/element for ~1% FP.
- **Cuckoo filter** (Fan, Andersen, Kaminsky, Mitzenmacher, *CoNEXT 2014*) — supports **deletion** and is more space-efficient than Bloom below ~3% FP; matters because roci deletes blobs (GC).
- **Ribbon filter** (Dillinger & Walzer, *USENIX ATC 2021*) / **xor filters** — **~30–40% smaller than Bloom** at the same FP rate for static/rarely-changing sets, at higher construction cost.

→ **roci mapping:** use a **cuckoo filter** for the mutable blob-presence set (deletes needed for GC), sized in single-digit MB; consider a **ribbon/xor filter** for static per-snapshot referrer sets. This is a few MB of RAM that removes most disk touches on the hottest path — cheap and squarely on-budget.

### 3.3 Referrers reverse index — incremental maintenance

The subject→referrers index (OCI `end-12`) must be maintained incrementally on each manifest put/delete so `GET referrers` is O(1) (Architecture / PLAN Phase 3). A single-file B-tree keyed by `(repo, subject-digest)` → list of referring descriptors gives O(log n) update and range-scan reads, reconstructable from the layout on cold start. **This same index is the lazy-pull metadata backbone** (§4.4) — it earns its cost twice over.

---

## 4. Hyperscale distribution: lazy pull & P2P (the growth path)

The strongest cross-cutting result: **the registry needs essentially no new protocol surface to participate in hyperscale distribution** — only fast **Range serving** (Phase 1) and **referrers** (Phase 3), both already planned.

### 4.1 The workload fact that justifies everything

**Slacker** (Harter et al., *USENIX FAST 2016*) — the anchor paper: **pulling is 76% of container start time, but only 6.4% of the image data is actually read at startup.** Lazy/on-demand fetch therefore yields large cold-start wins (dev cycle 20×, deploy 5× in their eval). The 6.4% is workload-dependent (skews higher for model-serving).

### 4.2 Standard-compatible lazy pull needs only Range + a digest-verified TOC

- **eStargz / stargz-snapshotter** (containerd; Google/NTT): a *valid* seekable gzip layer with a TOC entry + 51-byte footer and per-chunk digests; the containerd remote snapshotter fetches files on demand via **HTTP Range requests**. Registry requirement = **Range support + a digest-verified TOC annotation** — nothing else.
- **AWS SOCI ("Seekable OCI")** (Thompson et al., *arXiv 2026*): a file→byte-range index over *unmodified* compressed layers, **stored as an OCI referrer artifact**; FUSE + Range. Result: **1.3 GB image cold-start 20 s → 2.8 s (7.4×)**, up to **9.3×**; production in **ECS Fargate at 18.4 M tasks/day** (Prime Day 2025). Crossover: above **~80% access density**, a parallel full pull wins.

→ **roci mapping:** make **zero-copy Range serving a tracked benchmark** (concurrent small-Range throughput against a hot blob — the actual stargz/SOCI access pattern), not just a conformance checkbox. Keep referrers exactly as planned; SOCI proves referrers are the *lazy-pull index carrier*, not only signature storage.

### 4.3 Nydus — Rust precedent and a media-type constraint

**Nydus** (Dragonfly subproject; Alibaba/Ant), written in **Rust**: RAFS = a Merkle-tree **meta blob** (integrity verifiable at every read) + chunked **data blobs** (chunk-level dedup). "Zran" mode adds a **tiny `.meta` sidecar over a stock, unmodified `tar.gz`** — lazy pull of a standard image with no recompression. In-kernel via EROFS (Linux ≥ 5.16). Production: **>80% network-latency reduction** with Dragonfly P2P; startup minutes→seconds. → Two implications: (1) **Rust is proven in this exact performance domain** (closest technology sibling to roci); (2) Nydus-native RAFS blobs are **not tar** — so roci's invariant "on-disk = valid OCI Image Layout" must mean **descriptors + CAS of *any* blob content / foreign media types**, not "tar-only layers." (zot already serves Nydus images — precedent.)

### 4.4 P2P distribution: integrate, don't build

- **Uber Kraken** (P2P Docker registry): Agent (per-host) + **Origin (hash-ring seeders, pluggable S3/GCS/HDFS backends)** + Tracker (peer orchestration only) + Proxy + Build-Index. Production: **p50 10 s / p99 18 s** to distribute a 3 GB image to **2,600 hosts concurrently**; peak **20,000 blobs (100 MB–1 GB) in < 30 s** (~11 TB/30 s); **≥ 8,000 hosts/cluster**; sustains **> 50% of each host's max download speed regardless of cluster/image size.**
- **Dragonfly** (Alibaba → **CNCF Graduated, Jan 2026**): Manager/Scheduler/Seed-Peer/Peer; **tens of millions of launches/day**, **up to 90% bandwidth savings**, 100-TB model sets to hundreds of nodes in minutes. Production relief: **Kuaishou −70% avg / −80% peak** Harbor bandwidth, **>90% pull-time savings**.

Both systems sit **in front of a standard registry with pluggable object-storage backends** — they do not replace registry logic.

→ **roci mapping:** roci's Phase 8 scale-out (repo-sharded hash ring + peer proxy; compute-only shared-S3 vs. compute+storage-local topologies) covers the **registry tier**. The Dragonfly-grade origin-relief path is **roci-as-origin (S3 backend, compute-only) + external Kraken/Dragonfly P2P fabric**. **Out of scope: building P2P peer transfer inside the roci binary** — different failure domain, violates the minimal-deps invariant, and Kraken/Dragonfly already do it well. roci's job is to be a *good origin*: fast ranged reads, digest-stable metadata, pluggable backends.

### 4.5 Contradicting evidence (bounded claims, honest limits)

- **Lazy-pull cost is deferred, not eliminated** ("The Lazy Pod That Lies," *arXiv 2026*): time-to-first-prediction becomes size-independent (~17 s vs. eager 24–573 s), **but a full read of a 14 GB model took 105 s lazy vs. 72 s eager**; under sustained reads a node cache can exhaust and running pods fail file reads. → roci must **not** promise lazy-pull wins for high-access-density workloads; report benchmarks only in the low-density regime and include a "when it doesn't win" case.
- **FlacIO** (*USENIX FAST 2025*, Huawei): argues all current lazy/full schemes suffer I/O amplification; a memory-oriented "runtime image" beats full-image by up to **23×** and lazy-loading by **4.6×**. → A research direction to watch; it *reinforces* that the registry's stable job is cheap ranged + digest-verified serving regardless of which image abstraction wins.

---

## 5. Scale-out sharding: consistent hashing & keyed hashing

roci's cluster model (repo path → owning instance; peers proxy to owner) rests on decades of load-distribution theory.

### 5.1 Consistent hashing lineage

- **Karger et al.** (*STOC 1997*) — consistent hashing for web caching: adding/removing a bin moves only ~K/n keys, not a full remap.
- **Chord** (Stoica et al., *SIGCOMM 2001*) — consistent hashing as a scalable distributed lookup (O(log n) routing).
- **Amazon Dynamo** (DeCandia et al., *SOSP 2007*) — **virtual nodes** to smooth the load skew of plain consistent hashing; the production template for ring-based sharding.

### 5.2 The load-balancing guarantee roci should adopt

**Consistent Hashing with Bounded Loads** (Mirrokni, Thorup, Zadimoghaddam, *SODA 2018*; arXiv:1608.01350): plain consistent hashing balances no better than random → expected max load Θ(log n / log log n) — **some instances get badly overloaded.** CHBL adds a **user parameter c = 1+ε** capping any bin at ⌈c·m/n⌉, while an insert/delete moves only an **expected O(1/ε²)** extra keys (for ε ≤ 1). Deployed in Google's cloud LB, HAProxy, and Envoy (Maglev/ring-hash + bounded-load).

→ **roci mapping:** the base ring assigns repos to owners; **layer a bounded-load cap (c = 1+ε)** so a few hot repos cannot overload one instance — spill the overflow to the next instance on the ring. **Flagged tension:** bounded-load spill *reduces cache/storage locality* (a repo may be served by a non-primary owner), which fights the single-writer-per-repo invariant. Resolution: apply bounded-load **only to read/proxy load**, keep **writes pinned to the deterministic owner** (single-writer preserved); a spilled read proxies to a replica/cache, never mutates. Make ε configurable; default toward locality (small ε) for the storage-local topology, looser ε for the shared-S3 compute-only topology where locality matters less.

### 5.3 Ring vs. rendezvous vs. Maglev

- **Rendezvous / HRW hashing** (Thaler & Ravishankar, 1998): for each key, hash (key, node) for all nodes and pick the max — no ring state, naturally minimal disruption, trivial to implement for small clusters. Simpler than a virtual-node ring when membership is a small static list (**which is exactly zot/roci's `members` list**).
- **Maglev hashing** (Eisenbud et al., *Google, NSDI 2016*): precomputed lookup table (e.g. 65537 entries) giving near-perfect balance + minimal disruption + O(1) lookup; used by Envoy. Heavier than needed for a handful of members.

→ **roci mapping:** for a **small static `members` list, HRW/rendezvous is arguably simpler and more locality-stable than a virtual-node ring** — worth choosing over the ring for the initial cluster (fewer moving parts, no vnode tuning), reserving Maglev-style tables for large dynamic membership (not in current PLAN). zot uses a ring; roci **may** diverge to HRW for the static-member case. Either way, wrap with CHBL bounded-load.

### 5.4 Keyed hashing resists DoS

**SipHash** (Aumasson & Bernstein): a fast keyed PRF designed to stop **hash-flooding** — an attacker crafting keys that collide into one bucket to overload a node. Because the shard key is an attacker-influenced **repo path**, the shard hash **must be keyed** (per-cluster `hashKey`), exactly as zot does. → **roci mapping:** keep SipHash (or an equally keyed hash) with a per-cluster secret `hashKey`; never a plain unkeyed hash on the repo path. This is a security invariant, not just a balance choice.

### 5.5 Single-writer-per-shard avoids distributed locking

Assigning each repo a single owning writer (roci invariant 7) sidesteps distributed locks/consensus for the write path — the same principle behind partition-owner models (Dynamo-style ownership, Kafka partition leaders). The cost is a **proxy hop** when the receiving instance isn't the owner; Kraken's production numbers (proxying at 8k-host scale while sustaining >50% line rate) show proxy-forwarding overhead is acceptable at hyperscale. → Keep single-writer-per-repo; accept the proxy hop; make any instance a valid entry point.

---

## 6. Observability overhead — justifying "OTel on, cheap by default"

roci embeds OpenTelemetry from Phase 0 but behind a feature with cheap default sampling. Evidence it can be near-free:

- **Dapper** (Google, 2010): production distributed tracing at **aggressive low sampling** (as low as ~0.01–0.1% for high-QPS services) makes tracing overhead negligible while retaining statistical signal — the foundational argument for **sample, don't trace-everything**.
- **Canopy** (Kaldor et al., *SOSP 2017*): end-to-end tracing at Facebook scale with low overhead via sampling + streaming aggregation.
- **Recent tracing-overhead benchmarks** (ICPE 2025 / atlarge-research; independent studies): full-rate agent instrumentation can cost **single-digit to low-double-digit % latency/throughput**, but **head/tail sampling drops this to ~1–2% or below** at production sampling rates.
- **Metric cardinality** is the real footprint trap (OpenTelemetry cardinality-limits guidance; OTel↔Prometheus bridge benchmarks): unbounded label cardinality blows up memory. → roci must **bound metric label cardinality** (no per-digest/per-repo labels on high-frequency instruments) and default traces to low sampling.

→ **roci mapping:** default to **low-rate sampling** (Dapper lesson), keep OTel behind a cargo feature for minimal builds, **cap metric cardinality by design**, and keep instrumentation overhead on the benchmark dashboard (PLAN cross-cutting). Defensible position: **< ~2% overhead at default sampling**, backed by the tracing-overhead studies.

---

## 7. Consolidated design implications

**Adopt now (local-minimal core, Phases 0–5):**
1. CAS on OCI layout, digest = content address → O(1) open, dedup + integrity + safe caching by construction (Venti). SHA-256/512.
2. Derived, rebuildable indexes (tag, referrers) in a **single-file B-tree embedded KV (redb-class)** — not LSM (RUM/footprint); corroborated by zot using bbolt.
3. **Cuckoo filter** in RAM for the blob/manifest existence hot path (Data Domain/Foundation lever; deletes for GC).
4. **Inline online mark-and-sweep GC with a grace period**, roots = tags+manifests+referrers, coordinated with upload sessions — never offline (beats `distribution`; matches zot; FAST'13/'17).
5. **Zero-copy `sendfile`/`mmap` Range serving** as a *tracked benchmark* — the pull-speed lever and the lazy-pull enabler.
6. Referrers reverse index as planned — doubles as the lazy-pull metadata carrier (SOCI).
7. Allow **foreign-media-type blobs** under the OCI-layout invariant (Nydus/eStargz storability).

**Hyperscale growth path (opt-in, post-conformance, Phase 8+):**
8. Repo-sharded horizontal scale-out; **HRW/rendezvous** for the small static member list (simpler than a vnode ring), wrapped in **CHBL bounded-load (c=1+ε)** applied to read/proxy load only, writes pinned to the owner.
9. **Keyed SipHash** with per-cluster `hashKey` on the repo path (anti hash-flooding) — a security invariant.
10. Reach Dragonfly/Kraken-grade origin relief by being a **good origin + external P2P fabric**; do **not** build in-registry P2P.

**Out of scope / watch:**
11. Sub-blob chunk dedup, in-registry P2P agents, build-side lazy-conversion tooling, node-side snapshotter semantics, FlacIO runtime-image re-architecture. Registry surface stays: cheap ranged, digest-verified blob + metadata serving.

**Evidence gaps roci must close with its own benchmarks:**
12. No public Go-registry vs. Rust-registry perf/RSS benchmark exists; no production-grade Rust dist-spec registry exists (Nydus proves Rust viability in-domain). roci's Phase-1-onward benchmark suite (RSS, cold start, pull/push throughput, **concurrent-small-Range "lazy-pull workload"**) is the sole source of evidence for the low-overhead claim — treat it as a deliverable, not decoration.

---
## 8. Storage decision stress-test — more efficient alternatives


Every storage decision above was re-examined adversarially against current evidence to find more efficient alternatives. Verdict key: **KEEP** / **SWITCH** / **HYBRID** / **FUTURE**. New source keys are added to the Sources table.

### 8.1 Hash function — SWITCH default to SHA-512; HYBRID add BLAKE3 internally
- **SHA-512 over SHA-256 as the default OCI digest.** OCI permits both `sha256` and `sha512`. On 64-bit hardware **without** SHA-NI, SHA-512 is **36–50% faster per byte** (SHA-256 18.22 cpb vs SHA-512 11.58 cpb on Westmere; RESEARCH: SHA512-256). **With** SHA-NI, SHA-256 pulls ~20% ahead (0.87 vs 1.07 cpb; RESEARCH: Intel-SHANI), but SHA-NI cannot be assumed across roci's target matrix (VMs, containers, ARM SBCs). Net: **default new blob/manifest digests to `sha512`, accept both on push, expose the actual algo in `Docker-Content-Digest`.** Tradeoff: 128-hex filenames (vs 64) — negligible on modern FS; possible client UX friction with sha512 refs. Rust `sha2`/`ring` hardware-accelerate both.
- **BLAKE3 for internal-only paths (scrub, verified streaming).** BLAKE3 is **8–12× faster than SHA-256/512** on AVX-512 (0.49 cpb) and **3.3× on Apple-silicon hardware SHA** (1640 vs 492 MB/s; RESEARCH: BLAKE3-spec, Blazehash-M4). It **cannot** be an OCI wire digest (not a registered algorithm), but it is ideal for (a) **scrub** re-hashing (3–8× faster passes) and (b) **BLAKE3 Bao verified streaming** — a Bao tree stored as an OCI referrer artifact lets a client verify an individual `Range` chunk without fetching the whole blob (the SOCI/Nydus referrer pattern; ~1.3 s to build for a 2 GB layer, ~3% sidecar overhead). Rust: `blake3`, `bao-tree`. **[roci divergence]** BLAKE3 is confined to internal use; every wire digest stays sha256/sha512.
- SHA-512/256 (truncated) is **rejected** — not an OCI-registered algorithm.

### 8.2 Dedup mechanism — SWITCH hard-link → reflink (FICLONE), hard-link fallback
Hard-links couple deletion (space frees only when the last link drops → a smuggled refcount problem) and risk a catastrophic CoW-write-through-shared-inode hazard in a CAS. **Reflinks (`ioctl FICLONE`)** give identical O(1) space-sharing **with independent deletion and no write-through hazard** — blocks shared until (never-occurring) modification. Supported: btrfs, XFS (`reflink=1`), APFS, ReFS; Rust `reflink-copy` crate falls back to hard-link automatically on ext4/NFS (RESEARCH: FICLONE-man, reflink-copy). Verdict: **reflink primary, hard-link fallback.** Blob-granularity dedup **KEEP**; sub-chunk dedup remains **FUTURE** but the note is strengthened: **FastCDC** is 10× faster than Rabin at ±1.4% of its dedup ratio and 10–20% better than fixed chunking, with a production Rust crate (`fastcdc` v4) — a viable `roci-ext-dedup` (Nydus-RAFS-style) later (RESEARCH: FastCDC, fastcdc-rs, DupHunter).

### 8.3 GC — SWITCH to a backref index for O(garbage), keep grace-period as backstop
The current mark-sweep walks all reachable blobs each cycle: **O(total)**, not O(garbage). Data Domain's logical GC scaling with *logical* (pre-dedup) size was **20× slower at TC≥73×, up to 100× at extreme dedup** (RESEARCH: FAST17-GC). Fix: maintain a live **backref multimap `blob_digest → {manifest_digests}`** in the same embedded B-tree as the referrers index, updated transactionally on each manifest put/delete. Then a blob is collectable the moment its backref set empties (and grace period elapses) → **incremental GC is O(garbage), sweep visits only zero-backref blobs.** The FAST'17 warning against refcounting targets *chunk-level* refcounts across a global dedup namespace with snapshots — roci has neither (2-level manifest→blob, single-writer-per-repo), so a manifest-level backref index is trivially correct. **KEEP** the grace period (epoch/generation analog) and the online/never-offline guarantee. Physical-vs-logical enumeration is **KEEP** (roci is 2-level, not DDFS's 6-level Merkle tree).

### 8.4 Scrub — SWITCH full re-hash → CRC32C-on-write + staggered/adaptive; FS offload
Full periodic SHA re-hash is the worst strategy by the evidence: sequential, constant-rate, recomputes the write-time hash. Replace with: (1) store a fast **CRC32C/xxHash** checksum at write (hardware CRC32C ~50 GB/s vs SHA-256 ~4 GB/s → **~12× faster scrub passes**); (2) scrub with the fast checksum, **escalate to full SHA/BLAKE3 re-hash only on mismatch**; (3) **staggered + adaptive** scheduling — exploits LSE spatial/temporal locality for an **order-of-magnitude better mean-latent-error-time at ~2% overhead** vs sequential (RESEARCH: Scrub-FAST10); (4) on **btrfs/ZFS, delegate to the filesystem scrub** and disable the app-level pass (RESEARCH: ZFS-integrity). Sampling-based scrub is rejected as primary (detection latency too high for clustered errors). Rust: `crc32c`, `xxhash-rust`.

### 8.5 Existence filters — SWITCH static to BinaryFuse8; keep cuckoo, track Morton
For **static** per-snapshot referrer sets, **binary-fuse-8** strictly dominates xor and ribbon: **9.0 bits/key, ~55 ns lookup, 2× faster construction** than xor (RESEARCH: BinaryFuse) — and ships in the `xorf` crate as `BinaryFuse8`. Verdict: **SWITCH static filter from ribbon/xor → BinaryFuse8.** For the **mutable** blob-presence set, **KEEP cuckoo** (only production-Rust deletable filter); **track Morton filter** (1.3–2.5× faster lookups, 3–15× faster inserts at high load, 0.5–1.0 bits/key smaller; RESEARCH: Morton) as an upgrade once a Rust impl exists — candidate `roci-filter` module (~500 LoC). Counting-quotient filter noted but slower + no Rust crate.

### 8.6 Index engine — **[implemented — redb]** measured bake-off confirms LMDB faster but redb justified
redb's own published benchmarks show **LMDB is 1.8–3.0× faster on random reads (3× at 16 threads) and 35% smaller on disk** — LMDB's mmap single-level-store returns zero-copy read pointers (RESEARCH: redb-bench, LMDB-bench). For roci's read-heavy hot path this is material. **[measured — §9.8 first-party bake-off, RESEARCH: RociIndexBench]** The bake-off confirms LMDB's read advantage (**1.3–4.0× on point lookups, up to 4× on referrer range scans, dramatically better multi-thread scaling**) and disk advantage (**26–35% smaller**), but redb is **3–6× faster on writes**. Verdict: **KEEP redb as the shipped engine.** The read gap matters less than the architectural constraints: (1) the in-RAM `LogMetadataStore` handles the common local single-node case (§9.6: faster than *either* KV below ~2–4M refs); (2) the redb engine serves only the out-of-RAM / cluster case where disk-resident reads dominate and LMDB's advantage is real but the pure-Rust / `forbid(unsafe_code)` / static-musl story is decisive; (3) heed/LMDB's C FFI would break the musl release, deps-guard, and CodeQL scope. **Adoption threshold for heed:** if a future deployment needs >10M refs with sub-microsecond p50 reads *and* cannot use the in-RAM backend (hard RAM cap), adding heed behind the `MetadataStore` trait seam is justified — the trait is ready, the table layout is identical (§9.8), and the work is ~500 LoC. LSM (RocksDB/sled/fjall) **KEEP-rejected** (2–5× worse reads, compaction threads violate footprint). ART/Bε-tree = FUTURE (no durable Rust crate).

### 8.7 On-disk layout — KEEP flat CAS; ~~HYBRID 2-level fanout at scale~~ (rejected, spec conflict); accept tar+zstd
Flat `blobs/<alg>/<hex>` is correct for roci's random-`open()`-by-digest access; EXT4/XFS HTree handle tens of millions of entries with stable ~62 µs reads (RESEARCH: BfFS, GIGA+). The only risk is linear `readdir` during GC/scrub at scale — already avoided because GC marks via the in-memory index, not directory walks. ~~**HYBRID:** engage git-style **2-level fanout (`ab/cdef…`) above ~100K blobs** to keep subdirectories dcache-friendly (one extra warm dentry lookup, negligible).~~ **[corrected 2026-09-25] Fanout REJECTED:** the image-layout spec defines blob content at `blobs/<alg>/<encoded>` (`spec/image-spec/image-layout.md` §Blobs), so an `ab/cdef…` tree is no longer an OCI layout external tools can read — it breaks roci's interop invariant for a `readdir` benefit this section already shows is unused (the HTree evidence above means lookups by digest do not need it). **REJECT** Venti-arena/packfile single-file stores — they optimize sequential throughput at the cost of the O(1) random access that is roci's primary SLA. **Compression at rest: KEEP no-recompression** (recompressing changes the digest → OCI-contract violation); instead **accept and serve `tar+zstd` layers natively** (OCI v1.1) — zstd's 4× faster decompress benefits the client, and gzip decompression is already the pull bottleneck (RESEARCH: zstd-bench, containerd-gzip, OCI-1.1).

### 8.8 I/O path — SWITCH: kTLS+SSL_sendfile, fadvise, O_TMPFILE+linkat, copy_file_range
- **Zero-copy under TLS is a fiction without kTLS.** Plain `sendfile` cannot serve encrypted HTTPS — the TLS library bounces data through userspace. **kTLS + `SSL_sendfile`** restores in-kernel zero-copy under TLS: **+13–28% throughput** (nginx real test; RESEARCH: NginxKTLS, KTLSKernel). **SWITCH:** add an opt-in `ktls` feature (OpenSSL ≥ 3.0, Linux ≥ 5.2; runtime-detected, silent rustls fallback). Correct the "zero-copy blob serving" claim to "plaintext HTTP or kTLS-enabled HTTPS." **[corrected in §9]** io_uring `IORING_OP_SPLICE` is not ~8% but **10–25% *slower* than sendfile** for file→socket (confirmed by io_uring author Axboe + Netty #15747, Linux 6.15; no `IORING_OP_SENDFILE` exists/planned) — sendfile+kTLS is the read-path answer; io_uring is a **write-path** win only (see §9). Also **kTLS and io_uring `SEND_ZC` are mutually exclusive** on one socket.
- **fadvise hints (free):** `POSIX_FADV_SEQUENTIAL`+`DONTNEED` on full-blob GET (fires read-ahead, prevents large-blob page-cache pollution); `RANDOM`+`WILLNEED` for Range reads (RESEARCH: FadviseMan). **NOT O_DIRECT** (counter-productive for the registry access pattern). Rust `nix`/`rustix`, no kernel gate.
- **Upload staging: SWITCH mkstemp+rename → `O_TMPFILE`+`linkat(AT_EMPTY_PATH)`** (Linux ≥ 3.11; no-cap on ≥ 5.9). The staged inode is never namespace-visible → **no orphaned temp files, no TOCTOU, deletes the crash-cleanup code path**; `EEXIST` on link = correct dedup signal (RESEARCH: OTmpfileOracle). `commit=true` uses **fdatasync** (not fsync) — saves ~30–50 µs/blob.
- **Cross-repo blob mount (`end-11`) / sync: SWITCH to `copy_file_range`** — btrfs/XFS reflink O(1), ext4 in-kernel copy (no userspace transit), NFS server-side copy (RESEARCH: CopyFileRange). Keep hard-link/reflink as the primary same-FS dedup path; copy_file_range covers no-link/cross-dir/NFS/tmpfs. Rust `rustix::fs::copy_file_range`, kernel ≥ 5.19 stable + fallback.
- **Object store: KEEP 307 redirect but add a `redirect_min_size` (~1 MB) threshold** — <100 KB blobs lose up to 50% throughput to the extra handshake; manifests never redirected (RESEARCH: AlluxioRedirect, S3ECRBench). Server-side copies use **parallel S3 multipart** (115–190 vs 24–28 MB/s; client-facing push stays sequential per spec). S3 Express One Zone / local-NVMe LRU cache = **HYBRID hot-tier** (single-AZ → not primary durable store).

### 8.9 Net changes applied to the architecture
SHA-512 default + internal BLAKE3; reflink-primary dedup; backref-index O(garbage) GC; CRC32C+staggered scrub with FS offload; BinaryFuse8 static filter; **redb index engine (measured — §9.8 bake-off settled the heed/LMDB vs redb question: KEEP redb)**; ~~2-level fanout at scale~~ (rejected — §8.7); native tar+zstd; kTLS/fadvise/O_TMPFILE/copy_file_range on the I/O path. All are folded into [`ARCHITECTURE.md`](ARCHITECTURE.md) with `[refined from RESEARCH §8]` markers.

## 9. Local-store efficiency — is there an even more efficient design?

A second adversarial round asked whether anything beats the current local store (loose CAS + `sendfile` + append-log + in-RAM maps). Verdict: **the shape is confirmed near-optimal; three low-dependency ADOPTs improve it; everything else is FUTURE or rejected.** New source keys added to the table.

### 9.1 Substrate shape — CONFIRMED (loose large blobs + owned metadata log)
Four independent evidence chains confirm "loose large blobs served by `sendfile` + owned metadata log" is the efficient design, not a database-for-everything:
- **`sendfile` is decisive for large blobs:** AIStore production benchmark — `sendfile` gives **+3× throughput (44–50 vs 15–17 GiB/s) and 62–72% less CPU** for 1 GiB objects; no benefit <64 KiB (RESEARCH: AIStoreSendfile). Any substrate that puts large blobs in a DB/vLog **loses `sendfile`** (double-buffering) → 2–3× regression. Kills "all blobs in SQLite/LMDB", WiscKey-vLog, and SPDK for the large-blob path.
- **The DB-vs-file crossover is ~100 KB**, found independently three times: SQLite intern-v-extern (DB 2.2–2.4× faster <100 KB; file 2× faster >500 KB), SQLite-faster-than-fs (35% on Linux for 10 KB), MS "To BLOB or Not" (crossover 250 KB–1 MB) (RESEARCH: SQLiteInternBlob, SQLiteFasterFS, GrayBLOB). → small objects favor an engine/cache, large favor loose files.
- **DupHunter (ATC'20)** validates keeping layer tarballs **intact/loose**: naive dedup that reconstructs layers raises GET latency **36–98×**; the intact-primary tier gives 2× better GET latency (RESEARCH: DupHunter).
- **DADI (ATC'20)** confirms the registry's job is cheap ranged serving; runtime magic is client-side (RESEARCH: DADI).

### 9.2 ADOPT — in-memory small-blob content cache
Manifests/configs (1–50 KB) dominate request **count** (every pull reads them) but a trivial fraction of **bytes**. Extend the in-RAM metadata maps with a bounded `digest→bytes` **LRU cache** for blobs below `small_blob_threshold` (default 100 KB, the crossover). A manifest/config GET is then answered from RAM with **zero `open()`/`close()` syscall** (the Data Domain in-RAM-content lever); miss falls through to the loose file. Expected **35–80% latency cut** on the dominant request type (SQLiteFasterFS regime), bounded RAM (configurable, e.g. 256 MB / 1% RAM), **fully OCI-conformant** (the loose file still exists), ~50 LoC (`lru` crate). **Do NOT** make it KV-only-without-the-file (breaks the `blobs/<alg>/<hex>` MUST rule).

### 9.3 ADOPT — WAL group-commit on the metadata log
Under a push storm (CI pushing N images), per-op `fdatasync` on the append-log serializes at ~50–200 µs each (NVMe), capping throughput. **Group-commit** (leader coalesces all queued appends into one `fdatasync`, wakes all waiters — the PostgreSQL/RocksDB pattern) yields **10–250× fewer fsyncs** under load (**5–10× throughput on NVMe, 20–100× on HDD**), ~150 LoC, **zero new dependencies** (`std` `Mutex`/`Condvar`). Highest-ROI local-store change available. io_uring batched `fdatasync` on the write path is the same win via a different mechanism (**+14–18%**, Jasny PVLDB'26) and is the **one place io_uring helps** (RESEARCH: ZeroCopyIndexMem-derived, Jasny-PVLDB26).

### 9.4 ADOPT (≥5M records / HDD / embedded) — periodic rkyv mmap snapshot
Log replay costs ~20–40 ms at 1M records on NVMe (negligible) but **300–500 ms at 10M / 15–20 s on HDD**. A periodic **rkyv zero-copy snapshot** (`O_TMPFILE`+`linkat`, atomic, crash-safe; replay only the post-snapshot log tail) gives **O(1) cold start (<5 ms via `mmap` + demand-paging)** regardless of size, and **~10× lower RSS** (demand-paged pages vs heap `HashMap`). rkyv access = a **1.09 ns pointer cast**, no deserialize loop (RESEARCH: rkyv-bench, LMDB-SDC). Crates: `rkyv` + `memmap2` (both pure-Rust, no C). **Correction to ARCHITECTURE.md:** "millions of tags = tens of MB" **underestimates ~4×** — 1M tags ≈ **130 MB** heap RSS (32-byte keys + 32-byte digests + hashbrown overhead); 10M ≈ 1.3 GB. The mmap path is the fix for memory-constrained/edge deployments.

### 9.5 Corrections & FUTURE
- **io_uring read path: KEEP `sendfile`** — `IORING_OP_SPLICE` is **10–25% slower** (Axboe/Netty #15747), not ~8%; no `IORING_OP_SENDFILE` planned; `SEND_ZC` ⊗ kTLS. io_uring is **ADOPT on the write path only**, **FUTURE** as a full thread-per-core redesign — **compio** is the named carrier runtime (only actively-maintained TPC Rust runtime with an HTTP-compat bridge; tokio-uring's `!Send` futures can't host hyper), worth **−46% P95 / +18% throughput at high load** (Apache Iggy TPC migration) but **zero gain at light load** and ~18–36 months from production HTTP maturity (RESEARCH: NettyAxboe25, Jasny-PVLDB26, IggyTPC, CompioTPC).
- **Small-object packing (Haystack/f4/Venti-arenas): KEEP-CURRENT / FUTURE.** roci's content-addressed path already achieves Haystack's O(1)-IOP goal without an offset map; the flat CAS directory is dcache-safe on HTree/B-tree filesystems (GIGA+: 99.99% of dirs <8k entries; fanout was rejected in §8.7); `roci-meta.log` already *is* the Venti arena applied to metadata. Packing would save the 30–60% small-file block-alignment waste (BfFS) but regress GC O(garbage)→O(live), break the `blobs/<alg>/<hex>` MUST rule for external tools, and violate minimal-deps. Only a sealed **`roci-ext-coldstore`** tier for 100M+ dormant manifests (interop explicitly out of scope) justifies it — **FUTURE**. Deployment mitigation now: **ext4 `bigalloc`** cuts alignment waste 30%→~5–15% with zero code (RESEARCH: Haystack, f4, BfFS, GIGA+).

### 9.6 MEASURED — metadata residency crossover (in-RAM maps vs redb KV vs cuckoo filter)
A first-party benchmark (M4 Pro, 48 GB, APFS/NVMe, `--release`+LTO; each structure isolated for clean peak-RSS attribution; keys mirror roci's repo-qualified `(repo,tag)→sha256:<hex>`, ~276 B/ref; 1M random hot lookups per point — RESEARCH: RociScaleBench) turns §8.6/§9.4's "benchmark-first" guidance into numbers:

| refs | in-RAM `HashMap` RSS | HashMap lookup | redb lookup | redb on-disk | cuckoo RAM | cuckoo definite-miss |
|---|---|---|---|---|---|---|
| 1M | 298 MB | 296 ns | 991 ns | 270 MB | 3.2 MB | 177 ns |
| 5M | 1.38 GB | 380 ns | 1947 ns | 2.16 GB | 10.5 MB | 199 ns |
| 10M | 2.76 GB | 417 ns | 2704 ns | 4.30 GB | 18.9 MB | 240 ns |

- **In-RAM maps: 273 B/ref, linear hard heap** (corrects §9.4's ~130 B/ref — richer repo-qualified keys push it up). Heap-budget crossovers: **0.5 GB ≈ 1.8M refs, 1 GB ≈ 3.7M, 2 GB ≈ 7.3M, 4 GB ≈ 14.6M**.
- **Lookups: RAM wins at every size** — HashMap 62–417 ns vs redb 400–2704 ns (**3–6.5× slower**, widening with N as the B-tree deepens + page-faults). Confirms §9.1: while the working set fits RAM, moving maps to a KV is a *latency regression*, not a win.
- **Cuckoo filter is effectively free: 1.74 B/ref (~14 bits/key)** → **18.9 MB for 10M blobs**, flat. A definite-miss answer (~240 ns) replaces a `stat(ENOENT)` (**1042 ns**) → **~800 ns saved per absent probe** at a **~1.9% false-positive rate** (a false positive costs only the stat you'd have done — never a wrong answer). **VALIDATES** the shipped blob-presence filter.
- **Verdict (roci's decision line):** in-RAM `LogMetadataStore` is strictly better **below ~2–4M references** (smaller RSS *and* faster) — **roci's current single-node target, adopted up to ~2–4M refs (≈0.5–1 GB heap)**. The rkyv mmap snapshot (§9.4) is the first RSS lever *at* that band; the **redb map-to-disk KV earns its place only at ≥~10M refs, a hard RAM cap, or a shared-cluster store** (RSS becomes evictable page cache ~430 B/ref on disk instead of unbounded heap, accepting the 3–6× read hit). All three sit behind the `MetadataStore` trait seam; none is built ahead of its threshold.



### 9.7 MEASURED — roci vs distribution vs zot (first-party comparative benchmark)
`just bench` (docs/guide/benchmarks.md) runs roci, CNCF distribution 3.1.2 and zot 2.1.21 at their defaults (logging at `warn`) in pinned containers with disjoint cpusets, driving them with zb, vegeta, crane and a push-storm loadgen, and sampling cgroup v2 CPU and anonymous RSS (RESEARCH: RociCompareBench). **NON-AUTHORITATIVE: Docker Desktop VM, `quick` (1 rep)** — authoritative numbers need `just bench full` on a dedicated Linux host. What it changed:
- **The first run found roci losing most throughput metrics** (pull 4–24× below zot, push 2–5×, peak RSS 400 MiB vs 70). `just bench-perf` flamegraphs + syscall tables attributed each gap: 4 KiB `ReaderStream` blocking-pool hops on every blob GET (futex-bound), **software SHA-256 on arm64** (`sha2` compiles its ARMv8 backend only with feature `asm`: 0.55 vs 2.5 GiB/s), whole-body buffering of every upload (`to_bytes` + `to_vec`, violating invariant 4), a `stat` per blob HEAD, per-blob `fsync` where zot's default `commit=false` does none, and — for memory — transparent huge pages, an unbounded blocking pool and cross-thread buffer churn.
- **After the fixes** (ARCHITECTURE §Vertical scale, §RAM consumption): roci leads on startup (66 vs 187 ms zot), idle/corpus RSS (1.9/14.7 vs 49.8/65.6 MiB), push storm (1398 vs 334 images/s), 10 MB c=8 zb pull/push (2752/1914 vs 2451/1511 MiB/s) and server CPU/GiB (1.12 vs 1.66); peak RSS is ~at parity (80 vs 70 MiB); small c=1 push and crane gaps are within single-rep noise.
- **Open:** hot-path p99 at 1000 rps is ~2× zot (p50 equal or better). Controlled A/B runs ruled out handler time, the tokio scheduler flavour, allocator purging and hyper-util auto-detection; the VM's run-to-run p99 swing (2–10 ms) blocks further diagnosis — needs off-CPU/scheduler tracing on bare Linux.
- **Tooling finding:** zb cannot push to distribution (it drops the upload `Location` query carrying `_state`); distribution's zb cells are `n/a`.
- **`sendfile` under hyper is not possible**: hyper owns every socket write (its own `send_file` example streams a 4 KiB `ReaderStream`), so the residual pull-copy cost needs a roci-owned HTTP/1.1 writer — deferred (ARCHITECTURE §Vertical scale).

### 9.8 MEASURED — index engine bake-off (heed/LMDB vs redb)
`just bench-index` (`bench/index-engines/`, standalone Cargo project with `[workspace]` — NOT a root workspace member; heed/LMDB C FFI never enters the product dep graph) runs roci's real metadata schema against both engines: tags `(repo, tag) → (digest, media_type)`, referrers `(repo, subject, referrer) → descriptor`, media-types `(repo, digest) → media_type`, filtered-referrer and backref tables — identical composite-key layout to `crates/roci-storage/src/metadata/redb.rs`. Keys use the ~276 B/ref repo-qualified format from §9.6 (RESEARCH: RociIndexBench).

**NON-AUTHORITATIVE: Apple Silicon macOS (M-series), APFS/NVMe, `--release` + LTO (fat), single host.** Both engines use NoSync for population and read benchmarks (equal durability); write-throughput bench also NoSync (fair). 100K random hot lookups per data point.

**Read latency (1 thread, ns/op p50 / p99):**

| N refs | workload | redb p50/p99 | heed p50/p99 | redb/heed p50 |
|--------|----------|--------------|--------------|---------------|
| 100K | tag lookup | 1125/1625 | 875/1917 | 1.3× |
| 100K | existence (hit) | 1125/1708 | 875/1958 | 1.3× |
| 100K | existence (miss) | 1000/1500 | 708/1292 | 1.4× |
| 100K | referrer scan (p100) | 1541/2167 | 1209/2333 | 1.3× |
| 1M | tag lookup | 2750/4666 | 1708/3542 | 1.6× |
| 1M | existence (hit) | 2625/5375 | 1958/3834 | 1.3× |
| 1M | existence (miss) | 1750/4084 | 1375/2125 | 1.3× |
| 1M | referrer scan (p100) | 8916/21375 | 2208/4584 | 4.0× |

**Multi-threaded read scaling (8 threads, ns/op p50 / p99):**

| N refs | workload | redb p50/p99 | heed p50/p99 | redb/heed p50 |
|--------|----------|--------------|--------------|---------------|
| 100K | tag lookup | 5916/49166 | 834/2166 | 7.1× |
| 100K | existence (hit) | 5709/50958 | 958/2417 | 6.0× |
| 1M | tag lookup | 6667/48417 | 1500/3334 | 4.4× |
| 1M | referrer scan (p100) | 7084/52709 | 2125/4417 | 3.3× |

**On-disk size:**

| N refs | redb | heed (LMDB) | heed/redb |
|--------|------|-------------|-----------|
| 100K | 514 MB | 429 MB | 0.83× (17% smaller) |
| 1M | 4.02 GB | 2.97 GB | 0.74× (26% smaller) |

**Write throughput (NoSync, batch 1000):**

| N refs | redb ops/s | heed ops/s | redb/heed |
|--------|-----------|-----------|-----------|
| 100K | 154,070 | 50,652 | 3.0× faster |
| 1M | 141,146 | 22,870 | 6.2× faster |

- **heed/LMDB wins reads at every size and every thread count** — p50 1.3–1.6× faster single-threaded, widening to **4–7× at 8 threads** (redb's single-writer lock serializes readers through a `begin_read` guard; LMDB's MVCC mmap allows true concurrent readers with no coordination). Referrer range scans show the largest gap (4.0× at 1M single-threaded) because LMDB's B-tree page layout keeps adjacent keys physically contiguous in the mmap.
- **redb wins writes 3–6×** — its copy-on-write B-tree amortizes writes better than LMDB's COW page split; population time confirms (69s vs 117s at 1M).
- **heed/LMDB is 17–26% smaller on disk**, consistent with redb-bench's published ~35% figure (smaller here because the benchmark's composite keys are longer than the micro-benchmark).
- **Verdict: KEEP redb.** The read advantage is real but masked by three factors: (1) the in-RAM `LogMetadataStore` is the hot path for the majority of deployments (§9.6: faster than *either* KV), so the redb engine only matters when metadata exceeds RAM; (2) redb's write advantage matches roci's push-storm workload profile; (3) heed/LMDB requires C FFI (liblmdb.a), which would break `forbid(unsafe_code)`, the static-musl release (`scratch` container, no libc), `deps-guard`, and CodeQL scope. The `MetadataStore` trait seam is ready for heed if a future deployment crosses the adoption threshold (>10M refs, hard RAM cap, sub-µs read SLA).

## Sources

| # | Title | Authors / Org | Venue / Year | Relevance to roci |
|---|-------|---------------|--------------|-------------------|
| Venti | Venti: A New Approach to Archival Storage | Quinlan, Dorward — Bell Labs | USENIX FAST 2002 | CAS model roci reimplements: hash-addressed, write-once, dedup-by-construction, integrity-on-read, rebuildable index. Collision < 10⁻²⁰ at exabyte. |
| LBFS | A Low-Bandwidth Network File System | Muthitacharoen, Chen, Mazières — MIT | SOSP 2001 | Content-defined chunking; ~90% traffic cut. Sub-blob dedup = future extension, not core. |
| DataDomain | Avoiding the Disk Bottleneck in the Data Domain Dedup File System | Zhu, Li, Patterson — Data Domain | USENIX FAST 2008 | Bloom "summary vector" + locality cache remove ~99% index disk reads → roci's in-RAM existence filter. |
| PrimaryDedup | Primary Data Deduplication — Large Scale Study and System Design | Microsoft | USENIX ATC 2012 | Chunk dedup under tight RAM/CPU; larger chunks + selective dedup to cap index cost. |
| Foundation | Fast, Inexpensive Content-Addressed Storage in Foundation | Rhea, Cox, Pesterev | USENIX ATC 2008 | Efficient CAS on commodity HW; Bloom existence check → single-binary/no-DB posture viable. |
| GC-FAST13 | Concurrent Deletion in a Distributed CAS System with Global Dedup | (FAST'13 authors) | USENIX FAST 2013 | Safe concurrent deletion under global dedup → grace-period/generation GC. |
| GC-FAST17 | (Dedup file-system GC) | Douglis et al. | USENIX FAST 2017 | GC strategies in dedup FS; mark-sweep vs refcount tradeoffs. |
| DistroGC | Registry GC documentation (offline requirement) | CNCF `distribution` | docs (current) | Stop-the-world GC = the anti-pattern roci beats with inline+grace-period GC. |
| HarborGC | Online-GC race deleting in-flight blobs | Harbor (goharbor) | issue tracker | Empirical proof the non-transactional GC race is real in production. |
| RUM | Designing Access Methods: The RUM Conjecture | Athanassoulis et al. | EDBT 2016 | Read/Update/Memory amplification tradeoff → pick B-tree (read-heavy, low footprint) over LSM. |
| LSM | The Log-Structured Merge-Tree | O'Neil, Cheng, Gawlick, O'Neil | Acta Informatica 1996 | LSM = write-optimized; wrong fit for roci's read-heavy, low-footprint index. |
| RocksDB | RocksDB: A Persistent KV Store for Low-Latency Applications | Dong et al. — Facebook | SIGMOD 2020 | Quantified LSM read/space amp + compaction cost → avoid in minimal build. |
| Cuckoo | Cuckoo Filter: Practically Better Than Bloom | Fan, Andersen, Kaminsky, Mitzenmacher | CoNEXT 2014 | Deletable, space-efficient membership filter for the blob-presence set (GC needs deletes). |
| Ribbon | Ribbon Filter: Faster and Slimmer Alternative to Bloom | Dillinger, Walzer | USENIX ATC 2021 | ~30–40% smaller than Bloom for static referrer sets. |
| Karger97 | Consistent Hashing and Random Trees | Karger et al. — MIT | STOC 1997 | Foundational consistent hashing: minimal key movement on membership change. |
| Chord | Chord: A Scalable Peer-to-peer Lookup Service | Stoica et al. — MIT | SIGCOMM 2001 | Consistent hashing as scalable lookup; O(log n) routing. |
| Dynamo | Dynamo: Amazon's Highly Available Key-value Store | DeCandia et al. — Amazon | SOSP 2007 | Virtual nodes to smooth ring load skew; production ring-sharding template. |
| CHBL | Consistent Hashing with Bounded Loads | Mirrokni, Thorup, Zadimoghaddam — Google/UCPH | SODA 2018 (arXiv:1608.01350) | Cap load at c=1+ε with O(1/ε²) extra moves; used in Google LB/HAProxy/Envoy. roci's overload protection. |
| Maglev | Maglev: A Fast and Reliable Software Network LB | Eisenbud et al. — Google | NSDI 2016 | Lookup-table hashing (near-perfect balance, minimal disruption); heavier than needed for small member lists. |
| HRW | Using Name-Based Mappings to Increase Hit Rates (Rendezvous/HRW) | Thaler, Ravishankar | IEEE/ACM ToN 1998 | Stateless per-key node selection; simpler than vnode ring for static `members`. |
| SipHash | SipHash: A Fast Short-Input PRF | Aumasson, Bernstein | 2012 | Keyed hash resisting hash-flooding DoS on the attacker-influenced repo path. |
| Slacker | Slacker: Fast Distribution with Lazy Docker Containers | Harter et al. — UW-Madison | USENIX FAST 2016 | Pull=76% of start time, only 6.4% of data read → lazy-pull justification and cold-start target. |
| eStargz | eStargz / stargz-snapshotter | containerd (Google/NTT) | docs (current) | Lazy pull needs only Range + digest-verified TOC = roci Phase-1 surface. |
| SOCI | Seekable OCI: Lazy-Loading via Range-Request Indexing | Thompson et al. — AWS | arXiv 2026 | Index-as-referrer; 7.4–9.3× cold start; Fargate 18.4M tasks/day. Referrers = lazy-pull backbone. |
| Nydus | Nydus (RAFS/EROFS) container image service | Alibaba/Ant (Dragonfly) | project + Alibaba Cloud blogs | Rust precedent in-domain; foreign-media-type blobs must be storable; chunk dedup + Merkle integrity. |
| LazyPod | The Lazy Pod That Lies (deferred cost & failure modes) | Kliukovkin | arXiv 2026 | Counter-evidence: lazy cost deferred (105s vs 72s full read); cache-exhaustion failures; ~80% density crossover. |
| FlacIO | FlacIO: Flat and Collective I/O for Container Image Service | Liu et al. — Huawei | USENIX FAST 2025 | Up to 23×/4.6× over full/lazy; memory-oriented image direction to watch. |
| Kraken | Kraken: P2P Docker Registry | Uber | eng blog + repo | 20k blobs (100MB–1GB) < 30s; 2600 hosts p50 10s; ≥8k hosts/cluster; >50% line rate. Origin=hash-ring, pluggable backends → integrate externally. |
| Dragonfly | Dragonfly P2P image/file distribution | Alibaba → CNCF (Graduated 2026) | CNCF + Alibaba blogs | Tens of millions launches/day; up to 90% bandwidth savings; Kuaishou −80% peak origin load. External P2P fabric for roci-as-origin. |
| Dapper | Dapper, a Large-Scale Distributed Systems Tracing Infrastructure | Sigelman et al. — Google | Google TR 2010 | Aggressive low sampling → negligible tracing overhead. roci's default-cheap-sampling basis. |
| Canopy | Canopy: End-to-End Performance Tracing and Analysis | Kaldor et al. — Facebook | SOSP 2017 | Low-overhead tracing at scale via sampling + streaming aggregation. |
| TracingOH | Benchmarking the Overhead of Distributed Tracing Agents | atlarge-research / ICPE | 2025 | Full-rate agent overhead single/low-double-digit %; sampling → ~1–2%. Backs roci's <~2% claim. |
| OTelCard | Cardinality Limits in OpenTelemetry / OTLP↔Prometheus bridge benchmarks | OpenTelemetry | docs/benchmarks (current) | Unbounded label cardinality is the footprint trap → roci must cap metric cardinality by design. |
| BLAKE3-spec | BLAKE3: one function, fast everywhere | O'Connor, Aumasson, Neves, Wilcox-O'Hearn | blake3.io 2021 | 0.49 cpb (AVX-512) = 8–12× SHA-256/512; 1.3× SHA-256 on ARM1176; tree-parallel + verified streaming (Bao). Internal scrub/streaming hash. |
| SHA512-256 | SHA-512/256 (SHA-512 speed on 64-bit) | Gueron, Johnson, Walker — Intel | ePrint 2010/548 | SHA-512 36–50% faster/byte than SHA-256 on 64-bit without SHA-NI (11.58 vs 18.22 cpb). → default digest sha512. |
| Intel-SHANI | Xeon Scalable Cryptographic Performance | Intel | Intel dev doc 2017 | With SHA-NI: SHA-256 0.87 cpb vs SHA-512 1.07 cpb (SHA-256 ~20% ahead); gap inverts without SHA-NI. |
| Blazehash-M4 | Hash throughput benchmarks (Apple M4 Pro) | SecurityRonin | 2026 | ARMv8 HW SHA: SHA-256 492 MB/s vs BLAKE3 1640 MB/s (3.3×). Scrub speedup basis. |
| FICLONE-man | ioctl_ficlone(2) reflink | Linux man-pages | current | O(1) reflink, independent unlink, blocks shared until CoW; btrfs/XFS/APFS/ReFS. → reflink dedup. |
| reflink-copy | reflink-copy crate | Rust community | crates.io v0.1.30 | FICLONE/clonefile/FSCTL with automatic hard-link fallback. Rust readiness for reflink dedup. |
| FastCDC | FastCDC: Fast and Efficient Content-Defined Chunking | Xia et al. — HUST/UTA | USENIX ATC 2016 | 10× faster than Rabin, ±1.4% dedup ratio, 10–20% better than fixed chunking. Future sub-chunk dedup. |
| fastcdc-rs | fastcdc crate | nlfiedler | crates.io v4 | Pure-Rust FastCDC 2016+2020; makes `roci-ext-dedup` actionable. |
| DupHunter | End-to-end Dedup for Docker Registries | Zhao et al. | ACM TOS 2024 | Cross-layer registry redundancy is real; supports future chunk-dedup extension. |
| FAST17-GC | The Logic of Physical Garbage Collection in Deduplicating Storage | Douglis et al. — Dell EMC | USENIX FAST 2017 | Logical GC O(logical) = 20× slower at TC≥73×, 100× extreme; backref/physical enumeration fixes it. → O(garbage) GC. |
| Scrub-FAST10 | A Clean-Slate Look at Disk Scrubbing | Oprea, Juels — RSA Labs | USENIX FAST 2010 | Staggered+adaptive scrub: OOM better mean-latent-error-time at ~2% overhead vs sequential. |
| ZFS-integrity | End-to-end Data Integrity: A ZFS Case Study | Zhang et al. | USENIX FAST 2010 | Block checksums verified on scrub without app re-hash → FS-scrub offload on btrfs/ZFS. |
| BinaryFuse | Binary Fuse Filters: Fast and Smaller Than Xor Filters | Graf, Lemire — TELUQ | ACM JEA 2022 (arXiv:2201.01174) | 9.0 bits/key, ~55 ns lookup, 2× faster build than xor; dominates ribbon/xor. → BinaryFuse8 static filter (`xorf`). |
| Morton | Morton Filters: Faster, Space-Efficient Cuckoo Filters | Breslow, Jayasena — AMD | PVLDB 2018 | 1.3–2.5× faster lookups, 3–15× faster inserts at high load, 0.5–1.0 bits/key smaller than cuckoo. Mutable-filter upgrade (no Rust crate yet). |
| redb-bench | redb vs LMDB benchmarks | cberner (redb) | GitHub 2024/25 | LMDB 1.8–3.0× faster random reads, 35% smaller; redb 1.74× faster individual writes. → HYBRID index decision. |
| LMDB-bench | LMDB microbenchmarks | Symas | 2012 | mmap single-level-store: zero-copy reads, 3–4× LevelDB. `heed` (Rust) exposes it. |
| NginxKTLS | Improving NGINX Performance with kTLS + SSL_sendfile | F5/NGINX | 2021 | kTLS+SSL_sendfile +13–28% throughput → zero-copy under TLS. |
| KTLSKernel | Kernel TLS documentation | kernel.org | v5.2+ | In-kernel TLS record layer lets sendfile serve HTTPS zero-copy. |
| IoUringDBMS | io_uring for High-Performance DBMSs: When and How | Jasny et al. — TUD/TUM/TigerBeetle | PVLDB 2026 | Naive io_uring 1.06–1.10×; architecture-aware 2.05–2.31×. io_uring = FUTURE (needs redesign). |
| IoUringSplice | splice vs sendfile (io_uring file serving) | kernel-internals writeup | 2025 | io_uring splice ~8% slower per-transfer than sendfile today; parity at high concurrency. |
| FadviseMan | posix_fadvise(2) | Linux man-pages | current | SEQUENTIAL doubles read-ahead; DONTNEED prevents large-blob cache pollution. Free I/O win. |
| OTmpfileOracle | O_TMPFILE + linkat atomic staging | Oracle Linux / LWN | 2013/2024 | Namespace-invisible staging → no orphan temp files, no TOCTOU; Linux ≥3.11 (no-cap ≥5.9). |
| CopyFileRange | copy_file_range(2) | Linux man-pages | 5.19 stable | In-kernel file copy: btrfs/XFS reflink O(1), ext4 in-kernel, NFS server-side. → cross-repo mount. |
| AlluxioRedirect | S3 API redirect-cost benchmarks | Alluxio | 2025 | 307 redirect ≈0% for >1 MiB, up to −50% for <100 KiB → size-thresholded redirect. |
| S3ECRBench | Using S3 as a container registry | Ochagavía / Outerbounds | 2024 | Parallel S3 multipart 115–190 vs serial 24–28 MB/s (4–8×) → server-side parallel copy. |
| zstd-bench | Zstandard benchmarks (Silesia) | Facebook / Collet | 2024 | zstd -1 decompress 1550 MB/s vs gzip 390 (4×) at similar ratio. → accept tar+zstd natively. |
| containerd-gzip | Pull duration dominated by gzip decompress | containerd | 2026 | gzip inflate 100–200 MiB/s is the pull bottleneck (TF layer 30 s inflate vs 15 s fetch). |
| BfFS | Billion-files File Systems: A Comparison | Shaikh — GMU | arXiv 2024 | EXT4 read stable 10M→100M files (62 µs); flat CAS fine, fanout for readdir at scale. |
| GIGA+ | Scale and Concurrency of GIGA+ | Patil, Gibson — CMU | USENIX FAST 2011 | Local dirs handle millions of entries at 16–20k creates/s; 99.99% of real dirs <8k entries. |
| Haystack | Finding a Needle in Haystack: Facebook's Photo Storage | Beaver et al. — Facebook | USENIX OSDI 2010 | Packed volume files + 10 B/photo RAM offset map, 1 IOP/read, 4× reads/sec vs NFS. roci's content-addressed path already gives O(1) reads → packing not needed. |
| f4 | f4: Facebook's Warm BLOB Storage System | Muralidhar et al. — Facebook | USENIX OSDI 2014 | Erasure-coded warm tier at 65 PB. FUTURE cold-tier only; not baseline. |
| SQLiteInternBlob | Internal vs External BLOBs in SQLite | D.R. Hipp / SQLite | sqlite.org 2011/2022 | DB 2.2–2.4× faster <100 KB; file 2× faster >500 KB. Crossover ~100 KB → small-blob cache, large blobs loose. |
| SQLiteFasterFS | 35% Faster Than The Filesystem | SQLite team | sqlite.org 2017 | 10 KB blobs: 35% faster (Linux) to 5× (Win) in-DB vs loose files; 20% less space. → in-RAM small-blob cache win. |
| GrayBLOB | To BLOB or Not To BLOB | Gray, Liu, Bosworth et al. — Microsoft | MSR 2006 | DB faster <250 KB–1 MB, filesystem faster above. Corroborates the ~100 KB crossover. |
| AIStoreSendfile | Improving GET Performance with Zero-Copy File Transfers | Mehes — NVIDIA/AIStore | 2026 | sendfile +3× throughput (44–50 vs 15–17 GiB/s), 62–72% less CPU for 1 GiB objects; no benefit <64 KiB. Confirms loose+sendfile for large blobs. |
| WiscKey | WiscKey: Separating Keys from Values | Lu, Pillai, Arpaci-Dusseau ×2 | USENIX FAST 2016 | KV-separation 46–111× faster load, write-amp ~1.14; but vLog loses sendfile. FUTURE distributed tier only. |
| DupHunter | DupHunter: Flexible High-Performance Dedup for Docker Registries | Zhao et al. — VT/IBM | USENIX ATC 2020 | Naive dedup raises GET latency 36–98×; intact-layer tier 2× better. Validates loose layer blobs. |
| DADI | DADI Block-Level Image Service | Li et al. — Alibaba | USENIX ATC 2020 | Cold start <3 s (vs ~20 s); registry unchanged (standard HTTP). Registry = cheap ranged origin. |
| rkyv-bench | Rust Serialization Benchmark | djkoloski et al. | GitHub 2026 | rkyv access 1.09 ns (pointer cast) vs serde deserialize ms; snapshot O(1) mmap start. → rkyv metadata snapshot. |
| LMDB-SDC | The Lightning Memory-Mapped Database | Howard Chu — Symas | SDC 2015 | Single-level-store mmap: reads = direct pointer, O(1) sub-ms open regardless of size; 2M random reads/s. mmap-resident index model. |
| NettyAxboe25 | Netty io_uring splice vs sendfile (issue #15747) | Doxlik, Axboe, Netty | GitHub 2025 | IORING_OP_SPLICE 10–25% SLOWER than sendfile (1 MB: 6,000 vs 7,200 RPS), confirmed by io_uring author. → keep sendfile; corrects §8.8 "~8%". |
| Jasny-PVLDB26 | High-Performance DBMSs with io_uring: When and How | Jasny et al. — TUD/TUM/TigerBeetle | PVLDB 2026 | Naive io_uring 1.06–1.10×; batched writes +14–18%; SQPoll +32% (1 core). io_uring = write-path ADOPT, not read-path. |
| IggyTPC | Thread-per-Core io_uring migration (tokio→compio) | Apache Iggy | blog 2026 | TPC+compio: +18% throughput, −46% P95 at high load; zero gain at light load. compio = named future TPC runtime. |
| CompioTPC | compio async runtime | compio-rs | GitHub 2025 | Most-maintained TPC Rust runtime; compio-compat bridges hyper; tokio-uring !Send can't host hyper. FUTURE carrier. |
| RociScaleBench | roci metadata-residency scale benchmark (first-party) | roci | 2026-09-20, M4 Pro/48 GB/APFS-NVMe | in-RAM map 273 B/ref linear (2.76 GB @ 10M), 62–417 ns lookup; redb 3–6.5× slower reads, evictable ~430 B/ref on disk; cuckoo 1.74 B/ref (18.9 MB @ 10M), saves ~800 ns/miss vs stat(ENOENT), ~1.9% FP. → in-RAM maps to ~2–4M refs; KV at ≥~10M / RAM-cap / cluster. Backs §9.6. |
| RociCompareBench | roci vs CNCF distribution 3.1.2 vs zot 2.1.21 comparative benchmark (first-party) | roci | 2026-09-25, Docker Desktop (Apple M-series, 6 CPUs, linuxkit 7.0.12), quick/1 rep — non-authoritative | Before fixes roci lost pull 4–24×, push 2–5×, RSS ~6×; after streamed reads/uploads, hardware SHA-256, HEAD-from-metadata, THP opt-out etc. it leads startup, idle/corpus RSS, push storm, 10 MB c=8 pull/push, CPU/GiB; hot-path p99 ~2× zot open. Backs §9.7. |
| RociIndexBench | roci index-engine bake-off: heed (LMDB) vs redb (first-party) | roci | 2026-09-25, Apple Silicon macOS (M-series)/APFS-NVMe, --release + LTO | heed/LMDB 1.3–4× faster reads (4–7× at 8 threads), 17–26% smaller disk; redb 3–6× faster writes. KEEP redb: in-RAM backend covers hot path, pure-Rust/musl/forbid(unsafe) decisive; heed ready behind trait seam at >10M-ref threshold. Backs §8.6/§9.8. |

*Compiled 2026-09-19. §1–7 from the first scout wave + CHBL/Venti primary reads; §8 from LayoutHashCAS/IndexEngineFilters/DedupGCScrub/IOServingObjStore + BLAKE3/binary-fuse reads; §9 from IoUringE2E/SmallObjectPacking/ZeroCopyIndexMem/WholeRegistryEngine + Haystack/AIStore reads. All §8–9 scouts delivered briefs in yield text (local:// write avoided per prior lesson); one §9 scout wedged on a yield-schema mismatch and was harvested via recovered result.*
