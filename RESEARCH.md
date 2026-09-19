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

*Compiled 2026-09-19 from parallel scout research (RegistryDistFootprint, ShardingScaleOut, CASDedupGC, IndexQueryTelemetry) plus direct reads of the CHBL and Venti primary sources. Scout briefs interrupted at the write step; sources verified against their research transcripts and synthesized here.*
