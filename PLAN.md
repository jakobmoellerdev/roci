# roci — Master Build Plan

A phased plan for building **roci**, a Rust OCI Distribution registry. Philosophy: **start small, prove functional correctness against the conformance suite at every layer, then grow subsystems.** Each phase produces a working, testable binary. Algorithmic and footprint decisions are called out where they matter — they are designed in from the start, not bolted on.

Spec anchors (local): [`spec/distribution-spec/spec.md`](spec/distribution-spec/spec.md), [`spec/image-spec/spec.md`](spec/image-spec/spec.md), [`spec/image-spec/image-layout.md`](spec/image-spec/image-layout.md), [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md) (de-facto bearer-token auth + client examples).

Endpoint IDs below (`end-N`) refer to the spec's endpoint table. Error codes (`CODE`) refer to its error-code table.

## Document maintenance contract

roci's docs have single owners; keep them consistent as work lands. **When any of these change, update the owning doc in the same change:**

| Doc | Owns | Update when |
| --- | --- | --- |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | component model, storage/index/HTTP/observability/scaling design, architectural invariants | a design decision is made or **corrected** |
| [`SECURITY.md`](SECURITY.md) | threat model, boundary controls, security invariants, tracked CVE classes | a security decision is made or **corrected** |
| [`RESEARCH.md`](RESEARCH.md) | evidence, source tables, per-decision verdicts | **new research** is gathered (consolidate it here, then cite it from ARCHITECTURE/SECURITY) |
| **`PLAN.md`** (this file) | phased build steps + correctness gates | scope, sequencing, or a phase's tasks change |
| [`README.md`](README.md) | the high-level feature roadmap | a user-facing capability is added/removed/renamed |

Rules:
- **PLAN.md and the README roadmap MUST be kept updated** as phases progress and as design/security decisions land — a decision in ARCHITECTURE/SECURITY that adds or changes a build step or a feature is not "done" until PLAN and the README reflect it.
- **Architecture/security corrections consolidate into ARCHITECTURE.md / SECURITY.md** (mark `[refined from RESEARCH …]` where evidence-backed) — do not scatter design rationale into PLAN or README.
- **Freshly gathered research consolidates into RESEARCH.md** (with a Sources row), and is cited by key from the doc that acts on it; never inline a new source table elsewhere.
- Cross-references use section names / `RESEARCH:`-key citations so the docs stay a single connected graph.

---

## Guiding constraints (apply to every phase)

- **Correctness gate = conformance.** The distribution-spec ships a conformance suite (`spec/distribution-spec/conformance/`) across four categories: **Pull**, **Push**, **Content Discovery**, **Content Management**. A phase is "done" only when its category passes.
- **Footprint discipline.** Single static binary. No mandatory external DB or service. Streaming I/O — never buffer a full blob in memory. Bounded, configurable memory ceilings. Async runtime with a small, fixed worker pool.
- **Algorithmic smartness.** Content-addressable storage with O(1) blob lookup by digest; deduplication is free (same digest → same file). Index structures chosen for the query, not convenience. Zero-copy blob serving (`sendfile`/`mmap`) where the OS permits.
- **Clean seams.** Core dist-spec is a crate that knows nothing about extensions. Storage, auth, and extensions are traits behind the core. This is what makes "clear separation" real rather than aspirational.
- **Verification per phase:** conformance category + targeted unit/integration tests + a real-client smoke test (`skopeo copy`, `crane`, `oras`) against the running binary.

---

## Phase 0 — Foundations & skeleton

**Goal:** a binary that boots, serves `/v2/` (end-1 → `200`), and has the architectural seams in place. No storage yet.

- [x] Workspace layout: `roci-core` (HTTP + protocol), `roci-storage` (`Storage` + `MetadataStore` traits + local backend), `roci-config`, `roci-telemetry`, `roci-cli` (binary). Extension + `roci-cluster` crates added later.
- [ ] HTTP stack (axum/hyper or equivalent), **HTTP/2 multiplexing + keep-alive** with HTTP/1.1 fallback; async runtime; graceful shutdown. Pin `hyper` past CVE-2023-44487 (Rapid Reset).
- [x] **OpenTelemetry spine from day one** — `tracing` + `tracing-opentelemetry`, OTel SDK wired at startup. Every request handler is a span; logs are structured events on the trace. Console/no-op exporter for now (OTLP export lands in Phase 4). Footprint note: OTel behind a cargo feature so a minimal build can compile it out; sampling configurable and default-cheap.
- [x] `Digest` type: parse/validate `algorithm:hex`, constant-time compare, **wire allowlist = sha256/sha512 only** (reject SHA-1/unregistered → `DIGEST_INVALID`; BLAKE3 internal-only). Load-bearing — every subsystem keys off it. (SECURITY §Storage boundary.)
- [x] `RepositoryName` + `Reference` types enforcing spec grammars (name ≤255, tag ≤128) **before any filesystem path is constructed**, plus a `Storage`-layer backstop rejecting `..`/`.`/`NUL` components (SECURITY inv. 8; path-traversal CVE class).
- [ ] **Bounded-input guards:** manifest size cap (≤4 MiB) + JSON recursion-depth cap before parse; `n`/pagination caps on list endpoints; wired read/write timeouts + per-method rate limits (SECURITY inv. 14; CVE-2023-2253 class).
- [x] Error model → JSON `{ "errors": [{code,message,detail}] }` with all 14 codes as an enum; correct HTTP status mapping.
- [x] `GET /v2/` (end-1) returns `200`.
- [x] Config skeleton: zero-config defaults, single declarative file (format TBD — likely TOML/YAML), storage root path.

**Correctness gate:** `GET /v2/` returns `200`; malformed name/reference/digest rejected with correct code before any handler logic; a request emits one root span with structured log events attached.

---

## Phase 1 — Pull (read path) + storage core

**Goal:** serve a pre-populated OCI image layout as a registry. **Pull conformance passes.** This is the MUST-support minimum for any conforming registry.

- [ ] **`Storage` trait** (read surface): `blob_read`/`blob_stat`, `manifest_read`, existence checks; blob path = pure function of a validated digest → O(1) `open`.
- [ ] **`MetadataStore` trait** — default backend: append-only WAL + in-RAM maps (tag→digest, subject→referrers), rebuildable from the layout; read/resolve surface first (write in Phase 2). Embedded B-tree KV (heed/redb) is the feature-gated upgrade (bake-off in cross-cutting).
- [ ] **Existence filters:** cuckoo (mutable) + BinaryFuse8 (static) front the "present?" hot path so HEAD/dedup checks stay off disk; a filter hit is never the sole authority for `200` (membership checked — SECURITY inv. 10).
- [ ] **Small-blob LRU content cache** (<100 KB, capped): serve manifests/configs with zero syscall; miss → loose file. Keyed by `(repo, digest)` for cross-repo isolation.
- [ ] **Local backend on OCI image layout** ([`image-layout.md`](spec/image-spec/image-layout.md)): `blobs/<alg>/<hex>` CAS (default new digests `sha512`); `index.json` + `oci-layout`. Serve **any pre-existing OCI layout**, incl. **foreign media-type blobs** (Nydus/eStargz/SBOM/sig) as opaque bytes.
- [ ] `GET`/`HEAD /v2/<name>/blobs/<digest>` (end-2) — zero-copy `sendfile` (kTLS `SSL_sendfile` under HTTPS) + `fadvise` hints, `Docker-Content-Digest`+`Content-Length`, `404` on miss.
- [ ] `GET`/`HEAD /v2/<name>/manifests/<reference>` (end-3) — `Accept` negotiation, correct `Content-Type`, digest header. **Cache-control split:** by-digest → `ETag`+`immutable`+`If-None-Match`→`304`; by-tag → `no-cache` (SECURITY §HTTP boundary).
- [ ] **`Range` request support** (RFC 9110) for resumable + lazy-pull (eStargz/SOCI) partial reads.
- [ ] "Serve any OCI layout as a registry" verified: point roci at an existing layout dir, pull with skopeo.

**Correctness gate:** **Pull** conformance category passes. Smoke: `skopeo copy` *from* roci succeeds; digest verification on client matches.

---

## Phase 2 — Push (write path) + upload sessions

**Goal:** accept pushes. **Push conformance passes.** Round-trip: push then pull an identical image.

- [ ] Extend `Storage`/`MetadataStore`: `blob_write`, staged uploads, `manifest_put`, `tag_set`, **WAL append (group-commit)** for tag/backref writes.
- [ ] **Upload session manager** — the algorithmically interesting part:
  - [ ] `POST /v2/<name>/blobs/uploads/` (end-4a) → `202` + `Location` (server-generated UUID; validated before any path use — SECURITY inv. 8).
  - [ ] `PATCH …/blobs/uploads/<ref>` (end-5) — chunked upload, `Content-Range`, `416` on gap. Stream into an **`O_TMPFILE` staging inode** (namespace-invisible → no orphan temp, no TOCTOU); **per-session size cap** (`413`/`SIZE_INVALID`).
  - [ ] `PUT …/blobs/uploads/<ref>?digest=` (end-6) — finalize: **hash-on-write, verify digest BEFORE `linkat(AT_EMPTY_PATH)` promotes into CAS** (`DIGEST_INVALID`/`SIZE_INVALID`); `EEXIST` on link = dedup signal.
  - [ ] `GET …/blobs/uploads/<ref>` (end-13) — upload status → `204` + range.
  - [ ] Monolithic single-`POST` (end-4b) and POST-then-PUT paths.
- [ ] `PUT /v2/<name>/manifests/<reference>` (end-7) — size cap + bounded JSON parse (depth/dup-key), referenced-blob existence (`MANIFEST_BLOB_UNKNOWN`), **`Content-Type`↔`mediaType` agreement** (CVE-2021-41190), accept `subject` referencing absent manifest; updates tag + referrers + **backref** in one atomic WAL record.
- [ ] **Deduplication = reflink (`FICLONE`), hard-link fallback** — independent deletion, no write-through-shared-inode hazard; intra-path dedup is free (same digest → same file), extended across paths/repos. `open` with `O_NOFOLLOW`/`openat2 RESOLVE_BENEATH`.
- [ ] Cross-repo **blob mount** (end-11) → `201` via `copy_file_range` (btrfs/XFS O(1); no read+write roundtrip) when source has it, else `202`. (Double-authz enforced in Phase 6.)
- [ ] Crash-safety: `O_TMPFILE`+`linkat` + atomic WAL so an interrupted push never corrupts the CAS or desyncs the index.

**Correctness gate:** **Push** conformance passes. Smoke: `skopeo copy` *to* roci, then pull back → byte-identical. Resumable push (interrupt mid-chunk, resume) works.

---

## Phase 3 — Content Discovery + Content Management + Referrers

**Goal:** listing, deletion, and the referrers API. **Discovery + Management conformance pass.** Completes core dist-spec conformance.

- [ ] `GET /v2/<name>/tags/list` (end-8a) + paginated `?n=&last=` (end-8b) — lexical order, stable cursor, **server-side `n` cap** (SECURITY inv. 14; CVE-2023-2253 class), O(log n) `last` seek.
- [ ] `DELETE /v2/<name>/manifests/<reference>` (end-9) — `202`; deletion by tag and by digest. **All delete paths (blob/tag/referrer) pass one `can_delete()` guard** so `delete.enabled=false` can't be bypassed (CVE-2026-41888).
- [ ] `DELETE /v2/<name>/blobs/<digest>` (end-10) — `202`; `405`/`400` when deletion disabled (via the shared guard).
- [ ] **`index.json` write-behind** — tag/delete mutations update in-RAM maps + WAL immediately; the spec-visible `index.json` is rewritten by a coalescing background task (atomic `O_TMPFILE`+`linkat`), never per-op.
- [ ] **Referrers API** `GET /v2/<name>/referrers/<digest>` (end-12a) + `?artifactType=` (end-12b):
  - [ ] Maintain a **subject → referrers reverse index** (in the MetadataStore) updated on every manifest put/delete → O(1) read, not a repo scan. **This index is also the lazy-pull metadata backbone** (SOCI index / Nydus zran meta stored as referrers).
  - [ ] Return image index of referrers; `artifactType` filter sets `OCI-Filters-Applied`; **paginate + cap referrers-list size** (GHSA-259w-8hf6-59bj amplification); `Vary` on filtered responses.
  - [ ] Referrers-tag-schema fallback (`<alg>-<ref>` tag).
- [ ] Enable-referrers upgrade semantics (include preexisting subject manifests).

**Correctness gate:** **all four** conformance categories pass. roci is now a conformant OCI registry. Smoke: `oras` push/discover artifacts; `crane` referrers.

---

## Phase 4 — Configuration & operability baseline

**Goal:** make behavior fully config-driven and observable end-to-end. No new protocol surface; hardening the core into something deployable.

- [ ] Full config schema, validated on load with clear errors: storage root(s) + **subpaths/multi-backend**, `dedupe`, `gc`/`gcDelay`/`gcInterval`/`gcTimeWindow`, `commit` (→ `fdatasync`), `fastRestart` stamp, **2-level fanout threshold**, `small_blob_threshold` + cache cap, `redirect_min_size`, per-repo/total **quota**, size/`n` caps, listen addr, log level, feature toggles.
- [ ] **TLS** termination (server certs), **TLS 1.3 (0-RTT resumption)**; optional **kTLS + `SSL_sendfile`** (runtime-detected, silent rustls fallback, fallback is an alertable metric).
- [ ] **Rate limiting**, including **per-HTTP-method** limits (`TOOMANYREQUESTS`). Token-bucket, bounded memory.
- [ ] **Footprint knobs:** pin a low-fragmentation allocator (jemalloc/mimalloc); `rkyv` mmap snapshot toggle for constrained/edge; document ext4 `bigalloc` for manifest-dense deployments.
- [ ] **OpenTelemetry telemetry pipeline** — mature the Phase 0 spine into full three-signal export: traces + metrics + logs over **OTLP** (gRPC + HTTP), semantic-convention attributes, configurable exporter/sampler/batching. Per-request **root span + child spans** (authz → meta.resolve → blob.open → blob.stream; push: upload.session → digest.verify → cas.link → meta.append), W3C `traceparent` propagation across storage, extensions, and the cluster peer-proxy hop; background sweeps as linked root traces. **Tail-based sampling keeps all error/high-latency traces** at low default head-sampling (target <~2% overhead). Design: ARCHITECTURE §Observability.
- [ ] **Metrics via the OTel meter provider** — RED request metrics + storage/MetadataStore (incl. `wal.group_commit.batch_size`, `index.rss_bytes`)/GC/scrub/upload/cluster instruments defined once; **Prometheus `/metrics` is a scrape view over the same meters** (one source, two exports). **Cardinality caps enforced by construction:** digests/tags/repos/UUIDs are span attributes/log fields, never metric labels — labels drawn from the fixed set (`endpoint`,`method`,`status_class`,`error_code`,`backend`,`result`).
- [ ] **Error observability** — the 14 dist-spec error codes are the single vocabulary across signals: spec JSON body on the wire, `registry.request.errors{error_code}` counter, root span `ERROR` + `error.type=<code>` with the failing child span localizing the cause, one structured log event on the span (correlated by `trace_id`); 4xx client faults vs 5xx internal faults alerted separately; credentials redacted.
- [ ] Rootless verified (no privileged ports/paths required).
- [ ] Multi-OS/arch release builds (Linux/macOS, amd64/arm64), static where possible.

**Correctness gate:** config round-trips; TLS handshake with skopeo; traces land in an OTLP collector (Jaeger/Tempo) with spans linked across a full push; the same metrics scrape parses in Prometheus; rate limit returns `TOOMANYREQUESTS` under load.

---

## Phase 5 — Storage subsystem maturity

**Goal:** the "inline storage optimizations" from the feature set. Where algorithmic smartness earns its keep.

- [ ] **Garbage collection — online, O(garbage), grace-period.** Live **backref multimap `blob_digest → {manifest_digests}`** in the MetadataStore → collect the instant a backref set empties AND `gcDelay` elapses AND not pinned by an in-flight upload; never offline; full mark-sweep only as cold-start/rebuild backstop. Startup consistency check before GC is enabled.
- [ ] **Deduplication maturity: reflink (`FICLONE`) across paths/repos**, hard-link fallback (logged); dedupe cache `digest→location`. Sub-chunk (**FastCDC**) dedup deferred to `roci-ext-dedup` (Phase 7/future).
- [ ] **Data scrubbing — CRC32C-on-write + staggered/adaptive**, escalate to full SHA/BLAKE3 re-hash only on mismatch; delegate to **btrfs/ZFS scrub** where available (disable app pass). Not a blanket periodic re-hash.
- [ ] **rkyv mmap snapshot** of the metadata index — O(1) cold start + ~10× lower RSS at scale (large/HDD/edge); optional **WAL HMAC** for the compromised-storage-volume threat (SECURITY §Storage boundary).
- [ ] **Storage quotas** — per-repo/per-total byte caps enforced at blob finalize (`507`/`413`); concurrent-upload-session cap.
- [ ] **Index engine upgrade path** — feature-gated embedded B-tree KV (heed/LMDB or redb) for out-of-RAM metadata / shared cluster store; default stays append-log + maps (bake-off decides, cross-cutting).
- [ ] **Multiple storage paths / backends** from one server — routing over the `Storage` trait; per-repo/per-prefix selection. Prove the trait with a second backend (S3-compatible, with `redirect_min_size` + parallel-multipart server-side copy). Accept + serve **`tar+zstd`** layers natively (no recompression).

**Correctness gate:** GC removes only unreferenced blobs and is O(garbage) not O(total) (property test: reachable set preserved under concurrent push); scrub detects an injected corruption via CRC32C; reflink dedup shares extents with independent deletion; quota returns `507`/`413` at the cap; rkyv snapshot gives O(1) cold start; conformance still green.

---

## Phase 6 — Security & access control

**Goal:** the full auth matrix.

- [ ] **HTTP Basic** — local htpasswd (bcrypt).
- [ ] **HTTP Basic** — LDAP bind.
- [ ] **HTTP Bearer token** (Docker v2 token scheme — WWW-Authenticate challenge → repo-scoped token; see [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md)).
- [ ] **TLS mutual authentication** (client cert verification).
- [ ] **Identity-Based Access Control** — per-identity repo/action policies.
- [ ] **Live authorization reload** — reload authz config on file change while running, without restart or dropping connections.
- [ ] **Cross-repo mount double-authz** — `end-11` checks pull on `from` AND push on dest (SECURITY §HTTP boundary; Harbor GHSA-r4cx-r72v-m728).
- [ ] **307 redirect + sync SSRF containment** — repo-membership-gated, host-allowlisted, short-TTL signed URLs; sync upstream URL validation + no `accept_invalid_certs` (SECURITY §HTTP boundary).
- [ ] **TLS/0-RTT hardening** — `425 Too Early` on non-idempotent early-data; mTLS peer CA/pinning; kTLS-fallback alert (SECURITY §HTTP boundary).

**Correctness gate:** each auth mode gates `401`/`403` correctly (`UNAUTHORIZED`/`DENIED`); anonymous pull vs. authenticated push enforced; live authz change takes effect without restart; conformance passes under an auth-enabled profile.

---

## Phase 7 — Extensions

**Goal:** zot-parity feature extensions, each behind the core/extension seam, independently compilable.

- [ ] **Search extension** — advanced image queries (GraphQL, zot-compatible schema) over the metadata index (same embedded B-tree class, binary-fuse filters); fast filtered lookups, never storage scans.
- [ ] **Signatures** — cosign and notation: store/serve signature manifests via referrers; verification hooks (policy MAY require valid signatures).
- [ ] **BLAKE3 Bao verified-streaming** — build/store a Bao tree as an OCI referrer so clients verify individual `Range` chunks without fetching whole blobs (lazy-pull integrity). BLAKE3 stays internal; wire/descriptor digests remain sha256/sha512.
- [ ] **Lazy-pull origin readiness** — eStargz/SOCI need only Range + digest-verified referrer metadata (already in Phases 1/3); verify roci serves as a good origin (concurrent-small-Range benchmark in cross-cutting). No in-registry P2P.
- [ ] **Helm chart** support (Helm OCI artifact media types — falls out of foreign-media-type handling; verify with `helm push`/`pull`).
- [ ] **Vulnerability scanning** — Trivy integration; serve/store SBOMs (SPDX/CycloneDX) as referrers; vuln-DB refresh on the background scheduler.
- [ ] **Sync** — pull-and-synchronize from other dist-spec registries (periodic + on-demand); upstream URL + TLS validation (SECURITY §HTTP boundary).
- [ ] **Node exporter** mode for minimal builds (metrics without full server).
- [ ] **Swagger/OpenAPI** documentation generation.
- [ ] **Future extensions:** `roci-ext-dedup` (FastCDC sub-chunk dedup); `roci-ext-coldstore` (packed cold tier for 100M+ dormant manifests, interop out of scope). Tracked, not baseline.

**Correctness gate:** each extension has its own integration test + ecosystem-tool smoke (cosign verify, notation verify, helm pull, trivy scan, sync from a second registry); disabling an extension leaves core conformance intact.

---

## Phase 8 — Scale-out clustering (horizontal)

**Goal:** share load across a cluster of roci instances. Vertical scale (efficient scale-up on one box) is a continuous property of the core, tracked from Phase 1; this phase adds horizontal scale-out. Design: [`ARCHITECTURE.md`](ARCHITECTURE.md) "Scaling", reverse-engineered from [zot scale-out](https://zotregistry.dev/v2.1.21/articles/scaleout/). Depends on remote storage (Phase 5) and mTLS (Phase 6).

- [ ] `roci-cluster` feature crate: hash ring over configured `members`, **SipHash** on repo path → owning instance.
- [ ] **Repo sharding** — each repo owned/served/written by exactly one instance; single-writer invariant enforced.
- [ ] **Peer proxy** — receiver forwards to owner and proxies response; any instance is a valid entry point. mTLS between peers.
- [ ] `cluster` config section: ordered `members` (identical order per instance), `hashKey`, peer TLS.
- [ ] **Compute-only topology** — shared S3 backend + shared cache (Redis/DynamoDB-style, `remoteCache`), no per-instance local cache.
- [ ] **Compute + storage topology** — cache/storage local per instance, each owning its shards.
- [ ] Shared session store (external Redis-compatible) for UI/CLI across instances; sticky-LB fallback documented.

**Correctness gate:** a 3-instance cluster serves push/pull for any repo through any entry point (owner + non-owner proxy paths); repo ownership is stable under the hash ring; conformance passes against the cluster front. **Explicitly not HA** — instance/storage loss degrades the affected shard (documented, tested as expected behavior).

---

## Sequencing rationale

- **Phases 1→3 are the spine** — a conformant registry. Everything else is optional per the spec. Ship nothing else until all four conformance categories are green.
- **Read before write (1→2)** so the storage model and CAS invariants are proven on the simpler path first.
- **Referrers (3) after push (2)** because the reverse index depends on the manifest write path.
- **Ops/config (4) before storage maturity (5)** so GC/scrub run against a real, observable, rate-limited server.
- **Auth (6) after storage (5)** — auth wraps a subsystem that already behaves correctly; testing auth against a flaky core wastes effort.
- **Extensions (7) last** — they consume the stable core/storage/auth seams and must never be able to break core conformance.
- **Clustering (8) after storage + auth** — scale-out needs shared/remote storage (5) and peer mTLS (6) as prerequisites; it shares load, not a substitute for a correct single node.

## Cross-cutting, continuous

- [ ] Conformance suite in CI, run every phase — never regresses.
- [ ] Property tests for storage invariants (CAS, GC reachability, dedup).
- [ ] Benchmarks tracked from Phase 1: pull/push throughput, query latency, RSS baseline, cold-start time. **Vertical scale** (throughput/RSS scaling with cores/RAM on one box) is a tracked metric, not a hope.
- [ ] **Memory-scaling benchmark (from ARCHITECTURE §RAM consumption):** assert RSS scales with reference count, not stored bytes — measure RSS at 1M/10M refs (target ~130 MB/1.3 GB heap, ~10× less with the rkyv mmap snapshot), confirm RSS is flat while blob-corpus size grows, and run a 24 h push/pull **soak** to catch allocator fragmentation creep (validates the jemalloc/mimalloc choice).
- [ ] **HTTP roundtrip benchmark (from ARCHITECTURE §HTTP roundtrip efficiency):** measure real `docker pull`/`skopeo copy` roundtrip counts and wall-clock — assert warm re-pull collapses to `304`s over one kept-alive connection, cold multi-layer pull uses HTTP/2-multiplexed parallel blob streams, `HEAD` is body-free/syscall-free, and per-request manifest/HEAD latency stays O(1) as the corpus grows.
- [ ] **Index-engine bake-off (Phase 1 deliverable, from RESEARCH §8.6):** benchmark **heed/LMDB vs redb** on roci's real access pattern (tag lookup, referrer range-scan, existence check) to settle the default; LMDB is predicted ~1.8–3× faster on reads / 35% smaller, redb is the pure-Rust/musl fallback.
- [ ] **Instrument as you build** — every new subsystem (storage, upload sessions, referrers index, GC, auth, extensions) adds spans + OTel instruments in the same PR that adds the code, not retrofitted. Telemetry overhead stays on the benchmark dashboard so instrumentation never silently costs footprint.
- [ ] Fuzzing on manifest/digest/reference parsers (untrusted input boundary).
- [ ] **Security regression suite (from SECURITY §Tracked prior-art CVE classes):** one test per tracked class — path-traversal via `name`/`reference`/`upload-id`; wire non-`sha256/512` digest rejected; cross-repo mount without source authz denied; cross-repo presence/content oracle (HEAD/GET returns 404 for a globally-present blob absent from the repo); manifest size/`n`/depth caps; mutable-tag not cached immutable; single `can_delete()` guard; 0-RTT `425` on non-idempotent. Each fails pre-control, passes post-control.
- [ ] **Symlink/traversal backstop test:** `openat2 RESOLVE_BENEATH`/`O_NOFOLLOW` on all digest-derived opens; property test that path construction can never emit `/`, `..`, or `NUL` from a validated digest/name.
