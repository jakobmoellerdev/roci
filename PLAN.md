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
- [x] HTTP stack: axum on a `hyper-util` auto connection builder — **HTTP/2 multiplexing** (h2c prior-knowledge plaintext, ALPN `h2` under TLS; `max_concurrent_streams = 256`) + HTTP/1.1 keep-alive fallback; header-read and idle timeouts; graceful shutdown drains in-flight connections. `hyper` 1.x (past CVE-2023-44487 Rapid Reset).
- [x] **OpenTelemetry spine from day one** — `tracing` + `tracing-opentelemetry`, OTel SDK wired at startup. Every request handler is a span; logs are structured events on the trace. Console/no-op exporter for now (OTLP export lands in Phase 4). Footprint note: OTel behind a cargo feature so a minimal build can compile it out; sampling configurable and default-cheap.
- [x] `Digest` type: parse/validate `algorithm:hex`, constant-time compare, **wire allowlist = sha256/sha512 only** (reject SHA-1/unregistered → `DIGEST_INVALID`; BLAKE3 internal-only). Load-bearing — every subsystem keys off it. (SECURITY §Storage boundary.)
- [x] `RepositoryName` + `Reference` types enforcing spec grammars (name ≤255, tag ≤128) **before any filesystem path is constructed**, plus a `Storage`-layer backstop rejecting `..`/`.`/`NUL` components (SECURITY inv. 8; path-traversal CVE class).
- [x] **Bounded-input guards:** manifest size cap (≤4 MiB) + JSON recursion-depth cap before parse; `n`/pagination caps on list endpoints; wired read/write timeouts + per-method rate limits (SECURITY inv. 14; CVE-2023-2253 class). *(Timeouts/rate limits/config-driven caps completed in Phase 4.)*
- [x] Error model → JSON `{ "errors": [{code,message,detail}] }` with all 14 codes as an enum; correct HTTP status mapping.
- [x] `GET /v2/` (end-1) returns `200`.
- [x] Config skeleton: zero-config defaults, single declarative file (format TBD — likely TOML/YAML), storage root path.

**Correctness gate:** `GET /v2/` returns `200`; malformed name/reference/digest rejected with correct code before any handler logic; a request emits one root span with structured log events attached.

---

## Phase 1 — Pull (read path) + storage core

**Goal:** serve a pre-populated OCI image layout as a registry. **Pull conformance passes.** This is the MUST-support minimum for any conforming registry.

- [x] **`Storage` trait** (read surface): `read_blob`/`blob_size`/`open_blob`, `get_manifest`, existence checks; blob path = pure function of a validated digest → O(1) `open`.
- [x] **`MetadataStore` trait** — default backend `LogMetadataStore`: append-only CRC32C-framed `roci-meta.log` + in-RAM maps (tag→digest, digest→media_type, subject→referrers), replayed on startup and seeded from `index.json` for repos the log does not cover; reads resolve against it first and fall back to `index.json` (the layout stays the source of truth). **In-RAM maps are the adopted backend up to ~2–4M references (≈0.5–1 GB heap)** — *[refined from RESEARCH §9.6, first-party benchmark]* below that band in-RAM is smaller *and* 3–6.5× faster than a KV, so map-to-disk would be a regression. *(Deferred behind this trait seam, each past its measured threshold: WAL group-commit §9.3; rkyv mmap snapshot §9.4 as the first RSS lever at the ~2–4M band; embedded redb KV §8.6 only at ≥~10M refs / hard RAM cap / shared-cluster store, where its RSS is evictable page cache instead of unbounded heap.)*
- [x] **Existence filter:** cuckoo (mutable) blob-presence filter fronts the "present?" hot path — a definite-absent answer returns `404` with zero syscalls; a "maybe" always verifies on disk (never the sole authority — SECURITY inv. 10). Seeded from the CAS walk at startup + maintained on put/delete; a full-filter insert fails open (disable → no false negatives). *(BinaryFuse8 static referrer filter deferred: referrer sets are served from the in-RAM metadata map, so a filter over them pays only once referrers move behind the KV upgrade — RESEARCH §8.5.)*
- [x] **Small-blob LRU content cache** (≤100 KB, byte-capped): serves manifests/configs from RAM with zero syscalls; miss → loose file (never the sole copy). Keyed by `(repo, digest)` for cross-repo isolation; warmed on put/read, invalidated on delete, LRU-evicted to a byte budget.
- [x] **Local backend on OCI image layout** ([`image-layout.md`](spec/image-spec/image-layout.md)): `blobs/<alg>/<hex>` CAS (manifests are blobs); `index.json` (source of truth for tags/media-types/subject relation, tags via `org.opencontainers.image.ref.name`) + `oci-layout`. Serves **any pre-existing OCI layout**, incl. **foreign media-type blobs** (unknown descriptors preserved on read-modify-write). One image-layout root per repository.
- [x] `GET`/`HEAD /v2/<name>/blobs/<digest>` (end-2) — streamed via `open_blob` + `BlobRead::into_stream`: 256 KiB reads on the blocking pool with one chunk of read-ahead (no whole-blob buffering; a truncated file fails the body instead of ending it short). *(`sendfile`/`fadvise`/kTLS remain later optimizations — `sendfile` needs a roci-owned HTTP/1.1 body writer, since hyper owns the socket; ARCHITECTURE §Vertical scale.)* `Docker-Content-Digest`+`Content-Length`, `404` on miss.
- [x] `GET`/`HEAD /v2/<name>/manifests/<reference>` (end-3) — `Accept` read (advisory; stored `Content-Type` always returned), digest header. **Cache-control split:** by-digest → `ETag`+`immutable`+`If-None-Match`→`304`; by-tag → `no-cache` + `ETag` revalidation (SECURITY §HTTP boundary).
- [x] **`Range` request support** (RFC 9110): single-range `bytes=start-end`/`start-`/`-suffix` → `206`+`Content-Range`; unsatisfiable → `416`; malformed/multi-range ignored → full `200`; `Accept-Ranges: bytes` always advertised.
- [x] "Serve any OCI layout as a registry" verified: `FsStorage` reads a pre-existing `<repo>/{oci-layout,index.json,blobs/}` lazily (test `serves_external_oci_layout`).

**Correctness gate:** **Pull** conformance category passes. Smoke: `skopeo copy` *from* roci succeeds; digest verification on client matches.

---

## Phase 2 — Push (write path) + upload sessions

**Goal:** accept pushes. **Push conformance passes.** Round-trip: push then pull an identical image.

- [x] Extend `Storage`/`MetadataStore`: staged uploads, `put_manifest`, tag set, a `blob → manifests` **backref index** maintained on manifest put/delete, and **WAL group-commit** — the append (buffered write + flush + in-RAM apply) runs under the fast state lock while the durability `fdatasync` is coalesced behind a separate barrier, so N appends piled up during one in-flight sync share it.
- [x] **Upload session manager:**
  - [x] `POST /v2/<name>/blobs/uploads/` (end-4a) → `202` + `Location` with a **server-generated random 128-bit id** (validated by the `SafeComponent` backstop before any path use — SECURITY inv. 8; replaces the old pid-counter scheme).
  - [x] `PATCH …/blobs/uploads/<ref>` (end-5) — chunked upload, `Content-Range`, `416` on gap; **per-session size cap** (`413`/`SIZE_INVALID`, `MAX_UPLOAD` = 5 GiB), re-checked inside the finalize lock so a preempted over-cap PATCH cannot be promoted by a racing PUT. Staging is a named `uploads/<id>` file (resumable across requests) opened **`O_NOFOLLOW`** so a planted symlink cannot redirect an append; a per-session lock serializes append/finish/abort.
  - [x] **Streamed bodies** — every upload body (PATCH, finalizing PUT, monolithic POST) is written to the staging file frame-by-frame in 1 MiB batches on the blocking pool, never buffered whole (invariant 4); a failed/over-limit body truncates the staging file back so the session is unchanged. **Hash-on-write:** sha256 + CRC32C are computed as bytes land and kept with the session lock; finalize uses them when they cover the whole file, else (restart, sha512) re-hashes the staged file.
  - [x] `PUT …/blobs/uploads/<ref>?digest=` (end-6) — finalize: **verify the digest (hash-on-write or a stream re-hash), `fdatasync` when `storage.commit`, then atomically `rename` in place** into the CAS, syncing the CAS directory (and the layout marker/parents on first create) so a blob-only repo survives a crash. The monolithic `put_blob` promotes via **`O_TMPFILE`+`linkat`** on Linux (anonymous inode → write → `fsync` → `linkat`; `EEXIST` = content-addressed dedup), a per-op unique-temp + `fsync` + `rename` elsewhere.
  - [x] `GET …/blobs/uploads/<ref>` (end-13) — upload status → `204` + range.
  - [x] Monolithic single-`POST` (end-4b) — streamed through a short-lived session (begin → stream → finalize; aborted on any failure) — and POST-then-PUT paths.
- [x] `PUT /v2/<name>/manifests/<reference>` (end-7) — size cap + bounded JSON parse (depth), **referenced-blob existence** (config + layers → `MANIFEST_BLOB_UNKNOWN`; a config/layer descriptor present but malformed → `MANIFEST_INVALID`), **`Content-Type`↔`mediaType` agreement** (CVE-2021-41190 → `MANIFEST_INVALID`), accepts a `subject` referencing an absent manifest; records the tag, referrers, and **backref** edges (config + layers + image-index children + subject). *(The backref index is a derived, rebuildable cache populated only from the metadata log — Phase 5 GC rebuilds/validates it from the layout before consuming it; a failed backref append is non-fatal to the push. Single-atomic-WAL-record coupling of tag+referrers+backref deferred.)*
- [x] **Deduplication:** cross-path/-repo dedup promotes in contract order — **reflink (`FICLONE`, CoW, independent deletion) first**, then `std::fs::hard_link` (O(1) same-fs), then a `tokio` **streaming copy** (cross-device / no-hardlink), so a valid mount across devices/filesystems always completes (never a spurious `202`). The reflink/copy land in a unique temp with `fsync` + `rename` (never a partial blob under the digest). Intra-path dedup is free (same digest → same CAS file). An existing mount destination is validated **beneath-root, no-follow** as a regular file before it counts as an idempotent `201`, and a same-repo (`src == dest`) mount short-circuits.
- [x] Cross-repo **blob mount** (end-11) → `201` via the hard-link/reflink/copy path above (no read+write roundtrip), else falls through to a `202` session. *(Double-authz in Phase 6.)*
- [x] Crash-safety: `O_TMPFILE`+`linkat` (monolithic) or fsync-then-atomic-`rename` (chunked/mount), each with a containing-directory `fsync`, so an interrupted push never leaves a corrupt-but-named blob — a torn write stays under `uploads/` and is discarded. *(Single-record atomic WAL coupling of tag+referrers+backref deferred to Phase 5.)*

**Correctness gate:** **Push** conformance passes. Smoke: `skopeo copy` *to* roci, then pull back → byte-identical. Resumable push (interrupt mid-chunk, resume) works.

---

## Phase 3 — Content Discovery + Content Management + Referrers

**Goal:** listing, deletion, and the referrers API. **Discovery + Management conformance pass.** Completes core dist-spec conformance.

- [x] `GET /v2/<name>/tags/list` (end-8a) + paginated `?n=&last=` (end-8b) — lexical order, stable cursor, **server-side `n` cap** (SECURITY inv. 14; CVE-2023-2253 class), RFC 5988 `Link: <…?n=&last=<last served>>; rel="next"` when truncated. **Paged in storage:** `Storage::list_tags(repo, last, limit)` seeks a per-repo sorted tag map (O(log n) + page), so per-request work is bounded by the page, not the repo; a `last` that is not (or no longer) a tag resumes lexically after it (end-8b).
- [x] `DELETE /v2/<name>/manifests/<reference>` (end-9) — `202`; deletion by tag and by digest. **All delete paths (blob/manifest-by-tag/manifest-by-digest) pass one `AppState::can_delete()` guard** so `delete.enabled=false` (config `delete.enabled`, default `true`) can't be bypassed (CVE-2026-41888) → `405 UNSUPPORTED`.
- [x] `DELETE /v2/<name>/blobs/<digest>` (end-10) — `202`; `405` when deletion disabled (via the shared guard).
- [x] **`index.json` write-behind** — manifest put/delete and referrer mutations update in-RAM maps + WAL immediately and bump a per-repo dirty generation; a coalescing background task rebuilds `index.json` from the metadata store merged over the on-disk index (foreign descriptors preserved) and replaces it atomically (unique tmp + `rename` + dir `fsync`), clearing the entry only if no newer mutation raced it. Reads through roci of a dirty repo derive the current index in memory; external tools see an eventually-current, always-valid layout. *(`O_TMPFILE`+`linkat` for the index file deferred; the tmp+rename sequence is equally crash-safe.)*
- [x] **Referrers API** `GET /v2/<name>/referrers/<digest>` (end-12a) + `?artifactType=` (end-12b):
  - [x] **subject → referrers reverse index** in the MetadataStore, updated on manifest put/delete → O(1) read, not a repo scan. **Also the lazy-pull metadata backbone** (SOCI index / Nydus zran meta stored as referrers).
  - [x] Image index of referrers; `artifactType` filter sets `OCI-Filters-Applied` + `Vary: Accept`; **cursor pagination** `?n=&last=` with `Link` (filter carried into the next link), page capped at `MAX_PAGE`; `Storage::list_referrers(repo, subject, artifactType, last, limit)` seeks a digest-ordered per-subject index (plus a per-`artifactType` index for filtered pages), so lookup, copy and parse work are all bounded by the page (GHSA-259w-8hf6-59bj amplification). Layout fallbacks (`index.json` scan, tag schema) page the document they already read with the same order/cursor/filter semantics.
  - [x] Referrers-tag-schema fallback (`<alg>-<ref>` tag → its image index's `manifests`, de-duplicated; malformed → empty).
- [x] Enable-referrers upgrade semantics: `FsStorage::warm_referrers_from_layout` (run by `serve` before accepting requests) registers every pre-existing `index.json` descriptor carrying `subject` in the metadata store; idempotent. `FsStorage::reconcile_index_json` (also run by `serve`) rebuilds any repo whose `index.json` lags the replayed WAL (crash between WAL append and background rename) and imports tags from externally written layouts so rebuilds never drop them. `FsStorage::new` needs no Tokio runtime (the writer starts only when one is present).

**Correctness gate:** **all four** conformance categories pass (`just conformance`: 75 passed, 0 failed; the 4 skips are the suite's mutually exclusive branches — pre-seeded-registry setup, 202-mount fallback, auto-crossmount enabled). roci is now a conformant OCI registry. Smoke: `oras` push/discover artifacts; `crane` referrers.

---

## Phase 4 — Configuration & operability baseline

**Goal:** make behavior fully config-driven and observable end-to-end. No new protocol surface; hardening the core into something deployable.

- [x] Full config schema — one **TOML** file (`roci --config <path>`; absent → zero-config defaults), sections `[http]` (listen, `tls`, `timeouts`, `rate_limit`), `[storage]` (root, `cache_max_bytes`), `[limits]` (`max_body`/`max_upload`/`max_manifest`/`max_page`), `[delete]`, `[log]` (level, text/json), `[telemetry]` (OTLP, `sample_ratio`, Prometheus `metrics`); unknown keys rejected, cross-field validation on load with field-qualified errors; `--listen`/`--storage-root` override the file. Every former hardcoded cap (`MAX_BODY`/`MAX_UPLOAD`/`MAX_MANIFEST`/`MAX_PAGE`, cache capacity) is config-driven. *(Phase 5 added `storage.{dedupe,s3,subpaths,gc,scrub,quota,metadata}` with their subsystems; `storage.commit` (default `false`, zot's default: blob data + its publishing dir entry are fsynced only when `true`; manifests, WAL, `index.json` and the layout marker are always synced) landed with the comparative benchmark; `fastRestart`, the 2-level fanout threshold and `small_blob_threshold` remain unimplemented and so have no key — a schema key with no effect would be a silent no-op.)*
- [x] **TLS** termination (rustls, `ring` provider; PEM chain + key loaded before bind), TLS 1.3 preferred / 1.2 allowed, ALPN `h2`+`http/1.1`, **session resumption** via stateless tickets + session cache. **0-RTT early data is not accepted** (`max_early_data_size = 0`): hyper cannot surface `Early-Data` per request, so RFC 8470 `425` gating is impossible — refusing 0-RTT is the strictly safe form of SECURITY §HTTP boundary. *(Deferred: 0-RTT for idempotent GET/HEAD; optional **kTLS + `SSL_sendfile`** with its fallback metric — lands with the zero-copy blob path.)*
- [x] **Rate limiting**, **per-HTTP-method** token buckets (`http.rate_limit.per_method` + `default`; unlisted with no default → unlimited) → `429 TOOMANYREQUESTS` + `Retry-After`. Global per-method buckets (≤7, bounded memory); disabled → no layer at all. *(Per-client limiting deferred to Phase 6 auth, where a bounded client key exists.)*
- [x] **Footprint knobs:** `mimalloc` global allocator (cargo feature `mimalloc`, in `full` + release/container builds; musl-friendly, no background threads); ext4 guidance: **do not** use `bigalloc` for manifest-dense stores — it raises the allocation unit to the cluster size (e.g. 64 KiB), wasting most of each small manifest/config file; keep 4 KiB blocks (`bigalloc` pays only for large-file-dominated volumes). *(`rkyv` mmap snapshot toggle moves to Phase 5 with the snapshot itself.)*
- [x] **OpenTelemetry telemetry pipeline** — `otel` builds export traces + metrics + logs over **OTLP** (gRPC or HTTP, batch processors) when `[telemetry.otlp]` is set; `ParentBased(TraceIdRatioBased(sample_ratio))` head sampler (default 1%); `service.name`/`service.version` resource; logs bridged via `opentelemetry-appender-tracing`. Root span carries semconv `http.request.method`/`url.path`/`http.route`/`http.response.status_code`; W3C `traceparent` extracted from requests (verified in Jaeger); child spans `meta.resolve`, `meta.append`, `blob.open`, `upload.session`, `digest.verify`. **Tail-based sampling is a collector concern** (OTel Collector `tail_sampling` processor keeping `status_code=ERROR` + latency policies), not in-process. *(Deferred: `authz` span with Phase 6; `blob.stream`/`cas.link` child spans and storage-internal propagation; peer-proxy hop with `roci-cluster`; background sweeps with Phase 5.)*
- [x] **Metrics via the OTel meter provider** — RED `http.server.request.duration` (seconds, semconv buckets; labels `endpoint`,`method`,`status_class`) + `registry.request.errors{error_code}`, defined once; **Prometheus scrape view** over the same `MeterProvider` at `telemetry.metrics.path` (default `/metrics`, never under `/v2`). Cardinality bounded by construction (endpoint is a route class, never a raw path). *(Storage/MetadataStore/GC/scrub/upload/cluster instruments are defined with the subsystems in Phase 5+.)*
- [x] **Error observability** — every `ApiError` sets `error.type=<CODE>` on the request span, increments `registry.request.errors{error_code}`, and logs one event on the span (5xx at `error`, 4xx at `info`); no header values are logged.
- [x] Rootless verified: default `:5000`, any user-writable storage root, `serve` tested as the unprivileged test user; container runs as UID 65532 on a read-only root FS.
- [x] Multi-OS/arch release builds: `release.yml` (tag `v*`) builds `x86_64`/`aarch64` `linux-musl` (static) + `apple-darwin` on native runners with `--features full`, tar.gz + sha256 + build-provenance attestation, attached to a draft GitHub Release.

**Correctness gate:** config round-trips; TLS handshake with skopeo; traces land in an OTLP collector (Jaeger/Tempo) with spans linked across a full push; the same metrics scrape parses in Prometheus; rate limit returns `TOOMANYREQUESTS` under load. **Met:** config TOML round-trip test; `skopeo copy` push + pull over TLS byte-identical; a full push lands in Jaeger (OTLP gRPC) as `http.request` roots with `upload.session`/`digest.verify`/`meta.append` children and an ingested `traceparent` keeps its trace id; `promtool check metrics` passes on the scrape; burst-exhausted bucket returns `429 TOOMANYREQUESTS` + `Retry-After`; conformance still 75/0.

---

## Phase 5 — Storage subsystem maturity

**Goal:** the "inline storage optimizations" from the feature set. Where algorithmic smartness earns its keep.

- [x] **Atomic manifest record** (the Phase 2/3 deferral) — `Storage::put_manifest` takes the manifest's `ManifestLinks` (backref edges + referrer), committed with the manifest and its tag as **one** `MetaOp::PutManifest` WAL record (ARCHITECTURE invariant 15); `record_backrefs`/`add_referrer` are gone. `MetadataStore` is object-safe and complete (`Arc<dyn MetadataStore>`), `open_blob` returns a backend-agnostic `BlobRead` (file / range-reader / redirect), and `StorageBackend` adds `recover()` + `start_maintenance()`.
- [x] **Garbage collection — online, O(garbage), grace-period.** Live **backref multimap `blob_digest → {manifest_digests}`** in the MetadataStore → collect once a backref set is empty AND `storage.gc.delay_secs` elapsed untouched AND not pinned by an in-flight push (a shared fence around every existence check / finalize / mount vs the sweeper's exclusive re-check + unlink); never offline. **Prerequisite met:** a background **startup consistency check** rebuilds missing edges from the layout (roots = recorded manifests ∪ `index.json` descriptors ∪ image-index children; `PutBackrefs`, idempotent), registers layout-only roots, marks a repo with an unreadable root GC-unsafe, then seeds unreferenced blobs as candidates (the mark-sweep backstop); sweeps are refused until it completes. Abandoned upload sessions expire with the same sweep. Config `storage.gc.{enabled,delay_secs,interval_secs}` (on, 1 h, 1 h).
- [x] **Deduplication maturity:** reflink (`FICLONE`) → hard link → copy across paths/repos for mounts, now also for **uploads** of a blob another repo already holds (reflink → hard link only; the uploaded copy is the fallback) via the in-RAM **dedupe cache `digest→location`** (`storage.dedupe`, default on); the hard-link/copy fallbacks are logged and counted (`registry.dedupe.links{op,mechanism}`). Sub-chunk (**FastCDC**) dedup deferred to `roci-ext-dedup` (Phase 7/future).
- [x] **Data scrubbing — CRC32C-on-write + staggered/adaptive**, escalating to the full digest re-hash only on mismatch (the wire SHA-2 digest — BLAKE3 stays reserved for Bao, Phase 7); corrupt blobs are quarantined to `<root>/.roci-quarantine/` (absent → re-pushable); **btrfs/ZFS** detected and delegated (`storage.scrub.mode = "auto"`); bandwidth-capped; off by default. Not a blanket periodic re-hash.
- [x] **rkyv mmap snapshot** of the metadata index (`storage.metadata.snapshot`) — cut past `compact_threshold_bytes` of WAL growth together with **log compaction**; cold start maps + validates the snapshot and replays only the post-snapshot tail (reads = archived base + heap delta), falling back to the full WAL image if the snapshot is rejected; optional **WAL + snapshot HMAC** (`storage.metadata.hmac_key_file`; mismatched/unauthenticated logs moved aside). The one audited `unsafe` module (SECURITY inv. 7).
- [x] **Storage quotas** — `storage.quota.max_repo_bytes` (`413`), `max_total_bytes` (`507`, registry-wide across storage paths), enforced as one check-and-charge at blob finalize/mount; concurrent-upload-session cap `max_upload_sessions` (`429`, default 1024).
- [x] **Index engine upgrade path** — feature-gated embedded B-tree KV: **redb** (`storage.metadata.engine = "redb"`, cargo feature `redb`, in `full`) behind the same trait, verified by a shared cross-engine behavioral suite; default stays append-log + maps. *(heed/LMDB vs redb bake-off remains the cross-cutting benchmark below.)*
- [x] **Multiple storage paths / backends** from one server — `storage.subpaths` routes repo prefixes (longest `/`-boundary match) to their own FS root or backend; cross-backend mounts fall back to upload. Second backend **S3-compatible** (`roci-storage-s3`, feature `s3`, over `object_store` with `ring`): one OCI layout per repo in the bucket, local metadata + staging, **307 to a ≤60 s signed URL above `redirect_min_size`** (membership-checked; manifests never redirected), streamed **parallel multipart** finalize (`multipart_part_size`/`multipart_concurrency`), server-side copy for mount/dedupe with a parallel ranged-read→multipart copy above the 5 GiB single-copy limit, GC/quota/dedupe parity; scrub delegated to the object store. **`tar+zstd`** layers accepted and served byte-identical (blobs are opaque).

**Correctness gate:** GC removes only unreferenced blobs and is O(garbage) not O(total) (property test: reachable set preserved under concurrent push); scrub detects an injected corruption via CRC32C; reflink dedup shares extents with independent deletion; quota returns `507`/`413` at the cap; rkyv snapshot gives O(1) cold start; conformance still green. **Met:** a concurrent push/delete/sweep property test keeps every committed manifest's blobs present and collects deleted manifests' blobs; the sweep visits only the candidate set; an on-disk byte flip is caught by CRC32C, confirmed by re-hash and quarantined (unit test + live binary: blob `404` afterwards, file under `.roci-quarantine`); a layer pushed to a second repo shares storage with the first copy (hard link on ext4/APFS — the reflink branch is exercised through the `FICLONE` fault seam on Linux CI, which has no CoW filesystem) and survives deletion of the first; `413`/`507`/`429` asserted over HTTP; a snapshot reopen replays only the tail records (heap delta = tail) with a full-WAL fallback — cold start is O(snapshot bytes) validation with no per-record parse/alloc, not strictly O(1) (ARCHITECTURE §O(1) cold start); a live binary smoke covered GC collection, dedupe, quota, scrub quarantine, snapshot restart and HMAC key rotation; conformance 75/0 with the `--all-features` binary.

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
- [x] **Comparative benchmark vs CNCF distribution & zot** — `just bench` (pinned images, zb/vegeta/crane/loadgen in a runner container, cgroup CPU/RSS, interleaved reps) and `just bench-perf` (roci flamegraphs, syscalls, per-route latency, gaps vs competitors); reference run in RESEARCH §9.7, method in docs/guide/benchmarks.md. *(Open: hot-path p99 ~2× zot; authoritative `full` run on a dedicated Linux host.)*
- [ ] **Memory-scaling benchmark (from ARCHITECTURE §RAM consumption):** assert RSS scales with reference count, not stored bytes — measure RSS at 1M/10M refs (target ~130 MB/1.3 GB heap, ~10× less with the rkyv mmap snapshot), confirm RSS is flat while blob-corpus size grows, and run a 24 h push/pull **soak** to catch allocator fragmentation creep (validates the jemalloc/mimalloc choice).
- [ ] **HTTP roundtrip benchmark (from ARCHITECTURE §HTTP roundtrip efficiency):** measure real `docker pull`/`skopeo copy` roundtrip counts and wall-clock — assert warm re-pull collapses to `304`s over one kept-alive connection, cold multi-layer pull uses HTTP/2-multiplexed parallel blob streams, `HEAD` is body-free/syscall-free, and per-request manifest/HEAD latency stays O(1) as the corpus grows.
- [ ] **Index-engine bake-off (Phase 1 deliverable, from RESEARCH §8.6):** benchmark **heed/LMDB vs redb** on roci's real access pattern (tag lookup, referrer range-scan, existence check) to settle the default; LMDB is predicted ~1.8–3× faster on reads / 35% smaller, redb is the pure-Rust/musl fallback.
- [ ] **Instrument as you build** — every new subsystem (storage, upload sessions, referrers index, GC, auth, extensions) adds spans + OTel instruments in the same PR that adds the code, not retrofitted. Telemetry overhead stays on the benchmark dashboard so instrumentation never silently costs footprint.
- [ ] Fuzzing on manifest/digest/reference parsers (untrusted input boundary).
- [ ] **Security regression suite (from SECURITY §Tracked prior-art CVE classes):** one test per tracked class — path-traversal via `name`/`reference`/`upload-id`; wire non-`sha256/512` digest rejected; cross-repo mount without source authz denied; cross-repo presence/content oracle (HEAD/GET returns 404 for a globally-present blob absent from the repo); manifest size/`n`/depth caps; mutable-tag not cached immutable; single `can_delete()` guard; 0-RTT `425` on non-idempotent. Each fails pre-control, passes post-control.
- [ ] **Symlink/traversal backstop test:** `openat2 RESOLVE_BENEATH`/`O_NOFOLLOW` on all digest-derived opens; property test that path construction can never emit `/`, `..`, or `NUL` from a validated digest/name.
