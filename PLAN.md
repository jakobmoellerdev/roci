# roci — Master Build Plan

A phased plan for building **roci**, a Rust OCI Distribution registry. Philosophy: **start small, prove functional correctness against the conformance suite at every layer, then grow subsystems.** Each phase produces a working, testable binary. Algorithmic and footprint decisions are called out where they matter — they are designed in from the start, not bolted on.

Spec anchors (local): [`spec/distribution-spec/spec.md`](spec/distribution-spec/spec.md), [`spec/image-spec/spec.md`](spec/image-spec/spec.md), [`spec/image-spec/image-layout.md`](spec/image-spec/image-layout.md), [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md) (de-facto bearer-token auth + client examples).

Endpoint IDs below (`end-N`) refer to the spec's endpoint table. Error codes (`CODE`) refer to its error-code table.

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

- [ ] Workspace layout: `roci-core` (HTTP + protocol), `roci-storage` (traits + local backend), `roci-config`, `roci-cli` (binary). Extension crates added later.
- [ ] HTTP stack chosen (axum/hyper or equivalent) with async runtime; graceful shutdown.
- [ ] **OpenTelemetry spine from day one** — `tracing` + `tracing-opentelemetry`, OTel SDK wired at startup. Every request handler is a span; logs are structured events on the trace. Console/no-op exporter for now (OTLP export lands in Phase 4). Footprint note: OTel behind a cargo feature so a minimal build can compile it out; sampling configurable and default-cheap.
- [ ] `Digest` type: parse/validate `algorithm:hex`, constant-time compare, sha256 + sha512. This is load-bearing — every subsystem keys off it.
- [ ] `RepositoryName` + `Reference` (tag/digest) types enforcing the spec regexes (name, tag ≤128 chars).
- [ ] Error model → JSON `{ "errors": [{code,message,detail}] }` with all 14 codes as an enum; correct HTTP status mapping.
- [ ] `GET /v2/` (end-1) returns `200`.
- [ ] Config skeleton: zero-config defaults, single declarative file (format TBD — likely TOML/YAML), storage root path.

**Correctness gate:** `GET /v2/` returns `200`; malformed name/reference/digest rejected with correct code before any handler logic; a request emits one root span with structured log events attached.

---

## Phase 1 — Pull (read path) + storage core

**Goal:** serve a pre-populated OCI image layout as a registry. **Pull conformance passes.** This is the MUST-support minimum for any conforming registry.

- [ ] **Storage trait** (`Storage`): `blob_read`, `blob_stat`, `manifest_read`, `tag_resolve`, existence checks. Read-only surface first.
- [ ] **Local backend on OCI image layout** ([`image-layout.md`](spec/image-spec/image-layout.md)): `blobs/<alg>/<hex>` content-addressable store; `index.json` + tag mapping. Algorithmic point: blob path is a pure function of digest → O(1) open, no index lookup.
- [ ] `GET`/`HEAD /v2/<name>/blobs/<digest>` (end-2) — stream body, zero-copy where possible, `Docker-Content-Digest` + `Content-Length`, `404` on miss.
- [ ] `GET`/`HEAD /v2/<name>/manifests/<reference>` (end-3) — content negotiation via `Accept`, correct `Content-Type`, digest header.
- [ ] **`Range` request support** (RFC 9110) for resumable pull.
- [ ] "Serve any OCI layout as a registry" verified: point roci at an existing layout dir, pull with skopeo.

**Correctness gate:** **Pull** conformance category passes. Smoke: `skopeo copy` *from* roci succeeds; digest verification on client matches.

---

## Phase 2 — Push (write path) + upload sessions

**Goal:** accept pushes. **Push conformance passes.** Round-trip: push then pull an identical image.

- [ ] Extend `Storage`: `blob_write`, staged uploads, `manifest_put`, `tag_set`.
- [ ] **Upload session manager** — the algorithmically interesting part:
  - [ ] `POST /v2/<name>/blobs/uploads/` (end-4a) → `202` + `Location` with session UUID.
  - [ ] `PATCH …/blobs/uploads/<ref>` (end-5) — chunked upload, `Content-Range`, `416` on gap. Stream chunks straight to a staging file; never buffer.
  - [ ] `PUT …/blobs/uploads/<ref>?digest=` (end-6) — finalize: verify digest while streaming (hash-on-write), atomic rename into CAS, `DIGEST_INVALID`/`SIZE_INVALID` on mismatch.
  - [ ] `GET …/blobs/uploads/<ref>` (end-13) — upload status → `204` + range.
  - [ ] Monolithic single-`POST` (end-4b) and POST-then-PUT paths.
- [ ] `PUT /v2/<name>/manifests/<reference>` (end-7) — validate manifest JSON, referenced-blob existence check (`MANIFEST_BLOB_UNKNOWN`), accept `subject` referencing absent manifest (spec requirement), `413` on oversize.
- [ ] **Deduplication:** identical digest on upload → no rewrite; single stored copy (falls out of CAS naturally). Concurrent identical uploads both succeed, one copy retained.
- [ ] Cross-repo **blob mount** `POST …?mount=<digest>&from=<repo>` (end-11) → `201` if source has it, else fall through to normal upload `202`.
- [ ] Crash-safety: staging + atomic rename so an interrupted push never corrupts the CAS.

**Correctness gate:** **Push** conformance passes. Smoke: `skopeo copy` *to* roci, then pull back → byte-identical. Resumable push (interrupt mid-chunk, resume) works.

---

## Phase 3 — Content Discovery + Content Management + Referrers

**Goal:** listing, deletion, and the referrers API. **Discovery + Management conformance pass.** Completes core dist-spec conformance.

- [ ] `GET /v2/<name>/tags/list` (end-8a) and paginated `?n=&last=` (end-8b) — lexical ordering, stable pagination cursor.
- [ ] `DELETE /v2/<name>/manifests/<reference>` (end-9) — `202`; **image deletion by tag** and by digest.
- [ ] `DELETE /v2/<name>/blobs/<digest>` (end-10) — `202`; `405`/`400` when deletion disabled (config-gated).
- [ ] **Referrers API** `GET /v2/<name>/referrers/<digest>` (end-12a) + `?artifactType=` filter (end-12b):
  - [ ] Maintain a **subject → referrers index** updated on every manifest put/delete. Algorithmic point: reverse index so referrers is an O(1) index read, not a repository scan.
  - [ ] Return image index of referring descriptors; `artifactType` filter applies `OCI-Filters-Applied` header.
  - [ ] Referrers-tag-schema fallback compatibility (`<alg>-<ref>` tag).
- [ ] Enable-referrers upgrade semantics (include preexisting subject manifests).

**Correctness gate:** **all four** conformance categories pass. roci is now a conformant OCI registry. Smoke: `oras` push/discover artifacts; `crane` referrers.

---

## Phase 4 — Configuration & operability baseline

**Goal:** make behavior fully config-driven and observable end-to-end. No new protocol surface; hardening the core into something deployable.

- [ ] Full config schema: storage root, deletion toggles, size limits, listen addr, log level. Documented, validated on load with clear errors.
- [ ] **TLS** termination (server certs).
- [ ] **Rate limiting**, including **per-HTTP-method** limits (`TOOMANYREQUESTS`). Token-bucket, bounded memory.
- [ ] **OpenTelemetry telemetry pipeline** — mature the Phase 0 spine into full three-signal export: traces + metrics + logs over **OTLP** (gRPC + HTTP), resource/semantic-convention attributes (`service.name`, version), configurable exporter endpoint, sampler, and batching. Spans propagate across storage and (later) extension calls; W3C `traceparent` ingest/propagation.
- [ ] **Metrics via the OTel meter provider** — request counts/latencies, storage ops, upload-session gauges, GC/scrub counters defined once as OTel instruments. **Prometheus `/metrics` endpoint is an OTel exporter/scrape view** over those same instruments — one instrumentation source, two export paths (OTLP push + Prometheus pull), no duplicate metric definitions.
- [ ] Rootless verified (no privileged ports/paths required).
- [ ] Multi-OS/arch release builds (Linux/macOS, amd64/arm64), static where possible.

**Correctness gate:** config round-trips; TLS handshake with skopeo; traces land in an OTLP collector (Jaeger/Tempo) with spans linked across a full push; the same metrics scrape parses in Prometheus; rate limit returns `TOOMANYREQUESTS` under load.

---

## Phase 5 — Storage subsystem maturity

**Goal:** the "inline storage optimizations" from the feature set. Where algorithmic smartness earns its keep.

- [ ] **Garbage collection** of orphaned blobs — mark-and-sweep from manifests/tags as GC roots; online/concurrent-safe (don't sweep a blob mid-push). Reference-counted or generation-based to avoid full scans where possible.
- [ ] **Layer deduplication via hard links** when content identical across storage paths/backends (CAS already dedupes within a path).
- [ ] **Data scrubbing** — background integrity verification: re-hash blobs, detect bit-rot/mismatch, report.
- [ ] **Multiple storage paths / backends** from one server — routing layer over the `Storage` trait; per-repo or per-prefix backend selection.
- [ ] Storage-backend trait proven with a second backend (e.g. S3-compatible) to validate the abstraction.

**Correctness gate:** GC removes only unreferenced blobs (property test: reachable set preserved); scrub detects an injected corruption; dedup produces one inode for identical content; conformance still green.

---

## Phase 6 — Security & access control

**Goal:** the full auth matrix.

- [ ] **HTTP Basic** — local htpasswd (bcrypt).
- [ ] **HTTP Basic** — LDAP bind.
- [ ] **HTTP Bearer token** (Docker v2 token scheme — WWW-Authenticate challenge → repo-scoped token; see [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md)).
- [ ] **TLS mutual authentication** (client cert verification).
- [ ] **Identity-Based Access Control** — per-identity repo/action policies.
- [ ] **Live authorization reload** — reload authz config on file change while running, without restart or dropping connections.

**Correctness gate:** each auth mode gates `401`/`403` correctly (`UNAUTHORIZED`/`DENIED`); anonymous pull vs. authenticated push enforced; live authz change takes effect without restart; conformance passes under an auth-enabled profile.

---

## Phase 7 — Extensions

**Goal:** zot-parity feature extensions, each behind the core/extension seam, independently compilable.

- [ ] **Search extension** — advanced image queries (GraphQL, zot-compatible schema). Backed by a query index built from manifests; designed for fast filtered lookups, not scans.
- [ ] **Signatures** — cosign and notation: store and serve signature manifests via referrers; verification hooks.
- [ ] **Helm chart** support (Helm OCI artifact media types — falls out of generic artifact handling; verify with `helm push`/`pull`).
- [ ] **Vulnerability scanning** — Trivy integration; serve/store SBOMs (SPDX/CycloneDX) as referrers.
- [ ] **Sync** — pull-and-synchronize from other dist-spec conformant registries (periodic + on-demand mirroring).
- [ ] **Node exporter** mode for minimal builds (metrics without full server).
- [ ] **Swagger/OpenAPI** documentation generation.

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
- [ ] **Instrument as you build** — every new subsystem (storage, upload sessions, referrers index, GC, auth, extensions) adds spans + OTel instruments in the same PR that adds the code, not retrofitted. Telemetry overhead stays on the benchmark dashboard so instrumentation never silently costs footprint.
- [ ] Fuzzing on manifest/digest/reference parsers (untrusted input boundary).
