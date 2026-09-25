# roci — Security Design

Security design for **roci**, a Rust OCI Distribution registry. This document defines roci's defense-in-depth posture across build-time hardening, runtime hardening, authentication, authorization, and content trust.

## Design lineage

roci's security posture is reverse-engineered from [zot](https://zotregistry.dev)'s and adapted to Rust. Design sources (zot docs, v2.1.21):

- [zot — Security Posture](https://zotregistry.dev/v2.1.21/articles/security-posture/) — build-time and runtime hardening, conditional builds, non-root deployment, authn/authz options, HTTP timeouts.
- [zot — Architecture](https://zotregistry.dev/v2.1.21/general/architecture) — the "authn/authz enforced before storage access" model and the minimal/extension separation that bounds attack surface.
- [zot — Storage Planning](https://zotregistry.dev/v2.1.21/articles/storage/) — repository-boundary and data-integrity properties relevant to security (repo-local reads, scrub).

Companion: [`ARCHITECTURE.md`](ARCHITECTURE.md). Spec/auth reference: [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md) (de-facto bearer-token flow).

roci adopts zot's **defense-in-depth** philosophy: layered, industry-standard controls at build and deploy time, with flexibility where hardening and features conflict. **[roci divergence]** notes where Rust changes or strengthens the posture.

## Threat model (scope)

- **Assets:** stored blobs/manifests (integrity + confidentiality per access policy), signing/token keys, backend credentials, availability of the service.
- **Adversaries:** unauthenticated network clients; authenticated-but-unauthorized users attempting cross-repo access; malicious content pushers; slow/abusive connections (DoS); attackers exploiting memory-safety or dependency vulnerabilities.
- **Out of scope:** host OS hardening, network perimeter, physical security, compromised admin.

The two untrusted-input trust boundaries — the **HTTP request boundary** and the **storage boundary** — are analyzed concretely in their own sections below (attack class → control), grounded in real registry CVEs/GHSAs (see §Tracked prior-art CVE classes).

## Build-time hardening

### Memory safety (roci's strongest divergence)

**[roci divergence]** roci is written in safe Rust. The largest single class of registry CVEs — memory-corruption in a long-running network service parsing untrusted input (manifests, digests, ranges) — is eliminated by construction. `unsafe` is forbidden outside audited, isolated modules (zero-copy I/O) and gated by CI lint (`#![forbid(unsafe_code)]` in every crate that can afford it).

### Hardened binaries

Adopt zot's binary hardening intent:

- **PIE / ASLR.** Build position-independent executables so ASLR randomizes memory layout, preventing generic address-dependent exploits reused across deployments. (zot: PIE build-mode.)
- **Stripped, static release builds** with overflow checks retained where cheap; fuzzed parsers at the untrusted boundary (manifest/digest/reference — see [`PLAN.md`](PLAN.md) cross-cutting).

### Conditional builds (attack-surface control)

Directly from zot: functionality splits into a **core** Distribution Spec implementation and **extensions**, so dependency count and attack surface are controllable.

- **`roci-minimal`** — core only, fewest dependencies/libraries; for the security-minded.
- **`roci-full`** — minimal + all extensions; larger attack surface, more features.
- **Custom** — pick individual extensions (`cargo build --features search`) to sit anywhere on the minimal↔full spectrum.

Every extension is a cargo feature → excluded code is not compiled into the binary at all, not merely disabled at runtime. This is the primary attack-surface lever.

### Supply chain & CI/CD

Aligns with zot's OSSF best-practices intent:

- All PRs reviewed by code owners; CI blocks unreviewed commits to protected branches.
- CI gate: unit + functional + integration tests, OCI conformance suite, lint/style, performance-regression checks.
- **[roci divergence] Rust supply-chain tooling:** `cargo audit` / `cargo deny` for advisory + license + duplicate-dependency gating; `cargo vet` for trusted dependency provenance; reproducible builds; SBOM emitted per release. Released binaries scanned for known vulns before publish.

## Runtime hardening

### Unprivileged process

roci requires **no root privileges** (zot design). Recommended deployment: a dedicated, unprivileged user/group ID, no capabilities, read-only container root FS with the storage volume the only writable mount. No privileged ports by default.

### Enforcement point

**AuthN/AuthZ is enforced before any access into the storage layer** (zot architecture). No handler touches the `Storage` trait before the request identity is authenticated and the action authorized. This is an architectural invariant (see [`ARCHITECTURE.md`](ARCHITECTURE.md)).

### HTTP read/write timeouts

Adopt zot's configurable read/write timeouts (default `60s`) on both the API server and the metrics exporter, to bound slow-client and stalled-connection resource exhaustion.

- Larger values for large pushes/pulls over slow links.
- `0` disables (infinite) — flagged in docs as increasing exposure to stalled/abusive connections.

**[roci divergence]** timeouts pair with per-method rate limiting and bounded upload-session memory (streaming, never buffering a full blob) so a flood of concurrent uploads cannot exhaust RAM.

## Authentication

All interaction is over HTTP APIs; roci supports the full authn matrix (see [`PLAN.md`](PLAN.md) Phase 6). Auth is **opt-in**: enabled only when at least one of `auth.htpasswd`, `auth.ldap`, `auth.bearer`, `access_control`, or `http.tls.client_auth != "none"` is configured; otherwise no auth layer is installed and behavior is byte-identical to a pre-auth build. Operators are strongly advised to enable a mechanism suited to their deployment to prevent unauthorized access.

**Authentication order** (decided once per request):

1. If an `Authorization` header is present, it decides the identity; an invalid header yields `401` and **never falls back to anonymous**. **Exception:** `Basic` with both user and password empty (the `:` pair) is treated as no credentials (proceeds to step 2/3) — container-image clients (skopeo, podman, buildah) send this when they hold no credentials but must answer a Basic challenge to pull from anonymous-pull repos. A non-empty user with empty password, or empty user with a password, is still `401` "invalid credentials".
   - `Basic`: try htpasswd first. If the user is **absent** from htpasswd, try LDAP. A known htpasswd user with a wrong password fails without trying LDAP.
   - `Bearer`: verify the JWT against the configured public keys.
   - Any other scheme: `401`.
2. Otherwise, if the connection carried a verified client certificate, the identity comes from that certificate (Subject CN, else first DNS SAN; non-empty, ≤255 bytes, no control chars).
3. Otherwise the request is Anonymous.

| Mechanism | Notes |
| --- | --- |
| **HTTP Basic — local htpasswd** | bcrypt only (`$2a$`/`$2b$`/`$2y$`); line-numbered load errors; duplicate users or non-bcrypt hashes rejected. Unknown users verified against a dummy hash at the file's max bcrypt cost (timing-safe). Verify on `spawn_blocking`. |
| **HTTP Basic — LDAP** | Cargo feature `ldap` (roci-core `ldap`, roci-cli `ldap`, in `full`); without it `auth.ldap` fails startup. Search-then-bind with a service account; `ldap_escape`'d filter; empty password rejected (anonymous-bind trap); TLS always verified; bounded by `timeout_secs`. Directory errors → warn + `401`. |
| **HTTP Bearer token** | External token server only (roci does not issue tokens). Hand-rolled JWS verification over `ring` (no `jsonwebtoken` → avoids `rsa` crate RUSTSEC-2023-0071). ES256 (P-256) and RS256 (2048–8192 bit). `alg` must match key; `jwk`/`jku`/`x5u` headers rejected; `kid`/`x5c` ignored; ≤8192 bytes; `iss`==issuer; `aud` (string or array) contains service; `exp` required (30 s leeway); ≤64 `access` entries; only `type=repository`; constant-time repo-name compare. Keys loaded from PEM `PUBLIC KEY`/`CERTIFICATE` blocks. |
| **TLS mutual authentication (mTLS)** | rustls `WebPkiClientVerifier` (ring provider); `client_auth = optional` calls `.allow_unauthenticated()`; pins enforced by a wrapping verifier (unpinned cert fails the handshake). |

**Credential cache:** SHA-256(user‖0x00‖password) → identity, TTL `auth.cache_ttl_secs` (default 60, max 3600, 0 disables), 4096 entries (cleared when full); caches successful Basic (htpasswd + LDAP) only. Credentials, tokens, and `Authorization` values are **never logged**.

**Startup warning:** when a header mechanism (htpasswd, LDAP, bearer) is enabled without TLS, a warning is logged ("credentials travel in plaintext").

**Telemetry:** counter `registry.auth.decisions{method=anonymous|htpasswd|ldap|bearer|mtls, result=allowed|denied|unauthenticated|invalid}`; span `authn.authorize` with `auth.method`/`auth.result`.

TLS is supported for transport confidentiality; mTLS additionally authenticates the client. Anonymous access (e.g. public pull) is a policy choice, not a default.

## Authorization (access control)

After authentication, roci allows or denies a specific **action** (`pull`, `push`, `delete`) by a **principal** on a specific **repository** — Identity-Based Access Control (IBAC), configured in `[access_control]`.

**Token principals** (Bearer) are authorized **only by their `access` claims** — the IBAC policy is never consulted for them.

**IBAC rule matching:** every `[[access_control.repositories]]` entry has a glob `pattern` (`*` within one `/`-component, `**` across components including empty). The **single most-specific rule wins** (most literal bytes → fewest wildcard tokens → earliest declared); a narrow rule can remove grants a broad one gives.

**Grants for an authenticated (non-token) user:** `admins` → all actions. Everyone else gets the **union** of the winning rule's `anonymous`, `authenticated`, matching `users` policies, and matching `groups` policies (config `groups` map + LDAP directory groups).

**Grants for Anonymous:** the winning rule's `anonymous` list only.

**No `[access_control]` section:** every authenticated identity may do everything; Anonymous may do nothing.

**Decision → response:**

| Principal / condition | Response |
| --- | --- |
| Action allowed | proceed |
| Authenticated user, action not granted | `403 DENIED` "access denied" |
| Anonymous, not granted, a header mechanism configured | `401 UNAUTHORIZED` "authentication required" + challenge |
| Anonymous, not granted, no header mechanism | `403 DENIED` ("authentication required: present a trusted client certificate" if mTLS configured, else "anonymous access denied by policy") |
| Token principal missing the grant | `401 UNAUTHORIZED` "insufficient scope" + Bearer challenge with `error="insufficient_scope"` |
| Invalid credentials | `401 UNAUTHORIZED` "invalid credentials" + challenge without scope |

**Challenge header (`WWW-Authenticate`):** Bearer `realm,service[,scope]` when `auth.bearer` configured (Basic still accepted); else `Basic realm`; absent when no header mechanism. Actions in scope: pull → `pull`; push → `pull,push`; delete → `delete`.

**`GET /v2/`:** anonymous with a header mechanism → `401` challenge (no scope); anonymous without → `200`; any authenticated principal → `200`. The `/metrics` endpoint stays **unauthenticated** (merged after the auth-gated router in roci-cli).

**Endpoint → action:** pull = GET/HEAD blob, GET/HEAD manifest, tags list, referrers; push = POST uploads, PATCH/PUT/GET upload session, PUT manifest; delete = DELETE blob/manifest. Unknown path shapes keep `NAME_UNKNOWN` without authorization (no storage touched).

**Enforcement point:** `routes::dispatch`, after path parsing and before any `Storage` call — a single point satisfying SECURITY invariant 1 / ARCHITECTURE invariant 3.

**Middleware order at runtime:** request span → early-data → rate limit → authn → handler.

- Default-deny where a policy is configured; explicit anonymous-pull opt-in.
- **Live authorization reload:** only `[access_control]` is reloaded (2 s file poll, full `Config::load` validation on change; invalid → warn, keep old; other sections changed → warn restart required; section removed → `None`: anonymous denied, authenticated unrestricted). htpasswd/LDAP/bearer/TLS changes need restart.

## Content trust & integrity

- **Digest verification everywhere.** Every blob is verified against its digest on write (hash-on-write during upload finalize) and its identity is its content address on read. Constant-time digest comparison. A digest mismatch is `DIGEST_INVALID`.
- **Repository boundaries.** Repo-local-by-default blob reads (zot v2.1.21 `hydrateBlobOnRead=false`): a digest present only in the cross-repo dedupe cache is **not** served from another repo — returns `404` until explicitly mounted (`end-11`) or uploaded. Prevents cross-repo content leakage via shared dedupe. *(Phase 5: upload dedupe links another repo's copy only after the uploader has sent — and roci has verified — the full content, so it grants nothing the uploader did not already possess.)*
- **Data scrubbing.** A background scrub detects bit-rot/tampering on disk and reports it early. *(Phase 5: CRC32C recorded at write, full digest re-hash only on a mismatch; a blob whose content no longer matches its digest is quarantined beneath the root — `<root>/.roci-quarantine/` — so it is never served again and can be re-pushed; btrfs/ZFS integrity is delegated to the filesystem scrub.)*
- **Image signatures (extensions).** cosign and notation signatures stored/served via the referrers API; verification hooks let policy require valid signatures.
- **Vulnerability scanning (extension).** Trivy integration scans stored images; the vuln DB is refreshed on a configurable interval by the background scheduler. The scanner implementation is abstracted so it can change without user-facing impact.

## HTTP request-boundary controls

The HTTP edge is the primary untrusted-input boundary. Every control below is a **design requirement enforced before any storage or filesystem operation**; verdicts and CVE references come from an adversarial boundary review (`[refined from research]`).

- **Name / reference / digest validation before any path construction.** `RepositoryName`, `Reference`, and upload-session IDs MUST be parsed against their dist-spec grammars *before* a filesystem path is built from them (`RepositoryName` `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/…)*` ≤255 chars; `Reference` tag `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` or a digest). The spec name grammar excludes `..` by construction, so enforcing it is both spec-correct and traversal-proof; digest hex is charset-locked (`[a-f0-9]{64|128}`) so `blobs/<alg>/<hex>` can never contain a separator or `..`. Reject invalid input with `NAME_INVALID`/`DIGEST_INVALID`. **Defence-in-depth:** a `Storage`-layer backstop rejects any path component that is `..`, `.`, or contains `NUL`, even if the edge validated. (CVE-2021-21334 / GHSA-hmfx-3pcx-653p containerd path traversal; GHSA-qq97-vm5h-rrhg distribution name sanitisation; Harbor CVE-2019-3990.)
- **Wire digest algorithm allowlist.** Only `sha256` and `sha512` are accepted as wire digests; SHA-1/MD5/any unregistered algorithm → `DIGEST_INVALID` at parse time. **BLAKE3 is internal-only (scrub, Bao tree) and MUST NEVER appear as a wire/descriptor digest** — the referrers-index update path asserts every stored descriptor digest is in the allowlist (else a BLAKE3-unaware client silently skips verification = integrity bypass). (SHAttered 2017; OCI descriptor grammar.)
- **Cross-repo mount is double-authorized.** **[implemented — Phase 6]** `POST …?mount=<digest>&from=<src>` (`end-11`) requires **pull on `<src>` AND push on the destination repo — two independent checks**, the source check *before* `mount_blob`. If `from` fails `RepositoryName::parse`, or pull on `from` is not allowed, the mount silently falls through to a normal `202` upload session (no existence oracle). (Harbor GHSA-r4cx-r72v-m728; zot documents this class.)
- **Per-method authorization matrix + scope binding.** GET/HEAD⇒pull, POST/PATCH/PUT⇒push, DELETE⇒delete, checked per endpoint. Bearer-token `repository:<name>:<action>` scope is validated against the actual request path+method (constant-time name compare), never merely "a token is present." Anonymous-pull vs authenticated-push is enforced per endpoint. (CVE-2020-13401 scope confusion; GHSA-phw4-mc57-4hwc JWT signing-key injection; GHSA-3p65-76g6-3w7r pull-through credential exfiltration.)
- **SSRF / open-redirect containment.** roci never fetches a client- or manifest-supplied URL: `descriptor.urls` is not dereferenced; `subject`/`from` are repo names, not URLs. **[implemented — Phase 6]** The 307 signed-URL redirect (remote backend) is emitted only if the scheme is `https` (or `http` with `allow_http`), the host is in a **derived allowlist** (from `endpoint` host, or `s3.<region>.amazonaws.com` + `<bucket>.s3.<region>.amazonaws.com`), and the host is not internal (`roci_config::is_internal_host`); otherwise the blob is proxied (ranged) with a warning. At config load, `redirect_min_size > 0` with an endpoint whose host is internal → error. Repo membership is already enforced by the S3 backend's `head` on the repo-scoped key. The `sync` extension validates upstream URLs at config load (public `https://` only; reject metadata/loopback/private ranges) and MUST NOT accept invalid TLS certs. *(Sync-extension SSRF URL validation is carried to Phase 7 — `roci-ext-sync` is a stub; Phase 6 ships the reusable `is_internal_host`.)* (CVE-2022-24878 Flux, CVE-2023-45288 containerd pull-through, Harbor GHSA-jfh8-c2jp-hdph.)
- **Request-smuggling / desync hygiene.** HTTP/2 (frame-length framed) is the default and immune to CL/TE confusion; HTTP/1.1 keep-alive follows RFC 7230 (TE wins). Operators are warned that HTTP/1.1 behind a TE/CL-ambiguous proxy is a smuggling risk (prefer HTTP/2-only or a correct proxy). `Location`/response headers are built only from validated repo/id (no CRLF injection); header construction never `unwrap()`s attacker input into a panic. `hyper` is pinned past **CVE-2023-44487 / GHSA-rr69-rxr6-8qwv** (HTTP/2 Rapid Reset) and tracked by `cargo audit`.
- **DoS bounds (see also §DoS in Storage boundary).** Separate **manifest size cap** (default ≤4 MiB, distinct from the blob cap) checked before JSON parse; bounded JSON recursion depth; per-session upload size cap; `n`/pagination parameters on tag-list and referrers capped server-side (never allocate `O(n)` from a client integer) and served by a storage-level seek, so per-request work is bounded by the page, never by the repo's tag or referrer count; wired read/write timeouts + per-method rate limits. (CVE-2023-2253 / GHSA-hqxw-f8mx-cpmw catalog `n` OOM; GHSA-259w-8hf6-59bj referrers amplification.)
- **Cache-poisoning split (tag vs digest).** Manifest-by-**tag** responses are mutable → `Cache-Control: no-cache`/`must-revalidate`, no immutable ETag. Manifest/blob-by-**digest** responses are immutable → `ETag: "<digest>"`, `Cache-Control: immutable, max-age=31536000`, `If-None-Match`→`304`. Filtered referrers responses set an appropriate `Vary`. A mutable tag must never be cacheable as immutable. (GHSA-77mh-r6f6-crvq containerd cache poisoning; ARCHITECTURE invariant 14.)
- **TLS / 0-RTT.** **[implemented — Phase 6]** Direct 0-RTT stays refused (`max_early_data_size = 0`). An always-on middleware returns `425 Too Early` (code `DENIED`, "request sent in TLS early data; retry after the handshake completes") for any request carrying the `Early-Data: 1` header with a method other than GET/HEAD/OPTIONS (RFC 8470 §5.1, proxy-forwarded early data). Ticket-based 1-RTT resumption is on. *(kTLS-fallback alert deferred to the kTLS work in Phase 4; no kTLS path exists yet.)* mTLS (`http.tls.client_auth = optional|required`) uses a per-deployment CA with optional leaf-fingerprint pinning (`client_cert_sha256`); `accept_invalid_certs` is prohibited in sync and cluster configs. (RFC 8470; CVE-2022-26945 go-getter TLS bypass.)

## Storage-boundary controls

Everything operating on files derived from untrusted input. Content addressing is the structural backbone: the CAS path is a pure function of a validated digest, so substituting a blob's content changes its digest and thus its path — **content substitution in place is structurally impossible**.

- **Digest verified before promotion.** Upload streams into an anonymous `O_TMPFILE` inode with hash-on-write; the digest is verified **before** `linkat` promotes it into the CAS namespace. Because the inode is namespace-invisible until `linkat`, there is **no TOCTOU window** and no partially-verified blob is ever readable. At manifest PUT, referenced-blob existence is checked (`MANIFEST_BLOB_UNKNOWN` on miss); `Content-Type` MUST agree with the manifest `mediaType` field to prevent type confusion (CVE-2021-41190 / GHSA-qq97-vm5h-rrhg).
- **Symlink-escape backstop.** Every CAS/upload path is resolved **beneath the trusted store root**: each component (`<repo…>`, `blobs`, `<alg>`, digest / `uploads`, id) is opened with `O_NOFOLLOW`, so a symlink planted at *any* level — not just the leaf — cannot redirect a read, stat, or append outside the store. This is a portable component-wise `openat`+`O_NOFOLLOW` walk (no kernel-version dependency); a symlinked/absent component is reported absent (404), a genuine `EACCES` still surfaces as 500. Blob fds are never opened `O_RDWR` after promotion.
- **Reflink over hardlink (a security choice).** Cross-repo mount and dedup promote in contract order: **reflink (`FICLONE`) first** — CoW, independent deletion, no write-through-shared-inode hazard — then a **hard link** (O(1) same-fs), then a **crash-atomic streaming copy** (cross-device / no-hardlink). The shared-inode write-through risk of the hard-link fallback is bounded by never opening blob fds for writing. An existing mount destination is validated as a **regular file, no-follow**, before it counts as an idempotent `201`.
- **Implementation status — Phase 2.** The Linux fast paths are **implemented** (`roci-storage`), each with a portable fallback and covered on a real-Linux run (`just coverage-linux`): monolithic `put_blob` promotes via **`O_TMPFILE`+`linkat`** (anonymous inode, digest verified before it is namespace-visible; `EEXIST` is dedup success only if the existing entry is a regular file, else rejected) and **falls back to temp+`fsync`+rename** on a filesystem without `O_TMPFILE` (NFS/overlay); blob reads/stats/appends use the **beneath-root no-follow walk** above; dedup/mount tries **reflink → hard link → streaming copy**. **Chunked upload staging is a named `uploads/<id>` file by design** — an `O_TMPFILE` inode cannot survive between the separate PATCH requests of a resumable upload — so its safety rests on the beneath-root `O_NOFOLLOW` append open, a **per-session lock** serializing append/finish/abort, a **cap re-check inside the finalize lock**, the monolithic PUT's trailing body **appended inside `finish_upload` under that same lock** (no concurrent-PATCH injection), digest verified **before** the atomic `rename`, and an **`fsync` of the staging file's data before promotion** so the renamed blob has durable contents (a crash before `fsync`+rename leaves a torn write under `uploads/` which is discarded on recovery — no corrupt named blob is ever visible in the CAS). The CAS directory and layout marker/parents are also fsynced. **Phase 5:** the single-record atomic WAL coupling of manifest + tag + referrer + backref edges is implemented (`MetaOp::PutManifest`; ARCHITECTURE invariant 15).
- **Cross-repo isolation is authoritative, not advisory.** The global existence filter and the small-blob content cache are **fast-path optimizations, never the sole authority for a `200`**: a HEAD/GET first confirms repo membership in the metadata index, so a globally-present blob in another repo yields `404`, closing the **presence/content oracle** (directly analogous to **GHSA-f2g3-hh2r-cwgc** cross-repo cache resurrection). The small-blob cache is keyed by `(repo, digest)` (or membership-checked post-lookup). Repo-local-by-default reads (`hydrateBlobOnRead=false`) stand; 307 redirects are repo-membership-gated.
- **GC as an integrity property.** A blob is collected only when unreferenced **and** past its grace period **and** not pinned by an in-flight upload (defends the Harbor in-flight-deletion class). Manifest commit + blob backref update are one atomic WAL record so a crash never desynchronizes them; a startup consistency check verifies every referenced blob is in the backref map before GC is enabled. **All delete paths** (blob-by-digest, tag, referrer) pass through a single `can_delete()` guard so `delete.enabled=false` cannot be bypassed via an alternate path (CVE-2026-41888 / GHSA-6pjf-3r9x-m592). **[implemented — Phase 5]** "Pinned by an in-flight upload" is enforced by a fence: every path about to depend on a blob (existence check / `HEAD` before a manifest push, finalize, put, mount) refreshes its GC stamp under a shared lock that the sweeper takes exclusively while it re-checks and unlinks, so a sweep can never delete a blob between a client's existence check and the manifest referencing it. Sweeps are refused until the startup consistency check has rebuilt every backref edge from the layout; a repository with an unreadable root manifest is never swept. GC is internal maintenance and does not pass the client `can_delete()` guard — it only removes unreferenced blobs past their grace period, never a manifest, tag or referrer.
- **Blobs are opaque bytes — never parsed by media type.** roci NEVER decompresses, extracts, or parses layer/artifact blob content (tar, gzip, zstd, Nydus RAFS, eStargz, SBOM, signatures) — no server-side zip/tar-bomb surface. The **only** server-side parsing is manifest/image-config JSON (bounded: size cap, recursion-depth cap, deterministic duplicate-key handling) and roci's own WAL.
- **Quota / exhaustion.** Per-repo and per-total storage quotas (`max_repo_bytes`, `max_total_bytes`) are checked at blob finalize (`507`/`413` when exceeded); concurrent-upload-session count is capped; list-endpoint `n` is capped. Prevents a single push from filling the disk and denying all clients. **[implemented — Phase 5]** `storage.quota.max_repo_bytes` → `413 SIZE_INVALID`, `max_total_bytes` → `507` (registry-wide across every storage path), `max_upload_sessions` (default 1024) → `429 TOOMANYREQUESTS`; admission is one check-and-charge critical section at finalize/mount (no concurrent overshoot), a rejected finalize discards its session, and abandoned sessions are expired by GC after the grace period so stale staging cannot pin the session cap forever.
- **Metadata is a rebuildable cache, never trusted over the CAS.** The WAL, rkyv snapshot, and filters are derived state — a blob GET always opens the content-addressed file, so a tampered index can at worst mis-map a tag to a *different existing* blob (which a digest-verifying client detects), never forge arbitrary content. Under a "compromised storage volume" threat model, the WAL/snapshot get an optional **HMAC** (per-deployment key) since CRC32C authenticates nothing against an adversary; the rkyv snapshot carries an integrity header verified before any zero-copy cast (a crafted snapshot is otherwise UB). **[implemented — Phase 5]** `storage.metadata.hmac_key_file` (≥ 32 bytes, its own file) adds an HMAC-SHA256 tag to every WAL record and makes it the snapshot's integrity field; replay stops at the first unauthenticated record, and a log whose framing/key does not match the configuration is moved aside (`roci-meta.log.untrusted-<ts>`) rather than trusted — the state is rebuilt from the layout. Without a key the snapshot header carries a CRC32C (corruption, not adversary, detection); in both cases the header is verified and the archive fully validated before the one zero-copy access.

## Secrets handling

- Sensitive config (backend credentials, LDAP bind password via `auth.ldap.bind_password_file`, bearer verification keys via `auth.bearer.verify_key_file`, mTLS CA via `http.tls.client_ca`, S3 keys via `secret_access_key_file`) live in separate referenced files with stricter filesystem permissions, mountable as Kubernetes Secrets (zot config model).
- Cloud credentials resolvable via environment / instance IAM roles rather than inline config (avoid secrets at rest in the main config).
- Credentials, tokens, and `Authorization` header values are never logged or attached to spans; telemetry redacts credential-bearing fields. A startup warning fires when a header mechanism is enabled without TLS.

## Security invariants (must never regress)

1. No `Storage` access before authentication + authorization of the request.
2. Excluded extensions are not compiled into the binary (attack surface = enabled features only).
3. Every blob write is digest-verified; every read is content-addressed.
4. Cross-repo dedupe never leaks content across repository boundaries on read.
5. No blob is fully buffered in memory; upload/download memory is bounded regardless of client behavior.
6. `roci-minimal` carries the minimum dependency set required for a conformant registry.
7. `unsafe` code is confined to audited modules and CI-gated. **Audited modules (Phase 5):** exactly one — `roci-storage::metadata::snapshot` (`memmap2::Mmap::map` of the read-only snapshot file, and `rkyv::access_unchecked` only after the header integrity check and a full bytecheck validation of the same immutable bytes); `roci-storage` is `#![deny(unsafe_code)]` with a scoped `#[allow]` on those two statements, every other crate stays `#![forbid(unsafe_code)]`. Residual risk: an external actor truncating the mapped file while roci runs can raise SIGBUS (same class as LMDB/redb).
8. `RepositoryName`, `Reference`, and upload-session IDs are validated against their spec grammars before any filesystem path is constructed from them; a `Storage`-layer backstop rejects `..`/`.`/`NUL` path components.
9. Only `sha256`/`sha512` are wire digests; BLAKE3 is internal-only and never a wire/descriptor digest.
10. The existence filter and small-blob cache are never the sole authority for a `200`; repo membership is confirmed before serving cross-repo-shared content (no presence/content oracle).
11. Cross-repo mount authorizes both source (pull) and destination (push); 307 redirects are repo-membership-gated and host-allowlisted.
12. All delete operations (blob/tag/referrer) pass through one `can_delete()` guard; `delete.enabled=false` cannot be bypassed by an alternate path.
13. Blob content is never parsed/decompressed by media type; only manifest/config JSON is parsed, under size + depth + duplicate-key bounds.
14. Every client-supplied count/size (`n`, manifest size, upload total) is bounded before allocation; timeouts and per-method rate limits are wired.

## Tracked prior-art CVE classes (regression targets)

Real registry advisories that the boundary controls above defend; each is a CI/test regression target.

| Class | Advisory | roci control |
| --- | --- | --- |
| Path traversal via name/layer | CVE-2021-21334, GHSA-hmfx-3pcx-653p, GHSA-qq97-vm5h-rrhg, Harbor CVE-2019-3990 | grammar validation before path construction (inv. 8) |
| Manifest type confusion | CVE-2021-41190 / GHSA-qq97-vm5h-rrhg | `Content-Type`↔`mediaType` agreement; digest allowlist (inv. 9) |
| Cross-repo mount authz bypass | Harbor GHSA-r4cx-r72v-m728 | double-authz mount (inv. 11) |
| Token scope confusion / JWT key injection | CVE-2020-13401, GHSA-phw4-mc57-4hwc | per-request scope binding |
| Pull-through credential exfiltration / SSRF | GHSA-3p65-76g6-3w7r, CVE-2022-24878, CVE-2023-45288, Harbor GHSA-jfh8-c2jp-hdph | no client-URL fetch; 307 allowlist; sync URL validation |
| HTTP/2 Rapid Reset | CVE-2023-44487 / GHSA-rr69-rxr6-8qwv | pinned patched `hyper`; `cargo audit` gate |
| Unbounded allocation / OOM | CVE-2023-2253 / GHSA-hqxw-f8mx-cpmw, GHSA-259w-8hf6-59bj | manifest size + `n` caps (inv. 14) |
| Cross-repo cache resurrection oracle | GHSA-f2g3-hh2r-cwgc | membership check before cache/filter `200` (inv. 10) |
| Delete-control bypass | CVE-2026-41888 / GHSA-6pjf-3r9x-m592 | single `can_delete()` guard (inv. 12) |
| Cache poisoning (mutable tag cached immutable) | GHSA-77mh-r6f6-crvq | tag/digest cache-control split |
| Digest downgrade (SHA-1) | SHAttered 2017 | wire digest allowlist (inv. 9) |
| TLS/0-RTT replay, cert-validation bypass | RFC 8470, CVE-2022-26945 | `425 Too Early` on non-idempotent; no `accept_invalid_certs` |

## Reporting security issues

A `SECURITY.md`-style responsible-disclosure policy (contact, embargo, coordinated disclosure) will govern reported vulnerabilities, following the zot precedent. TBD before first release.
