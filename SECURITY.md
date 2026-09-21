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

All interaction is over HTTP APIs; roci supports the full zot authn matrix (see [`PLAN.md`](PLAN.md) Phase 6). Operators are strongly advised to enable a mechanism suited to their deployment to prevent unauthorized access.

| Mechanism | Notes |
| --- | --- |
| **HTTP Basic — local htpasswd** | bcrypt-hashed credentials in an htpasswd file. |
| **HTTP Basic — LDAP** | Bind against a directory; credentials never stored locally. |
| **HTTP Bearer token** | Docker V2 token scheme: `WWW-Authenticate` challenge → repo-scoped bearer token. Auth reference: [`spec/docker-registry-api-v2.md`](spec/docker-registry-api-v2.md). |
| **TLS mutual authentication (mTLS)** | Client-certificate verification; identity derived from the cert. |

TLS is supported for transport confidentiality; mTLS additionally authenticates the client. Anonymous access (e.g. public pull) is a policy choice, not a default.

## Authorization (access control)

After authentication, roci allows or denies a specific **action** by a **user/identity** on a specific **repository** — Identity-Based Access Control (IBAC).

- Policies map identity → repository (glob/prefix) → permitted actions (pull, push, delete, …).
- Default-deny where a policy is configured; explicit anonymous-pull opt-in.
- **Live authorization reload:** authz policy can be modified in the running config and reload without restart or dropping connections (zot supports live modification of authorization config). Only authorization is live-reloadable; other config changes require restart.

## Content trust & integrity

- **Digest verification everywhere.** Every blob is verified against its digest on write (hash-on-write during upload finalize) and its identity is its content address on read. Constant-time digest comparison. A digest mismatch is `DIGEST_INVALID`.
- **Repository boundaries.** Repo-local-by-default blob reads (zot v2.1.21 `hydrateBlobOnRead=false`): a digest present only in the cross-repo dedupe cache is **not** served from another repo — returns `404` until explicitly mounted (`end-11`) or uploaded. Prevents cross-repo content leakage via shared dedupe.
- **Data scrubbing.** The scrub extension re-hashes blobs periodically to detect bit-rot/tampering on disk and report it early.
- **Image signatures (extensions).** cosign and notation signatures stored/served via the referrers API; verification hooks let policy require valid signatures.
- **Vulnerability scanning (extension).** Trivy integration scans stored images; the vuln DB is refreshed on a configurable interval by the background scheduler. The scanner implementation is abstracted so it can change without user-facing impact.

## HTTP request-boundary controls

The HTTP edge is the primary untrusted-input boundary. Every control below is a **design requirement enforced before any storage or filesystem operation**; verdicts and CVE references come from an adversarial boundary review (`[refined from research]`).

- **Name / reference / digest validation before any path construction.** `RepositoryName`, `Reference`, and upload-session IDs MUST be parsed against their dist-spec grammars *before* a filesystem path is built from them (`RepositoryName` `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/…)*` ≤255 chars; `Reference` tag `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` or a digest). The spec name grammar excludes `..` by construction, so enforcing it is both spec-correct and traversal-proof; digest hex is charset-locked (`[a-f0-9]{64|128}`) so `blobs/<alg>/<hex>` can never contain a separator or `..`. Reject invalid input with `NAME_INVALID`/`DIGEST_INVALID`. **Defence-in-depth:** a `Storage`-layer backstop rejects any path component that is `..`, `.`, or contains `NUL`, even if the edge validated. (CVE-2021-21334 / GHSA-hmfx-3pcx-653p containerd path traversal; GHSA-qq97-vm5h-rrhg distribution name sanitisation; Harbor CVE-2019-3990.)
- **Wire digest algorithm allowlist.** Only `sha256` and `sha512` are accepted as wire digests; SHA-1/MD5/any unregistered algorithm → `DIGEST_INVALID` at parse time. **BLAKE3 is internal-only (scrub, Bao tree) and MUST NEVER appear as a wire/descriptor digest** — the referrers-index update path asserts every stored descriptor digest is in the allowlist (else a BLAKE3-unaware client silently skips verification = integrity bypass). (SHAttered 2017; OCI descriptor grammar.)
- **Cross-repo mount is double-authorized.** `POST …?mount=<digest>&from=<src>` (`end-11`) requires **pull on `<src>` AND push on the destination repo — two independent checks**, the source check *before* the blob is read. Checking only the destination lets a blob be exfiltrated from a private source into a readable destination. (Harbor GHSA-r4cx-r72v-m728; zot documents this class.)
- **Per-method authorization matrix + scope binding.** GET/HEAD⇒pull, POST/PATCH/PUT⇒push, DELETE⇒delete, checked per endpoint. Bearer-token `repository:<name>:<action>` scope is validated against the actual request path+method (constant-time name compare), never merely "a token is present." Anonymous-pull vs authenticated-push is enforced per endpoint. (CVE-2020-13401 scope confusion; GHSA-phw4-mc57-4hwc JWT signing-key injection; GHSA-3p65-76g6-3w7r pull-through credential exfiltration.)
- **SSRF / open-redirect containment.** roci never fetches a client- or manifest-supplied URL: `descriptor.urls` is not dereferenced; `subject`/`from` are repo names, not URLs. The 307 signed-URL redirect (remote backend) is emitted only after repo-membership verification, to a host matching a configured allowlist (never `169.254.169.254`/RFC-1918/link-local), with a short (≤60 s) blob-scoped signature. The `sync` extension validates upstream URLs at config load (public `https://` only; reject metadata/loopback/private ranges) and MUST NOT accept invalid TLS certs. (CVE-2022-24878 Flux, CVE-2023-45288 containerd pull-through, Harbor GHSA-jfh8-c2jp-hdph.)
- **Request-smuggling / desync hygiene.** HTTP/2 (frame-length framed) is the default and immune to CL/TE confusion; HTTP/1.1 keep-alive follows RFC 7230 (TE wins). Operators are warned that HTTP/1.1 behind a TE/CL-ambiguous proxy is a smuggling risk (prefer HTTP/2-only or a correct proxy). `Location`/response headers are built only from validated repo/id (no CRLF injection); header construction never `unwrap()`s attacker input into a panic. `hyper` is pinned past **CVE-2023-44487 / GHSA-rr69-rxr6-8qwv** (HTTP/2 Rapid Reset) and tracked by `cargo audit`.
- **DoS bounds (see also §DoS in Storage boundary).** Separate **manifest size cap** (default ≤4 MiB, distinct from the blob cap) checked before JSON parse; bounded JSON recursion depth; per-session upload size cap; `n`/pagination parameters on tag-list and referrers capped server-side (never allocate `O(n)` from a client integer); wired read/write timeouts + per-method rate limits. (CVE-2023-2253 / GHSA-hqxw-f8mx-cpmw catalog `n` OOM; GHSA-259w-8hf6-59bj referrers amplification.)
- **Cache-poisoning split (tag vs digest).** Manifest-by-**tag** responses are mutable → `Cache-Control: no-cache`/`must-revalidate`, no immutable ETag. Manifest/blob-by-**digest** responses are immutable → `ETag: "<digest>"`, `Cache-Control: immutable, max-age=31536000`, `If-None-Match`→`304`. Filtered referrers responses set an appropriate `Vary`. A mutable tag must never be cacheable as immutable. (GHSA-77mh-r6f6-crvq containerd cache poisoning; ARCHITECTURE invariant 14.)
- **TLS / 0-RTT.** Non-idempotent requests (POST/PATCH/PUT/DELETE) carrying TLS 1.3 `Early-Data` are rejected with `425 Too Early` (RFC 8470) — only idempotent GET/HEAD may use 0-RTT. kTLS fallback to userspace TLS is logged and alertable (`registry.sendfile.zerocopy{result=fallback}`), never silent. Cluster-peer mTLS uses a per-cluster CA / cert pinning; `accept_invalid_certs` is prohibited in sync and cluster configs. (RFC 8470; CVE-2022-26945 go-getter TLS bypass.)

## Storage-boundary controls

Everything operating on files derived from untrusted input. Content addressing is the structural backbone: the CAS path is a pure function of a validated digest, so substituting a blob's content changes its digest and thus its path — **content substitution in place is structurally impossible**.

- **Digest verified before promotion.** Upload streams into an anonymous `O_TMPFILE` inode with hash-on-write; the digest is verified **before** `linkat` promotes it into the CAS namespace. Because the inode is namespace-invisible until `linkat`, there is **no TOCTOU window** and no partially-verified blob is ever readable. At manifest PUT, referenced-blob existence is checked (`MANIFEST_BLOB_UNKNOWN` on miss); `Content-Type` MUST agree with the manifest `mediaType` field to prevent type confusion (CVE-2021-41190 / GHSA-qq97-vm5h-rrhg).
- **Symlink-escape backstop.** Every CAS/upload path is resolved **beneath the trusted store root**: each component (`<repo…>`, `blobs`, `<alg>`, digest / `uploads`, id) is opened with `O_NOFOLLOW`, so a symlink planted at *any* level — not just the leaf — cannot redirect a read, stat, or append outside the store. This is a portable component-wise `openat`+`O_NOFOLLOW` walk (no kernel-version dependency); a symlinked/absent component is reported absent (404), a genuine `EACCES` still surfaces as 500. Blob fds are never opened `O_RDWR` after promotion.
- **Reflink over hardlink (a security choice).** Cross-repo mount and dedup promote in contract order: **reflink (`FICLONE`) first** — CoW, independent deletion, no write-through-shared-inode hazard — then a **hard link** (O(1) same-fs), then a **crash-atomic streaming copy** (cross-device / no-hardlink). The shared-inode write-through risk of the hard-link fallback is bounded by never opening blob fds for writing. An existing mount destination is validated as a **regular file, no-follow**, before it counts as an idempotent `201`.
- **Implementation status — Phase 2.** The Linux fast paths are **implemented** (`roci-storage`), each with a portable fallback and covered on a real-Linux run (`just coverage-linux`): monolithic `put_blob` promotes via **`O_TMPFILE`+`linkat`** (anonymous inode, digest verified before it is namespace-visible; `EEXIST` is dedup success only if the existing entry is a regular file, else rejected) and **falls back to temp+`fsync`+rename** on a filesystem without `O_TMPFILE` (NFS/overlay); blob reads/stats/appends use the **beneath-root no-follow walk** above; dedup/mount tries **reflink → hard link → streaming copy**. **Chunked upload staging is a named `uploads/<id>` file by design** — an `O_TMPFILE` inode cannot survive between the separate PATCH requests of a resumable upload — so its safety rests on the beneath-root `O_NOFOLLOW` append open, a **per-session lock** serializing append/finish/abort, a **cap re-check inside the finalize lock**, the monolithic PUT's trailing body **appended inside `finish_upload` under that same lock** (no concurrent-PATCH injection), digest verified **before** the atomic `rename`, and an **`fsync` of the staging file's data before promotion** so the renamed blob has durable contents (a crash before `fsync`+rename leaves a torn write under `uploads/` which is discarded on recovery — no corrupt named blob is ever visible in the CAS). The CAS directory and layout marker/parents are also fsynced. The single-record atomic WAL coupling of tag+referrers+backref remains deferred to Phase 5.
- **Cross-repo isolation is authoritative, not advisory.** The global existence filter and the small-blob content cache are **fast-path optimizations, never the sole authority for a `200`**: a HEAD/GET first confirms repo membership in the metadata index, so a globally-present blob in another repo yields `404`, closing the **presence/content oracle** (directly analogous to **GHSA-f2g3-hh2r-cwgc** cross-repo cache resurrection). The small-blob cache is keyed by `(repo, digest)` (or membership-checked post-lookup). Repo-local-by-default reads (`hydrateBlobOnRead=false`) stand; 307 redirects are repo-membership-gated.
- **GC as an integrity property.** A blob is collected only when unreferenced **and** past its grace period **and** not pinned by an in-flight upload (defends the Harbor in-flight-deletion class). Manifest commit + blob backref update are one atomic WAL record so a crash never desynchronizes them; a startup consistency check verifies every referenced blob is in the backref map before GC is enabled. **All delete paths** (blob-by-digest, tag, referrer) pass through a single `can_delete()` guard so `delete.enabled=false` cannot be bypassed via an alternate path (CVE-2026-41888 / GHSA-6pjf-3r9x-m592).
- **Blobs are opaque bytes — never parsed by media type.** roci NEVER decompresses, extracts, or parses layer/artifact blob content (tar, gzip, zstd, Nydus RAFS, eStargz, SBOM, signatures) — no server-side zip/tar-bomb surface. The **only** server-side parsing is manifest/image-config JSON (bounded: size cap, recursion-depth cap, deterministic duplicate-key handling) and roci's own WAL.
- **Quota / exhaustion.** Per-repo and per-total storage quotas (`max_repo_bytes`, `max_total_bytes`) are checked at blob finalize (`507`/`413` when exceeded); concurrent-upload-session count is capped; list-endpoint `n` is capped. Prevents a single push from filling the disk and denying all clients.
- **Metadata is a rebuildable cache, never trusted over the CAS.** The WAL, rkyv snapshot, and filters are derived state — a blob GET always opens the content-addressed file, so a tampered index can at worst mis-map a tag to a *different existing* blob (which a digest-verifying client detects), never forge arbitrary content. Under a "compromised storage volume" threat model, the WAL/snapshot get an optional **HMAC** (per-deployment key) since CRC32C authenticates nothing against an adversary; the rkyv snapshot carries an integrity header verified before any zero-copy cast (a crafted snapshot is otherwise UB).

## Secrets handling

- Sensitive config (backend credentials, LDAP bind password, token signing keys) MAY live in separate referenced files with stricter filesystem permissions, and mount as Kubernetes Secrets (zot config model).
- Cloud credentials resolvable via environment / instance IAM roles rather than inline config (avoid secrets at rest in the main config).
- Signing/token keys never logged; telemetry redacts credential-bearing fields.

## Security invariants (must never regress)

1. No `Storage` access before authentication + authorization of the request.
2. Excluded extensions are not compiled into the binary (attack surface = enabled features only).
3. Every blob write is digest-verified; every read is content-addressed.
4. Cross-repo dedupe never leaks content across repository boundaries on read.
5. No blob is fully buffered in memory; upload/download memory is bounded regardless of client behavior.
6. `roci-minimal` carries the minimum dependency set required for a conformant registry.
7. `unsafe` code is confined to audited modules and CI-gated.
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
