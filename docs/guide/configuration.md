# Configuration

roci follows a **config-driven** design: all behavior is controlled from configuration rather than build-time code paths. It starts with zero config and sane defaults, and grows into a single declarative **TOML** file — no external database is required to run.

## Zero-config defaults

With no configuration, roci:

- Listens on `127.0.0.1:5000` (plaintext HTTP/1.1 and HTTP/2 prior-knowledge).
- Stores content as an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) under `./roci-data`.
- Enables only the core distribution API — no extensions, no rate limits, no telemetry export.

## Command-line flags

| Flag | Purpose |
| --- | --- |
| `--config <PATH>` | Load a TOML config file. Unknown keys and invalid values abort startup with a field-qualified error (non-zero exit). |
| `--listen <ADDR>` | Override `http.listen`. |
| `--storage-root <DIR>` | Override `storage.root`. |

Flags are applied on top of the file, and the result is validated again.

## Configuration file

Every section and field is optional; omitted fields keep the defaults shown.

```toml
[http]
listen = "127.0.0.1:5000"

# TLS termination (omit for plaintext). TLS 1.3 preferred, 1.2 allowed; ALPN h2 + http/1.1;
# session-ticket resumption. 0-RTT early data is refused.
# tls = { cert = "/etc/roci/tls.crt", key = "/etc/roci/tls.key" }

[http.timeouts]
read_header_secs = 10   # max time to receive a request head
idle_secs = 120         # idle keep-alive connections are closed after this

[http.rate_limit]
enabled = false
# Token buckets: `rate` requests/second sustained, `burst` capacity. Global per method.
# default = { rate = 200, burst = 400 }        # methods without their own bucket
# per_method.PUT   = { rate = 20, burst = 40 } # GET HEAD POST PUT PATCH DELETE
# Exhausted → 429 TOOMANYREQUESTS with Retry-After. A method with no bucket and no default is unlimited.

[storage]
root = "./roci-data"
cache_max_bytes = 268435456   # small-blob LRU cache budget; 0 disables it
dedupe = true                 # link (reflink → hard link) a blob another repo already stores
commit = false                # fsync blob data before acknowledging (zot's `commit`); manifests/WAL/index are always synced

[storage.gc]                  # online, O(garbage) garbage collection
enabled = true
delay_secs = 3600             # grace period an unreferenced blob must stay untouched
interval_secs = 3600          # period between sweeps

[storage.scrub]               # background integrity verification
enabled = false
interval_secs = 86400         # target period of one full pass
max_bytes_per_sec = 67108864  # read-bandwidth ceiling
mode = "auto"                 # auto: delegate to btrfs/ZFS scrub where present; app: always run

[storage.quota]               # 0 = unlimited
max_repo_bytes = 0            # per repository → 413 SIZE_INVALID
max_total_bytes = 0           # registry-wide, across every storage path → 507
max_upload_sessions = 1024    # concurrent upload sessions → 429 TOOMANYREQUESTS

[storage.metadata]
engine = "log"                # log: append-only WAL + in-RAM maps; redb: embedded B-tree KV (`redb` build)
snapshot = false              # log engine: serve from an rkyv mmap snapshot + WAL tail
compact_threshold_bytes = 67108864  # compact the WAL / cut a snapshot past this size
# hmac_key_file = "/etc/roci/meta.key"  # ≥ 32-byte key authenticating WAL records + snapshot

# Route a repository prefix to its own storage path or backend (zot `subPaths`).
# The longest prefix on a `/` boundary wins; roots must not nest.
# [storage.subpaths."team-a"]
# root = "/srv/roci/team-a"

# S3-compatible object storage (the `s3` build). `root` then holds only local state
# (metadata WAL, upload staging); blobs, manifests and index.json live in the bucket.
# [storage.subpaths.mirror]
# root = "/var/lib/roci/mirror-state"
# s3 = { bucket = "roci", region = "eu-central-1", prefix = "registry",
#        secret_access_key_file = "/run/secrets/s3", access_key_id = "AKIA…",
#        redirect_min_size = 1048576, redirect_ttl_secs = 60 }

[limits]
max_body = 268435456          # one request body (chunk or monolithic upload)
max_upload = 5368709120       # cumulative bytes per upload session
max_manifest = 4194304        # manifest size, checked before JSON parse (must be <= max_body)
max_page = 1000               # server-side cap on `n` for tags / referrers

[delete]
enabled = true                # false → every delete endpoint returns 405 UNSUPPORTED

[log]
level = "info"                # tracing EnvFilter directive; RUST_LOG takes precedence
format = "text"               # or "json"

[telemetry]                   # effective in builds with the `otel` feature (e.g. `full`)
sample_ratio = 0.01           # head sampling for root traces, [0, 1]
# otlp = { endpoint = "http://localhost:4317", protocol = "grpc" }  # or protocol = "http" (:4318)
metrics = { enabled = false, path = "/metrics" }  # Prometheus scrape view; path must not be under /v2
```

### Authentication & access control

Auth is **opt-in**: no auth layer is installed unless at least one of `auth.htpasswd`, `auth.ldap`, `auth.bearer`, `access_control`, or `http.tls.client_auth != "none"` is configured. Without any, behavior is identical to a registry with no auth.

::: warning /metrics is unauthenticated
The Prometheus `/metrics` endpoint is merged after the auth-gated router and stays unauthenticated regardless of auth configuration. Restrict access to it via network policy or a reverse proxy if needed.
:::

```toml
[auth]
realm = "roci"              # WWW-Authenticate realm for Basic challenges (default "roci")
cache_ttl_secs = 60         # credential cache TTL; max 3600, 0 disables caching

# --- HTTP Basic: local htpasswd (bcrypt only: $2a$/$2b$/$2y$) ---
[auth.htpasswd]
path = "/etc/roci/htpasswd"

# --- HTTP Basic: LDAP (requires the `ldap` cargo feature / `full` build) ---
# [auth.ldap]
# url = "ldaps://ldap.example.com"          # ldaps:// or ldap:// with start_tls = true
# start_tls = false
# bind_dn = "cn=svc,dc=example,dc=com"
# bind_password_file = "/run/secrets/ldap"
# base_dn = "ou=people,dc=example,dc=com"
# user_attribute = "uid"                    # default "uid"
# user_filter = "(objectClass=person)"      # optional; must start with ( and end with )
# group_attribute = "memberOf"              # optional; returns LDAP group DNs for the user
# ca_file = "/etc/roci/ldap-ca.pem"         # optional; system roots used if absent
# timeout_secs = 5

# --- HTTP Bearer: external token server (roci does not issue tokens) ---
# [auth.bearer]
# realm = "https://auth.example.com/token"
# service = "registry.example.com"
# issuer = "auth.example.com"
# verify_key_file = "/etc/roci/token-key.pem"  # PEM: PUBLIC KEY and/or CERTIFICATE blocks (ES256, RS256)

# --- mTLS fields on [http.tls] ---
# [http.tls]
# cert = "/etc/roci/tls.crt"
# key = "/etc/roci/tls.key"
# client_auth = "none"         # none | optional | required (default "none")
# client_ca = "/etc/roci/client-ca.pem"          # required when client_auth != none
# client_cert_sha256 = ["aabbccdd...64hex..."]    # optional leaf-fingerprint pins (case-insensitive)

# --- Access control (IBAC) ---
[access_control]
admins = ["admin"]                               # these identities get all actions on all repos

[access_control.groups]
team-a = ["alice", "bob"]                         # config-defined groups (also merged with LDAP groups)

[[access_control.repositories]]
pattern = "team-a/**"                             # glob: * within component, ** across (incl. empty)
anonymous = ["pull"]                              # actions granted to anonymous requests
authenticated = ["pull"]                          # actions granted to any authenticated user
policies = [
  { users = ["alice"], actions = ["pull", "push", "delete"] },
  { groups = ["team-a"], actions = ["pull", "push"] },
]

[[access_control.repositories]]
pattern = "public/**"
anonymous = ["pull"]
authenticated = ["pull", "push"]
```

**Authentication order:** `Authorization` header decides (Basic: htpasswd first, then LDAP; Bearer: JWT verify) → else verified client cert → else Anonymous. An invalid header always yields `401`, never falls back to anonymous. **Exception:** `Basic` with both user and password empty (the `:` pair) is treated as no credentials — container-image clients (skopeo, podman, buildah) send this when answering a Basic challenge without stored credentials, so anonymous pull still works.

**IBAC rule matching:** the single most-specific rule wins (most literal bytes, then fewest wildcards, then earliest). A narrow rule can remove grants a broad one gives. Bearer token principals are authorized only by their token's `access` claims (IBAC not consulted).

**Live reload:** only `[access_control]` is reloaded (2 s file poll). Changes to `[auth]`, `[auth.htpasswd]`, `[auth.ldap]`, `[auth.bearer]`, or `[http.tls]` require a restart.

### Observability notes

- Traces, metrics, and logs share one OpenTelemetry pipeline; an incoming W3C `traceparent` header is honored.
- Metric labels are bounded (`endpoint`, `method`, `status_class`, `error_code`); digests, tags, and repository names appear only on spans and logs.
- Keep every error or slow trace with the OTel Collector's `tail_sampling` processor; roci only head-samples.
- A minimal build (no `otel` feature) logs a warning and ignores `telemetry.otlp` / `telemetry.metrics.enabled`.

## Build flavors

roci compiles in two flavors (see [Architecture](/design/architecture)):

- **minimal** — the core distribution API only, with the smallest possible dependency graph.
- **full** — the core plus the optional extensions (`roci-ext-*`) for signatures, search, sync, and scanning, the S3 storage backend (`s3`), the embedded redb metadata engine (`redb`), LDAP authentication (`ldap`), OpenTelemetry export, and the `mimalloc` allocator. Release binaries and the container image are built with `full`. Configuring `s3`, `engine = "redb"`, or `auth.ldap` in a build without the corresponding feature aborts startup with a field-qualified error.

Every extension is reachable from the CLI **only** behind a cargo feature, never as an unconditional dependency. Behavior is then selected at runtime through configuration.

## Storage notes

- **Garbage collection** runs online. A blob is reclaimed only after it has been unreferenced by every manifest in its repository *and* untouched (no push, `HEAD`, or existence check) for `delay_secs`; at startup a consistency check rebuilds missing backref edges from the layout before the first sweep, so a pre-existing or externally written layout is never collected by mistake. Abandoned upload sessions older than `delay_secs` are removed by the same sweep.
- **Quotas** count logical bytes: a blob counts once per repository that holds it, even when deduplicated on disk.
- **Scrub** verifies each blob against the CRC32C recorded when it was written and re-hashes with the full digest only on a mismatch; a blob whose content no longer matches its digest is moved to `<root>/.roci-quarantine/` so it reads as absent and can be pushed again.
- **HMAC keys** and **S3 secrets** are read from separate files so they can carry stricter permissions or be mounted as Kubernetes Secrets.

## Filesystem guidance

For manifest-dense stores on ext4, keep the default 4 KiB block size and do **not** enable `bigalloc`: it raises the allocation unit to the cluster size (e.g. 64 KiB), wasting most of each small manifest or config file. On btrfs or ZFS keep `scrub.mode = "auto"`: the filesystem's own scrub already verifies every block, so roci skips its application pass.
