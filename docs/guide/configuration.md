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

### Observability notes

- Traces, metrics, and logs share one OpenTelemetry pipeline; an incoming W3C `traceparent` header is honored.
- Metric labels are bounded (`endpoint`, `method`, `status_class`, `error_code`); digests, tags, and repository names appear only on spans and logs.
- Keep every error or slow trace with the OTel Collector's `tail_sampling` processor; roci only head-samples.
- A minimal build (no `otel` feature) logs a warning and ignores `telemetry.otlp` / `telemetry.metrics.enabled`.

## Build flavors

roci compiles in two flavors (see [Architecture](/design/architecture)):

- **minimal** — the core distribution API only, with the smallest possible dependency graph.
- **full** — the core plus the optional extensions (`roci-ext-*`) for signatures, search, sync, and scanning, OpenTelemetry export, and the `mimalloc` allocator. Release binaries and the container image are built with `full`.

Every extension is reachable from the CLI **only** behind a cargo feature, never as an unconditional dependency. Behavior is then selected at runtime through configuration.

## Filesystem guidance

For manifest-dense stores on ext4, keep the default 4 KiB block size and do **not** enable `bigalloc`: it raises the allocation unit to the cluster size (e.g. 64 KiB), wasting most of each small manifest or config file.

Phase 5 storage knobs (garbage collection, quotas, multiple storage paths) are added to this file together with the features they configure — see [`PLAN.md`](https://github.com/jakobmoellerdev/roci/blob/main/PLAN.md).
