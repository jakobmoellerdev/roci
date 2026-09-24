# Getting started

roci is a single binary. Run it as a container, as a downloaded release binary, or from source. Each option starts a zero-config registry: no config file and no database.

::: warning macOS: port 5000
On macOS, the AirPlay Receiver (Control Center) already listens on `*:5000`. A roci **binary** still binds `127.0.0.1:5000` fine, but `docker run -p 5000:5000` fails. On macOS, publish another host port (e.g. `-p 5001:5000`, used below), or turn off *System Settings → General → AirDrop & Handoff → AirPlay Receiver*.
:::

## Option 1: container image

Multi-arch (`linux/amd64`, `linux/arm64`), static, `scratch`-based, runs as a nonroot user:

```sh
docker run -d --name roci --read-only \
  -v roci-data:/var/lib/roci -p 5001:5000 \
  ghcr.io/jakobmoellerdev/roci:latest

curl http://localhost:5001/v2/   # → {}
```

Content persists in the `roci-data` volume across restarts. See [Container image](/guide/container) for tags, config files, and provenance verification.

## Option 2: release binary

Every [GitHub release](https://github.com/jakobmoellerdev/roci/releases) ships static Linux (musl) and macOS binaries for `x86_64` and `aarch64`:

```sh
# Pick one: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl,
#           x86_64-apple-darwin, aarch64-apple-darwin
TARGET=aarch64-apple-darwin
curl -fsSLO "https://github.com/jakobmoellerdev/roci/releases/latest/download/roci-${TARGET}.tar.gz"
curl -fsSL "https://github.com/jakobmoellerdev/roci/releases/latest/download/roci-${TARGET}.tar.gz.sha256" | shasum -a 256 -c
tar xzf "roci-${TARGET}.tar.gz"

# Optional: verify the signed build provenance
gh attestation verify "roci-${TARGET}.tar.gz" --owner jakobmoellerdev

./roci-${TARGET}/roci --storage-root ./roci-data
```

## Option 3: from source

Requires **Rust** via [`rustup`](https://rustup.rs). The pinned toolchain in `rust-toolchain.toml` installs automatically on the first `cargo` invocation.

```sh
git clone https://github.com/jakobmoellerdev/roci && cd roci
cargo run -p roci-cli                     # minimal build
cargo run -p roci-cli --features full     # + OpenTelemetry export, Prometheus /metrics, mimalloc
```

To build, test, and contribute, see [Developing locally](/guide/developing).

## Flags

```sh
roci --help
```

| Flag | Purpose |
| --- | --- |
| `--config` | TOML config file (see [Configuration](/guide/configuration)). |
| `--listen` | Address to bind (default `127.0.0.1:5000`). |
| `--storage-root` | Directory for the on-disk OCI image layout (default `./roci-data`). |

## Push and pull

The examples use `localhost:5001` (the container from option 1). For a binary or source build, use `127.0.0.1:5000`.

Copy a multi-arch image in with [`skopeo`](https://github.com/containers/skopeo). `--all` copies the whole image index. Without it, skopeo on macOS looks for a `darwin` image and fails:

```sh
skopeo copy --all --dest-tls-verify=false \
  docker://alpine:latest \
  docker://localhost:5001/alpine:latest

curl http://localhost:5001/v2/alpine/tags/list   # → {"name":"alpine","tags":["latest"]}
```

Docker treats `localhost` registries as insecure-allowed, so push and pull work without extra setup:

```sh
docker pull localhost:5001/alpine:latest
docker tag localhost:5001/alpine:latest localhost:5001/mine:v1
docker push localhost:5001/mine:v1
```

[`oras`](https://oras.land) and [`crane`](https://github.com/google/go-containerregistry) work the same way, e.g. `oras repo tags --plain-http localhost:5001/alpine`.

::: tip Docker Desktop + a host binary
If roci runs as a binary on the host, Docker Desktop's daemon (inside its VM) cannot reach the host's `127.0.0.1`. Use `skopeo`/`oras`/`crane` against the binary, or run roci as a container (option 1) to `docker push`/`docker pull`.
:::

Storage is a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) with one layout per repository (`<storage-root>/<repo>/{oci-layout,index.json,blobs/}`), so you can inspect it with standard OCI tooling.

## Next steps

- [Configuration](/guide/configuration): TLS, rate limits, size limits, telemetry.
- [Container image](/guide/container): tags, config files, provenance.
