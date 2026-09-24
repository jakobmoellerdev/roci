# Container image

roci ships as a **hardened, fully static** container image: a musl-static binary on a `scratch` base with no shell, no libc, and no package manager. It runs as an unprivileged nonroot UID (`65532`), and the storage directory is the only writable path. The image is built with the `full` feature set (OpenTelemetry export, Prometheus `/metrics`, `mimalloc`).

## Run

```sh
docker run -d --name roci --read-only \
  -v roci-data:/var/lib/roci -p 5000:5000 \
  ghcr.io/jakobmoellerdev/roci:latest
```

Mount the root filesystem read-only; only the storage volume needs to be writable. By default the container listens on `0.0.0.0:5000` and stores content in `/var/lib/roci`.

::: warning macOS
The AirPlay Receiver holds port `5000` on macOS. Publish another host port instead: `-p 5001:5000`.
:::

## Tags

| Tag | Meaning |
| --- | --- |
| `latest` | Newest release. |
| `X.Y.Z` / `X.Y` | A specific release, or the newest patch of a minor line. Pin one of these in production. |
| `main` | Rolling build of the `main` branch. |
| `<commit-sha>` | Immutable build of one commit. |

All tags are multi-arch manifests (`linux/amd64`, `linux/arm64`).

## Configuration file

Passing arguments replaces the default command (`--listen 0.0.0.0:5000 --storage-root /var/lib/roci`). A config file must therefore set both values itself:

```toml
# roci.toml
[http]
listen = "0.0.0.0:5000"

[storage]
root = "/var/lib/roci"

[telemetry.metrics]
enabled = true     # Prometheus scrape at /metrics
```

```sh
docker run -d --name roci --read-only \
  -v roci-data:/var/lib/roci \
  -v "$PWD/roci.toml:/etc/roci/roci.toml:ro" \
  -p 5000:5000 \
  ghcr.io/jakobmoellerdev/roci:latest --config /etc/roci/roci.toml
```

In Kubernetes, mount the file from a ConfigMap and TLS keys from a Secret. See [Configuration](/guide/configuration) for every key.

## Build locally

```sh
just container          # build + smoke-test the running container
just container-multiarch # build the multi-arch image (linux/amd64, linux/arm64)
```

## Supply-chain provenance

Every published image has a signed [build-provenance attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations), plus an embedded SBOM and SLSA provenance. Verify a pulled image with:

```sh
gh attestation verify oci://ghcr.io/jakobmoellerdev/roci:latest --owner jakobmoellerdev
```

## Platforms

Container images are **Linux-only**, because OCI/Docker has no darwin runtime. The image is built on native per-arch runners, with no QEMU emulation:

- **Pull requests** build and smoke-test only `linux/arm64` (on an `ubuntu-24.04-arm` runner) to save time.
- **`main`** and **`v*` release tags** build `linux/amd64` and `linux/arm64`, assemble a multi-arch manifest, and push it to GHCR.

`darwin/amd64` and `darwin/arm64` binaries are attached to each [GitHub release](https://github.com/jakobmoellerdev/roci/releases) instead of being published as container platforms.
