# Container image

roci ships as a **hardened, fully static** container image: a musl-static binary on a `scratch` base with no shell, no libc, and no package manager. It runs as an unprivileged nonroot UID (`65532`), and the storage directory is the only writable path. The image is built with the `full` feature set (S3, redb, LDAP, OpenTelemetry export, Prometheus `/metrics`, `mimalloc`).

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

In Kubernetes, mount the file from a ConfigMap and TLS keys — plus `storage.metadata.hmac_key_file` and an S3 `secret_access_key_file`, if used — from a Secret. Garbage collection, scrub quarantine (`.roci-quarantine/`) and metadata snapshots all stay inside the storage volume, so the read-only root filesystem is unaffected. See [Configuration](/guide/configuration) for every key.

## Image metadata

Every published image carries the [OCI pre-defined annotation keys](https://github.com/opencontainers/image-spec/blob/v1.1.1/annotations.md#pre-defined-annotation-keys) in three places: as image-config labels (`docker inspect`), as annotations on each per-arch manifest, and as annotations on the multi-arch index (which GHCR uses for the package description, source link, and license).

| Key | Value |
| --- | --- |
| `created` | Commit date of the built revision (UTC, RFC 3339). It is not the wall-clock build time, so rebuilding a commit gives the same value. |
| `version` | `X.Y.Z` for a `vX.Y.Z` release tag, otherwise `<cargo version>+g<short sha>` |
| `revision` | Full commit SHA |
| `source`, `url` | `https://github.com/jakobmoellerdev/roci` |
| `documentation` | `https://jakobmoellerdev.github.io/roci/` |
| `authors`, `vendor`, `licenses` | From `[workspace.package]` in `Cargo.toml` (`licenses` is an SPDX expression: `Apache-2.0`) |
| `title`, `description` | `roci`, plus a one-line summary |

`base.name`/`base.digest` are omitted because the runtime stage is `FROM scratch`, which has no reference or digest. `ref.name` is omitted because the spec scopes it to `index.json` descriptors in an image layout. [`scripts/oci-meta.sh`](https://github.com/jakobmoellerdev/roci/blob/main/scripts/oci-meta.sh) is the single source of these values for CI and `just container`. A release build fails if the tag does not match the `Cargo.toml` version.

```sh
docker buildx imagetools inspect --raw ghcr.io/jakobmoellerdev/roci:latest | jq .annotations
```

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
