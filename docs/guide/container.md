# Container image

roci ships as a **hardened, fully static** container image: a musl-static binary on a `scratch` base — no shell, no libc, no package manager — running as an unprivileged nonroot UID with the storage directory as the only writable path.

## Run

```sh
docker run --read-only -v roci-data:/var/lib/roci -p 5000:5000 \
  ghcr.io/jakobmoellerdev/roci
```

Mount the root filesystem read-only; only the storage volume needs to be writable.

## Build locally

```sh
just container          # build + smoke-test the running container
just container-multiarch # build the multi-arch image (linux/amd64, linux/arm64)
```

## Supply-chain provenance

`main` builds push to GHCR with a signed
[build-provenance attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations)
plus an embedded SBOM and SLSA provenance. Verify a pulled image with:

```sh
gh attestation verify oci://ghcr.io/jakobmoellerdev/roci:latest --owner jakobmoellerdev
```

## Platforms

Container images are **Linux-only** (OCI/Docker has no darwin runtime). The image
is built on native per-arch runners — no QEMU emulation:

- **Pull requests** build only `linux/arm64` (on an `ubuntu-24.04-arm` runner) to save time.
- **`main`** builds both `linux/amd64` and `linux/arm64`, assembles a multi-arch manifest, and pushes it to GHCR.

`darwin/amd64` and `darwin/arm64` binaries build cleanly from the same workspace and are produced by the release pipeline (macOS runners), not as container platforms.
