# Getting started

## Run a registry locally

roci starts a zero-config registry on `127.0.0.1:5000` by default:

```sh
cargo run -p roci-cli
```

Point [`skopeo`](https://github.com/containers/skopeo), [`crane`](https://github.com/google/go-containerregistry), or [`oras`](https://oras.land) at it. See the flags with:

```sh
cargo run -p roci-cli -- --help
```

Common flags:

| Flag | Purpose |
| --- | --- |
| `--listen` | Address to bind (default `127.0.0.1:5000`). |
| `--storage-root` | Directory for the on-disk content-addressable store. |

## Prerequisites

- **Rust** via [`rustup`](https://rustup.rs) — the pinned toolchain in `rust-toolchain.toml` installs automatically on the first `cargo` invocation.

That is all you need to *run* roci. To build, test, and contribute, see [Developing locally](/guide/developing).

## Push and pull

With a registry running on `127.0.0.1:5000`, copy an image into it with `skopeo`:

```sh
skopeo copy --dest-tls-verify=false \
  docker://alpine:latest \
  docker://127.0.0.1:5000/alpine:latest
```

Storage is a filesystem-backed content-addressable store: under `--storage-root`, each repository gets `<repo>/blobs/<algo>/<hex>`, `<repo>/manifests/<algo>/<hex>`, and `<repo>/tags/<tag>`. This is roci's own CAS layout, not an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md), so inspect it with those paths rather than expecting `oci-layout`/`index.json` at the root.
