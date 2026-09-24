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
| `--config` | TOML config file (see [Configuration](/guide/configuration)). |
| `--listen` | Address to bind (default `127.0.0.1:5000`). |
| `--storage-root` | Directory for the on-disk OCI image layout. |

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

Because storage is a plain [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md), you can also inspect the `--storage-root` directory directly with standard OCI tooling.
