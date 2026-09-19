# syntax=docker/dockerfile:1

# Hardened, fully static, scratch-based image for roci.
#
# Build stage compiles a static musl binary; the final stage is `scratch` (no
# shell, no libc, no package manager) containing only the binary and running as
# an unprivileged numeric UID. This is the smallest possible attack surface
# (SECURITY.md: rootless, no capabilities, read-only root FS with the storage
# volume the only writable mount).
#
# Multi-arch: linux/amd64 and linux/arm64 (container images are Linux-only;
# macOS/darwin binaries are produced as release artifacts, not container images).
#
# Build (single arch, local):
#   docker build -t roci:latest .
# Build (multi-arch, requires buildx + QEMU):
#   docker buildx build --platform linux/amd64,linux/arm64 -t roci:latest .

# --- Build stage: musl-static compile --------------------------------------
FROM --platform=$BUILDPLATFORM rust:1.98-alpine AS builder

# musl-dev provides the static C runtime bits; no other C deps are used.
RUN apk add --no-cache musl-dev

WORKDIR /src

# Map the target platform to a Rust musl target so cross-arch builds work.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) echo "x86_64-unknown-linux-musl" > /tmp/rust-target ;; \
      arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    rustup target add "$(cat /tmp/rust-target)"

# Copy the whole workspace and build the CLI statically. (Spec submodules are
# not needed to build the binary; only to run the conformance suite.)
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    target="$(cat /tmp/rust-target)" && \
    cargo build --release --target "$target" -p roci-cli && \
    cp "target/$target/release/roci" /roci && \
    strip /roci

# Pre-create the storage directory owned by the nonroot UID so the scratch
# image has a writable data dir without needing a shell or chown at runtime.
RUN mkdir -p /rootfs/var/lib/roci && chown -R 65532:65532 /rootfs/var/lib/roci

# --- Final stage: scratch --------------------------------------------------
FROM scratch AS runtime

# Copy the static binary and the pre-owned storage directory.
COPY --from=builder /roci /roci
COPY --from=builder --chown=65532:65532 /rootfs/var/lib/roci /var/lib/roci

# Run as an unprivileged, well-known nonroot UID:GID (no shell, no root).
USER 65532:65532

# The storage directory is the only writable path; the rest of the root FS can
# be mounted read-only.
VOLUME ["/var/lib/roci"]
EXPOSE 5000

ENTRYPOINT ["/roci"]
CMD ["--listen", "0.0.0.0:5000", "--storage-root", "/var/lib/roci"]
