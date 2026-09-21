# roci task runner. Recipes mirror the CI gates 1:1 so `just ci` green ⇒ CI green.
# Requires `just` (https://github.com/casey/just). See README "Developing locally".

# List recipes.
default:
    @just --list

# Fetch the pinned OCI spec submodules (run once after clone).
init:
    git submodule update --init --depth 1

# Format check (CI `fmt` job).
fmt:
    cargo fmt --all --check

# Auto-format in place (dev convenience; not a CI gate).
fmt-fix:
    cargo fmt --all

# Lint both build flavors, warnings = errors (CI `clippy` job). Clippy is the
# sole gate that compiles the minimal flavor (ARCHITECTURE.md invariant 1).
clippy:
    cargo clippy --workspace --all-targets --all-features --profile ci -- -D warnings
    cargo clippy --workspace --no-default-features --profile ci -- -D warnings

# Tests via nextest + doctests (CI `test + coverage` job). `--cargo-profile ci`
# builds under the shared `ci` profile (nextest's own `--profile` selects a
# nextest test profile, of which only `default` exists).
test:
    cargo nextest run --workspace --all-features --cargo-profile ci
    cargo test --workspace --all-features --doc --profile ci

# Build both flavors (dev convenience). The minimal flavor's CI compile gate is
# now the clippy job; `just build` still compiles both locally as a sanity check.
build:
    cargo build --workspace --no-default-features --profile ci
    cargo build --workspace --all-features --profile ci

# Assert no extension crate leaks into the minimal build (CI `minimal-deps-guard` job).
deps-guard:
    #!/usr/bin/env bash
    set -euo pipefail
    if cargo tree -p roci-cli --no-default-features --edges normal --prefix none \
       | grep -E 'roci-ext-|roci-cluster'; then
      echo 'extension crate leaked into the minimal build'
      exit 1
    fi
    echo 'minimal dep graph clean'

# Supply-chain gate (CI `audit` job); requires `cargo deny` installed.
audit:
    cargo deny check

# Lint the GitHub Actions workflows (CI `actionlint` job). Requires `actionlint`.
lint-workflows:
    actionlint -color

# Security-audit the workflows (CI `zizmor` workflow). Requires `zizmor` (`uv tool install zizmor` or `cargo install zizmor`).
zizmor:
    zizmor .github/workflows .github/actions

# Enforce the 95% line-coverage floor, refresh COVERAGE.md + the README badge (CI `coverage` job).
# Requires `cargo-llvm-cov` (`cargo install cargo-llvm-cov`) + `llvm-tools-preview`.
coverage:
    bash scripts/coverage.sh

# Install the git pre-commit hook (fmt, clippy, coverage, conformance; workflow lint when workflows staged).
hooks:
    ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
    @echo "installed .git/hooks/pre-commit"

# Show the uncovered lines (developer aid; not a CI gate).
coverage-report:
    cargo llvm-cov --workspace --all-features --summary-only
    cargo llvm-cov report --show-missing-lines

# Reproduce the CI Linux coverage gate locally in a container (for darwin
# devs, and the only way to exercise the Linux-only fast paths). Builds the
# toolchain image once, copies the tracked working tree into a container via
# `docker cp` (no bind-mount, so it works regardless of Docker Desktop file
# sharing), runs scripts/coverage.sh on real Linux, and copies the regenerated
# lcov.info / cobertura.xml / COVERAGE.md / README badge back to the host.
# A named volume holds the Linux build artifacts across runs (fast re-runs);
# they never touch the host's macOS target/. Requires Docker.
coverage-linux:
    #!/usr/bin/env bash
    set -euo pipefail
    root="$(git rev-parse --show-toplevel)"
    docker build -t roci-coverage:local -f Containerfile.coverage .
    name="roci-cov-$$"
    # A fresh per-run target volume: reusing one across runs let stale
    # `.profraw`/artifacts from a previous commit skew the measured line set
    # (a false 100%). An ephemeral volume guarantees the gate reflects the
    # current tree — the price is a full Linux recompile each run.
    vol="roci-coverage-target-$$"
    docker volume create "$vol" >/dev/null
    # A helper container with the target volume mounted; we cp the source in,
    # run the gate as non-root, cp results out, then remove container + volume.
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker create --name "$name" -v "$vol":/target -w /roci \
      roci-coverage:local \
      bash -c "chown -R roci:roci /roci /target && su roci -c 'export CARGO_HOME=/home/roci/.cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:\$PATH && git config --global --add safe.directory /roci && cd /roci && bash scripts/coverage.sh'" >/dev/null
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true; docker volume rm "$vol" >/dev/null 2>&1 || true' EXIT
    # Copy the tracked tree in (including .git so coverage.sh's `git rev-parse`
    # works). COPYFILE_DISABLE + --no-xattrs/--no-mac-metadata strip macOS
    # AppleDouble and com.apple.provenance xattrs the Linux extractor rejects;
    # target/ is excluded so host macOS artifacts never enter the Linux build.
    COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata \
      --exclude=./target --exclude='._*' --exclude='*/fsmonitor--daemon.ipc' \
      -C "$root" -cf - . | docker cp - "$name:/roci"
    docker start -a "$name" && rc=0 || rc=$?
    # Copy the regenerated reports back regardless of pass/fail.
    for f in lcov.info cobertura.xml COVERAGE.md README.md; do
      docker cp "$name:/roci/$f" "$root/$f" 2>/dev/null || true
    done
    exit $rc

# Reproduce the CI CodeQL rust analysis locally (macOS devs cannot run the
# CodeQL check, which is Linux-only) and print the path-injection alert count.
# Builds the pinned CodeQL bundle image, extracts a database with the in-repo
# barrier model pack applied, and fails if any path-injection alert remains —
# so the sanitizer model can be validated without blind CI round-trips.
# Requires Docker.
codeql-local:
    #!/usr/bin/env bash
    set -euo pipefail
    root="$(git rev-parse --show-toplevel)"
    docker build -t roci-codeql:local -f Containerfile.codeql .
    name="roci-codeql-$$"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker create --name "$name" -w /roci roci-codeql:local sleep infinity >/dev/null
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
    docker start "$name" >/dev/null
    COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata \
      --exclude=./target --exclude='._*' --exclude='*/fsmonitor--daemon.ipc' \
      -C "$root" -cf - . | docker cp - "$name:/roci"
    docker exec "$name" bash -c '
      set -euo pipefail
      cd /roci
      codeql database create /db --language=rust --build-mode=none --overwrite >/dev/null 2>&1
      codeql database analyze /db --rerun --format=sarif-latest --output=/tmp/r.sarif \
        --additional-packs=/roci/.github/codeql/extensions \
        --model-packs=roci/path-sanitizers rust-code-scanning.qls >/dev/null 2>&1
      n=$(jq "[.runs[].results[]|select(.ruleId==\"rust/path-injection\")]|length" /tmp/r.sarif)
      echo "rust/path-injection alerts: $n"
      test "$n" = "0"
    '

# Run the roci-storage test suite on real ext4 / btrfs / XFS filesystems
# (macOS/CI run only on a single overlay/ext4, so the per-FS reflink / hard-link
# / O_TMPFILE / copy branches are otherwise only simulated via FORCE_* seams).
# Builds Containerfile.filesystems, then in a PRIVILEGED container makes a
# loopback image of each filesystem, mounts it, and runs the suite with TMPDIR
# on the mount so FsStorage exercises that filesystem's real syscall behavior.
# Requires Docker with privileged/loop support.
test-filesystems:
    #!/usr/bin/env bash
    set -euo pipefail
    root="$(git rev-parse --show-toplevel)"
    docker build -t roci-filesystems:local -f Containerfile.filesystems .
    name="roci-fs-$$"
    docker rm -f "$name" >/dev/null 2>&1 || true
    # Privileged + loop control so the harness can losetup/mount loopback images.
    docker create --privileged --name "$name" -w /roci roci-filesystems:local sleep infinity >/dev/null
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
    docker start "$name" >/dev/null
    COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata \
      --exclude=./target --exclude='._*' --exclude='*/fsmonitor--daemon.ipc' \
      -C "$root" -cf - . | docker cp - "$name:/roci"
    docker exec "$name" bash /roci/scripts/test-filesystems.sh

# Full local gate — run before pushing (the required CI checks).
ci: lint-workflows fmt clippy test build deps-guard coverage conformance

# Build + run the OCI conformance suite against a locally-started roci
# (CI `conformance` job). Requires Go 1.17+ and the pinned spec submodule
# (run `just init` first if absent). Shares scripts/conformance.sh with the
# pre-commit hook.
conformance: init
    bash scripts/conformance.sh

# Build the hardened scratch image and smoke-test the running container
# (CI `container` workflow). Requires Docker. Uses a named volume so the
# image's nonroot ownership is preserved on the read-only root FS.
container:
    #!/usr/bin/env bash
    set -euo pipefail
    docker build -t roci:local -f Containerfile .
    docker rm -f roci-local >/dev/null 2>&1 || true
    docker volume rm roci-local-data >/dev/null 2>&1 || true
    docker volume create roci-local-data >/dev/null
    docker run -d --name roci-local -p 5000:5000 --read-only -v roci-local-data:/var/lib/roci roci:local
    trap 'docker rm -f roci-local >/dev/null 2>&1 || true; docker volume rm roci-local-data >/dev/null 2>&1 || true' EXIT
    for _ in $(seq 1 30); do
      [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/v2/)" = "200" ] && break || sleep 1
    done
    test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/v2/)" = "200"
    data="hello-roci"; digest="sha256:$(printf '%s' "$data" | shasum -a 256 | cut -d' ' -f1)"
    test "$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary "$data" "http://127.0.0.1:5000/v2/smoke/repo/blobs/uploads/?digest=$digest")" = "201"
    test "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:5000/v2/smoke/repo/blobs/$digest")" = "200"
    echo "container smoke test passed"

# Build the multi-arch image for both Linux platforms (requires buildx + QEMU).
container-multiarch:
    docker buildx build --platform linux/amd64,linux/arm64 -t roci:multiarch -f Containerfile .
