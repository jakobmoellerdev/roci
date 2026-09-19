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

# Lint both build flavors, warnings = errors (CI `clippy` job).
clippy:
    cargo clippy --workspace --all-targets --all-features --profile ci -- -D warnings
    cargo clippy --workspace --no-default-features -- -D warnings

# Tests via nextest + doctests (CI `test` job).
test:
    cargo nextest run --workspace --all-features --profile ci
    cargo test --workspace --all-features --doc

# Build both flavors (CI `build-flavors` job).
build:
    cargo build --workspace --no-default-features
    cargo build --workspace --all-features

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

# Enforce 100% line coverage, refresh COVERAGE.md + the README badge (CI `coverage` job).
# Requires `cargo-llvm-cov` (`cargo install cargo-llvm-cov`) + `llvm-tools-preview`.
coverage:
    bash scripts/coverage.sh

# Install the git pre-commit hook (fmt, clippy, workflow lint, coverage).
hooks:
    ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
    @echo "installed .git/hooks/pre-commit"

# Show the uncovered lines (developer aid; not a CI gate).
coverage-report:
    cargo llvm-cov --workspace --all-features --summary-only
    cargo llvm-cov report --show-missing-lines

# Full local gate — run before pushing (the required CI checks).
ci: lint-workflows fmt clippy test build deps-guard coverage

# Requires Go 1.17+. Serves on 127.0.0.1:5000 with a temp storage root.
# NOTE: the roci CLI flags below are the intended shape; align with roci-cli's actual arg parser once Phase 0 lands.
# Build + run the OCI conformance suite against a locally-started roci (CI `conformance` job).
conformance: init
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --profile ci -p roci-cli --all-features
    storage="$(mktemp -d)"
    ./target/ci/roci --storage-root "$storage" --listen 127.0.0.1:5000 &
    srv=$!
    trap 'kill $srv 2>/dev/null || true' EXIT
    for _ in $(seq 1 30); do
      curl -sf http://127.0.0.1:5000/v2/ >/dev/null && break || sleep 1
    done
    ( cd spec/distribution-spec/conformance && go test -c -o conformance.test )
    OCI_ROOT_URL=http://127.0.0.1:5000 \
    OCI_NAMESPACE=roci-conformance/test \
    OCI_CROSSMOUNT_NAMESPACE=roci-conformance/other \
    OCI_TEST_PULL=1 OCI_TEST_PUSH=1 OCI_TEST_CONTENT_DISCOVERY=1 OCI_TEST_CONTENT_MANAGEMENT=1 \
    OCI_HIDE_SKIPPED_WORKFLOWS=1 \
    ./spec/distribution-spec/conformance/conformance.test

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
