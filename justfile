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

# Full local gate — run before pushing (the required CI checks).
ci: lint-workflows fmt clippy test build deps-guard

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
