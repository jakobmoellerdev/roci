#!/usr/bin/env bash
# Build roci and run the OCI distribution conformance suite against it.
# Single source of truth shared by `just conformance`, the pre-commit hook,
# and mirrored by the `conformance` CI workflow.
#
# Requires: Go 1.17+ and the pinned spec submodule
# (spec/distribution-spec/conformance/). Fails loudly if either is missing so a
# commit cannot pass without a real conformance run.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

# The conformance suite is a Go module from the pinned submodule.
if [ ! -f spec/distribution-spec/conformance/go.mod ]; then
  echo "conformance: spec submodule missing — run 'just init' (git submodule update --init)" >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "conformance: Go toolchain not found (need Go 1.17+)" >&2
  exit 1
fi

# Build the full-flavor binary that CI conformance-tests.
cargo build --profile ci -p roci-cli --all-features

# Bind an ephemeral loopback port so a running dev server never collides.
port="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

storage="$(mktemp -d)"
./target/ci/roci --storage-root "$storage" --listen "127.0.0.1:${port}" &
srv=$!
cleanup() {
  kill "$srv" 2>/dev/null || true
  rm -rf "$storage"
}
trap cleanup EXIT

# Wait for readiness (GET /v2/ -> 200).
ready=""
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${port}/v2/" >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ -z "$ready" ]; then
  echo "conformance: roci did not become ready within 30s" >&2
  exit 1
fi

# Build the conformance binary and run all four categories from within the
# submodule dir (as CI does) so its report.html/junit.xml artifacts land
# inside the submodule, never the parent working tree.
(
  cd spec/distribution-spec/conformance
  go test -c -o conformance.test
  OCI_ROOT_URL="http://127.0.0.1:${port}" \
    OCI_NAMESPACE=roci-conformance/test \
    OCI_CROSSMOUNT_NAMESPACE=roci-conformance/other \
    OCI_AUTOMATIC_CROSSMOUNT=false \
    OCI_TEST_PULL=1 OCI_TEST_PUSH=1 OCI_TEST_CONTENT_DISCOVERY=1 OCI_TEST_CONTENT_MANAGEMENT=1 \
    OCI_HIDE_SKIPPED_WORKFLOWS=1 \
    ./conformance.test
)
