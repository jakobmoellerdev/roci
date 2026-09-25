#!/usr/bin/env bash
# Lint the roci Helm chart and assert its render-time security guards.
# Run from the repo root: `just helm-lint` (also the `lint` job of the CI
# `helm` workflow). Requires `helm` (3.18+ or 4.x).
set -euo pipefail

chart=charts/roci
S3="$chart/ci/s3-rustfs-values.yaml"

bash scripts/helm-deps.sh

helm lint --strict "$chart" --set auth.allowAnonymous=true
for f in "$chart"/ci/*-values.yaml; do
  helm lint --strict "$chart" -f "$f"
  helm template roci-ci "$chart" -n roci-ci -f "$f" >/dev/null
done

# expect_fail <substring> <helm template args...>: rendering must fail and
# name the guard that tripped.
expect_fail() {
  local want="$1" out
  shift
  if out="$(helm template roci-ci "$chart" -n roci-ci "$@" 2>&1)"; then
    echo "helm-lint: rendering succeeded, want failure containing: $want (args: $*)" >&2
    exit 1
  fi
  if [[ "$out" != *"$want"* ]]; then
    echo "helm-lint: rendering failed without: $want (args: $*)" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "helm-lint: rejected as expected: $want"
}

expect_fail 'set auth.allowAnonymous=true to run an open registry'
expect_fail 'rustfs.secret.allowInsecureDefaults is not permitted' -f "$S3" --set rustfs.secret.allowInsecureDefaults=true
expect_fail 'rustfs.mtls.enabled is unsupported' -f "$S3" --set rustfs.mtls.enabled=true
expect_fail 'rustfs.replicaCount must be >= 4' -f "$S3" --set rustfs.replicaCount=3
expect_fail 'S3 mode requires RustFS distributed mode' -f "$S3" --set rustfs.mode.standalone.enabled=true
expect_fail 's3.accessKeyId is required' -f "$S3" --set rustfs.secret.existingSecret=creds
expect_fail 'bogusKey' --set auth.allowAnonymous=true --set bogusKey=1
expect_fail 'containerSecurityContext' --set auth.allowAnonymous=true --set containerSecurityContext.privileged=true

echo "helm-lint: all checks passed"
