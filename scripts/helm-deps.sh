#!/usr/bin/env bash
# Fetch the roci chart's subchart archives into charts/roci/charts/, verified
# against the committed charts/roci/Chart.lock. `helm dependency build` needs
# the repositories registered; a throwaway repo config keeps the user's helm
# setup untouched. Used by scripts/helm-lint.sh and scripts/k0s-e2e.sh.
set -euo pipefail

chart=charts/roci
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export HELM_REPOSITORY_CONFIG="$tmp/repositories.yaml"
export HELM_REPOSITORY_CACHE="$tmp/cache"

helm repo add rustfs https://charts.rustfs.com >/dev/null
helm dependency build "$chart" >/dev/null
