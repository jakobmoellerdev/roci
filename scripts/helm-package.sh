#!/usr/bin/env bash
# Package charts/roci, with its subchart archives verified against the committed
# Chart.lock, for publication as an OCI artifact. Prints the package path.
# Used by the `chart` job of .github/workflows/release.yml.
#
# Usage: scripts/helm-package.sh <out-dir> [version]
#   version  release version (the `v*` tag without `v`). Stamps both the chart
#            version and appVersion, so the chart released with vX.Y.Z deploys
#            the image ghcr.io/<owner>/roci:X.Y.Z. Omitted: Chart.yaml as-is.
set -euo pipefail

out="${1:?usage: helm-package.sh <out-dir> [version]}"
version="${2:-}"

bash scripts/helm-deps.sh

args=(--destination "$out")
if [ -n "$version" ]; then
  args+=(--version "$version" --app-version "$version")
fi
mkdir -p "$out"
helm package charts/roci "${args[@]}" |
  sed -n 's/^Successfully packaged chart and saved it to: //p'
