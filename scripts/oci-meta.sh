#!/usr/bin/env bash
# Emit the OCI pre-defined annotation keys (image-spec annotations.md) for the
# roci container image, one `key=value` per line. Single source of truth for
# both CI (container.yml: config labels, manifest + index annotations) and
# local builds (`just container`).
#
# Values derive from the checked-out commit and `[workspace.package]` in
# Cargo.toml, so they are reproducible for a given commit:
#   created  — committer date of HEAD (UTC, RFC 3339), not wall-clock build time
#   version  — `X.Y.Z` on a `refs/tags/vX.Y.Z` build (must equal the Cargo
#              version), otherwise `<cargo version>+g<short sha>` (SemVer build metadata)
#   revision — full commit SHA
#
# Deliberately omitted (not applicable to this image):
#   base.name / base.digest — the runtime stage is `FROM scratch`, which has no
#                             reference or digest.
#   ref.name                — only valid on descriptors in an image layout's
#                             `index.json`, not on a pushed manifest/index.
#
# Usage: scripts/oci-meta.sh [GIT_REF]   (GIT_REF defaults to $GITHUB_REF)
set -euo pipefail

cd "$(dirname "$0")/.."
ref="${1:-${GITHUB_REF:-}}"

# Read a scalar/first-array-element from [workspace.package] in Cargo.toml.
pkg() {
  sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml \
    | sed -n "s/^$1 *= *\[\{0,1\}\"\([^\"]*\)\".*/\1/p" | head -n1
}

cargo_version="$(pkg version)"
repo="$(pkg repository)"
revision="$(git rev-parse HEAD)"
created="$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ HEAD)"

if [[ "$ref" == refs/tags/v* ]]; then
  version="${ref#refs/tags/v}"
  if [[ "$version" != "$cargo_version" && "$version" != "$cargo_version"-* ]]; then
    echo "tag v$version does not match Cargo.toml version $cargo_version" >&2
    exit 1
  fi
else
  version="${cargo_version}+g$(git rev-parse --short=12 HEAD)"
fi

cat <<EOF
org.opencontainers.image.created=${created}
org.opencontainers.image.authors=$(pkg authors)
org.opencontainers.image.url=${repo}
org.opencontainers.image.documentation=https://jakobmoellerdev.github.io/roci/
org.opencontainers.image.source=${repo}
org.opencontainers.image.version=${version}
org.opencontainers.image.revision=${revision}
org.opencontainers.image.vendor=$(pkg authors)
org.opencontainers.image.licenses=$(pkg license)
org.opencontainers.image.title=roci
org.opencontainers.image.description=A Rust implementation of the OCI Distribution Specification: a minimal, static, rootless OCI registry.
EOF
