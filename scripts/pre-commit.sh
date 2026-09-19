#!/usr/bin/env bash
# roci pre-commit hook. Runs the most important gates before a commit, then
# refreshes the coverage report/badge and re-stages them so the report is
# always committed in sync with the code.
#
# Install with `just hooks` (symlinks this into .git/hooks/pre-commit), or use
# the pre-commit framework via .pre-commit-config.yaml.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

staged="$(git diff --cached --name-only)"

# Rust gates only when Rust sources (or the manifests) are staged — keeps
# doc-only commits fast.
if echo "$staged" | grep -qE '\.rs$|(^|/)Cargo\.(toml|lock)$'; then
  echo "[pre-commit] rustfmt"
  cargo fmt --all --check

  echo "[pre-commit] clippy (all features + minimal)"
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo clippy --workspace --no-default-features -- -D warnings

  echo "[pre-commit] coverage (100% lines) + report refresh"
  # scripts/coverage.sh enforces 100% on Linux and is tolerant on other
  # platforms (a few Unix-filesystem-specific lines are covered on Linux CI).
  bash scripts/coverage.sh
  # Re-stage the regenerated report and badge so they land in this commit.
  git add COVERAGE.md README.md

  echo "[pre-commit] OCI distribution conformance"
  # Blocks the commit unless the built binary passes the full conformance
  # suite (all four categories). Requires Go 1.17+ and the pinned spec
  # submodule; scripts/conformance.sh fails loudly if either is missing.
  bash scripts/conformance.sh
fi

# Workflow lint/security only when workflow files are staged.
if echo "$staged" | grep -qE '^\.github/(workflows|actions)/'; then
  if command -v actionlint >/dev/null 2>&1; then
    echo "[pre-commit] actionlint"; actionlint -ignore 'unknown permission scope "code-quality"'
  fi
  if command -v zizmor >/dev/null 2>&1; then
    echo "[pre-commit] zizmor"; zizmor --config .github/zizmor.yml .github/workflows .github/actions
  fi
fi

echo "[pre-commit] all gates passed"
