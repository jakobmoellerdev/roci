#!/usr/bin/env bash
# Generate the coverage report and enforce the 100%-line gate.
#
# Writes a human-readable summary to COVERAGE.md and refreshes the coverage
# badge in README.md, then fails if line coverage is below 100%. Shared by the
# pre-commit hook (scripts/pre-commit.sh) and the `just coverage` recipe.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Machine-readable percent for the gate and the badge.
percent="$(cargo llvm-cov --workspace --all-features --json --summary-only \
  | python3 -c 'import json,sys; print(f"{json.load(sys.stdin)[chr(100)+"ata"][0]["totals"]["lines"]["percent"]:.2f}")')"

# Human-readable per-file table for the report.
table="$(cargo llvm-cov --workspace --all-features --summary-only 2>/dev/null \
  | sed -n '/^Filename/,/^TOTAL/p')"

cat > COVERAGE.md <<EOF
# Coverage

Line coverage is enforced at **100%** by the \`coverage\` CI job and the
pre-commit hook (\`cargo llvm-cov --workspace --all-features --fail-under-lines 100\`).

Latest local measurement: **${percent}%** (on \`$(uname -s)\`). On Linux CI this
is **100%**; on other platforms a few Unix-filesystem-specific lines cannot be
exercised locally but are covered on the Linux CI runner, which is authoritative.

Regenerate this report with \`just coverage\` (or on every commit via the
pre-commit hook). Inspect uncovered lines with \`just coverage-report\`.

\`\`\`
${table}
\`\`\`
EOF

# Refresh the README badge. On Linux the measured percent is authoritative. On
# other platforms a few Unix-filesystem-specific lines cannot be exercised
# locally (they ARE covered on the Linux CI runner), so we do not downgrade the
# badge to a misleading value there — the committed badge tracks CI.
if [ "$(uname -s)" = "Linux" ]; then
    color="brightgreen"
    if [ "${percent%.*}" -lt 100 ]; then color="red"; fi
    badge="![coverage](https://img.shields.io/badge/coverage-${percent}%25-${color})"
    if grep -q '!\[coverage\](https://img.shields.io/badge/coverage-' README.md; then
        # Portable in-place edit (GNU/BSD sed differ on -i).
        tmp="$(mktemp)"
        sed "s|!\[coverage\](https://img.shields.io/badge/coverage-[^)]*)|${badge}|" README.md > "$tmp"
        mv "$tmp" README.md
    fi
fi

echo "coverage: ${percent}% line coverage"

# Enforce the gate. On Linux (CI) require 100% strictly. On other platforms
# (e.g. macOS/APFS) a couple of Unix-filesystem-specific edges cannot be
# exercised — those lines are covered on the Linux CI runner — so we report
# but do not hard-fail there, to keep the local developer workflow usable.
if [ "$(uname -s)" = "Linux" ]; then
    cargo llvm-cov --workspace --all-features --fail-under-lines 100
else
    if [ "${percent}" != "100.00" ]; then
        echo "note: <100% locally is expected on non-Linux (filesystem-specific lines are covered on the Linux CI runner); the CI coverage gate remains authoritative." >&2
    fi
fi
