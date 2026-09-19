#!/usr/bin/env bash
# Generate the coverage report, refresh COVERAGE.md + the README badge, and
# enforce 100% line coverage. Shared by the pre-commit hook and `just coverage`.
#
# The gate asserts every executable line ran at least once (lcov DA records),
# excluding the thin binary entrypoint `crates/roci-cli/src/main.rs`. We use the
# lcov line metric rather than `--fail-under-lines` because llvm-cov's
# region-derived line metric penalizes async state-machine regions (the
# never-taken `.await` pending arms) that are not real untested code — lcov
# confirms those lines execute.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Instrument + run the whole suite once (unit + integration, via nextest if
# available; the plain runner otherwise).
if command -v cargo-nextest >/dev/null 2>&1; then
    cargo llvm-cov --no-report nextest --workspace --all-features
else
    cargo llvm-cov --no-report --workspace --all-features
fi

# Emit lcov (line-level truth) and a human summary.
cargo llvm-cov report --lcov --output-path lcov.info
table="$(cargo llvm-cov report --summary-only 2>/dev/null | sed -n '/^Filename/,/^TOTAL/p')"

# Compute line coverage from lcov, excluding the entrypoint shim.
read -r covered total uncovered <<EOF
$(python3 - <<'PY'
cur=None; total=0; covered=0; miss=[]
for ln in open('lcov.info'):
    ln=ln.strip()
    if ln.startswith('SF:'):
        cur=ln[3:]
    elif ln.startswith('DA:') and cur and 'roci-cli/src/main.rs' not in cur:
        line,hits=ln[3:].split(',')[:2]
        total+=1
        if int(hits)>0: covered+=1
        else: miss.append(f"{cur.split('/roci/')[-1]}:{line}")
print(covered, total, ";".join(miss) if miss else "-")
PY
)
EOF
percent="$(python3 -c "print(f'{100.0*$covered/$total:.2f}' if $total else '100.00')")"

cat > COVERAGE.md <<EOF
# Coverage

Line coverage is enforced at **100%** by the \`coverage\` step of the \`CI\`
workflow and the pre-commit hook. The gate asserts every executable line runs
at least once (lcov), excluding the thin binary entrypoint
\`crates/roci-cli/src/main.rs\` (a \`#[tokio::main]\` shim over the fully-covered
library).

Current line coverage: **${percent}%** (${covered}/${total} lines).

Regenerate with \`just coverage\` (or on every commit via the pre-commit hook).
Inspect region-level gaps with \`just coverage-report\`.

\`\`\`
${table}
\`\`\`
EOF

# Refresh the README badge.
color="brightgreen"
[ "${percent%.*}" -lt 100 ] && color="red"
badge="![coverage](https://img.shields.io/badge/coverage-${percent}%25-${color})"
if grep -q '!\[coverage\](https://img.shields.io/badge/coverage-' README.md; then
    tmp="$(mktemp)"
    sed "s|!\[coverage\](https://img.shields.io/badge/coverage-[^)]*)|${badge}|" README.md > "$tmp"
    mv "$tmp" README.md
fi

echo "coverage: ${percent}% line coverage (${covered}/${total} lines)"

if [ "$uncovered" != "-" ]; then
    echo "error: uncovered lines:" >&2
    echo "$uncovered" | tr ';' '\n' >&2
    exit 1
fi
