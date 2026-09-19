# Developing locally

roci uses [`just`](https://github.com/casey/just) as its task runner. **Every recipe mirrors a CI gate**, so passing locally means passing the required CI checks.

## Prerequisites

- **Rust** via [`rustup`](https://rustup.rs) — the pinned toolchain in `rust-toolchain.toml` installs automatically on the first `cargo` invocation.
- [`just`](https://github.com/casey/just) — the task runner.
- [`cargo-nextest`](https://nexte.st) — test runner used by CI.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) — supply-chain gate.
- [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) — coverage gate (`rustup component add llvm-tools-preview` too).
- **Go 1.17+** — only for the OCI conformance suite.
- [`actionlint`](https://github.com/rhysd/actionlint) and [`zizmor`](https://github.com/zizmorcore/zizmor) — only for linting/auditing the GitHub Actions workflows.

Install the cargo tools in one line:

```sh
cargo install just cargo-nextest cargo-deny cargo-llvm-cov
```

## First-time setup

Fetch the pinned OCI spec submodules:

```sh
git submodule update --init --depth 1   # or: just init
```

Install the git pre-commit hook (when Rust sources are staged it runs fmt,
clippy, the 100% coverage gate, and the full OCI conformance suite; it also
runs workflow lint/security when workflows are staged, and refreshes
`COVERAGE.md` + the badge on every commit):

```sh
just hooks   # or, with the pre-commit framework: pre-commit install
```

## Tasks

| Command | What it does |
| --- | --- |
| `just` | List all recipes |
| `just init` | Fetch pinned spec submodules |
| `just fmt` / `just fmt-fix` | Check / apply formatting |
| `just clippy` | Lint both build flavors, warnings = errors |
| `just test` | Run tests (nextest) + doctests |
| `just build` | Build minimal and full flavors |
| `just deps-guard` | Assert no extension crate leaks into the minimal build |
| `just lint-workflows` | Lint the GitHub Actions workflows (actionlint) |
| `just zizmor` | Security-audit the workflows (zizmor) |
| `just audit` | `cargo deny` supply-chain check |
| `just coverage` | Enforce 100% line coverage (cargo-llvm-cov) |
| `just coverage-report` | Show uncovered lines (developer aid) |
| `just ci` | Run the full local gate before pushing |
| `just conformance` | Run the OCI dist-spec conformance suite against a local roci |
| `just container` | Build the hardened scratch image and smoke-test it |
| `just container-multiarch` | Build the multi-arch image (linux/amd64, linux/arm64) |

## CI parity

`just ci` runs the same checks GitHub Actions requires — if it passes locally, the required CI checks pass. **Run `just ci` before pushing or opening a PR.**

## Coverage gate

**100% line coverage is enforced.** CI compiles the workspace once (instrumented) and runs tests under `cargo llvm-cov nextest`, then enforces `--fail-under-lines 100`. New code must ship with tests that cover every line; inspect gaps with `just coverage-report`.

The gate is strict on the Linux CI runner; `scripts/coverage.sh` is intentionally tolerant on non-Linux (e.g. macOS/APFS) where a couple of Unix-filesystem-specific edges cannot be exercised locally — those lines are covered on Linux CI, which remains authoritative.

## Security & static analysis

Beyond the required gate, CI runs three security/static-analysis workflows: `actionlint` (workflow linting, part of the `CI` workflow), `zizmor` (GitHub Actions security audit), and `codeql` (CodeQL SAST for Rust). When editing any workflow, keep it `actionlint`- and `zizmor`-clean: pin third-party actions by commit SHA, set `persist-credentials: false` on checkout, and avoid over-broad token permissions.
