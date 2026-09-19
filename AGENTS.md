# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

**roci** — a Rust implementation of the OCI Distribution Specification (an OCI registry). See [`README.md`](README.md) for goals and the feature roadmap.

## Design docs (read before non-trivial work)

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component/crate model, build flavors (minimal/full), storage subsystem, background scheduler, **scaling (vertical + horizontal scale-out)**, architectural invariants.
- [`SECURITY.md`](SECURITY.md) — build/runtime hardening, authn/authz matrix, content trust, security invariants.
- [`PLAN.md`](PLAN.md) — phased master build plan; each phase gated on the OCI conformance suite.
- [`RESEARCH.md`](RESEARCH.md) — peer-reviewed + industry evidence (CAS/dedup/GC, consistent hashing, lazy-pull, P2P, index structures, telemetry overhead) with a Sources table; cite it when justifying a storage or scale-out decision.

These are reverse-engineered from and cite zot's design as prior art: [Architecture](https://zotregistry.dev/v2.1.21/general/architecture), [Storage](https://zotregistry.dev/v2.1.21/articles/storage/), [Security Posture](https://zotregistry.dev/v2.1.21/articles/security-posture/), [Scale-out](https://zotregistry.dev/v2.1.21/articles/scaleout/). When a design question arises, consult these docs first; they mark **[roci divergence]** where roci intentionally differs from zot. Respect the stated invariants — do not violate them without updating the design doc and flagging it.

### Keeping docs consistent (maintenance contract)

Each doc has one owner; when your change touches its concern, update it **in the same change** (see [`PLAN.md`](PLAN.md) §Document maintenance contract for the full table):

- **Design decisions or corrections** → consolidate into [`ARCHITECTURE.md`](ARCHITECTURE.md) (and [`SECURITY.md`](SECURITY.md) for security). Do not scatter design rationale into PLAN or README; mark evidence-backed refinements `[refined from RESEARCH …]`.
- **Freshly gathered research** → consolidate into [`RESEARCH.md`](RESEARCH.md) with a Sources row, then cite it by key from the doc that acts on it. Never inline a new source table elsewhere.
- **[`PLAN.md`](PLAN.md) (build steps) and the [`README.md`](README.md) high-level feature roadmap MUST be kept updated** whenever a decision adds/changes a build step or a user-facing capability — a design/security decision is not "done" until PLAN and the README reflect it.
- Respect the stated **invariants**; changing one requires updating its owning doc and flagging the change.
- **[`docs/`](docs/) (the VitePress site) MUST be kept in sync** with any user-facing or design change: the [Roadmap page](docs/roadmap.md) mirrors the README roadmap, and the design overviews under `docs/design/` link the canonical root docs. See § *Documentation site (`docs/`)* below.

## Documentation site (`docs/`)

The public documentation site is a [VitePress](https://vitepress.dev/) app in [`docs/`](docs/), deployed to GitHub Pages by [`.github/workflows/docs.yml`](.github/workflows/docs.yml) on every push to `main` (pull requests build-only, validating the site and its internal links).

- **Work in `docs/`.** `npm install` once, then `npm run docs:dev` for a hot-reloading preview and `npm run docs:build` to reproduce the CI build (VitePress fails the build on dead internal links, so a green build means links resolve). Commit the `docs/package-lock.json` when dependencies change — the workflow uses `npm ci`.
- **Design pages don't duplicate.** The overviews under `docs/design/` (`architecture`, `security`, `storage`, `plan`, `research`) are summaries that **link** the canonical root docs ([`ARCHITECTURE.md`](ARCHITECTURE.md), [`SECURITY.md`](SECURITY.md), [`PLAN.md`](PLAN.md), [`RESEARCH.md`](RESEARCH.md)), which remain the source of truth. When you change a canonical doc, update the matching overview in the **same change** so the site does not drift; never fork design rationale into the site.
- **Roadmap mirrors the README.** [`docs/roadmap.md`](docs/roadmap.md) mirrors the README feature roadmap. A capability whose status changes MUST be updated in both `README.md` and `docs/roadmap.md` in one change (this extends the maintenance contract above).
- **Guide pages track behavior.** When a user-facing capability changes (CLI flags, config surface, container usage, local-dev tasks), update the relevant page under `docs/guide/` alongside the code and the README.
- **Branding is not re-authored here.** Theming maps the [`assets/BRAND.md`](assets/BRAND.md) palette onto VitePress variables in `docs/.vitepress/theme/brand.css`; the logo/favicon/social-card in `docs/public/` are **copies** of the source-of-truth SVGs in `assets/`. When the brand assets change, re-copy them (`cp assets/{logo.svg,logo-dark.svg,favicon.svg,icon.svg,social-card.svg} docs/public/`) — never recolor gradients or hand-edit the copies.
- **Workflow hygiene.** Keep `docs.yml` `actionlint`- and `zizmor`-clean like every other workflow: pin actions by commit SHA, `persist-credentials: false` on checkout, default-deny `permissions` with only the deploy job holding `pages: write` + `id-token: write`.

## OCI specs (local reference)

The authoritative OCI specs are vendored locally as git submodules, each pinned to **v1.1.1**. Read them from the local checkout — do **not** fetch them from the web:

```
spec/distribution-spec/spec.md    # OCI Distribution Spec (registry API)
spec/image-spec/spec.md           # OCI Image Spec
spec/image-spec/image-layout.md   # OCI Image Layout (on-disk storage format)
spec/docker-registry-api-v2.md    # Docker Registry HTTP API V2 (de-facto companion: bearer-token auth, worked pull/push/delete examples)
```

The full submodules live at `spec/distribution-spec/` and `spec/image-spec/`.

If a file is missing or empty (fresh clone), populate the submodules first:

```sh
git submodule update --init --depth 1
```

`spec/docker-registry-api-v2.md` is a vendored snapshot of Docker Hub's Registry API V2 reference (source URL and fetch date in its header). It is authoritative only for the de-facto Docker bearer-token auth flow and worked client examples; for the protocol itself the OCI specs above win. Refresh it by re-fetching the source URL, not by hand-editing.

When implementing or verifying any registry endpoint, error code, media type, or workflow, cite and follow these specs as the source of truth. The submodules are pinned; do not bump their commits without an explicit instruction.

## CI & local development

- **Before pushing / opening a PR, run `just ci`.** It runs the required CI checks locally — `actionlint` (workflow lint), `fmt`, `clippy` (both flavors), `test`+`coverage` (one instrumented build), `build` (minimal flavor; the full flavor is compiled by the coverage build), and `deps-guard`. Green `just ci` ⇒ green required CI. See [`README.md`](README.md) "Developing locally" for the full recipe table.
- **100% line coverage is enforced.** `ci.yml`'s `test + coverage` job compiles the workspace **once** (instrumented) and runs the tests under `cargo llvm-cov nextest`, then `scripts/coverage.sh` asserts every executable line ran (lcov), excluding the thin `roci-cli/src/main.rs` entrypoint (its logic lives in the fully-covered library). It gates on lcov line coverage — not `--fail-under-lines`, whose region-derived metric penalizes async `.await` state-machine arms that always execute — so the gate is deterministic 100% on Linux and macOS. A PR dropping below 100% fails; inspect region gaps with `just coverage-report`. The job also emits `cobertura.xml` and reports it to GitHub via `actions/upload-code-coverage` (needs `code-quality: write`), feeding GitHub's PR coverage gate ("Restrict code coverage").
- **Security & static analysis**: three gates run in CI — `actionlint` (a job in `ci.yml`, lints workflow YAML + shellchecks `run:` blocks), `zizmor.yml` (GitHub Actions security auditor, SARIF to code scanning), and `codeql.yml` (CodeQL SAST for Rust, `build-mode: none`, tuned for speed via `.github/codeql/config.yml`: scoped to `crates/`, default query suite, `threads: 0`). CodeQL runs on **every** push to `main` and **every** PR (no path filter): the `code_scanning` repo ruleset requires a CodeQL result to merge, and a path-filtered run is *skipped* on docs-only PRs — leaving the required check waiting forever — so it must always run to keep the gate satisfiable. To keep the always-on run cheap, `codeql.yml` uses **overlay analysis** (CodeQL ≥ 2.23.8): `main`/`schedule` runs build a full *overlay-base* database and cache it (`actions/cache`, key `codeql-overlay-base-rust-<sha>`); PRs restore that base and run in *overlay* mode (`CODEQL_OVERLAY_DATABASE_MODE`), re-analyzing only changed files. Overlay is driven **manually** (not the server-side feature flag), and since manual mode does not self-heal a cache miss, a PR only requests `overlay` when the restore hit — otherwise it runs a full analysis. `dependency-caching` + `trap-caching` accelerate that cold path. Overlay needs the merge-base reachable (`fetch-depth: 0`) and git ≥ 2.36 for the repo's submodules (ubuntu-latest satisfies this). Run `just lint-workflows` and `just zizmor` locally; CodeQL runs only on GitHub. Keep workflows `actionlint`- and `zizmor`-clean (pin third-party actions by commit SHA, `persist-credentials: false` on checkout, least-privilege permissions).
- **CI is fork-safe and uses a read-only token.** `ci.yml`, `audit.yml`, and `conformance.yml` default to `permissions: contents: read` and use no secrets, so autonomous-agent PRs (including from forks) run the full gate without a write token. The `test + coverage` job additionally grants `code-quality: write` + `pull-requests: read` to report coverage — fork PRs lack this and the upload step skips gracefully. `zizmor.yml`/`codeql.yml` need `security-events: write` for SARIF but execute no PR code. Never add a step needing a write token or secret to the build/test path. Privileged merge automation belongs in `auto-merge.yml` (base-repo context, no PR code).
- **Agentic PRs**: apply the `automerge` label to request auto-merge. Auto-merge still requires green CI **and** a code-owner approval (`SECURITY.md` policy) — the label does not bypass review.
- **Toolchain is pinned** in `rust-toolchain.toml`. Do not hardcode a different toolchain in a workflow; bump the pin (and the matching `dtolnay/rust-toolchain@<version>` refs in `.github/actions/setup-rust/action.yml` and `ci.yml`) in one change.
- **Build-flavor invariants** ([`ARCHITECTURE.md`](ARCHITECTURE.md) 1 & 2): every new extension crate MUST be named `roci-ext-*` (or `roci-cluster`) and be reachable from `roci-cli` **only** behind a cargo feature, never as an unconditional dependency. `just deps-guard` / the `minimal-deps-guard` CI job enforces this.
- **Every crate** carries `#![forbid(unsafe_code)]` unless it is an audited zero-copy module explicitly exempted ([`SECURITY.md`](SECURITY.md) invariant 7).
- **Conformance**: `just conformance` builds the Go conformance binary from the pinned `spec/distribution-spec` submodule and runs it against a locally-started roci; run `just init` first if the submodules are absent.
- **Pre-commit hook**: run `just hooks` once to install `.git/hooks/pre-commit` (or `pre-commit install` with the framework via `.pre-commit-config.yaml`). It runs fmt, clippy (both flavors), workflow lint/security (when workflows are staged), and the 100% coverage gate, and regenerates [`COVERAGE.md`](COVERAGE.md) + the README badge, re-staging them so the coverage report stays in sync with each commit.
- **Container image** ([`Containerfile`](Containerfile)): hardened static musl binary on `scratch`, nonroot UID, read-only root FS with only the storage volume writable. The `container` CI workflow builds and smoke-tests on **native per-arch runners** (no QEMU): PRs build `linux/arm64` only (on `ubuntu-24.04-arm`) to save time; `main` builds `linux/amd64` + `linux/arm64`, merges a multi-arch manifest, and pushes to GHCR with a signed build-provenance attestation (`actions/attest-build-provenance`) + embedded SBOM/SLSA provenance. It also builds+attests a standalone static binary per Linux arch. Test locally with `just container`. Container images are Linux-only; darwin ships as cross-compiled release binaries, not images. When changing `Containerfile`, keep it scratch-based and nonroot — do not add a shell or run as root.
