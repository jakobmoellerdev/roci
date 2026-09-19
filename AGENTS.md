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

- **Before pushing / opening a PR, run `just ci`.** It runs the exact required CI checks locally — `actionlint` (workflow lint), `fmt`, `clippy` (both flavors), `test`, `build` (both flavors), `deps-guard`. Green `just ci` ⇒ green required CI. See [`README.md`](README.md) "Developing locally" for the full recipe table.
- **Security & static analysis**: three additional gates run in CI — `actionlint` (a job in `ci.yml`, lints workflow YAML + shellchecks `run:` blocks), `zizmor.yml` (GitHub Actions security auditor, uploads SARIF to code scanning), and `codeql.yml` (CodeQL SAST for Rust, `build-mode: none`, guarded until Rust code exists). Run `just lint-workflows` and `just zizmor` locally; CodeQL runs only on GitHub. When editing any workflow, keep it `actionlint`- and `zizmor`-clean (pin third-party actions by SHA, no over-broad token permissions).
- **CI is fork-safe and uses a read-only token.** `ci.yml`, `audit.yml`, and `conformance.yml` declare `permissions: contents: read` and use no secrets, so autonomous-agent PRs (including from forks) run the full gate without a write token. `zizmor.yml` and `codeql.yml` need `security-events: write` to upload SARIF but execute no PR code. Never add a step needing a write token or secret to `ci.yml`/`audit.yml`/`conformance.yml`. Privileged merge automation belongs in `auto-merge.yml`, which runs in base-repo context and executes no PR code.
- **Agentic PRs**: apply the `automerge` label to request auto-merge. Auto-merge still requires green CI **and** a code-owner approval (`SECURITY.md` policy) — the label does not bypass review.
- **Toolchain is pinned** in `rust-toolchain.toml`. Do not hardcode a different toolchain in a workflow; bump the pin (and the matching `dtolnay/rust-toolchain@<version>` refs in `.github/actions/setup-rust/action.yml` and `ci.yml`) in one change.
- **Build-flavor invariants** ([`ARCHITECTURE.md`](ARCHITECTURE.md) 1 & 2): every new extension crate MUST be named `roci-ext-*` (or `roci-cluster`) and be reachable from `roci-cli` **only** behind a cargo feature, never as an unconditional dependency. `just deps-guard` / the `minimal-deps-guard` CI job enforces this.
- **Every crate** carries `#![forbid(unsafe_code)]` unless it is an audited zero-copy module explicitly exempted ([`SECURITY.md`](SECURITY.md) invariant 7).
- **Conformance**: `just conformance` builds the Go conformance binary from the pinned `spec/distribution-spec` submodule and runs it against a locally-started roci; run `just init` first if the submodules are absent.
