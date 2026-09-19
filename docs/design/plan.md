# Build plan

::: tip Canonical source
This is a summary. The authoritative, maintained plan lives in [`PLAN.md`](https://github.com/jakobmoellerdev/roci/blob/main/PLAN.md) at the repo root — it is the source of truth and defines the [document maintenance contract](https://github.com/jakobmoellerdev/roci/blob/main/PLAN.md).
:::

roci is built in phases, each gated on the OCI conformance suite. The phases build the dist-spec surface first, then storage maturity, security, extensions, and scale-out.

| Phase | Focus |
| --- | --- |
| 0 | Foundations & skeleton |
| 1 | Pull (read path) + storage core |
| 2 | Push (write path) + upload sessions |
| 3 | Content discovery + content management + referrers |
| 4 | Configuration & operability baseline |
| 5 | Storage subsystem maturity |
| 6 | Security & access control |
| 7 | Extensions (signatures, search, sync, scanning) |
| 8 | Scale-out clustering (horizontal) |

Cross-cutting concerns (telemetry, conformance, the 100% coverage gate, workflow security) run continuously across every phase.

## Document maintenance contract

`PLAN.md` defines a maintenance contract: each design doc has one owner, and a decision is not "done" until `PLAN.md` and the README roadmap reflect any added/changed build step or user-facing capability. This documentation site mirrors that roadmap on the [Roadmap](/roadmap) page and must be updated in the same change — see `AGENTS.md` for the full upkeep contract.
