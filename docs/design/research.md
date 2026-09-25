# Research

::: tip Canonical source
This is a pointer. The full evidence base — peer-reviewed and industry sources with a Sources table — lives in [`RESEARCH.md`](https://github.com/jakobmoellerdev/roci/blob/main/RESEARCH.md) at the repo root.
:::

`RESEARCH.md` collects the academic and industry evidence backing roci's storage and scale-out decisions. Design docs cite it by key when justifying a decision; new evidence is consolidated there with a Sources row rather than inlined elsewhere.

Topics covered:

1. Content-addressable storage, dedup, and the "local minimal" core.
2. Safe online garbage collection (the non-transactional-lifecycle problem).
3. Index & query structures under a footprint budget.
4. Hyperscale distribution: lazy pull & P2P (the growth path).
5. Scale-out sharding: consistent hashing & keyed hashing.
6. Observability overhead — justifying "OTel on, cheap by default".
7. Consolidated design implications.
8. Storage decision stress-test — more efficient alternatives.
9. Local-store efficiency — is there an even more efficient design? (incl. §9.7 comparative benchmark vs distribution/zot)

See also: [Architecture](/design/architecture) · [Storage](/design/storage).
