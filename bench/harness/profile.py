"""Pure analysis of roci profiling artifacts (folded stacks, syscalls, metrics)."""

from __future__ import annotations

import re
from collections import Counter

KERNEL_PCT = 50.0
HASHING_PCT = 15.0
COPY_ALLOC_PCT = 15.0
JSON_PCT = 10.0
RUNTIME_PCT = 20.0
SYNC_SHARE_PCT = 20.0
META_SYSCALLS_PER_REQ = 3.0
TRANSPORT_FACTOR = 2.0
GAP_PCT = 10.0

CATEGORIES: list[tuple[str, re.Pattern | None]] = [
    ("kernel", re.compile(r"_\[k\]$")),
    ("hashing", re.compile(r"sha2|sha256|sha512|blake3|crc32")),
    ("copy/alloc", re.compile(r"memcpy|memmove|memset|mi_|malloc|free|realloc|alloc::")),
    ("json", re.compile(r"serde_json|serde::")),
    ("tls", re.compile(r"rustls|ring::")),
    ("http", re.compile(r"hyper|h2::|http::|axum|tower")),
    ("runtime", re.compile(r"tokio::|parking_lot|futures")),
    ("roci", re.compile(r"roci_")),
    ("std-other", re.compile(r"std::|core::")),
    ("other", None),
]

Stacks = list[tuple[list[str], int]]

# Leaf frames that are the cost of the profilers themselves (perf trace's syscall
# tracepoints, perf's software-event bookkeeping), not of roci.
INSTRUMENTATION = re.compile(r"^(perf_|__perf_|syscall_trace_|trace_|ftrace_)|_swevent_")


def parse_folded(text: str) -> Stacks:
    out = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        stack, _, n = line.rpartition(" ")
        try:
            out.append((stack.split(";"), int(n)))
        except ValueError:
            continue
    return out


def _total(stacks: Stacks) -> int:
    return sum(n for _, n in stacks) or 1


def strip_instrumentation(stacks: Stacks) -> tuple[Stacks, float]:
    """Drop stacks whose leaf is profiler overhead; return (kept, removed_pct)."""
    kept = [(f, n) for f, n in stacks if not INSTRUMENTATION.search(f[-1].removesuffix("_[k]"))]
    total = sum(n for _, n in stacks)
    removed = total - sum(n for _, n in kept)
    return kept, round(removed * 100 / total, 2) if total else 0.0


def self_top(stacks: Stacks, n: int = 15) -> list[tuple[str, int, float]]:
    c: Counter = Counter()
    for frames, k in stacks:
        c[frames[-1]] += k
    t = _total(stacks)
    return [(f, k, round(k * 100 / t, 2)) for f, k in c.most_common(n)]


def inclusive_top(stacks: Stacks, n: int = 15, prefix: tuple[str, ...] = ("roci_",)) -> list[tuple[str, int, float]]:
    c: Counter = Counter()
    for frames, k in stacks:
        for f in set(frames):
            if f.startswith(prefix):
                c[f] += k
    t = _total(stacks)
    return [(f, k, round(k * 100 / t, 2)) for f, k in c.most_common(n)]


def classify(frame: str) -> str:
    for name, rx in CATEGORIES:
        if rx is None or rx.search(frame):
            return name
    return "other"


def categorize(stacks: Stacks) -> dict[str, float]:
    c: Counter = Counter()
    for frames, k in stacks:
        c[classify(frames[-1])] += k
    t = _total(stacks)
    return {name: round(c[name] * 100 / t, 2) for name, _ in CATEGORIES if c[name]}


_NUM = re.compile(r"^[0-9.]+$")


def parse_perf_trace_summary(text: str) -> dict[str, dict]:
    """Sum `perf trace -s` per-thread rows (syscall calls [errors] total min avg max stddev)."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 7 or not re.match(r"^[a-z_][a-z0-9_]*$", parts[0]):
            continue
        nums = parts[1:]
        if not all(_NUM.match(x) for x in nums[:6]):
            continue
        calls = int(nums[0])
        total = float(nums[2] if len(nums) >= 7 and _NUM.match(nums[6].rstrip("%")) else nums[1])
        e = out.setdefault(parts[0], {"calls": 0, "total_ms": 0.0})
        e["calls"] += calls
        e["total_ms"] = round(e["total_ms"] + total, 6)
    return out


def parse_strace_summary(text: str) -> dict[str, dict]:
    """Parse `strace -c` (% time, seconds, usecs/call, calls, [errors], syscall)."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) not in (5, 6) or not _NUM.match(parts[0]) or parts[-1] == "total":
            continue
        try:
            out[parts[-1]] = {"calls": int(parts[3]), "total_ms": float(parts[1]) * 1000}
        except ValueError:
            continue
    return out


_PROM = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)")


def _prom(text: str, prefix: str) -> dict[tuple[str, str], float]:
    out = {}
    for line in text.splitlines():
        m = _PROM.match(line)
        if not m or not m[1].startswith(prefix):
            continue
        for suf in ("_sum", "_count"):
            if m[1].endswith(suf):
                try:
                    out[(suf, m[2] or "{}")] = float(m[3])
                except ValueError:
                    pass
    return out


def metrics_delta(before: str, after: str, prefix: str = "http_server_request_duration") -> list[dict]:
    b, a = _prom(before, prefix), _prom(after, prefix)
    rows = []
    for (suf, labels), cnt in a.items():
        if suf != "_count":
            continue
        dcount = cnt - b.get(("_count", labels), 0.0)
        dsum = a.get(("_sum", labels), 0.0) - b.get(("_sum", labels), 0.0)
        if dcount <= 0:
            continue
        rows.append({"labels": labels, "count": int(dcount), "sum_s": dsum, "mean_ms": dsum / dcount * 1000})
    rows.sort(key=lambda r: r["sum_s"], reverse=True)
    return rows


def _gap_phase(key: str) -> str:
    p = key.split(".")[0]
    return {"storm": "storm", "hot": "hot", "crane": "crane", "zb": "zb", "cpu": "zb"}.get(p, "—")


def gaps(compare_summary: dict, meta) -> list[dict]:
    """Rows where the best competitor beats roci by > GAP_PCT in the metric's `better` direction.

    `meta(key)` returns (label, unit, better) or None.
    """
    rows = []
    for key, per in compare_summary.get("metrics", {}).items():
        m = meta(key)
        # mib_per_s is rps × size: same ratio as the rps row, so it would only duplicate it.
        if not m or "roci" not in per or len(per) < 2 or key.endswith(".mib_per_s"):
            continue
        better = m[2]
        roci = per["roci"]["median"]
        others = {r: s["median"] for r, s in per.items() if r != "roci"}
        name, best = (max if better == "higher" else min)(others.items(), key=lambda kv: kv[1])
        if better == "higher":
            beats = best > roci * (1 + GAP_PCT / 100)
        else:
            beats = best < roci * (1 - GAP_PCT / 100)
        if beats:
            ratio = best / roci if roci else float("inf")
            factor = ratio if better == "higher" else (roci / best if best else float("inf"))
            rows.append({"metric": key, "roci": roci, "best": best, "competitor": name,
                         "ratio": ratio, "factor": factor, "phase": _gap_phase(key)})
    rows.sort(key=lambda r: r["factor"], reverse=True)
    return rows


def findings(phase_data: dict, gap_rows: list[dict] | None = None) -> list[str]:
    """phase_data: {phase: {"categories", "syscalls", "hot_requests", "vegeta_p50_ms": {ep}, "routes"}}."""
    out = []
    for g in gap_rows or []:
        out.append(f"gap: `{g['metric']}` roci {g['roci']:.4g} vs {g['competitor']} {g['best']:.4g} "
                   f"({g['factor']:.1f}× worse) — profile phase: {g['phase']}")
    for ph, d in phase_data.items():
        cat = d.get("categories") or {}
        if cat.get("kernel", 0) > KERNEL_PCT:
            out.append(f"{ph}: >50% CPU in kernel — syscall/IO-bound; see syscall table")
        if cat.get("hashing", 0) > HASHING_PCT:
            out.append(f"{ph}: digest hashing is {cat['hashing']:.1f}% of CPU — check re-hash avoidance / algorithm choice")
        if cat.get("copy/alloc", 0) > COPY_ALLOC_PCT:
            out.append(f"{ph}: {cat['copy/alloc']:.1f}% in copy/alloc — check buffer reuse and zero-copy paths")
        if cat.get("json", 0) > JSON_PCT:
            out.append(f"{ph}: {cat['json']:.1f}% in JSON (de)serialization")
        if cat.get("runtime", 0) > RUNTIME_PCT:
            out.append(f"{ph}: {cat['runtime']:.1f}% in async runtime/scheduling overhead")
        sc = d.get("syscalls") or {}
        tot = sum(v["total_ms"] for v in sc.values())
        syncs = sum(sc.get(k, {}).get("total_ms", 0) for k in ("fsync", "fdatasync"))
        if tot and syncs / tot * 100 > SYNC_SHARE_PCT:
            out.append(f"{ph}: durability syncs dominate syscall time — consider group commit")
        if ph == "hot":
            reqs = d.get("hot_requests") or 0
            meta = sum(sc.get(k, {}).get("calls", 0) for k in ("openat", "statx", "newfstatat", "fstat"))
            if reqs and meta / reqs > META_SYSCALLS_PER_REQ:
                out.append(f"hot: {meta / reqs:.1f} metadata syscalls per request")
            routes = d.get("routes") or []
            for ep, p50 in (d.get("vegeta_p50_ms") or {}).items():
                needle = "manifests" if ep.startswith("manifest") else ("blobs" if ep.startswith("blob") else None)
                if not needle:
                    continue
                r = next((r for r in routes if needle in r["labels"]), None)
                if r and p50 > TRANSPORT_FACTOR * r["mean_ms"]:
                    out.append("hot: client-observed latency ≫ handler time — overhead is in connection/transport, not handlers")
                    break
    return out
