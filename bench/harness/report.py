"""Aggregate per-rep metrics and render the comparison report."""

from __future__ import annotations

import re
import statistics

# key -> (label, unit, better)
METRICS: dict[str, tuple[str, str, str]] = {
    "startup.empty_ms": ("Startup, empty store", "ms", "lower"),
    "startup.populated_ms": ("Startup, populated store", "ms", "lower"),
    "startup.populated_first_manifest_ms": ("Startup → first manifest served", "ms", "lower"),
    "memory.idle_anon_mib": ("Idle anon RSS", "MiB", "lower"),
    "memory.corpus_anon_mib": ("Anon RSS after corpus seed", "MiB", "lower"),
    "memory.peak_anon_mib": ("Peak anon RSS (whole run)", "MiB", "lower"),
    "storm.images_per_s": ("Push storm throughput", "images/s", "higher"),
    "storm.p99_ms": ("Push storm p99 per image", "ms", "lower"),
    "crane.push_s": ("crane push (85 MiB image)", "s", "lower"),
    "crane.push_second_repo_s": ("crane push, blobs already present", "s", "lower"),
    "crane.pull_cold_s": ("crane pull, cold page cache", "s", "lower"),
    "crane.pull_warm_s": ("crane pull, warm", "s", "lower"),
    "crane.fleet_pull_s": ("crane fleet pull (concurrent)", "s", "lower"),
    "cpu.zb_cpu_s_per_gib": ("Server CPU per GiB moved (zb)", "CPU-s/GiB", "lower"),
    "disk.bytes": ("Disk used after run", "bytes", "lower"),
}
for _ep in ("manifest_get", "blob_head", "blob_head_missing", "tags_list"):
    METRICS[f"hot.{_ep}.max_sustained_rps"] = (f"{_ep}: max sustained rps", "rps", "higher")
    METRICS[f"hot.{_ep}.p50_ms"] = (f"{_ep}: p50 @ first step", "ms", "lower")
    METRICS[f"hot.{_ep}.p99_ms"] = (f"{_ep}: p99 @ first step", "ms", "lower")

_ZB = re.compile(r"^zb\.(?P<slug>[a-z0-9_]+)\.c(?P<c>\d+)\.(?P<m>rps|p50_ms|p99_ms|mib_per_s)$")
_ZB_META = {"rps": ("rps", "higher"), "p50_ms": ("ms", "lower"), "p99_ms": ("ms", "lower"),
            "mib_per_s": ("MiB/s", "higher")}

GROUPS = [("Startup", "startup."), ("Memory", "memory."), ("Push storm (loadgen)", "storm."),
          ("Hot path (vegeta)", "hot."), ("Real client (crane)", "crane."), ("Throughput (zb)", "zb."),
          ("CPU efficiency", "cpu."), ("Disk", "disk.")]


def metric_meta(key: str) -> tuple[str, str, str] | None:
    if key in METRICS:
        return METRICS[key]
    if m := _ZB.match(key):
        unit, better = _ZB_META[m["m"]]
        return (f"{m['slug']} c={m['c']} {m['m']}", unit, better)
    return None


def summarize(per_rep: list[dict]) -> dict:
    """per_rep: [{registry: {"metrics": {k: v}, "failed": [phase], "client_bound": {ep: r}}}]"""
    regs: list[str] = []
    for rep in per_rep:
        for r in rep:
            if r not in regs:
                regs.append(r)
    values: dict[str, dict[str, list[float]]] = {}
    failed: dict[str, list[str]] = {r: [] for r in regs}
    client_bound: dict[str, dict[str, float]] = {r: {} for r in regs}
    unsupported: dict[str, dict[str, str]] = {r: {} for r in regs}
    for rep in per_rep:
        for r, d in rep.items():
            for ph in d.get("failed", []):
                if ph not in failed[r]:
                    failed[r].append(ph)
            client_bound[r].update(d.get("client_bound", {}))
            unsupported[r].update(d.get("unsupported", {}))
            for k, v in d.get("metrics", {}).items():
                if v is not None:
                    values.setdefault(k, {}).setdefault(r, []).append(float(v))
    metrics: dict[str, dict[str, dict]] = {}
    for k, per in values.items():
        metrics[k] = {}
        for r, vs in per.items():
            med = statistics.median(vs)
            cv = (statistics.stdev(vs) / statistics.mean(vs) * 100) if len(vs) > 1 and statistics.mean(vs) else 0.0
            metrics[k][r] = {"median": med, "min": min(vs), "max": max(vs), "cv": cv, "n": len(vs)}
    return {"registries": regs, "metrics": metrics, "failed": failed, "client_bound": client_bound,
            "unsupported": unsupported}


def _phase_of(key: str) -> str:
    return {"startup": "startup_empty", "memory": "startup_empty", "storm": "storm", "hot": "hot",
            "crane": "crane", "zb": "zb", "cpu": "zb", "disk": "disk"}[key.split(".")[0]]


def _fmt(v: float) -> str:
    if abs(v) >= 1e6:
        return f"{v:,.0f}"
    if abs(v) >= 100:
        return f"{v:.0f}"
    if abs(v) >= 10:
        return f"{v:.1f}"
    return f"{v:.3g}"


def render_markdown(summary: dict, env: dict, title_note: str | None = None) -> str:
    regs = summary["registries"]
    has_roci = "roci" in regs and len(regs) > 1
    others = [r for r in regs if r != "roci"]
    L: list[str] = ["# Registry benchmark: " + " vs ".join(regs), ""]
    if title_note:
        L += [f"> **{title_note}**", ""]
    if env.get("docker_desktop"):
        L += ["> **NON-AUTHORITATIVE: Docker Desktop VM**", ""]
    if env.get("github_actions"):
        L += ["> **Shared CI runner — compare ratios within this run only**", ""]
    L += ["## Environment", ""]
    for k in ("run_id", "profile", "reps", "seed", "git_sha", "git_dirty", "cpu_model", "NCPU", "MemTotal",
              "OperatingSystem", "KernelVersion", "ServerVersion", "Driver", "CgroupVersion", "backing_fs",
              "server_cpus", "client_cpus", "server_memory", "fixture_digest"):
        if k in env:
            L.append(f"- **{k}**: `{env[k]}`")
    for r, img in env.get("images", {}).items():
        L.append(f"- **image {r}**: `{(img.get('RepoDigests') or [img.get('Id')])[0]}`")
    L.append("")
    L += ["Cells are `median [min–max]` over reps. `vs roci` = other/roci median; `≈` = ranges overlap; "
          "`⚠ unstable` = CV > 10%.", ""]
    footnotes: list[str] = []
    for gname, prefix in GROUPS:
        keys = [k for k in summary["metrics"] if k.startswith(prefix) and metric_meta(k)]
        if not keys:
            continue
        keys.sort(key=lambda k: (list(METRICS).index(k) if k in METRICS else len(METRICS), k))
        hdr = ["metric"] + regs + ([f"{o} vs roci" for o in others] if has_roci else [])
        L += [f"## {gname}", "", "| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
        for k in keys:
            label, unit, better = metric_meta(k)
            row = [f"{label} ({unit}, {better} better)"]
            m = summary["metrics"][k]
            for r in regs:
                if _phase_of(k) in summary["failed"].get(r, []):
                    row.append("FAILED")
                    continue
                why = summary.get("unsupported", {}).get(r, {}).get(_phase_of(k))
                if why:
                    row.append("n/a ²")
                    fn = f"² n/a for {r}: {why}"
                    if fn not in footnotes:
                        footnotes.append(fn)
                    continue
                s = m.get(r)
                if not s:
                    row.append("—")
                    continue
                cell = f"{_fmt(s['median'])} [{_fmt(s['min'])}–{_fmt(s['max'])}]"
                if s["cv"] > 10:
                    cell += " ⚠ unstable"
                if k.startswith("hot.") and k.endswith("max_sustained_rps"):
                    ep = k.split(".")[1]
                    if ep in summary["client_bound"].get(r, {}):
                        cell += " ¹"
                        fn = "¹ stopped by `client_bound`: ≥ r (load generator limit)"
                        if fn not in footnotes:
                            footnotes.append(fn)
                row.append(cell)
            if has_roci:
                base = m.get("roci")
                for o in others:
                    s = m.get(o)
                    if not base or not s or not base["median"] or "FAILED" in row:
                        row.append("—")
                        continue
                    overlap = s["min"] <= base["max"] and base["min"] <= s["max"]
                    row.append(("≈" if overlap else "") + f"{s['median'] / base['median']:.2f}")
            L.append("| " + " | ".join(row) + " |")
        L.append("")
    failed = {r: p for r, p in summary["failed"].items() if p}
    if failed:
        L += ["## Failures", ""] + [f"- **{r}**: FAILED phases {', '.join(p)}" for r, p in failed.items()] + [""]
    L += footnotes
    return "\n".join(L).rstrip() + "\n"
