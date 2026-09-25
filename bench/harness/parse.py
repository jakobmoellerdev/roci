"""Parsers for third-party load-tool output (zb, vegeta)."""

from __future__ import annotations

import json
import re

_UNITS_MS = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "μs": 1e-3, "ms": 1.0, "s": 1e3, "m": 60e3, "h": 3600e3}
_DUR_PART = re.compile(r"([0-9]*\.?[0-9]+)(ns|us|µs|μs|ms|s|m|h)")


def parse_go_duration(s: str) -> float:
    """Parse a Go `time.Duration.String()` value (e.g. `1m2.5s`) into milliseconds."""
    s = s.strip()
    if s in ("0", "0s"):
        return 0.0
    pos, total = 0, 0.0
    for m in _DUR_PART.finditer(s):
        if m.start() != pos:
            raise ValueError(f"bad duration: {s!r}")
        total += float(m.group(1)) * _UNITS_MS[m.group(2)]
        pos = m.end()
    if pos != len(s) or pos == 0:
        raise ValueError(f"bad duration: {s!r}")
    return total


_SEP = re.compile(r"^=+$", re.M)
_NAME = re.compile(r"^Test name:\s+(.+?)\s*$", re.M)
_RPS = re.compile(r"^Requests per second:\s+(\S+)", re.M)
_FAILED = re.compile(r"^Failed requests:\s+(\d+)", re.M)
_LAT = re.compile(r"^(min|max|p50|p75|p90|p99):\s+(\S+)", re.M)
_TTFB = re.compile(r"^(Manifest HEAD|Manifest GET|Config|Layer) TTFB (p50|p99):\s+(\S+)", re.M)


def parse_zb(stdout: str) -> list[dict]:
    """Parse zb's tabwriter stdout into one record per test block."""
    out = []
    for block in _SEP.split(stdout):
        name = _NAME.search(block)
        if not name:
            continue
        rec: dict = {"name": name.group(1)}
        if m := _RPS.search(block):
            rec["rps"] = float(m.group(1))
        if m := _FAILED.search(block):
            rec["failed"] = int(m.group(1))
        for k, v in _LAT.findall(block):
            rec[f"{k}_ms"] = parse_go_duration(v)
        for what, p, v in _TTFB.findall(block):
            key = what.lower().replace(" ", "_")
            rec[f"{key}_ttfb_{p}"] = parse_go_duration(v)
        out.append(rec)
    return out


def parse_vegeta(json_text: str) -> dict:
    """Parse `vegeta report -type=json` (latencies are integer ns) into ms."""
    d = json.loads(json_text)
    lat = d.get("latencies", {})
    return {
        "requests": d.get("requests", 0),
        "rate": d.get("rate", 0.0),
        "throughput": d.get("throughput", 0.0),
        "status_codes": dict(d.get("status_codes") or {}),
        "p50_ms": lat.get("50th", 0) / 1e6,
        "p90_ms": lat.get("90th", 0) / 1e6,
        "p99_ms": lat.get("99th", 0) / 1e6,
        "max_ms": lat.get("max", 0) / 1e6,
    }
