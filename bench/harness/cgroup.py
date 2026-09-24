"""cgroup v2 CPU / anonymous-memory sampling for a registry container."""

from __future__ import annotations

import contextlib
import os
import threading
import time


def find_cgroup(container_id: str) -> str:
    for cand in (f"/sys/fs/cgroup/system.slice/docker-{container_id}.scope", f"/sys/fs/cgroup/docker/{container_id}"):
        if os.path.isfile(os.path.join(cand, "memory.stat")):
            return cand
    root = "/sys/fs/cgroup"
    base_depth = root.count(os.sep)
    for dirpath, dirnames, _ in os.walk(root):
        if dirpath.count(os.sep) - base_depth >= 4:
            dirnames[:] = []
        for d in dirnames:
            if container_id in d:
                p = os.path.join(dirpath, d)
                if os.path.isfile(os.path.join(p, "memory.stat")):
                    return p
    raise RuntimeError(f"cgroup v2 dir for {container_id} not found (cgroup v1 hosts unsupported)")


def _kv(path: str) -> dict[str, int]:
    out = {}
    with open(path) as f:
        for line in f:
            k, _, v = line.partition(" ")
            with contextlib.suppress(ValueError):
                out[k] = int(v)
    return out


class Sampler:
    """Polls memory.stat (anon/file) and cpu.stat (usage_usec) every 100 ms."""

    def __init__(self, cgroup_dir: str, interval: float = 0.1):
        self.dir = cgroup_dir
        self.interval = interval
        self.samples: list[tuple[float, int, int, int]] = []
        self.phases: dict[str, list[float]] = {}
        self._stop = threading.Event()
        stat = _kv(os.path.join(cgroup_dir, "memory.stat"))
        if "anon" not in stat:
            raise RuntimeError(f"cgroup v2 dir for {cgroup_dir} not found (cgroup v1 hosts unsupported)")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def sample(self):
        try:
            mem = _kv(os.path.join(self.dir, "memory.stat"))
            cpu = _kv(os.path.join(self.dir, "cpu.stat"))
        except OSError:
            return None  # container stopped / cgroup removed
        s = (time.monotonic(), mem.get("anon", 0), mem.get("file", 0), cpu.get("usage_usec", 0))
        self.samples.append(s)
        return s

    def _run(self):
        while not self._stop.is_set():
            self.sample()
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)

    def retarget(self, cgroup_dir: str):
        """Follow the container to its new cgroup dir after a restart (same container ID)."""
        self.dir = cgroup_dir

    @contextlib.contextmanager
    def phase(self, name: str):
        self.sample()
        start = time.monotonic()
        try:
            yield
        finally:
            self.sample()
            self.phases[name] = [start, time.monotonic()]

    def _window(self, start: float, end: float):
        return [s for s in self.samples if start <= s[0] <= end]

    def phase_metrics(self, name: str) -> dict:
        start, end = self.phases[name]
        w = self._window(start, end)
        if len(w) < 2:
            return {"cpu_s": None, "peak_anon_mib": None}
        return {"cpu_s": (w[-1][3] - w[0][3]) / 1e6, "peak_anon_mib": max(s[1] for s in w) / 2**20}

    def current_anon_mib(self) -> float | None:
        s = self.sample()
        return s[1] / 2**20 if s else None

    def peak_anon_mib(self) -> float | None:
        return max((s[1] for s in self.samples), default=0) / 2**20 if self.samples else None

    def dump_csv(self, path: str, t0: float = 0.0):
        with open(path, "w") as f:
            f.write("t_s,anon_bytes,file_bytes,usage_usec\n")
            for t, a, fb, u in self.samples:
                f.write(f"{t - t0:.3f},{a},{fb},{u}\n")
