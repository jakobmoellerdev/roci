"""Benchmark orchestrator (runs inside the runner container; see bench/run.sh)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request

from . import cgroup, fixtures, parse, profile, report

RESULTS = "/results"
WORK = "/work"
BENCH = "/bench"
PHASES = ["startup_empty", "storm", "hot", "startup_populated", "crane", "zb", "disk"]
PROFILED = ("storm", "hot", "crane", "zb")
MT_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
ENDPOINTS = ("manifest_get", "blob_head", "blob_head_missing", "tags_list")
P99_BUDGET_MS = 20.0
ZB_SIZE_MIB = {"1MB": 1, "10MB": 10, "100MB": 100}


class PhaseFailed(Exception):
    pass


class HarnessBroken(Exception):
    pass


class PhaseUnsupported(Exception):
    """The phase's tool cannot drive this registry; recorded as n/a, not a failure."""


# zb v2.1.21 `getLocation` (cmd/zb/helper.go) keeps only the path of the upload
# Location header, dropping distribution's mandatory `_state` query token, so every
# zb push to distribution fails 404 BLOB_UPLOAD_INVALID ("invalid secret").
UNSUPPORTED = {("distribution", "zb"): "zb drops the upload Location query (`_state`) that distribution requires"}


def log(msg: str):
    print(msg, flush=True)


def run(cmd: list[str], timeout: float, check: bool = True, **kw) -> subprocess.CompletedProcess:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired as e:
        raise PhaseFailed(f"timeout after {timeout}s: {' '.join(cmd)}\n{e.stderr or ''}") from e
    if check and p.returncode != 0:
        raise PhaseFailed(f"exit {p.returncode}: {' '.join(cmd)}\n{p.stdout[-4000:]}\n{p.stderr[-4000:]}")
    return p


def docker(*args: str, timeout: float = 300, check: bool = True) -> str:
    return run(["docker", *args], timeout=timeout, check=check).stdout.strip()


def http_status(url: str, method: str = "GET", headers: dict | None = None, timeout: float = 2.0) -> int:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return 0


def http_text(url: str, timeout: float = 10.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode()


def parse_started_at(s: str) -> float:
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$", s)
    if not m:
        raise PhaseFailed(f"unparseable StartedAt {s!r}")
    base = dt.datetime.fromisoformat(m[1] + ("+00:00" if m[3] == "Z" else m[3]))
    return base.timestamp() + (float("0." + m[2]) if m[2] else 0.0)


class Bench:
    def __init__(self):
        with open(f"{BENCH}/config.toml", "rb") as f:
            self.cfg = tomllib.load(f)
        self.mode = os.environ.get("BENCH_MODE", "compare")
        self.profile_name = os.environ.get("BENCH_PROFILE", "quick")
        self.p = self.cfg["profiles"][self.profile_name]
        self.seed = int(self.cfg["seed"])
        self.registries = [r for r in os.environ.get("BENCH_REGISTRIES", "roci,zot,distribution").split(",") if r]
        self.reps = int(self.p["reps"])
        if self.mode == "perf":
            self.registries, self.reps = ["roci"], 1
        self.mem = os.environ.get("BENCH_SERVER_MEMORY", "4g")
        self.server_cpus = os.environ["BENCH_SERVER_CPUS"]
        self.runner_image = os.environ["BENCH_RUNNER_IMAGE"]
        self.first_corpus: list[str] | None = None
        self.env: dict = {}
        self.fixture_dir = f"{WORK}/fixtures/app"
        self.syscall_tool = "perf trace"
        self.call_graph = "dwarf,8192"
        self.profile_data: dict[str, dict] = {}

    # ---------------------------------------------------------------- setup
    def arch(self) -> str:
        a = docker("info", "--format", "{{.Architecture}}")
        m = {"x86_64": "amd64", "aarch64": "arm64"}
        if a not in m:
            log(f"bench: unsupported docker architecture {a!r}")
            sys.exit(1)
        return m[a]

    def image_for(self, name: str) -> str:
        if name == "roci":
            return os.environ["BENCH_ROCI_PERF_IMAGE" if self.mode == "perf" else "BENCH_ROCI_IMAGE"]
        return self.cfg["images"][name][self.arch_]

    def write_env(self):
        info = json.loads(docker("info", "--format", "{{json .}}"))
        env = {
            "run_id": os.environ.get("BENCH_RUN_ID"), "mode": self.mode, "profile": self.profile_name,
            "seed": self.seed, "reps": self.reps, "registries": self.registries,
            "git_sha": os.environ.get("BENCH_GIT_SHA"), "git_dirty": os.environ.get("BENCH_GIT_DIRTY") == "1",
            "server_cpus": self.server_cpus, "client_cpus": os.environ.get("BENCH_CLIENT_CPUS"),
            "server_memory": self.mem, "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
        }
        for k in ("ServerVersion", "KernelVersion", "OperatingSystem", "NCPU", "MemTotal", "Driver",
                  "CgroupVersion", "CgroupDriver"):
            env[k] = info.get(k)
        env["docker_desktop"] = "Docker Desktop" in (info.get("OperatingSystem") or "")
        cpu = {}
        with open("/proc/cpuinfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                cpu.setdefault(k.strip(), v.strip())
        env["cpu_model"] = cpu.get("model name") or f"CPU part {cpu.get('CPU part', '?')}"
        docker("volume", "create", "bench-probe")
        try:
            env["backing_fs"] = docker("run", "--rm", "-v", "bench-probe:/v", "--entrypoint", "stat",
                                       self.runner_image, "-f", "-c", "%T", "/v")
        finally:
            docker("volume", "rm", "-f", "bench-probe", check=False)
        env["images"] = {}
        for r in self.registries:
            j = json.loads(docker("image", "inspect", self.image_for(r)))[0]
            env["images"][r] = {"ref": self.image_for(r), "Id": j["Id"], "RepoDigests": j.get("RepoDigests")}
        env["tools"] = {
            "vegeta": run(["vegeta", "-version"], 30, check=False).stdout.strip(),
            "crane": run(["crane", "version"], 30, check=False).stdout.strip(),
            "python": run(["python3", "--version"], 30, check=False).stdout.strip(),
            "zb": "v2.1.21",
        }
        env["fixture_digest"] = self.fixture_digest
        self.env = env
        self.save_env()

    def save_env(self):
        with open(f"{RESULTS}/env.json", "w") as f:
            json.dump(self.env, f, indent=2)

    # ------------------------------------------------------------ container
    def create(self, name: str):
        datadir = "/var/lib/roci" if name == "roci" else "/var/lib/registry"
        args = ["create", "--name", f"bench-{name}", "--network", "roci-bench", "--cpuset-cpus", self.server_cpus,
                "--memory", self.mem, "--memory-swap", self.mem, "-v", f"bench-{name}-data:{datadir}"]
        if name == "roci":
            args += ["-e", "RUST_LOG=warn", self.image_for(name)]
            if self.mode == "perf":
                args += ["--config", "/bench-roci.toml", "--listen", "0.0.0.0:5000", "--storage-root", "/var/lib/roci"]
        else:
            args.append(self.image_for(name))
        docker(*args)
        if name == "roci" and self.mode == "perf":
            docker("cp", f"{BENCH}/registries/roci-perf.toml", "bench-roci:/bench-roci.toml")
        elif name == "zot":
            docker("cp", f"{BENCH}/registries/zot.json", "bench-zot:/etc/zot/config.json")
        elif name == "distribution":
            docker("cp", f"{BENCH}/registries/distribution.yml", "bench-distribution:/etc/distribution/config.yml")

    def wait_ready(self, name: str, url: str) -> float:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if http_status(url + "/v2/", timeout=1.0) == 200:
                ready = time.time()
                started = parse_started_at(docker("inspect", "-f", "{{.State.StartedAt}}", f"bench-{name}"))
                return (ready - started) * 1000
            time.sleep(0.005)
        raise PhaseFailed(f"bench-{name} not ready within 60s")

    def cgroup_dir(self, name: str) -> str:
        return cgroup.find_cgroup(docker("inspect", "-f", "{{.Id}}", f"bench-{name}"))

    # ---------------------------------------------------------------- phases
    def ph_storm(self, name, url, out, m):
        corpus, stats = f"{out}/corpus.json", f"{out}/stats.json"
        p = run(["loadgen", "seed", "-registry", url, "-repos", str(self.p["corpus_repos"]),
                 "-tags", str(self.p["corpus_tags"]), "-seed", str(self.seed),
                 "-concurrency", str(self.p["storm_concurrency"]), "-corpus", corpus, "-stats", stats],
                timeout=1800, check=False)
        st = json.load(open(stats)) if os.path.exists(stats) else {}
        if p.returncode != 0:
            raise PhaseFailed(f"loadgen exit {p.returncode}\n{p.stderr}\nerror_samples: "
                              f"{json.dumps(st.get('error_samples'), indent=1)}")
        m["storm.images_per_s"] = st["images_per_s"]
        m["storm.p99_ms"] = st["latency_ms"]["p99"]
        digests = [i["manifest_digest"] for i in json.load(open(corpus))["images"]]
        if self.first_corpus is None:
            self.first_corpus = digests
        elif digests != self.first_corpus:
            raise HarnessBroken(f"corpus digests for {name} differ from the first registry of the run")
        self.units["storm"] = st["images"]

    def targets(self, url: str, out: str) -> dict[str, str]:
        corpus = json.load(open(f"{out}/corpus.json"))
        imgs, repos = corpus["images"], corpus["repos"]
        acc = f"Accept: {MT_MANIFEST}\n"
        sets = {
            "manifest_get": [f"GET {url}/v2/{i['repo']}/manifests/{i['tag']}\n{acc}" for i in imgs],
            "blob_head": [f"HEAD {url}/v2/{i['repo']}/blobs/{i['layer_digest']}\n" for i in imgs],
            "blob_head_missing": [
                f"HEAD {url}/v2/{repos[k % len(repos)]}/blobs/sha256:"
                f"{hashlib.sha256(f'missing/{k}'.encode()).hexdigest()}\n" for k in range(len(imgs))],
            "tags_list": [f"GET {url}/v2/{r}/tags/list\n" for r in repos],
        }
        paths = {}
        for ep, lines in sets.items():
            random.Random(self.seed).shuffle(lines)
            paths[ep] = f"{WORK}/targets-{ep}.txt"
            with open(paths[ep], "w") as f:
                f.write("\n".join(lines) + "\n")
        return paths

    def vegeta(self, target: str, rate: int, secs: int, bin_path: str) -> dict:
        run(["vegeta", "attack", f"-targets={target}", f"-rate={rate}/1s", f"-duration={secs}s", "-timeout=10s",
             "-workers=32", "-max-workers=1024", "-keepalive=true", "-http2=false", f"-output={bin_path}"],
            timeout=secs + 60)
        return parse.parse_vegeta(run(["vegeta", "report", "-type=json", bin_path], timeout=120).stdout)

    def ph_hot(self, name, url, out, m):
        paths = self.targets(url, out)
        ladder, raw, total = self.p["ladder_rps"], {}, 0
        self.vegeta_p50 = {}
        for ep, tgt in paths.items():
            self.vegeta(tgt, ladder[0], self.p["warmup_secs"], f"{WORK}/warmup.bin")
            want = "404" if ep == "blob_head_missing" else "200"
            best, steps = 0, []
            for i, r in enumerate(ladder):
                if i:
                    time.sleep(1)
                v = self.vegeta(tgt, r, self.p["step_secs"], f"{WORK}/{ep}-{r}.bin")
                total += v["requests"]
                share = v["status_codes"].get(want, 0) / v["requests"] if v["requests"] else 0.0
                ok_status, ok_p99, ok_rate = share == 1.0, v["p99_ms"] <= P99_BUDGET_MS, v["rate"] >= 0.95 * r
                step = {"rps": r, **v, "status_share": share, "pass": ok_status and ok_p99 and ok_rate,
                        "client_bound": ok_status and ok_p99 and not ok_rate}
                steps.append(step)
                if i == 0:
                    m[f"hot.{ep}.p50_ms"], m[f"hot.{ep}.p99_ms"] = v["p50_ms"], v["p99_ms"]
                    self.vegeta_p50[ep] = v["p50_ms"]
                if not step["pass"]:
                    if step["client_bound"]:
                        self.client_bound[ep] = r
                    break
                best = r
            m[f"hot.{ep}.max_sustained_rps"] = best
            raw[ep] = steps
        with open(f"{out}/hot.json", "w") as f:
            json.dump({"steps": raw, "client_bound": self.client_bound}, f, indent=2)
        self.units["hot"] = total

    def ph_startup_populated(self, name, url, out, m, first_img):
        docker("restart", f"bench-{name}", timeout=120)
        m["startup.populated_ms"] = self.wait_ready(name, url)
        if first_img:
            started = parse_started_at(docker("inspect", "-f", "{{.State.StartedAt}}", f"bench-{name}"))
            u = f"{url}/v2/{first_img['repo']}/manifests/{first_img['tag']}"
            deadline = time.monotonic() + 60
            while http_status(u, headers={"Accept": MT_MANIFEST}) != 200:
                if time.monotonic() > deadline:
                    raise PhaseFailed("first manifest not served within 60s after restart")
                time.sleep(0.005)
            m["startup.populated_first_manifest_ms"] = (time.time() - started) * 1000
        self.sampler.retarget(self.cgroup_dir(name))

    def crane_pull(self, ref: str, i: int) -> list[str]:
        if self.pull_to_devnull:
            return ["crane", "pull", "--insecure", "--format=tarball", ref, "/dev/null"]
        return ["crane", "pull", "--insecure", "--format=oci", ref, f"{WORK}/pull/{i}"]

    def clear_pulls(self):
        shutil.rmtree(f"{WORK}/pull", ignore_errors=True)

    def timed(self, cmd: list[str]) -> float:
        t0 = time.monotonic()
        run(cmd, timeout=600)
        return time.monotonic() - t0

    def ph_crane(self, name, url, out, m):
        host = f"bench-{name}:5000"
        ref = f"{host}/bench/app:v1"
        m["crane.push_s"] = self.timed(["crane", "push", "--insecure", self.fixture_dir, ref])
        m["crane.push_second_repo_s"] = self.timed(
            ["crane", "push", "--insecure", self.fixture_dir, f"{host}/bench/app-copy:v1"])
        if self.pull_to_devnull is None:  # probe once whether tarball-to-/dev/null works
            p = run(["crane", "pull", "--insecure", "--format=tarball", ref, "/dev/null"], 600, check=False)
            self.pull_to_devnull = p.returncode == 0
            self.env["crane_pull_target"] = "/dev/null tarball" if self.pull_to_devnull else "oci dir on runner fs"
            self.save_env()
        run(["sync"], 120)
        try:
            with open("/proc/sys/vm/drop_caches", "w") as f:
                f.write("3\n")
            cold = True
        except OSError as e:
            cold = False
            self.env["cold_cache_unavailable"] = str(e)
            self.save_env()
        t = self.timed(self.crane_pull(ref, 0))
        m["crane.pull_cold_s"] = t if cold else None
        self.clear_pulls()
        m["crane.pull_warm_s"] = self.timed(self.crane_pull(ref, 0))
        self.clear_pulls()
        t0 = time.monotonic()
        procs = [subprocess.Popen(self.crane_pull(ref, i), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                  text=True) for i in range(self.p["fleet"])]
        errs = []
        for pr in procs:
            try:
                _, err = pr.communicate(timeout=max(1, 600 - (time.monotonic() - t0)))
            except subprocess.TimeoutExpired:
                pr.kill()
                err = "timeout"
            if pr.returncode != 0:
                errs.append(err)
        m["crane.fleet_pull_s"] = time.monotonic() - t0
        self.clear_pulls()
        if errs:
            raise PhaseFailed("fleet pull failed:\n" + "\n".join(errs))
        self.units["crane"] = fixtures.layout_bytes(self.fixture_dir) * (4 + self.p["fleet"])

    def ph_zb(self, name, url, out, m):
        if (name, "zb") in UNSUPPORTED:
            raise PhaseUnsupported(UNSUPPORTED[(name, "zb")])
        gib = 0.0
        stdout_all = []
        for size, n in self.p["zb_requests"].items():
            for c in self.p["zb_concurrency"]:
                rx = f"^((Push Monolith|Push Chunk Streamed|Pull) {size}|Pull 75% and Push 25% Mixed {size})$"
                p = run(["zb", "-c", str(c), "-n", str(n), "-d", f"{WORK}/zb", "--skip-cleanup", "-t", rx, url],
                        timeout=1800)
                stdout_all.append(p.stdout)
                recs = parse.parse_zb(p.stdout)
                if not recs:
                    raise PhaseFailed(f"zb produced no parseable tests for {size} c={c}:\n{p.stdout[-2000:]}")
                for r in recs:
                    if r.get("failed"):
                        raise PhaseFailed(f"zb {r['name']} c={c}: {r['failed']} failed requests")
                    slug = re.sub(r"[^a-z0-9]", "_", r["name"].lower())
                    k = f"zb.{slug}.c{c}"
                    m[f"{k}.rps"], m[f"{k}.p50_ms"], m[f"{k}.p99_ms"] = r["rps"], r["p50_ms"], r["p99_ms"]
                    m[f"{k}.mib_per_s"] = r["rps"] * ZB_SIZE_MIB[size]
                    gib += n * ZB_SIZE_MIB[size] / 1024
        with open(f"{out}/zb.stdout", "w") as f:
            f.write("\n".join(stdout_all))
        self.zb_gib = gib
        self.units["zb"] = gib

    def ph_disk(self, name, url, out, m):
        docker("stop", f"bench-{name}", timeout=120)
        o = docker("run", "--rm", "-v", f"bench-{name}-data:/v:ro", "--entrypoint", "du", self.runner_image,
                   "-sB1", "/v")
        m["disk.bytes"] = int(o.split()[0])

    # -------------------------------------------------------------- profiling
    def perf_start(self, phase: str, name: str, url: str):
        pid = docker("inspect", "-f", "{{.State.Pid}}", f"bench-{name}")
        os.makedirs(f"{WORK}/perf", exist_ok=True)
        with open(f"{RESULTS}/profile/{phase}.metrics.before.txt", "w") as f:
            f.write(http_text(url + "/metrics"))
        rec = subprocess.Popen(["perf", "record", "-F", "99", "--call-graph", self.call_graph, "-g", "-p", pid,
                                "-o", f"{WORK}/perf/{phase}.data"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        out = f"{RESULTS}/profile/{phase}.syscalls.txt"
        if self.syscall_tool == "perf trace":
            tr = subprocess.Popen(["perf", "trace", "-s", "-p", pid, "-o", out],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        else:
            tr = subprocess.Popen(["strace", "-c", "-f", "-p", pid, "-o", out],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(1)  # let both attach
        return rec, tr

    def perf_stop(self, phase: str, url: str, procs) -> dict:
        rec, tr = procs
        info: dict = {}
        for p in (rec, tr):
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
        errs = {}
        for key, p in (("record", rec), ("trace", tr)):
            try:
                _, err = p.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                p.kill()
                _, err = p.communicate()
            errs[key] = (p.returncode, err or "")
        try:
            with open(f"{RESULTS}/profile/{phase}.metrics.after.txt", "w") as f:
                f.write(http_text(url + "/metrics"))
        except OSError as e:
            info["metrics_error"] = str(e)
        sc_path = f"{RESULTS}/profile/{phase}.syscalls.txt"
        sc_text = open(sc_path).read() if os.path.exists(sc_path) else ""
        parser = profile.parse_perf_trace_summary if self.syscall_tool == "perf trace" else profile.parse_strace_summary
        info["syscalls"] = parser(sc_text)
        if not info["syscalls"]:
            first = next((ln for ln in errs["trace"][1].splitlines() if ln.strip()), "no output")
            info["syscalls_unavailable"] = f"{self.syscall_tool}: {first}"
            if self.syscall_tool == "perf trace":
                self.syscall_tool = "strace"
                self.env["syscall_tool"] = "strace"
                self.save_env()
        data = f"{WORK}/perf/{phase}.data"
        rc, err = errs["record"]
        # perf exits 0 or 130/-2 on SIGINT depending on version.
        if not os.path.exists(data) or os.path.getsize(data) == 0 or rc not in (0, 130, -2):
            first = next((ln for ln in err.splitlines() if ln.strip()), f"perf record exit {rc}")
            info["unavailable"] = first
            return info
        folded = f"{RESULTS}/profile/{phase}.folded"
        sh = (f"perf script -i {data} --no-inline 2>/dev/null | inferno-collapse-perf --all > {folded} && "
              f"inferno-flamegraph --title 'roci {phase}' < {folded} > {RESULTS}/profile/{phase}.svg")
        p = subprocess.run(["bash", "-o", "pipefail", "-c", sh], capture_output=True, text=True, timeout=1800)
        stacks = profile.parse_folded(open(folded).read()) if os.path.exists(folded) else []
        if p.returncode != 0 or not stacks:
            first = next((ln for ln in p.stderr.splitlines() if ln.strip()), "no samples")
            info["unavailable"] = first
        else:
            stacks, info["instrumentation_pct"] = profile.strip_instrumentation(stacks)
            info["stacks"] = stacks
            # inferno prefixes the thread name (comm); a well-unwound stack then starts at a thread entry.
            # (musl's static binaries root every stack at `libc_start_main_stage2`.)
            roots = re.compile(r"^(_start|main|clone3?|start_thread|thread_start|_?_?libc_start|std::rt|"
                               r"std::sys::.*thread|ret_from_fork)")
            truncated = sum(n for fr, n in stacks if not any(roots.search(f) for f in fr[:3]))
            total = sum(n for _, n in stacks) or 1
            info["truncated_pct"] = round(truncated * 100 / total, 1)
            if total and truncated / total > 0.5 and self.call_graph != "fp":
                self.call_graph = "fp"
                self.env["perf_call_graph"] = "fp (dwarf stacks truncated)"
                self.save_env()
        if os.environ.get("BENCH_KEEP_PERF_DATA") == "1":
            shutil.move(data, f"{RESULTS}/profile/{phase}.data")
        else:
            os.remove(data)
        return info

    # ------------------------------------------------------------ registry
    def run_registry(self, rep: int, name: str) -> dict:
        out = f"{RESULTS}/raw/{rep}/{name}"
        os.makedirs(out, exist_ok=True)
        url = f"http://bench-{name}:5000"
        m: dict = {}
        failed: list[str] = []
        unsupported: dict[str, str] = {}
        self.client_bound, self.units = {}, {}
        self.vegeta_p50 = {}
        self.sampler = None
        docker("rm", "-f", f"bench-{name}", check=False)
        docker("volume", "rm", "-f", f"bench-{name}-data", check=False)
        first_img = None

        def phase(ph: str, fn, *a) -> bool:
            log(f"[rep {rep}] {name}: {ph} start")
            procs = None
            try:
                if self.mode == "perf" and ph in PROFILED:
                    try:
                        procs = self.perf_start(ph, name, url)
                    except (OSError, urllib.error.URLError, PhaseFailed) as e:
                        self.profile_data[ph] = {"unavailable": f"profiler start: {e}"}
                if self.sampler and ph in ("storm", "hot", "crane", "zb"):
                    with self.sampler.phase(ph):
                        fn(name, url, out, m, *a)
                else:
                    fn(name, url, out, m, *a)
                return True
            except PhaseUnsupported as e:
                unsupported[ph] = str(e)
                log(f"[rep {rep}] {name}: {ph} n/a: {e}")
                return True
            except PhaseFailed as e:
                failed.append(ph)
                with open(f"{out}/{ph}.err", "w") as f:
                    f.write(str(e))
                log(f"[rep {rep}] {name}: {ph} FAILED: {str(e).splitlines()[0]}")
                return False
            finally:
                if procs:
                    self.profile_data[ph] = self.perf_stop(ph, url, procs)
                if self.sampler and ph in self.sampler.phases:
                    pm = self.sampler.phase_metrics(ph)
                    self.profile_data.setdefault(ph, {}).update(pm) if self.mode == "perf" else None
                    if ph == "zb" and pm["cpu_s"] is not None and getattr(self, "zb_gib", 0):
                        m["cpu.zb_cpu_s_per_gib"] = pm["cpu_s"] / self.zb_gib

        def startup_empty(name, url, out, m):
            self.create(name)
            docker("start", f"bench-{name}")
            m["startup.empty_ms"] = self.wait_ready(name, url)
            try:
                self.sampler = cgroup.Sampler(self.cgroup_dir(name))
            except RuntimeError as e:
                raise HarnessBroken(str(e)) from e
            time.sleep(5)
            m["memory.idle_anon_mib"] = self.sampler.current_anon_mib()

        def storm(name, url, out, m):
            self.ph_storm(name, url, out, m)
            time.sleep(5)
            m["memory.corpus_anon_mib"] = self.sampler.current_anon_mib()

        self.zb_gib = 0.0
        self.pull_to_devnull = getattr(self, "pull_to_devnull", None)
        try:
            if phase("startup_empty", startup_empty):
                phase("storm", storm)
                if os.path.exists(f"{out}/corpus.json"):
                    first_img = json.load(open(f"{out}/corpus.json"))["images"][0]
                    phase("hot", self.ph_hot)
                else:
                    failed.append("hot")
                ready = phase("startup_populated", self.ph_startup_populated, first_img)
                if ready:
                    phase("crane", self.ph_crane)
                    phase("zb", self.ph_zb)
                    phase("disk", self.ph_disk)
                else:
                    failed.extend(p for p in ("crane", "zb", "disk") if p not in failed)
            else:
                failed.extend(p for p in PHASES[1:] if p not in failed)
        finally:
            if self.sampler:
                self.sampler.stop()
                m["memory.peak_anon_mib"] = self.sampler.peak_anon_mib()
                t0 = self.sampler.samples[0][0] if self.sampler.samples else 0.0
                self.sampler.dump_csv(f"{out}/cgroup.csv", t0)
            with open(f"{out}/container.log", "w") as f:
                f.write(run(["docker", "logs", f"bench-{name}"], 60, check=False).stdout)
                f.write(run(["docker", "logs", f"bench-{name}"], 60, check=False).stderr)
            docker("rm", "-f", f"bench-{name}", check=False)
            docker("volume", "rm", "-f", f"bench-{name}-data", check=False)
        res = {"metrics": m, "failed": failed, "unsupported": unsupported, "client_bound": self.client_bound, "units": self.units}
        with open(f"{out}/metrics.json", "w") as f:
            json.dump(res, f, indent=2)
        return res

    # ---------------------------------------------------------------- main
    def main(self) -> int:
        os.makedirs(RESULTS, exist_ok=True)
        self.arch_ = self.arch()
        log(f"bench: mode={self.mode} profile={self.profile_name} reps={self.reps} registries={self.registries}")
        log("bench: building fixture")
        self.fixture_digest = fixtures.build_app_layout(self.fixture_dir, self.seed)
        for r in self.registries:
            if r != "roci":
                log(f"bench: pulling {self.image_for(r)}")
                docker("pull", self.image_for(r), timeout=900)
        self.write_env()
        saved = {}
        if self.mode == "perf":
            os.makedirs(f"{RESULTS}/profile", exist_ok=True)
            for k, v in (("perf_event_paranoid", "-1"), ("kptr_restrict", "0")):
                p = f"/proc/sys/kernel/{k}"
                try:
                    saved[p] = open(p).read().strip()
                    with open(p, "w") as f:
                        f.write(v)
                except OSError as e:
                    self.env.setdefault("tunables_error", {})[k] = str(e)
        per_rep: list[dict] = []
        try:
            for rep in range(self.reps):
                order = list(self.registries)
                random.Random(self.seed * 1000 + rep).shuffle(order)
                log(f"[rep {rep}] order: {order}")
                per_rep.append({name: self.run_registry(rep, name) for name in order})
        except HarnessBroken as e:
            log(f"bench: HARNESS BROKEN: {e}")
            return 1
        finally:
            for p, v in saved.items():
                try:
                    with open(p, "w") as f:
                        f.write(v)
                except OSError as e:
                    log(f"bench: WARNING could not restore {p}={v}: {e}")
            self.save_env()
        summary = report.summarize(per_rep)
        with open(f"{RESULTS}/summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        note = "PROFILING BUILD — not comparable" if self.mode == "perf" else None
        with open(f"{RESULTS}/report.md", "w") as f:
            f.write(report.render_markdown(summary, self.env, note))
        if self.mode == "perf":
            with open(f"{RESULTS}/profile_report.md", "w") as f:
                f.write(self.profile_report(per_rep[0]["roci"]))
        return 1 if any(summary["failed"].values()) else 0

    def profile_report(self, res: dict) -> str:
        compare = None
        if os.path.exists("/compare/summary.json"):
            compare = json.load(open("/compare/summary.json"))
        gap_rows = profile.gaps(compare, report.metric_meta) if compare else []
        pdata = {}
        for ph in PROFILED:
            d = self.profile_data.get(ph, {})
            before, after = (f"{RESULTS}/profile/{ph}.metrics.{w}.txt" for w in ("before", "after"))
            routes = (profile.metrics_delta(open(before).read(), open(after).read())
                      if os.path.exists(before) and os.path.exists(after) else [])
            units = res["units"].get(ph)
            pdata[ph] = {**d, "categories": profile.categorize(d["stacks"]) if d.get("stacks") else {},
                         "routes": routes, "units": units,
                         "cpu_ms_per_unit": (d["cpu_s"] * 1000 / units) if d.get("cpu_s") and units else None}
        pdata["hot"]["hot_requests"] = res["units"].get("hot")
        pdata["hot"]["vegeta_p50_ms"] = self.vegeta_p50
        unit_name = {"storm": "image", "hot": "request", "crane": "byte", "zb": "GiB"}
        L = ["# roci profile report", "", "> **PROFILING BUILD — not comparable** (symbolized, frame pointers)", ""]
        if self.env.get("docker_desktop"):
            L += ["> **NON-AUTHORITATIVE: Docker Desktop VM**", ""]
        L += ["## Environment", ""]
        for k in ("run_id", "profile", "git_sha", "git_dirty", "cpu_model", "KernelVersion", "OperatingSystem",
                  "server_cpus", "syscall_tool", "perf_call_graph", "tunables_error"):
            if k in self.env:
                L.append(f"- **{k}**: `{self.env[k]}`")
        if res["failed"]:
            L.append(f"- **FAILED phases**: {', '.join(res['failed'])}")
        L += ["", "## Findings", ""]
        fl = profile.findings({k: v for k, v in pdata.items()}, gap_rows)
        L += [f"- {x}" for x in fl] or ["- none above thresholds"]
        L.append("")
        if compare is not None:
            L += ["## Gaps vs competitors", "", "| metric | roci | best competitor | ratio | phase |",
                  "|---|---|---|---|---|"]
            L += [f"| `{g['metric']}` | {g['roci']:.4g} | {g['best']:.4g} ({g['competitor']}) | {g['ratio']:.2f} | "
                  f"{g['phase']} |" for g in gap_rows] or ["| — | | | | none > 10% |"]
            L.append("")
        for ph in PROFILED:
            d = pdata[ph]
            L += [f"## Phase `{ph}`", ""]
            fmt = lambda v, p=".3g": "—" if v is None else format(v, p)  # noqa: E731
            L += [f"- cpu_s: {fmt(d.get('cpu_s'))}",
                  f"- cpu_ms per {unit_name[ph]}: {fmt(d.get('cpu_ms_per_unit'))} (units: {d.get('units')})",
                  f"- peak_anon_mib: {fmt(d.get('peak_anon_mib'))}"]
            if d.get("instrumentation_pct"):
                L.append(f"- profiler overhead removed (perf tracepoint leaf frames): {d['instrumentation_pct']}%")
            if d.get("truncated_pct") is not None:
                L.append(f"- stacks not rooted at a thread entry: {d['truncated_pct']}%")
            if d.get("unavailable"):
                L += [f"- CPU profile: unavailable ({d['unavailable']})", ""]
            else:
                L += [f"- flamegraph: [profile/{ph}.svg](profile/{ph}.svg)", "", "| category | % samples |",
                      "|---|---|"] + [f"| {c} | {p} |" for c, p in
                                      sorted(d["categories"].items(), key=lambda kv: -kv[1])]
                L += ["", "Top self frames:", "", "| frame | weight | % |", "|---|---|---|"]
                L += [f"| `{f[:140]}` | {n} | {p} |" for f, n, p in profile.self_top(d["stacks"])]
                L += ["", "Top inclusive roci frames:", "", "| frame | weight | % |", "|---|---|---|"]
                L += [f"| `{f[:140]}` | {n} | {p} |" for f, n, p in profile.inclusive_top(d["stacks"])]
            L += ["", f"Top syscalls ({self.env.get('syscall_tool', 'perf trace')}):", ""]
            if d.get("syscalls"):
                L += ["| syscall | calls | total ms |", "|---|---|---|"]
                L += [f"| {s} | {v['calls']} | {v['total_ms']:.1f} |" for s, v in
                      sorted(d["syscalls"].items(), key=lambda kv: -kv[1]["total_ms"])[:15]]
            else:
                L.append(f"unavailable ({d.get('syscalls_unavailable', 'no data')})")
            L += ["", "Server-side routes (`http.server.request.duration` delta):", ""]
            if d["routes"]:
                L += ["| labels | count | mean ms |", "|---|---|---|"]
                L += [f"| `{r['labels']}` | {r['count']} | {r['mean_ms']:.3f} |" for r in d["routes"]]
            else:
                L.append("no data")
            L.append("")
        return "\n".join(L)


def main() -> int:
    return Bench().main()


if __name__ == "__main__":
    sys.exit(main())
