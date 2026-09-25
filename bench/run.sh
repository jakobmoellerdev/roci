#!/usr/bin/env bash
# Host entrypoint for the registry benchmark (see docs/guide/benchmarks.md).
#   bench/run.sh [compare|perf] [quick|full] [compare-results-dir]
# Needs only rootful Docker; every tool runs inside the pinned runner image.
set -euo pipefail

mode="${1:-compare}"
profile="${2:-quick}"
compare_dir="${3:-}"

case "$mode" in compare | perf) ;; *) echo "bench: mode must be compare|perf, got '$mode'" >&2; exit 1 ;; esac
case "$profile" in quick | full) ;; *) echo "bench: profile must be quick|full, got '$profile'" >&2; exit 1 ;; esac
if [[ -n "$compare_dir" ]]; then
  if [[ "$mode" != perf ]]; then
    echo "bench: a compare-results-dir is only accepted in perf mode" >&2
    exit 1
  fi
  if [[ ! -f "$compare_dir/summary.json" ]]; then
    echo "bench: $compare_dir/summary.json not found" >&2
    exit 1
  fi
  compare_dir="$(cd "$compare_dir" && pwd)"
fi

cd "$(git rev-parse --show-toplevel)"
command -v docker >/dev/null || { echo "bench: docker not found" >&2; exit 1; }

sha="$(git rev-parse --short=12 HEAD)"
dirty=0
[[ -n "$(git status --porcelain)" ]] && dirty=1
run_id="$(date -u +%Y%m%dT%H%M%SZ)-${sha}"
[[ $dirty == 1 ]] && run_id+="-dirty"
run_id+="-${profile}"
[[ $mode == perf ]] && run_id+="-perf"

ncpu="$(docker info --format '{{.NCPU}}')"
if ((ncpu < 4)); then
  echo "bench: need >= 4 CPUs visible to Docker" >&2
  exit 1
fi
if [[ -z "${BENCH_SERVER_CPUS:-}" || -z "${BENCH_CLIENT_CPUS:-}" ]]; then
  half=$((ncpu / 2))
  ((half > 4)) && half=4
  BENCH_SERVER_CPUS="0-$((half - 1))"
  BENCH_CLIENT_CPUS="${half}-$((2 * half - 1))"
fi

echo "bench: run $run_id (server cpus $BENCH_SERVER_CPUS, client cpus $BENCH_CLIENT_CPUS)"
# BENCH_ROCI_PREBUILT=<ref>: benchmark a published roci image (e.g. the GHCR
# build of this commit) instead of building one. It is retagged locally so the
# harness is unchanged; its digest is recorded in env.json.
if [[ -n "${BENCH_ROCI_PREBUILT:-}" ]]; then
  if ! docker pull "$BENCH_ROCI_PREBUILT"; then
    echo "bench: cannot pull $BENCH_ROCI_PREBUILT (not published yet? container.yml pushes main commits)" >&2
    exit 1
  fi
  docker tag "$BENCH_ROCI_PREBUILT" roci-bench/roci:local
else
  docker build -t roci-bench/roci:local -f Containerfile .
fi
# BENCH_RUNNER_PREBUILT=1: roci-bench/runner:local is already loaded (CI builds
# it with a layer cache).
if [[ "${BENCH_RUNNER_PREBUILT:-0}" != 1 ]]; then
  docker build -t roci-bench/runner:local -f bench/Containerfile.runner bench
fi
if [[ $mode == perf ]]; then
  docker build -t roci-bench/roci:perf -f bench/Containerfile.roci-perf .
fi

docker network inspect roci-bench >/dev/null 2>&1 || docker network create roci-bench >/dev/null
docker rm -f roci-bench-runner >/dev/null 2>&1 || true

docker create --name roci-bench-runner --privileged --cgroupns=host --pid=host \
  --network roci-bench --cpuset-cpus "$BENCH_CLIENT_CPUS" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e BENCH_MODE="$mode" \
  -e BENCH_PROFILE="$profile" \
  -e BENCH_RUN_ID="$run_id" \
  -e BENCH_GIT_SHA="$sha" \
  -e BENCH_GIT_DIRTY="$dirty" \
  -e BENCH_ROCI_IMAGE=roci-bench/roci:local \
  -e BENCH_ROCI_PERF_IMAGE=roci-bench/roci:perf \
  -e BENCH_RUNNER_IMAGE=roci-bench/runner:local \
  -e BENCH_SERVER_CPUS="$BENCH_SERVER_CPUS" \
  -e BENCH_CLIENT_CPUS="$BENCH_CLIENT_CPUS" \
  -e BENCH_SERVER_MEMORY="${BENCH_SERVER_MEMORY:-4g}" \
  -e BENCH_REGISTRIES="${BENCH_REGISTRIES:-roci,zot,distribution}" \
  -e BENCH_KEEP_PERF_DATA="${BENCH_KEEP_PERF_DATA:-0}" \
  -e GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" \
  roci-bench/runner:local >/dev/null

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
  mkdir -p "bench/results/$run_id"
  docker cp roci-bench-runner:/results/. "bench/results/$run_id/" >/dev/null 2>&1 || true
  docker rm -f roci-bench-runner >/dev/null 2>&1 || true
  docker network rm roci-bench >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n "$compare_dir" ]]; then
  docker cp "$compare_dir/summary.json" roci-bench-runner:/compare/summary.json
fi

rc=0
docker start -a roci-bench-runner || rc=$?
echo "bench: report at bench/results/$run_id/report.md"
[[ $mode == perf ]] && echo "bench: profile report at bench/results/$run_id/profile_report.md"
exit "$rc"
