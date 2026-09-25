#!/usr/bin/env bash
# End-to-end test of charts/roci on a live Kubernetes cluster (the `k0s` job
# of the CI `helm` workflow). Installs the chart into a PSS-restricted
# namespace, runs helm test and the OCI conformance suite through the
# registry's NodePort, and for the s3-rustfs scenario proves the blob lands in RustFS,
# survives the loss of one RustFS pod, and that RustFS is NetworkPolicy-fenced.
# Both scenarios assert graceful SIGTERM shutdown and restart persistence.
#
# Env:
#   SCENARIO         filesystem | s3-rustfs (charts/roci/ci/<SCENARIO>-values.yaml)
#   CONFORMANCE_DIR  absolute path of the directory holding conformance.test
#   ARTIFACT_DIR     existing directory for diagnostics/port-forward logs
# Assumes a reachable cluster (kubectl/helm on PATH) whose container runtime
# already holds the `roci:ci` image. Run from the repo root.
set -euo pipefail

: "${SCENARIO:?}" "${CONFORMANCE_DIR:?}" "${ARTIFACT_DIR:?}"
case "$SCENARIO" in
  filesystem) AUTH=() ;;
  s3-rustfs) AUTH=(-u conformance:conformance) ;;
  *) echo "k0s-e2e: unknown SCENARIO '$SCENARIO' (filesystem | s3-rustfs)" >&2; exit 2 ;;
esac
[ -d "$ARTIFACT_DIR" ] || { echo "k0s-e2e: ARTIFACT_DIR '$ARTIFACT_DIR' does not exist" >&2; exit 2; }

NS=roci-ci
REL=roci-ci
# Keep in sync with hooks.image in charts/roci/values.yaml.
CURL_IMAGE=curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
EMPTY_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
REG="" # http://<node>:<nodePort>, set after install
WORK="$(mktemp -d)"
PF_PIDS=()

log() { echo "k0s-e2e: $*"; }
die() { echo "k0s-e2e: FAIL: $*" >&2; exit 1; }

kill_port_forwards() {
  local pid
  for pid in ${PF_PIDS[@]+"${PF_PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  PF_PIDS=()
}

diagnostics() {
  set +e
  echo "--- helm status"; helm status "$REL" -n "$NS"
  echo "--- resources"; kubectl get all,pvc,networkpolicy,jobs -n "$NS" -o wide
  echo "--- secrets (names only)"; kubectl get secrets -n "$NS"
  echo "--- pods"; kubectl describe pods -n "$NS"
  echo "--- events"; kubectl get events -n "$NS" --sort-by=.lastTimestamp
  echo "--- logs"; kubectl logs -n "$NS" -l "app.kubernetes.io/instance=$REL" --all-containers --prefix --tail=500
}

on_exit() {
  local status=$?
  kill_port_forwards
  if [ "$status" -ne 0 ]; then
    echo "::group::diagnostics"
    diagnostics 2>&1 | tee "$ARTIFACT_DIR/diagnostics.txt"
    echo "::endgroup::"
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap on_exit EXIT

# pf <svc> <local>:<remote>: background port-forward, ready once TCP answers.
pf() {
  local svc="$1" ports="$2" local_port="${2%%:*}"
  kubectl -n "$NS" port-forward "svc/$svc" "$ports" >"$ARTIFACT_DIR/pf-$svc.log" 2>&1 &
  PF_PIDS+=("$!")
  for _ in $(seq 1 30); do
    if curl -s -o /dev/null "http://127.0.0.1:$local_port/"; then return 0; fi
    sleep 1
  done
  die "port-forward to svc/$svc ($ports) not ready after 30s"
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# push_blob <repo> <file>: monolithic upload, expects 201.
push_blob() {
  local repo="$1" file="$2" code
  code="$(curl -sS ${AUTH[@]+"${AUTH[@]}"} -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/octet-stream' --data-binary "@$file" \
    "$REG/v2/$repo/blobs/uploads/?digest=sha256:$(sha256_of "$file")")" || true
  [ "$code" = 201 ] || { echo "push $file to $repo: HTTP $code, want 201" >&2; return 1; }
}

# get_blob <repo> <file>: expects 200 with the file's bytes; a 307 would be a
# redirect leaking the in-cluster RustFS URL.
get_blob() {
  local repo="$1" file="$2" code
  code="$(curl -sS ${AUTH[@]+"${AUTH[@]}"} --max-redirs 0 -o "$WORK/got" -w '%{http_code}' \
    "$REG/v2/$repo/blobs/sha256:$(sha256_of "$file")")" || true
  [ "$code" = 200 ] || { echo "get $file from $repo: HTTP $code, want 200" >&2; return 1; }
  [ "$(sha256_of "$WORK/got")" = "$(sha256_of "$file")" ] || { echo "get $file from $repo: digest mismatch" >&2; return 1; }
}

# retry <attempts> <sleep> <cmd...>
retry() {
  local n="$1" delay="$2" i
  shift 2
  for i in $(seq 1 "$n"); do
    if "$@"; then return 0; fi
    [ "$i" -lt "$n" ] && sleep "$delay"
  done
  return 1
}

# probe <url>: curl <url> from a fresh, unlabelled, PSS-restricted pod and
# print the container's exit code (0 = reachable).
probe() {
  local url="$1" name="np-probe-$RANDOM" phase="" overrides
  overrides="$(cat <<JSON
{"apiVersion":"v1","spec":{"automountServiceAccountToken":false,
 "securityContext":{"runAsNonRoot":true,"runAsUser":65532,"runAsGroup":65532,"seccompProfile":{"type":"RuntimeDefault"}},
 "containers":[{"name":"$name","image":"$CURL_IMAGE",
  "command":["curl","-sS","-o","/dev/null","--max-time","5","$url"],
  "securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}
JSON
)"
  kubectl -n "$NS" run "$name" --restart=Never --image="$CURL_IMAGE" --overrides="$overrides" >/dev/null
  for _ in $(seq 1 60); do
    phase="$(kubectl -n "$NS" get pod "$name" -o jsonpath='{.status.phase}')"
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 1
  done
  case "$phase" in Succeeded|Failed) ;; *) die "probe pod $name stuck in phase '$phase'" ;; esac
  kubectl -n "$NS" get pod "$name" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}'
  kubectl -n "$NS" delete pod "$name" --wait=false >/dev/null
}

# 1. PSS-restricted namespace.
log "namespace $NS (PodSecurity restricted)"
kubectl create namespace "$NS"
kubectl label namespace "$NS" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# 2. Canary: enforcement must be live, so a clean install proves compliance.
if out="$(kubectl -n "$NS" run pss-canary --restart=Never --image=registry.k8s.io/pause:3.10 --dry-run=server \
  --overrides='{"apiVersion":"v1","spec":{"containers":[{"name":"pss-canary","image":"registry.k8s.io/pause:3.10","securityContext":{"privileged":true}}]}}' 2>&1)"; then
  die "privileged canary pod was admitted: PodSecurity enforcement is not active"
fi
[[ "$out" == *"violates PodSecurity"* ]] || die "canary rejected for an unexpected reason: $out"
log "PSS canary rejected: violates PodSecurity"

# 3. Scenario prerequisites.
if [ "$SCENARIO" = s3-rustfs ]; then
  kubectl -n "$NS" create secret generic roci-ci-htpasswd --from-file=htpasswd=scripts/conformance/htpasswd
fi

# 4. Install; the post-install bucket-init Job must succeed inside this call.
bash scripts/helm-deps.sh
log "helm install ($SCENARIO)"
helm upgrade --install "$REL" charts/roci -n "$NS" -f "charts/roci/ci/$SCENARIO-values.yaml" \
  --wait=watcher --timeout 10m

# 5. Rollouts.
kubectl -n "$NS" rollout status "statefulset/$REL" --timeout=5m
if [ "$SCENARIO" = s3-rustfs ]; then
  kubectl -n "$NS" rollout status "statefulset/$REL-rustfs" --timeout=5m
fi

# 6. Chart test pod (the upstream RustFS test pod is not PSS-restricted).
helm test "$REL" -n "$NS" --filter "name=$REL-test" --logs --timeout 5m

# 7. Registry endpoint: the CI values expose it as a NodePort. Not `kubectl
# port-forward`: it exits on the first reset forwarded connection, and roci
# closes a connection whose upload it rejects with 401 (the conformance
# suite's unauthenticated first attempt) before reading the body.
node_ip="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
node_port="$(kubectl -n "$NS" get svc "$REL" -o jsonpath='{.spec.ports[0].nodePort}')"
[ -n "$node_ip" ] && [ -n "$node_port" ] || die "registry NodePort not found (service.type must be NodePort)"
REG="http://$node_ip:$node_port"
log "registry at $REG"
retry 30 2 curl -sf ${AUTH[@]+"${AUTH[@]}"} -o /dev/null "$REG/v2/" || die "GET /v2/ never returned 200"

# 8. OCI conformance (mirrors scripts/conformance.sh).
log "OCI conformance"
creds="${AUTH[1]:-:}"
(
  cd "$CONFORMANCE_DIR"
  OCI_ROOT_URL="$REG" \
    OCI_NAMESPACE=roci-conformance/test \
    OCI_CROSSMOUNT_NAMESPACE=roci-conformance/other \
    OCI_AUTOMATIC_CROSSMOUNT=false \
    OCI_USERNAME="${creds%%:*}" OCI_PASSWORD="${creds#*:}" \
    OCI_TEST_PULL=1 OCI_TEST_PUSH=1 OCI_TEST_CONTENT_DISCOVERY=1 OCI_TEST_CONTENT_MANAGEMENT=1 \
    OCI_HIDE_SKIPPED_WORKFLOWS=1 \
    ./conformance.test
)

# 9. A 2 MiB blob (above roci's default 1 MiB redirect threshold) round-trips
# without a redirect.
head -c 2097152 /dev/urandom >"$WORK/blob-a"
push_blob e2e/blob "$WORK/blob-a" || die "push blob-a"
get_blob e2e/blob "$WORK/blob-a" || die "get blob-a"
log "blob-a round-trip ok"

if [ "$SCENARIO" = s3-rustfs ]; then
  # 10. The blob physically lives in RustFS (key <repo>/blobs/<alg>/<hex>).
  ak="$(kubectl -n "$NS" get secret "$REL-rustfs-secret" -o jsonpath='{.data.RUSTFS_ACCESS_KEY}' | base64 -d)"
  sk="$(kubectl -n "$NS" get secret "$REL-rustfs-secret" -o jsonpath='{.data.RUSTFS_SECRET_KEY}' | base64 -d)"
  pf "$REL-rustfs-svc" 19000:9000
  hex="$(sha256_of "$WORK/blob-a")"
  code="$(printf 'user = "%s:%s"\n' "$ak" "$sk" | curl -sS -K - -o "$WORK/obj" -w '%{http_code}' \
    --aws-sigv4 "aws:amz:us-east-1:s3" -H "x-amz-content-sha256: $EMPTY_SHA256" \
    "http://127.0.0.1:19000/roci/e2e/blob/blobs/sha256/$hex")" || true
  [ "$code" = 200 ] || die "RustFS GET object: HTTP $code, want 200"
  [ "$(sha256_of "$WORK/obj")" = "$hex" ] || die "RustFS object digest mismatch"
  log "blob-a stored in RustFS bucket roci"

  # 11. Lose one of four RustFS pods: reads (2 of 4 needed) and writes (write
  # quorum 3) must keep working.
  log "RustFS pod loss: scaling $REL-rustfs to 3"
  kill_port_forwards # RustFS port-forward; its pod set is about to change
  kubectl -n "$NS" scale "statefulset/$REL-rustfs" --replicas=3
  kubectl -n "$NS" wait --for=delete "pod/$REL-rustfs-3" --timeout=180s
  retry 18 10 get_blob e2e/blob "$WORK/blob-a" || die "read with one RustFS pod down"
  head -c 2097152 /dev/urandom >"$WORK/blob-b"
  retry 18 10 push_blob e2e/blob "$WORK/blob-b" || die "write with one RustFS pod down"
  get_blob e2e/blob "$WORK/blob-b" || die "read back blob-b with one RustFS pod down"
  log "read + write ok with 3 of 4 RustFS pods"
  kubectl -n "$NS" scale "statefulset/$REL-rustfs" --replicas=4
  kubectl -n "$NS" rollout status "statefulset/$REL-rustfs" --timeout=5m

  # 12. NetworkPolicy: an unlabelled pod reaches roci but not RustFS.
  rc="$(probe "http://$REL:5000/v2/")"
  [ "$rc" = 0 ] || die "probe pod could not reach roci (exit $rc): probe networking broken"
  rc="$(probe "http://$REL-rustfs-svc:9000/health")"
  [ "$rc" != 0 ] || die "unlabelled pod reached RustFS: NetworkPolicy not enforced"
  log "NetworkPolicy: roci reachable (exit 0), RustFS blocked (exit $rc)"
fi

# 13. Graceful SIGTERM shutdown (grace period 30s) and persistence.
start="$(date +%s)"
kubectl -n "$NS" delete pod "$REL-0" --wait=true --timeout=60s
elapsed=$(($(date +%s) - start))
[ "$elapsed" -lt 15 ] || die "pod $REL-0 took ${elapsed}s to stop: SIGTERM not handled"
log "pod $REL-0 stopped in ${elapsed}s"
retry 60 2 kubectl -n "$NS" get pod "$REL-0" -o name >/dev/null || die "pod $REL-0 not recreated"
kubectl -n "$NS" wait --for=condition=Ready "pod/$REL-0" --timeout=180s
retry 30 2 get_blob e2e/blob "$WORK/blob-a" || die "blob-a lost across restart"
if [ "$SCENARIO" = s3-rustfs ]; then
  get_blob e2e/blob "$WORK/blob-b" || die "blob-b lost across restart"
fi
log "blobs persisted across restart"

echo "k0s e2e ($SCENARIO): all checks passed"
