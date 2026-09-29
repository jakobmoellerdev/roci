# Kubernetes (Helm)

A hardened Helm chart for roci lives at `charts/roci/`. It deploys roci as a single-replica StatefulSet with optional high-availability S3 storage backed by the [RustFS](https://rustfs.com) subchart.

## Install

Create a namespace with Pod Security Standards restricted enforcement:

```sh
kubectl create namespace roci
kubectl label namespace roci \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

Install the chart published with a roci release. Every `v*` release pushes it to GHCR as an OCI artifact, version-locked to the release: chart `X.Y.Z` has `appVersion` `X.Y.Z` and deploys `ghcr.io/jakobmoellerdev/roci:X.Y.Z`. The RustFS subchart is bundled.

```sh
helm install roci oci://ghcr.io/jakobmoellerdev/charts/roci --version <X.Y.Z> -n roci \
  --set auth.allowAnonymous=true
```

Each published chart carries a build-provenance attestation; verify it before installing:

```sh
gh attestation verify oci://ghcr.io/jakobmoellerdev/charts/roci:<X.Y.Z> --owner jakobmoellerdev
```

To install from a checkout (e.g. unreleased `main`), build the chart dependencies first:

```sh
helm repo add rustfs https://charts.rustfs.com
helm dependency build charts/roci
helm install roci charts/roci -n roci \
  --set auth.allowAnonymous=true
```

The remaining examples use the local `charts/roci` path; substitute `oci://ghcr.io/jakobmoellerdev/charts/roci --version <X.Y.Z>` for a released chart.

The `--set auth.allowAnonymous=true` flag is required for a minimal install. Without it (and without configuring `auth.htpasswd.existingSecret` or `auth.accessControl`), rendering fails with an error reminding you to configure authentication.

## Secure defaults and authentication

The chart is **secure by default**: rendering fails unless authentication is configured or anonymous access is explicitly enabled. To configure htpasswd authentication, create a Kubernetes Secret containing bcrypt htpasswd lines and reference it:

```sh
kubectl -n roci create secret generic roci-htpasswd \
  --from-file=htpasswd=./htpasswd
helm install roci charts/roci -n roci \
  --set auth.htpasswd.existingSecret=roci-htpasswd
```

For fine-grained access control, set `auth.accessControl` (rendered as TOML into the roci config). When TLS is not terminated in front of roci, set `tls.existingSecret` to a `kubernetes.io/tls` Secret so credentials are not sent in plaintext.

## S3 mode with RustFS

Enable S3 storage by setting `rustfs.enabled=true`. This switches roci from local-filesystem blob storage to an S3-compatible backend served by the bundled RustFS subchart.

### HA topology

RustFS is deployed in **distributed mode** with a minimum of 4 pods (`rustfs.replicaCount`, enforced by the chart). With `drivesPerNode: 1`, this creates a 4-drive erasure set with default parity 2 and write quorum 3. The set **tolerates the loss of one pod** for both reads and writes.

Pod anti-affinity (`rustfs.affinity.podAntiAffinity.enabled: true`, on by default) spreads RustFS pods across nodes. A `PodDisruptionBudget` with `maxUnavailable: 1` prevents voluntary evictions from dropping below quorum.

### Credentials

By default, RustFS credentials are set in `rustfs.secret.rustfs.access_key` and `rustfs.secret.rustfs.secret_key`. For production, create a dedicated Secret and reference it via `rustfs.secret.existingSecret`. When using an existing Secret, you must also set `s3.accessKeyId` to match the Secret's `RUSTFS_ACCESS_KEY` value.

`rustfs.secret.allowInsecureDefaults` is rejected by the chart's render-time guard.

### Erasure-coding tolerance

With 4 pods and default parity, the cluster survives one pod loss. To increase tolerance, raise `rustfs.replicaCount` (must be >= 4); RustFS picks a larger default parity for more drives.

### Bucket bootstrap

RustFS creates no buckets at startup. Two steps handle it, in this order:

1. **roci creates the bucket.** The chart always sets `create_bucket = true` in the roci config. At startup roci sends a signed CreateBucket through the RustFS Service. `200` and `409` count as success; anything else is retried with backoff for up to 60 s. After that, each `/readyz` check makes one more attempt until one succeeds. `/readyz` stays `503` until the bucket is writable, so `helm install --wait` blocks until then. roci cannot rely on a hook for this: Helm runs `post-install` hooks only after `--wait` sees roci Ready.
2. **The bucket-init Job confirms every RustFS pod.** A new bucket reaches the RustFS pods asynchronously, and a pod can reject `PutObject` with `NoSuchBucket` for seconds after creation. roci only sees the Service. The `post-install,post-upgrade` hook Job therefore PUTs the bucket (idempotent) and writes and deletes a `.roci-bucket-init-probe` object on every pod through the headless Service. It completes only once each pod accepts the write, so `helm install` returns only after all pods know the bucket.

### Private-CA trust

The chart has no CA setting: its only S3 endpoint is the in-cluster RustFS, which is plaintext (see Limitations). For roci deployed outside the chart against a private-CA HTTPS endpoint, such as a cert-manager-issued one, set `ca_file` in `[storage.s3]` (see [Configuration](./configuration.md)).

### redirect_min_size = 0

The chart forces `redirect_min_size = 0` in the roci config. Clients cannot reach the in-cluster RustFS Service, so roci must proxy every blob instead of issuing 307 redirects.

### External S3

External S3 endpoints are out of scope for the chart: it templates, fences and e2e-tests only the bundled RustFS subchart.

## Health endpoints

The chart uses dedicated health endpoints for kubelet probes:

- **`GET /readyz`** (startup + readiness) — returns `200 ok` when startup recovery has finished and a storage write probe has succeeded, `503` with a fixed reason (`not ready: recovery in progress` or `not ready: storage unavailable`) otherwise. One storage check is bounded at 2 s so a hung backend reads as `503`, not a probe timeout. These endpoints are outside `/v2/`, require **no authentication**, and are not subject to rate limiting.
- **`GET /livez`** (liveness) — returns `200` unconditionally once the listener is bound.
- Both accept `HEAD` in addition to `GET`.

## Hardening summary

| Control | Detail |
| --- | --- |
| Pod Security Standards | Namespace `pod-security.kubernetes.io/enforce=restricted` |
| UID | 65532 (nonroot) |
| Root filesystem | Read-only |
| Capabilities | `drop: [ALL]`, no adds |
| Seccomp | `RuntimeDefault` |
| AppArmor | `RuntimeDefault` |
| User namespaces | `hostUsers: false` |
| ServiceAccount | Created, but `automountServiceAccountToken: false`; no RBAC |
| NetworkPolicies | Per-workload: registry, RustFS, bucket-init, test. RustFS reachable only from roci, bucket-init, and peer RustFS pods |
| Secrets | roci and the bucket-init Job read them as 0440 file mounts, never environment variables; the roci config is itself a Secret (it carries the S3 access key id). Upstream RustFS takes its credentials via `envFrom` |
| Auth guard | Rendering fails without auth configuration or explicit `allowAnonymous`; RustFS default credentials rejected |
| Images | RustFS, busybox and curl are digest-pinned (`tag@sha256:...`); pin roci with `image.digest` (else the `appVersion` tag) |
| `/metrics` | Off by default; when enabled it is unauthenticated on the registry port. `networkPolicy.ingressFrom` restricts who reaches that port |
| `/readyz` / `/livez` | Unauthenticated health endpoints; expose only a readiness flag and a short reason string — no internal state or version info |

## Helm test

Run the chart's built-in test:

```sh
helm test roci -n roci --filter name=roci-test --logs --timeout 5m
```

The upstream RustFS chart's test pod lacks the security context required by PSS restricted. Always use `--filter name=<fullname>-test` to run only the roci test pod.

## Limitations

- **Single replica.** roci runs as exactly one replica (ARCHITECTURE invariant 7: each repository has one writing instance). The S3 backend keeps metadata and upload staging on a local PVC, so a second replica would diverge. Clustering is planned for Phase 8.
- **Bundled RustFS only.** The chart does not template external S3 endpoints.
- **RustFS mTLS unsupported.** The RustFS 1.0.0 subchart's `mtls.enabled` bundles server TLS and client-certificate authentication into a single `RUSTFS_SERVER_MTLS_ENABLE` flag — there is no server-TLS-only mode. `object_store` (roci's S3 client) has no client-certificate identity API, so roci cannot present a client cert. In-cluster S3 traffic remains plaintext, confined by NetworkPolicy. The chart rejects `rustfs.mtls.enabled` with this explanation. For a private-CA S3 endpoint outside the chart, set `ca_file`.
