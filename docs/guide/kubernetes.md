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

Build the chart dependencies and install:

```sh
helm repo add rustfs https://charts.rustfs.com
helm dependency build charts/roci
helm install roci charts/roci -n roci \
  --set auth.allowAnonymous=true
```

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

RustFS creates no buckets at startup. The bucket-init Job (`post-install,post-upgrade` hook) creates `s3.bucket` with a curl SigV4 `PUT`, retrying until RustFS has formed its erasure set; a `409` on upgrade counts as success. roci itself starts before the bucket exists: startup recovery lists the bucket, tolerates the miss, and binds (it waits out S3 client retries, up to about a minute, while RustFS is still unreachable).

### redirect_min_size = 0

The chart forces `redirect_min_size = 0` in the roci config. Clients cannot reach the in-cluster RustFS Service, so roci must proxy every blob instead of issuing 307 redirects.

### External S3

External S3 endpoints are out of scope. The roci scratch image has no CA bundle, so TLS-terminated external S3 would require injecting certificates. Only the bundled RustFS subchart is supported.

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

## Helm test

Run the chart's built-in test:

```sh
helm test roci -n roci --filter name=roci-test --logs --timeout 5m
```

The upstream RustFS chart's test pod lacks the security context required by PSS restricted. Always use `--filter name=<fullname>-test` to run only the roci test pod.

## Limitations

- **Single replica.** roci runs as exactly one replica (ARCHITECTURE invariant 7: each repository has one writing instance). The S3 backend keeps metadata and upload staging on a local PVC, so a second replica would diverge. Clustering is planned for Phase 8.
- **Bundled RustFS only.** External S3 endpoints are unsupported because the scratch image has no CA bundle.
- **RustFS mTLS unsupported.** roci's S3 client cannot trust a private RustFS CA; in-cluster traffic is plaintext and confined by NetworkPolicy.
- **Chart appVersion 0.2.0.** This predates the SIGTERM graceful-shutdown fix. Until the next release, pod stop waits for the full grace period before SIGKILL.
