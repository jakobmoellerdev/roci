# roci Helm chart

Hardened Helm chart for [roci](https://github.com/jakobmoellerdev/roci), a Rust OCI registry, with optional HA S3 storage on RustFS.

Each roci release `vX.Y.Z` publishes this chart as `oci://ghcr.io/jakobmoellerdev/charts/roci` version `X.Y.Z` (`appVersion` `X.Y.Z`):

```sh
helm install roci oci://ghcr.io/jakobmoellerdev/charts/roci --version <X.Y.Z> -n roci --set auth.allowAnonymous=true
```

See the [Kubernetes (Helm) guide](https://jakobmoellerdev.github.io/roci/guide/kubernetes) for installation, configuration, and hardening details.
