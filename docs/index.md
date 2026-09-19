---
layout: home

hero:
  name: roci
  text: A fast, minimal OCI registry in Rust
  tagline: A Rust implementation of the OCI Distribution Specification — single static binary, zero-config start, no runtime dependencies.
  image:
    light: /icon.svg
    dark: /icon.svg
    alt: roci
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: What is roci?
      link: /guide/introduction
    - theme: alt
      text: View on GitHub
      link: https://github.com/jakobmoellerdev/roci

features:
  - title: Minimal footprint
    details: A single static binary with a tiny memory and CPU baseline — no daemon sprawl, no external database. Suitable for edge, CI, and colocated Kubernetes.
  - title: Fast queries
    details: An index designed for low-latency tag, manifest, referrer, and search lookups, with zero-copy blob serving where the OS allows it.
  - title: Config-driven
    details: Start with zero config and sane defaults; grow into a single declarative config file. All behavior is controlled from configuration, not build-time code paths.
  - title: OCI image layout on disk
    details: Storage is a plain OCI image layout, so any layout can be served directly as a registry and inspected with standard tooling.
  - title: Core vs. extensions
    details: The dist-spec surface is a stable core; signatures, search, sync, scanning, and metrics are cleanly separated extensions compiled and configured independently.
  - title: Rootless & hardened
    details: No root privileges required. Ships as a hardened static musl binary on a scratch base, running as a nonroot UID with a read-only root filesystem.
---
