# Documentation site

This site is built with [VitePress](https://vitepress.dev/) and lives in the `docs/` directory. It is deployed to GitHub Pages by the `docs` workflow (`.github/workflows/docs.yml`) on every push to `main`.

## Local development

From the `docs/` directory:

```sh
npm install        # first time only
npm run docs:dev   # hot-reloading dev server
```

Build and preview the production site:

```sh
npm run docs:build
npm run docs:preview
```

## Structure

```
docs/
├── .vitepress/
│   ├── config.mts        # site config: nav, sidebar, head, edit links
│   └── theme/
│       ├── index.ts      # extends the VitePress default theme
│       └── brand.css     # roci brand tokens → VitePress theme variables
├── public/               # static assets served at the site root
│   ├── logo.svg          # copied from repo-root assets/ (source of truth)
│   ├── logo-dark.svg
│   ├── favicon.svg
│   ├── icon.svg
│   └── social-card.svg
├── guide/                # user + contributor guide
├── design/               # design overviews that link the canonical root docs
├── roadmap.md            # mirrors the README feature roadmap
└── index.md              # home page
```

## Branding

Theming uses the roci brand palette from [`assets/BRAND.md`](https://github.com/jakobmoellerdev/roci/blob/main/assets/BRAND.md), mapped onto VitePress's `--vp-c-brand-*` variables in `docs/.vitepress/theme/brand.css`. The logo, favicon, and social card in `docs/public/` are **copies** of the source-of-truth SVGs in the repo-root `assets/` directory.

::: warning Keep assets in sync
When the brand assets in `assets/` change, re-copy them into `docs/public/`:

```sh
cp assets/{logo.svg,logo-dark.svg,favicon.svg,icon.svg,social-card.svg} docs/public/
```

Never recolor the brand gradients or hand-edit the copies — edit the source SVGs in `assets/`.
:::

## Keeping content current

The design pages under `docs/design/` are **overviews that link the canonical documents** (`ARCHITECTURE.md`, `SECURITY.md`, `RESEARCH.md`) rather than duplicating them. The build plan has no overview page — `PLAN.md` is the single source and is linked directly (e.g. from the [Configuration](/guide/configuration) guide). When a design or user-facing capability changes, update:

1. The owning canonical doc at the repo root (per the maintenance contract in `AGENTS.md`).
2. The matching overview or roadmap entry in `docs/` so the site does not drift.

See `AGENTS.md` § *Documentation site (`docs/`)* for the full upkeep contract.
