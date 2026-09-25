import { defineConfig } from 'vitepress'

// GitHub Pages serves a project site under /<repo>/, so the site base must
// match the repository name. Overridable via DOCS_BASE for a custom domain.
const base = process.env.DOCS_BASE ?? '/roci/'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  base,
  lang: 'en-US',
  title: 'roci',
  description:
    'A Rust implementation of the OCI Distribution Specification — a minimal, fast, config-driven OCI container registry.',
  cleanUrls: true,
  lastUpdated: true,
  metaChunk: true,

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}favicon.svg` }],
    ['meta', { name: 'theme-color', content: '#CE422B' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'roci' }],
    [
      'meta',
      {
        property: 'og:description',
        content: 'A Rust implementation of the OCI Distribution Specification.',
      },
    ],
    ['meta', { property: 'og:image', content: `${base}social-card.svg` }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:image', content: `${base}social-card.svg` }],
  ],

  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: {
      light: '/logo.svg',
      dark: '/logo-dark.svg',
      alt: 'roci',
    },
    siteTitle: false,

    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'Design', link: '/design/architecture' },
      { text: 'Roadmap', link: '/roadmap' },
      {
        text: 'Reference',
        items: [
          { text: 'OCI Distribution Spec', link: 'https://specs.opencontainers.org/distribution-spec/' },
          { text: 'OCI Image Spec', link: 'https://specs.opencontainers.org/image-spec/' },
          { text: 'zot (prior art)', link: 'https://zotregistry.dev' },
        ],
      },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Guide',
          items: [
            { text: 'Introduction', link: '/guide/introduction' },
            { text: 'Getting started', link: '/guide/getting-started' },
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'Container image', link: '/guide/container' },
            { text: 'Benchmarks', link: '/guide/benchmarks' },
          ],
        },
        {
          text: 'Contributing',
          items: [
            { text: 'Developing locally', link: '/guide/developing' },
            { text: 'Documentation site', link: '/guide/documentation' },
          ],
        },
      ],
      '/design/': [
        {
          text: 'Design',
          items: [
            { text: 'Architecture', link: '/design/architecture' },
            { text: 'Security', link: '/design/security' },
            { text: 'Storage', link: '/design/storage' },
            { text: 'Research', link: '/design/research' },
          ],
        },
      ],
    },

    editLink: {
      pattern: 'https://github.com/jakobmoellerdev/roci/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    search: {
      provider: 'local',
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/jakobmoellerdev/roci' },
    ],

    footer: {
      message: 'Released under the Apache License 2.0.',
      copyright: 'Copyright © 2026 roci contributors',
    },
  },
})
