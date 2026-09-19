/**
 * roci docs theme — extends the VitePress default theme with the roci brand
 * palette (see assets/BRAND.md). Do not recolor the brand gradients; this file
 * only maps the brand tokens onto VitePress's theming variables.
 */
import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import './brand.css'

export default {
  extends: DefaultTheme,
} satisfies Theme
