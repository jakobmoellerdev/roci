# roci brand assets

Source-of-truth brand assets for roci. Everything here is hand-authored SVG so it
scales losslessly and stays diff-friendly; rasterize on demand for contexts that
need PNG/ICO.

## Concept

- **Mark** — a rounded hexagon (the container / registry envelope) enclosing three
  stacked bars: the layers of an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
  (blob → manifest → index). Top bar brightest, fading down to slate.
- **Wordmark** — `roci` set in a monospace face; the leading `r` carries the Rust
  accent, `oci` sits in slate. Lowercase and terse, matching the project's tone.

## Palette

| Token          | Hex        | Use                                            |
| -------------- | ---------- | ---------------------------------------------- |
| Rust (bright)  | `#F4713B`  | Gradient start; top layer bar; `r` glyph       |
| Rust (base)    | `#CE422B`  | Gradient end; primary brand orange             |
| Rust (deep)    | `#9E2F1E`  | Middle layer bar (`rustDim` gradient end)      |
| Slate          | `#5B6875`  | `oci` glyph and third layer bar on light bg    |
| Slate (light)  | `#AEB9C6`  | Third layer bar on dark bg                     |
| Slate (text)   | `#C4CDD8`  | `oci` glyph on dark bg                          |
| Muted          | `#8A97A6`  | Taglines, secondary text                       |
| Ink            | `#12161C`  | Monochrome-black stamp; favicon tile           |
| Canvas (dark)  | `#0D1117` → `#161B22` | Dark backdrops / social card gradient |

Brand gradients (top-left → bottom-right):

- `rust`: `#F4713B` → `#CE422B`
- `rustDim`: `#CE422B` → `#9E2F1E`

## Geometry (shared primitive)

Every asset reuses one mark, so keep these coordinates in sync when editing:

- Hexagon path: `M50 4 L92 28 V76 L50 100 L8 76 V28 Z`, stroke width `6`, `stroke-linejoin="round"`.
- Layer bars: three `40×12` rounded rects (`rx=3`) at `y = 34, 50, 66`, `x = 30`.
- Wordmark: `font-size 72`, `font-weight 700`, `letter-spacing -2`,
  font stack `'SF Mono','JetBrains Mono','DejaVu Sans Mono',ui-monospace,monospace`.

## Assets

| File                       | Dimensions | Purpose                                        |
| -------------------------- | ---------- | ---------------------------------------------- |
| `logo.svg`                 | 400×140    | Primary horizontal lockup (light backgrounds)  |
| `logo-dark.svg`            | 400×140    | Lockup tuned for dark backgrounds              |
| `logo-mono-white.svg`      | 400×140    | Single-color white stamp (dark/photographic)   |
| `logo-mono-black.svg`      | 400×140    | Single-color ink stamp (print / one-color)     |
| `icon.svg`                 | 128×128    | Square mark — avatars, app icons, social        |
| `favicon.svg`              | 32×32      | Small-optimized icon on a dark tile             |
| `wordmark.svg`             | 280×100    | Wordmark only, no mark                          |
| `social-card.svg`          | 1280×640   | Social / Open Graph preview card                |

## Usage

- **Clear space** — keep padding of at least one bar-height (`~12px` at native
  scale) around the lockup; the SVGs already bake in a margin.
- **Backgrounds** — use `logo.svg` on light, `logo-dark.svg` on dark. Over busy
  or photographic backgrounds use a monochrome stamp.
- **Color** — never recolor the gradients or swap the orange for another hue.
  Single-color contexts use the mono stamps, not a flattened brand orange.
- **Don't** — stretch, rotate, add drop shadows, reflow the mark/wordmark spacing,
  or place the mark inside another container shape.

## Rasterizing

SVG is the master format. To produce a PNG/ICO for a context that needs it
(e.g. a docs favicon), render with any SVG rasterizer, for example:

```sh
# 512px icon
rsvg-convert -w 512 -h 512 assets/icon.svg -o icon-512.png
# multi-size favicon
rsvg-convert -w 32 -h 32 assets/favicon.svg -o favicon-32.png
```
