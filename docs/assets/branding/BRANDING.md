# Enva — NieR:Automata Design Language

> YoRHa Env[A]rmament Unit — Visual Identity Specification
>
> Last updated: 2026-03-31

## Color Palette

### Primary

| Token | Hex | Usage |
|-------|-----|-------|
| `--nier-black` | `#0a0a0a` | Page background, primary surfaces |
| `--nier-ivory` | `#e8e6e3` | Primary text, headings on dark |
| `--nier-gold` | `#c4a35a` | Accent, links, interactive elements, logo mark |
| `--nier-gold-light` | `#d4b46a` | Hover states, highlighted text |
| `--nier-gold-dark` | `#8b7355` | Large text only (decorative headings, borders) |

### Secondary

| Token | Hex | Usage |
|-------|-----|-------|
| `--nier-surface` | `#1a1a18` | Card backgrounds, elevated surfaces |
| `--nier-surface-alt` | `#2a2a26` | Input fields, secondary cards |
| `--nier-muted` | `#4a4a46` | Secondary text on light, borders |
| `--nier-border` | `#3a3a36` | Dividers, subtle separators |
| `--nier-danger` | `#c45a5a` | Error states, destructive actions |
| `--nier-success` | `#5ac47a` | Success states, confirmations |

### WCAG AA Contrast Verification

| Pair | Ratio | Status |
|------|-------|--------|
| Ivory `#e8e6e3` on Black `#0a0a0a` | 15.89:1 | PASS |
| Gold `#c4a35a` on Black `#0a0a0a` | 8.23:1 | PASS |
| Gold `#c4a35a` on Surface `#1a1a18` | 7.25:1 | PASS |
| Gold `#c4a35a` on Card `#2a2a26` | 5.99:1 | PASS |
| Ivory `#e8e6e3` on Surface `#1a1a18` | 13.99:1 | PASS |
| Muted `#4a4a46` on Ivory `#e8e6e3` | 7.15:1 | PASS |
| Black `#0a0a0a` on Ivory `#e8e6e3` | 15.89:1 | PASS |
| Gold-dark `#8b7355` on Black `#0a0a0a` | 4.41:1 | LARGE TEXT ONLY (>=18pt) |

## Typography

### Font Stack

| Role | Family | Fallback | Weight | Source |
|------|--------|----------|--------|--------|
| Display / H1-H2 | EB Garamond | Georgia, serif | 400, 500, 600 | Google Fonts |
| Body / UI | Jost | system-ui, sans-serif | 300, 400, 500, 600 | Google Fonts |
| Code / Terminal | Share Tech Mono | monospace | 400 | Google Fonts |

### Scale

| Token | Size | Line Height | Usage |
|-------|------|-------------|-------|
| `--text-xs` | 11px | 1.4 | Badges, micro-labels |
| `--text-sm` | 13px | 1.5 | Secondary text, captions |
| `--text-base` | 15px | 1.6 | Body text |
| `--text-lg` | 18px | 1.5 | Section subtitles |
| `--text-xl` | 24px | 1.3 | Section headings |
| `--text-2xl` | 32px | 1.2 | Page titles |
| `--text-hero` | 48px | 1.1 | Hero headline |

### Google Fonts Import

```css
@import url('https://fonts.googleapis.com/css2?family=EB+Garamond:ital,wght@0,400;0,500;0,600;1,400&family=Jost:wght@300;400;500;600&family=Share+Tech+Mono&display=swap');
```

## Spacing & Layout

| Token | Value |
|-------|-------|
| `--space-xs` | 4px |
| `--space-sm` | 8px |
| `--space-md` | 16px |
| `--space-lg` | 24px |
| `--space-xl` | 40px |
| `--space-2xl` | 64px |
| `--radius` | 2px |
| `--radius-lg` | 4px |
| `--content-max` | 1120px |

NieR:Automata UI favors sharp edges. Border-radius should be minimal (2-4px max) or zero.

## Decorative Elements

### Diamond Separator

```
◇ ─────────────── ◇
```

CSS implementation: thin 1px `--nier-border` line with `◇` (U+25C7) characters or rotated squares at endpoints.

### HUD Border

Double-line border with corner brackets. Outer border: 1px solid `--nier-border`. Inner content inset by 8px. Corner marks rendered as pseudo-elements or inline SVG.

```
┌──────────────────────────┐
│  ┌────────────────────┐  │
│  │  Content area       │  │
│  └────────────────────┘  │
└──────────────────────────┘
```

### Section Title Pattern

```
「 SECTION TITLE 」
```

Japanese-style corner brackets (「U+300C, 」U+300D) flanking uppercase titles in EB Garamond.

### Scanline Overlay

Repeating horizontal lines at 2px intervals, 1px height, `rgba(232,230,227,0.03)` on dark backgrounds. Applied via CSS `background-image: repeating-linear-gradient(...)`.

```css
.scanline-overlay {
  background-image: repeating-linear-gradient(
    0deg,
    rgba(232, 230, 227, 0.03) 0px,
    rgba(232, 230, 227, 0.03) 1px,
    transparent 1px,
    transparent 3px
  );
}
```

### Noise Texture

Subtle grain overlay at 5% opacity via CSS `filter` or inline SVG `<feTurbulence>`. Use sparingly on hero sections only.

## Animation Principles

| Effect | Duration | Easing | Usage |
|--------|----------|--------|-------|
| Typewriter text | 40ms per char | `steps(1)` | Hero headline, status messages |
| Fade in | 600ms | `ease-out` | Card reveals, section entries |
| Scanline sweep | 800ms | `linear` | Page transitions |
| Diamond expand | 400ms | `cubic-bezier(0.4, 0, 0.2, 1)` | Modal open, element focus |
| Glow pulse | 2000ms | `ease-in-out` infinite | Active/selected states |

## CSS Variable Export

```css
:root {
  /* Palette */
  --nier-black: #0a0a0a;
  --nier-ivory: #e8e6e3;
  --nier-gold: #c4a35a;
  --nier-gold-light: #d4b46a;
  --nier-gold-dark: #8b7355;
  --nier-surface: #1a1a18;
  --nier-surface-alt: #2a2a26;
  --nier-muted: #4a4a46;
  --nier-border: #3a3a36;
  --nier-danger: #c45a5a;
  --nier-success: #5ac47a;

  /* Typography */
  --font-display: 'EB Garamond', Georgia, serif;
  --font-body: 'Jost', system-ui, sans-serif;
  --font-mono: 'Share Tech Mono', monospace;

  --text-xs: 11px;
  --text-sm: 13px;
  --text-base: 15px;
  --text-lg: 18px;
  --text-xl: 24px;
  --text-2xl: 32px;
  --text-hero: 48px;

  /* Spacing */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 40px;
  --space-2xl: 64px;

  /* Borders */
  --radius: 2px;
  --radius-lg: 4px;

  /* Layout */
  --content-max: 1120px;

  /* Shadows */
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.4);
  --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.5);
  --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.6);
  --shadow-glow: 0 0 20px rgba(196, 163, 90, 0.15);
}
```
