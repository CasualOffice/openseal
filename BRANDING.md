# Branding

How to credit OpenSeal in a product built with it. Everything here is optional: the
[Apache License 2.0](LICENSE) asks only for the notices in [ATTRIBUTION.md](ATTRIBUTION.md#what-the-license-requires).

## Wording

- Preferred: **Powered by OpenSeal**
- Alternative: **Built with OpenSeal**
- Link: https://github.com/CasualOffice/openseal

Write "OpenSeal" as one word with a capital S. Avoid wording that suggests a partnership or endorsement, such as
"Official OpenSeal partner" or "Certified by OpenSeal", unless the project has agreed to it in writing.

## Logo assets

Use the files in [docs/assets/](docs/assets/) as they are: don't recolour, stretch, crop or add effects.

| File | Use |
| --- | --- |
| [`logo.svg`](docs/assets/logo.svg) | Badge and wordmark, for light backgrounds |
| [`logo-dark.svg`](docs/assets/logo-dark.svg) | Badge and wordmark, for dark backgrounds |
| [`mark.svg`](docs/assets/mark.svg) | Badge alone, for small spaces (at least 16 px) |

Leave clear space around the logo of at least a quarter of its height. In a footer, about 20 px of height is plenty.

## Accessibility

- A logo used as attribution needs a text alternative: `alt="Powered by OpenSeal"` on the image, or visible text
  beside a decorative image (`alt=""`).
- A link must be reachable by keyboard and have a visible focus style. Its accessible name should say where it goes,
  for example "Powered by OpenSeal (opens GitHub)".
- Text should meet WCAG 2.2 AA contrast (4.5:1 for small text). Use the dark-background logo on dark themes.
- Attribution should never cover content, block interaction, flash, or appear as a pop-up, banner or watermark.
  OpenSeal never adds attribution to your application or to the PDFs it produces.

## Snippets

### Plain text

```text
Powered by OpenSeal — https://github.com/CasualOffice/openseal
```

### Markdown

```markdown
Powered by [OpenSeal](https://github.com/CasualOffice/openseal)
```

### HTML

A small footer credit that follows the page's colour scheme. The image is decorative because the link text names it.

```html
<a class="powered-by-openseal" href="https://github.com/CasualOffice/openseal">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="/assets/openseal-logo-dark.svg">
    <img src="/assets/openseal-logo.svg" alt="" width="84" height="20">
  </picture>
  <span>Powered by OpenSeal</span>
</a>
<style>
  .powered-by-openseal { display: inline-flex; gap: .5rem; align-items: center; font-size: .875rem; color: inherit; }
  .powered-by-openseal:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; }
</style>
```

### React (TSX)

```tsx
export function PoweredByOpenSeal({ dark = false }: { dark?: boolean }) {
  return (
    <a
      href="https://github.com/CasualOffice/openseal"
      style={{ display: "inline-flex", gap: "0.5rem", alignItems: "center", fontSize: "0.875rem", color: "inherit" }}
    >
      <img src={dark ? "/assets/openseal-logo-dark.svg" : "/assets/openseal-logo.svg"} alt="" width={84} height={20} />
      <span>Powered by OpenSeal</span>
    </a>
  );
}
```

Copy the SVGs from [docs/assets/](docs/assets/) into your own static files; the paths above are examples.
