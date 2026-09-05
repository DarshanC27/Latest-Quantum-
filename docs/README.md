# Quantum Ready — marketing site

Static HTML, CSS and JavaScript. No build step, no framework, no bundler.
Edit the files and the change is live.

## Publishing on GitHub Pages

Settings → Pages → Source: **Deploy from a branch** → Branch `main`, folder
`/docs` → Save. The site appears at `https://<user>.github.io/Quantum.Ready/`
within a minute or two.

For a custom domain, add a `CNAME` file here containing the domain, then point
a CNAME record at `<user>.github.io`.

## Files

| Path | Purpose |
|---|---|
| `index.html` | The whole page |
| `assets/style.css` | Design tokens and layout |
| `assets/app.js` | Theme toggle, menu, Mosca calculator, reveals |

## Things to change before launch

- **Pricing.** The tiers say "quoted per estate" and "retained". Put real
  numbers in once you have them — indicative pricing qualifies leads and
  saves you calls with people who were never going to buy.
- **Contact form — not connected.** No destination is set, so the form
  currently tells visitors to reach the founders on LinkedIn. Set one of the
  two fields in the `CONTACT` block at the top of `assets/app.js`:
  `email` opens the visitor's mail client, `formEndpoint` POSTs JSON to
  Formspree, Netlify Forms or your own handler. **This is the site's primary
  call to action — wire it up before you drive any traffic.**
- **Company LinkedIn URL.** Three placeholders carry a guessed slug behind
  `TODO` comments: the social row, the footer, and `sameAs` in the structured
  data.
- **Canonical URL** in `index.html` if you use a custom domain.
- **Social preview image.** `og:image` is not set; add a 1200×630 PNG and
  reference it, or links will unfurl without a picture.

## Design provenance

The palette, type and layout come from the `ui-ux-pro-max` design system for
B2B cybersecurity SaaS. Two deliberate departures from first instinct:

- **Light mode by default.** The dataset flags dark-by-default as an
  anti-pattern for B2B trust. Dark is offered via the toggle and follows the
  system preference; it is not imposed.
- **Accent is orange-700, not orange-600.** The generated palette's `#ea580c`
  gives white button labels only 3.56:1, under the 4.5:1 floor. `#c2410c`
  reaches 5.18:1 and keeps the warm CTA contrast.

All 30 foreground/background pairs meet WCAG AA in both themes.

## The calculator

`recalculate()` in `app.js` mirrors `quantumready/engine/quantum.py` exactly,
verified across 84 combinations of X, Y and Z. **If you change one, change
both** — a marketing page that disagrees with the tool it sells is worse than
having no calculator at all.
