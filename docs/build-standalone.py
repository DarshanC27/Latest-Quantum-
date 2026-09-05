#!/usr/bin/env python3
"""Inline the stylesheet and script into a single deployable file.

Run after editing index.html, assets/style.css or assets/app.js:

    python docs/build-standalone.py

The multi-file version stays the source of truth. standalone.html exists
because a single file cannot break on a wrong asset path, which is the
most common way a static site ends up rendering as unstyled text.
"""
import pathlib

here = pathlib.Path(__file__).parent
html = (here / "index.html").read_text(encoding="utf-8")
css = (here / "assets/style.css").read_text(encoding="utf-8")
js = (here / "assets/app.js").read_text(encoding="utf-8")

before = html
html = html.replace('<link rel="stylesheet" href="assets/style.css">',
                    "<style>\n" + css + "\n</style>", 1)
html = html.replace('<script src="assets/app.js" defer></script>',
                    "<script>\n" + js + "\n</script>", 1)
if html == before:
    raise SystemExit("nothing inlined — did the link/script tags change?")

(here / "standalone.html").write_text(html, encoding="utf-8")
print(f"standalone.html written ({len(html) // 1024} KB)")
