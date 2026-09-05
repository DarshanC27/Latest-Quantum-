"""Publishable study report.

Aggregate figures only — this document is written to be put on the
internet, so it must not name an exposed organisation. Charts are inline
SVG rather than a charting library, keeping the file self-contained and
printable.
"""

from __future__ import annotations

import html as _html
from typing import List, Sequence, Tuple

from ..study import StudySummary

BLUE = "#2563eb"
ORANGE = "#c2410c"
GREEN = "#15803d"
RED = "#b3123b"
GREY = "#94a3b8"


def _e(value) -> str:
    return _html.escape(str(value if value is not None else ""), quote=True)


_CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{--bg:#f8fafc;--panel:#fff;--ink:#1e293b;--muted:#475569;--line:#e2e8f0;
  --accent:#2563eb;--soft:#eef2f8}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--panel:#151f35;--ink:#e8eefc;
  --muted:#a7b6d4;--line:#26334d;--accent:#60a5fa;--soft:#1c2942}}
:root[data-theme="dark"]{--bg:#0b1220;--panel:#151f35;--ink:#e8eefc;--muted:#a7b6d4;
  --line:#26334d;--accent:#60a5fa;--soft:#1c2942}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.65 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:940px;margin:0 auto;padding:48px 24px 80px}
h1{font-size:clamp(1.9rem,4.6vw,2.9rem);letter-spacing:-.025em;line-height:1.12;margin:0 0 .3em}
h2{font-size:1.35rem;margin:2.6em 0 .7em;padding-bottom:.35em;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:0 0 .5em}
p{margin:0 0 1em;max-width:70ch}
.sub{color:var(--muted);font-size:.95rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;margin-bottom:16px}
.headline{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:14px;margin:28px 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;text-align:center}
.stat .n{font-size:2.4rem;font-weight:700;letter-spacing:-.03em;line-height:1.05;font-variant-numeric:tabular-nums}
.stat .l{font-size:.76rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-top:6px}
.bad{color:#b3123b}.good{color:#15803d}.warn{color:#a16207}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.tblwrap{overflow-x:auto}
.note{background:var(--soft);border-left:4px solid var(--accent);border-radius:0 8px 8px 0;
  padding:16px 20px;margin:22px 0}
.note strong{display:block;margin-bottom:.3em}
svg{max-width:100%;height:auto;display:block}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);color:var(--muted);font-size:.86rem}
@media print{body{background:#fff}.card,.stat{box-shadow:none;break-inside:avoid}}
"""


def _bar_chart(rows: Sequence[Tuple[str, float]], *, unit: str = "%",
               colour: str = BLUE, width: int = 620) -> str:
    """Horizontal bars. Labels sit outside the bar so short bars stay readable."""
    if not rows:
        return "<p class='sub'>No data.</p>"
    label_w, row_h, gap, value_w = 230, 26, 8, 58
    bar_w = width - label_w - value_w - 16
    peak = max(v for _, v in rows) or 1
    height = len(rows) * (row_h + gap)

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="Bar chart of {len(rows)} values">']
    for i, (label, value) in enumerate(rows):
        y = i * (row_h + gap)
        w = max(2, (value / peak) * bar_w)
        parts.append(
            f'<text x="0" y="{y + row_h * 0.7:.0f}" font-size="12.5" fill="currentColor" '
            f'opacity=".82">{_e(label[:38])}</text>'
            f'<rect x="{label_w}" y="{y + 4}" width="{bar_w}" height="{row_h - 8}" '
            f'rx="4" fill="currentColor" opacity=".08"/>'
            f'<rect x="{label_w}" y="{y + 4}" width="{w:.1f}" height="{row_h - 8}" '
            f'rx="4" fill="{colour}"/>'
            f'<text x="{label_w + bar_w + 10}" y="{y + row_h * 0.7:.0f}" font-size="12.5" '
            f'font-weight="600" fill="currentColor">{value:g}{unit}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _grade_chart(grades: dict, total: int, width: int = 620) -> str:
    order = ["A", "B", "C", "D", "E", "F"]
    colours = {"A": GREEN, "B": "#65a30d", "C": "#a16207", "D": ORANGE, "E": "#b45309", "F": RED}
    counts = [(g, grades.get(g, 0)) for g in order]
    peak = max([c for _, c in counts] + [1])
    bar_w, gap, height = 68, 22, 190

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="Distribution of readiness grades">']
    for i, (grade, count) in enumerate(counts):
        h = (count / peak) * 120
        x = i * (bar_w + gap) + 20
        y = 140 - h
        pct = (100 * count / total) if total else 0
        parts.append(
            f'<rect x="{x}" y="{y:.1f}" width="{bar_w}" height="{max(h,2):.1f}" rx="5" '
            f'fill="{colours[grade]}"/>'
            f'<text x="{x + bar_w/2:.0f}" y="{y - 7:.0f}" text-anchor="middle" font-size="12" '
            f'font-weight="700" fill="currentColor">{count}</text>'
            f'<text x="{x + bar_w/2:.0f}" y="160" text-anchor="middle" font-size="15" '
            f'font-weight="800" fill="currentColor">{grade}</text>'
            f'<text x="{x + bar_w/2:.0f}" y="177" text-anchor="middle" font-size="11" '
            f'fill="currentColor" opacity=".62">{pct:.0f}%</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def render(summary: StudySummary, *, title: str = "", author: str = "Quantum Ready") -> str:
    s = summary
    title = title or f"Post-quantum readiness of {s.cohort}"

    headline = [
        (f"{s.pct(s.pqc_ready)}%", "Offer post-quantum key exchange",
         "good" if s.pct(s.pqc_ready) > 50 else "bad"),
        (f"{s.pct(s.mosca_exposed)}%", "Exposed under Mosca's inequality",
         "bad" if s.pct(s.mosca_exposed) > 50 else "good"),
        (f"{s.median_readiness:g}", "Median readiness score", ""),
        (f"{s.scanned}", "Organisations assessed", ""),
    ]
    stats_html = "".join(
        f'<div class="stat"><div class="n {cls}">{_e(n)}</div><div class="l">{_e(l)}</div></div>'
        for n, l, cls in headline
    )

    controls = [
        ("Post-quantum key exchange offered", s.pct(s.pqc_ready)),
        ("TLS 1.3 supported", s.pct(s.tls13)),
        ("Forward secrecy on every suite", s.pct(s.forward_secrecy)),
        ("HSTS enabled", s.pct(s.hsts)),
        ("CAA records published", s.pct(s.caa)),
        ("DMARC enforcing (quarantine/reject)", s.pct(s.dmarc_enforcing)),
        ("DNSSEC enabled", s.pct(s.dnssec)),
    ]
    problems = [
        ("Deprecated TLS still accepted", s.pct(s.deprecated_tls)),
        ("Broken or weak cipher suites", s.pct(s.weak_ciphers)),
        ("No post-quantum key exchange", s.pct(s.scanned - s.pqc_ready)),
    ]

    keys = _bar_chart([(k, v) for k, v in s.key_algorithms.most_common(8)],
                      unit="", colour=BLUE)
    sigs = _bar_chart([(k, v) for k, v in s.signature_algorithms.most_common(6)],
                      unit="", colour=GREY)

    finding_rows = "".join(
        f"<tr><td><code>{_e(fid)}</code></td><td class='num'>{count}</td>"
        f"<td class='num'>{100*count/s.scanned:.0f}%</td></tr>"
        for fid, count in s.findings.most_common(12)
    ) if s.scanned else ""

    pqc_detail = ""
    if s.pqc_groups:
        pqc_detail = (
            "<h3>Which groups those organisations offer</h3>"
            + _bar_chart([(k, v) for k, v in s.pqc_groups.most_common()], unit="", colour=GREEN)
        )

    errors = ""
    if s.errors:
        errors = ("<h3>Subjects that could not be assessed</h3><div class='tblwrap'><table>"
                  "<thead><tr><th>Reason</th><th class='num'>Count</th></tr></thead><tbody>"
                  + "".join(f"<tr><td>{_e(k)}</td><td class='num'>{v}</td></tr>"
                            for k, v in s.errors.most_common())
                  + "</tbody></table></div>")

    intercept_note = ""
    if s.intercepted:
        intercept_note = (
            f"<div class='note'><strong>TLS interception detected on "
            f"{s.intercepted} subject(s)</strong>Those results describe a "
            "middlebox rather than the origin server, and are excluded from "
            "no figure here — treat them as a lower bound on the true "
            "configuration quality.</div>"
        )

    lifetime = (f"{s.median_cert_lifetime} days" if s.median_cert_lifetime
                else "not determined")

    return f"""<!doctype html>
<html lang="en-GB"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title>
<meta name="description" content="Aggregate post-quantum readiness measurements across {_e(s.cohort)}.">
<style>{_CSS}</style>
</head><body><div class="wrap">

<p class="sub">{_e(author)} · research note</p>
<h1>{_e(title)}</h1>
<p class="sub">
  {s.scanned} of {s.total} organisations assessed ·
  {s.started_at:%d %B %Y} · measurements taken from the public internet
</p>

{stats_html and f'<div class="headline">{stats_html}</div>'}

<div class="note">
  <strong>Aggregate figures only</strong>
  No organisation is identified in this document. Findings affecting
  individual bodies were handled through private disclosure to those
  bodies. The purpose here is to establish a baseline for the sector, not
  to rank its members.
</div>

<h2>What was measured</h2>
<p>
  Each organisation's public web estate was assessed from the internet, in
  the same way any visitor's browser would connect. For each, the scanner
  read the certificate chain, negotiated protocol versions and cipher
  suites directly, and probed for hybrid ML-KEM key exchange — the
  measurement that determines whether traffic captured today survives a
  future quantum computer.
</p>
<p>
  Scope was limited to the apex domain and <code>www</code>. No subdomain
  enumeration, no authentication, no attempt to access anything not served
  to the public. Every request identified itself.
</p>

{intercept_note}

<h2>Controls in place</h2>
<p class="sub">Percentage of assessed organisations with each control.</p>
<div class="card">{_bar_chart(controls, colour=BLUE)}</div>

<h2>Where the sector is exposed</h2>
<div class="card">{_bar_chart(problems, colour=RED)}</div>

<h2>Post-quantum readiness</h2>
<p>
  <strong>{s.pct(s.pqc_ready)}%</strong> of assessed organisations negotiate a
  hybrid post-quantum key exchange. The remainder establish every session
  key using elliptic-curve or finite-field Diffie-Hellman, both of which
  Shor's algorithm solves outright — meaning traffic recorded today can be
  decrypted retrospectively once a cryptographically relevant quantum
  computer exists.
</p>
<div class="card">{_grade_chart(dict(s.grades), s.scanned)}
  <p class="sub" style="margin:.8rem 0 0">Readiness grade distribution.
  Median score {s.median_readiness:g}/100.</p>
</div>
{pqc_detail and f'<div class="card">{pqc_detail}</div>'}

<h2>Certificate cryptography in use</h2>
<div class="card">
  <h3>Public key algorithms observed</h3>
  {keys}
  <h3 style="margin-top:1.6rem">Signature algorithms observed</h3>
  {sigs}
  <p class="sub" style="margin-top:1rem">
    Median certificate lifetime: <strong>{_e(lifetime)}</strong>. Shorter
    lifetimes matter beyond hygiene: an estate that reissues routinely can
    pivot to post-quantum algorithms as a configuration change, while one
    that reissues rarely cannot.
  </p>
</div>

<h2>Most common findings</h2>
<div class="card tblwrap">
  <table>
    <thead><tr><th>Finding</th><th class="num">Organisations</th><th class="num">Share</th></tr></thead>
    <tbody>{finding_rows}</tbody>
  </table>
</div>

{errors and f'<h2>Method notes</h2><div class="card">{errors}</div>'}

<h2>Method</h2>
<p>
  Measurements were taken with an open-source scanner; the detection logic
  for every finding above can be read and reproduced. The scanner builds
  its own TLS handshakes rather than delegating to the local library,
  because a scanner limited by its own OpenSSL version reports "not
  supported" for capabilities it simply cannot ask about.
</p>
<p>
  Post-quantum support is established via the HelloRetryRequest mechanism
  (RFC 8446 §4.1.4): the group is offered with no key share, and a
  supporting server must name it in its retry. This proves support without
  completing a key exchange.
</p>

<footer>
  <p>{_e(author)} · Aggregate research note · {s.finished_at:%d %B %Y}</p>
  <p>Measurements describe the externally visible estate only. Internal
  systems, VPNs, code signing and backups are not observable from the
  public internet and are excluded from every figure above.</p>
</footer>
</div></body></html>"""
