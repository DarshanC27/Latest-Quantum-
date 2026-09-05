"""Self-contained HTML report.

One file, no external requests, prints to PDF cleanly, and readable in
both light and dark. It has to survive being emailed to a board and
opened on a locked-down machine, so everything is inline.
"""

from __future__ import annotations

import html as _html
from typing import List

from ..model import ScanResult
from . import serialise

SEVERITY_COLOURS = {
    "critical": "#b3123b",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#0e7490",
    "info": "#4b5563",
}

STATUS_COLOURS = {"pass": "#15803d", "attention": "#a16207", "fail": "#b3123b"}


def _e(value) -> str:
    return _html.escape(str(value if value is not None else ""), quote=True)


_CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f7f7f5; --panel:#ffffff; --ink:#1c1c1a; --muted:#61615c;
  --line:#e2e2dd; --accent:#3d5a8a; --accent-soft:#eef2f8;
  --shadow:0 1px 2px rgba(0,0,0,.05),0 4px 12px rgba(0,0,0,.04);
}
@media (prefers-color-scheme:dark){
  :root{--bg:#16161a; --panel:#1e1e23; --ink:#ececea; --muted:#a0a09a;
        --line:#32323a; --accent:#8fabd8; --accent-soft:#23293a;
        --shadow:0 1px 2px rgba(0,0,0,.3),0 4px 14px rgba(0,0,0,.25);}
}
:root[data-theme="dark"]{--bg:#16161a; --panel:#1e1e23; --ink:#ececea; --muted:#a0a09a;
  --line:#32323a; --accent:#8fabd8; --accent-soft:#23293a;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 4px 14px rgba(0,0,0,.25);}
:root[data-theme="light"]{--bg:#f7f7f5; --panel:#ffffff; --ink:#1c1c1a; --muted:#61615c;
  --line:#e2e2dd; --accent:#3d5a8a; --accent-soft:#eef2f8;
  --shadow:0 1px 2px rgba(0,0,0,.05),0 4px 12px rgba(0,0,0,.04);}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 80px}
h1,h2,h3{line-height:1.25;margin:0 0 .4em}
h1{font-size:2rem;letter-spacing:-.02em}
h2{font-size:1.3rem;margin-top:2.4em;padding-bottom:.4em;border-bottom:1px solid var(--line)}
h3{font-size:1.02rem}
p{margin:0 0 1em}
a{color:var(--accent)}
.sub{color:var(--muted);font-size:.92rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:20px 22px;box-shadow:var(--shadow);margin-bottom:16px}
.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:26px 0}
.score{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:18px;text-align:center;box-shadow:var(--shadow)}
.score .n{font-size:2.3rem;font-weight:650;letter-spacing:-.02em;line-height:1.1}
.score .l{font-size:.76rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-top:6px}
.verdict{border-left:4px solid var(--accent);background:var(--accent-soft);
  border-radius:0 8px 8px 0;padding:18px 22px;margin:20px 0}
.verdict.exposed{border-left-color:#b3123b;background:rgba(179,18,59,.07)}
.formula{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1.05rem;
  font-weight:600;margin:.4em 0}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:4px;
  border-radius:0 10px 10px 0;padding:16px 20px;margin-bottom:12px;box-shadow:var(--shadow)}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:.7rem;
  font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#fff;vertical-align:middle}
.qtag{display:inline-block;margin-left:6px;padding:2px 8px;border-radius:20px;
  font-size:.68rem;font-weight:600;background:var(--accent-soft);color:var(--accent);
  border:1px solid var(--accent)}
.finding h3{margin:.5em 0 .3em}
.finding dl{margin:.6em 0 0;display:grid;grid-template-columns:max-content 1fr;gap:4px 14px}
.finding dt{color:var(--muted);font-size:.78rem;text-transform:uppercase;
  letter-spacing:.05em;padding-top:3px}
.finding dd{margin:0}
.tblwrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.9rem;min-width:520px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
tbody tr:last-child td{border-bottom:none}
.bar{height:7px;background:var(--line);border-radius:4px;overflow:hidden;min-width:90px}
.bar span{display:block;height:100%;background:var(--accent);border-radius:4px}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:.72rem;
  font-weight:650;color:#fff;text-transform:uppercase;letter-spacing:.04em}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em;
  background:var(--accent-soft);padding:1px 5px;border-radius:4px}
.note{color:var(--muted);font-size:.88rem}
ul{margin:0 0 1em;padding-left:1.3em}
li{margin-bottom:.35em}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);
  color:var(--muted);font-size:.85rem}
@media print{
  body{background:#fff}
  .card,.finding,.score{box-shadow:none;break-inside:avoid}
  h2{break-after:avoid}
  .wrap{max-width:none;padding:0}
}
"""


def _scores(result: ScanResult) -> str:
    counts = result.counts_by_severity()
    readiness = result.readiness
    tiles = [
        (f"{result.risk_score:g}", f"Security score ({result.risk_grade})"),
        (
            f"{readiness.score:g}" if readiness else "—",
            f"Quantum readiness ({readiness.grade})" if readiness else "Quantum readiness",
        ),
        (str(counts["critical"]), "Critical"),
        (str(counts["high"]), "High"),
        (str(len(result.discovered_hosts)), "Hosts assessed"),
    ]
    cells = "".join(
        f'<div class="score"><div class="n">{_e(value)}</div>'
        f'<div class="l">{_e(label)}</div></div>'
        for value, label in tiles
    )
    return f'<div class="scores">{cells}</div>'


def _mosca(result: ScanResult) -> str:
    mosca = result.mosca
    if not mosca:
        return ""
    css_class = "verdict exposed" if mosca.at_risk else "verdict"
    assumptions = "".join(f"<li>{_e(a)}</li>" for a in mosca.assumptions)
    return f"""
<h2>Mosca's inequality</h2>
<div class="{css_class}">
  <div class="formula">{_e(mosca.formula)} &nbsp;&rarr;&nbsp; {_e(mosca.verdict)}</div>
  <p>{_e(mosca.explanation)}</p>
</div>
<p class="sub">Where <strong>X</strong> is how long the data must stay confidential,
<strong>Y</strong> is how long migration takes, and <strong>Z</strong> is the time
until a cryptographically relevant quantum computer exists. If X + Y exceeds Z,
data being protected today will still be sensitive when it becomes readable.</p>
<div class="card"><strong>Assumptions</strong><ul>{assumptions}</ul>
<p class="note">These are planning judgements, not measurements. Change them to
match your own retention obligations and risk appetite.</p></div>
"""


def _readiness(result: ScanResult) -> str:
    readiness = result.readiness
    if not readiness:
        return ""
    rows = ""
    for name, value, maximum in readiness.rows():
        pct = (value / maximum * 100) if maximum else 0
        rows += (
            f"<tr><td>{_e(name)}</td>"
            f'<td><div class="bar"><span style="width:{pct:.0f}%"></span></div></td>'
            f"<td>{value:.1f} / {maximum:.0f}</td></tr>"
        )
    return f"""
<h2>Quantum readiness breakdown</h2>
<p>{_e(readiness.narrative)}</p>
<div class="card tblwrap"><table>
<thead><tr><th>Control</th><th>Progress</th><th>Score</th></tr></thead>
<tbody>{rows}</tbody></table></div>
"""


def _findings(result: ScanResult) -> str:
    findings = [f for f in result.sorted_findings() if f.severity != "info"]
    if not findings:
        return "<h2>Findings</h2><div class='card'>No issues were identified.</div>"

    blocks: List[str] = []
    for finding in findings:
        colour = SEVERITY_COLOURS[finding.severity]
        qtag = '<span class="qtag">quantum</span>' if finding.quantum_relevant else ""
        compliance = (
            f"<dt>Compliance</dt><dd>{_e(', '.join(finding.compliance))}</dd>"
            if finding.compliance else ""
        )
        references = ""
        if finding.references:
            links = "<br>".join(
                f'<a href="{_e(r.split(" ")[-1])}">{_e(r)}</a>' if "http" in r else _e(r)
                for r in finding.references
            )
            references = f"<dt>References</dt><dd>{links}</dd>"
        blocks.append(f"""
<div class="finding" style="border-left-color:{colour}">
  <span class="badge" style="background:{colour}">{_e(finding.severity)}</span>{qtag}
  <h3>{_e(finding.title)}</h3>
  <dl>
    <dt>Where</dt><dd><code>{_e(finding.target)}</code></dd>
    <dt>Observed</dt><dd>{_e(finding.detail)}</dd>
    <dt>Impact</dt><dd>{_e(finding.impact)}</dd>
    <dt>Fix</dt><dd>{_e(finding.remediation)}</dd>
    {compliance}{references}
  </dl>
</div>""")
    return "<h2>Findings</h2>" + "".join(blocks)


def _remediation(result: ScanResult) -> str:
    if not result.remediation:
        return ""
    rows = ""
    for action in result.remediation:
        tools = f'<br><span class="note">Tools: {_e(", ".join(action.tools))}</span>' if action.tools else ""
        rows += f"""<tr>
<td><strong>{action.priority}</strong></td>
<td><strong>{_e(action.title)}</strong><br><span class="note">{_e(action.why)}</span>
<br>{_e(action.how)}{tools}</td>
<td>{_e(action.effort)}</td><td>{_e(action.phase)}</td></tr>"""
    return f"""
<h2>Remediation plan</h2>
<p class="sub">Ordered by severity, then by effort, so the cheapest way to remove
the most risk comes first.</p>
<div class="card tblwrap"><table>
<thead><tr><th>#</th><th>Action</th><th>Effort</th><th>Phase</th></tr></thead>
<tbody>{rows}</tbody></table></div>
"""


def _endpoints(result: ScanResult) -> str:
    rows = ""
    for endpoint in result.endpoints:
        if not endpoint.reachable:
            rows += (
                f"<tr><td><code>{_e(endpoint.host)}</code></td>"
                f'<td colspan="5" class="note">unreachable — {_e(endpoint.error)}</td></tr>'
            )
            continue
        leaf = endpoint.leaf
        pqc = endpoint.pqc_ready
        pqc_cell = (
            f'<span class="pill" style="background:#15803d">yes</span>'
            if pqc else '<span class="pill" style="background:#b3123b">no</span>'
        )
        key = leaf.public_key.display if leaf and leaf.public_key else "—"
        expiry = leaf.days_until_expiry() if leaf else None
        rows += f"""<tr>
<td><code>{_e(endpoint.host)}</code></td>
<td>{_e(key)}</td>
<td>{_e(leaf.signature_algorithm if leaf else '—')}</td>
<td>{_e(f'{expiry}d' if expiry is not None else '—')}</td>
<td>{_e(_versions(endpoint))}</td>
<td>{pqc_cell}</td></tr>"""
    return f"""
<h2>Endpoints</h2>
<div class="card tblwrap"><table>
<thead><tr><th>Host</th><th>Key</th><th>Signature</th><th>Expires</th>
<th>TLS</th><th>PQC</th></tr></thead>
<tbody>{rows}</tbody></table></div>
"""


def _versions(endpoint) -> str:
    from ..crypto import tlsparams as tp

    return ", ".join(
        tp.VERSION_NAMES.get(v, str(v)).replace("TLS ", "")
        for v in endpoint.supported_versions
    ) or "—"


def _inventory(result: ScanResult) -> str:
    if not result.crypto_assets:
        return ""
    seen = set()
    rows = ""
    for asset in result.crypto_assets:
        key = (asset.name, asset.kind)
        if key in seen:
            continue
        seen.add(key)
        safe = (
            '<span class="pill" style="background:#15803d">safe</span>'
            if asset.quantum_safe
            else f'<span class="pill" style="background:#b3123b">{_e(asset.broken_by or "weak")}</span>'
        )
        rows += f"""<tr><td><code>{_e(asset.name)}</code></td><td>{_e(asset.kind)}</td>
<td>{asset.classical_bits or '—'}</td><td>{asset.quantum_bits}</td>
<td>{safe}</td><td>{_e(asset.replacement or '—')}</td></tr>"""
    return f"""
<h2>Cryptographic inventory</h2>
<p class="sub">Every algorithm observed in use. "Quantum bits" is the security
remaining against a cryptographically relevant quantum computer: Shor's algorithm
takes public-key algorithms to zero, while Grover halves symmetric strength.</p>
<div class="card tblwrap"><table>
<thead><tr><th>Algorithm</th><th>Use</th><th>Classical bits</th><th>Quantum bits</th>
<th>Status</th><th>Replacement</th></tr></thead>
<tbody>{rows}</tbody></table></div>
"""


def _licences(result: ScanResult) -> str:
    if not result.licences:
        return ""
    rows = ""
    for record in result.licences:
        colour = SEVERITY_COLOURS.get(record.risk, "#4b5563")
        rows += f"""<tr><td><strong>{_e(record.component)}</strong></td>
<td>{_e(record.version or '—')}</td><td><code>{_e(record.licence)}</code></td>
<td>{_e(record.category)}</td>
<td><span class="pill" style="background:{colour}">{_e(record.risk)}</span></td>
<td class="note">{_e(record.obligation)}</td></tr>"""
    return f"""
<h2>Third-party components and licences</h2>
<p class="sub">Detected from what a browser loads, so this covers front-end
components and the platform only. Reconcile it against your build system for a
complete picture.</p>
<div class="card tblwrap"><table>
<thead><tr><th>Component</th><th>Version</th><th>Licence</th><th>Category</th>
<th>Risk</th><th>Obligation</th></tr></thead>
<tbody>{rows}</tbody></table></div>
"""


def _compliance(result: ScanResult) -> str:
    if not result.compliance:
        return ""
    blocks = ""
    for framework in result.compliance:
        colour = STATUS_COLOURS.get(framework.status, "#4b5563")
        controls = ""
        for control in framework.controls:
            ccolour = STATUS_COLOURS.get(control.status, "#4b5563")
            evidence = (
                f'<br><span class="note">{_e("; ".join(control.evidence))}</span>'
                if control.evidence else ""
            )
            controls += (
                f'<tr><td><span class="pill" style="background:{ccolour}">'
                f"{_e(control.status)}</span></td>"
                f"<td><strong>{_e(control.reference)}</strong><br>"
                f"{_e(control.requirement)}{evidence}</td></tr>"
            )
        blocks += f"""
<div class="card">
  <span class="pill" style="background:{colour}">{_e(framework.status)}</span>
  <h3 style="display:inline;margin-left:8px">{_e(framework.name)}</h3>
  <p class="sub">{_e(framework.authority)} &middot; {_e(framework.applies_to)}<br>
  <strong>Timeline:</strong> {_e(framework.deadline)}</p>
  <div class="tblwrap"><table><tbody>{controls}</tbody></table></div>
</div>"""
    return f"<h2>Compliance position</h2>{blocks}"


def _dns(result: ScanResult) -> str:
    posture = result.dns_result
    if posture is None:
        return ""
    if not posture.available:
        return (
            "<h2>DNS posture</h2><div class='card note'>DNS checks could not run: "
            "no resolver was reachable from the scanning host.</div>"
        )
    def yes_no(flag: bool) -> str:
        colour = "#15803d" if flag else "#a16207"
        return f'<span class="pill" style="background:{colour}">{"yes" if flag else "no"}</span>'

    return f"""
<h2>DNS posture</h2>
<div class="card tblwrap"><table><tbody>
<tr><th>CAA records</th><td>{yes_no(bool(posture.caa_records))} {_e(', '.join(posture.caa_records[:4]))}</td></tr>
<tr><th>DNSSEC</th><td>{yes_no(posture.dnssec)}</td></tr>
<tr><th>SPF</th><td>{yes_no(bool(posture.spf))} <span class="note">{_e((posture.spf or '')[:90])}</span></td></tr>
<tr><th>DMARC</th><td>{yes_no(bool(posture.dmarc))} <span class="note">policy: {_e(posture.dmarc_policy or 'none set')}</span></td></tr>
<tr><th>Mail exchangers</th><td>{_e(', '.join(posture.mx_records[:3]) or '—')}</td></tr>
</tbody></table></div>
"""


def _notes(result: ScanResult) -> str:
    items = result.scan_notes + result.errors
    if not items:
        return ""
    entries = "".join(f"<li>{_e(n)}</li>" for n in items)
    return f"<h2>Scan notes</h2><div class='card'><ul>{entries}</ul></div>"


def render(result: ScanResult) -> str:
    """Produce the complete report document."""
    target = result.target
    title = f"Post-Quantum Readiness — {target.organisation or target.domain}"

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title>
<style>{_CSS}</style>
</head><body><div class="wrap">
<div style="display:flex;align-items:center;gap:.7rem;margin-bottom:var(--space-3)">
  <svg viewBox="0 0 64 64" width="34" height="34" aria-hidden="true" style="flex:none">
    <path d="M4 32c6-18 10-18 16 0s10 18 16 0" fill="none"
          stroke="var(--accent)" stroke-width="5.5" stroke-linecap="round"/>
    <g fill="#c2410c">
      <rect x="40" y="22" width="5" height="20" rx="2.5"/>
      <rect x="49" y="16" width="5" height="32" rx="2.5"/>
      <rect x="58" y="26" width="5" height="12" rx="2.5"/>
    </g>
  </svg>
  <span style="font-weight:700;letter-spacing:-.02em;font-size:1.05rem">Quantum Ready</span>
</div>
<h1>{_e(target.organisation or target.domain)}</h1>
<p class="sub">Post-quantum readiness and cryptographic risk assessment<br>
Domain <code>{_e(target.domain)}</code> &middot;
scanned {result.started_at:%d %B %Y at %H:%M} UTC &middot;
{result.duration_seconds:.1f}s &middot;
{len(result.discovered_hosts)} host(s)</p>

{_scores(result)}
{_mosca(result)}
{_readiness(result)}
{_findings(result)}
{_remediation(result)}
{_endpoints(result)}
{_inventory(result)}
{_licences(result)}
{_dns(result)}
{_compliance(result)}
{_notes(result)}

<footer>
<p>Generated by <strong>{serialise.TOOL_NAME} {serialise.TOOL_VERSION}</strong>.
This assessment covers the externally visible estate only. Internal systems,
VPNs, code signing, database and backup encryption, and hardware security
modules are not visible to an external scan and need a separate inventory —
which is what the NCSC 2028 discovery phase asks for.</p>
<p>Compliance mappings are provided for orientation and are not legal advice.</p>
</footer>
</div></body></html>"""
