"""The dashboard page.

Kept as a single inline string so the package has no data files to install
and the server has nothing to read from disk at request time.
"""

from __future__ import annotations

PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quantum.Ready — live scanner</title>
<style>
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f7f7f5;--panel:#fff;--ink:#1c1c1a;--muted:#61615c;--line:#e2e2dd;
  --accent:#3d5a8a;--soft:#eef2f8;--ok:#15803d;--warn:#a16207;--bad:#b3123b;
  --shadow:0 1px 2px rgba(0,0,0,.05),0 4px 12px rgba(0,0,0,.04);
}
@media (prefers-color-scheme:dark){:root{
  --bg:#16161a;--panel:#1e1e23;--ink:#ececea;--muted:#a0a09a;--line:#32323a;
  --accent:#8fabd8;--soft:#23293a;--ok:#4ade80;--warn:#fbbf24;--bad:#fb7185;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 4px 14px rgba(0,0,0,.25);}}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:36px 20px 80px}
h1{font-size:1.9rem;letter-spacing:-.02em;margin:0 0 .2em}
h2{font-size:1.15rem;margin:2em 0 .6em;padding-bottom:.35em;border-bottom:1px solid var(--line)}
.sub{color:var(--muted);margin:0 0 1.8em}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:20px;box-shadow:var(--shadow);margin-bottom:16px}
form{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;align-items:end}
label{display:block;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);margin-bottom:5px;font-weight:600}
input,select{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:7px;
  background:var(--bg);color:var(--ink);font:inherit;font-size:.94rem}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:-1px}
button{padding:10px 20px;border:0;border-radius:7px;background:var(--accent);color:#fff;
  font:inherit;font-weight:600;cursor:pointer;white-space:nowrap}
button:disabled{opacity:.5;cursor:not-allowed}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--accent)}
.full{grid-column:1/-1}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.progress{height:8px;background:var(--line);border-radius:5px;overflow:hidden;margin:14px 0 8px}
.progress span{display:block;height:100%;width:0;background:var(--accent);
  border-radius:5px;transition:width .35s ease}
#log{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem;
  max-height:240px;overflow-y:auto;background:var(--bg);border:1px solid var(--line);
  border-radius:7px;padding:12px;white-space:pre-wrap;word-break:break-word}
#log div{padding:1px 0;color:var(--muted)}
#log div.now{color:var(--ink);font-weight:600}
.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.score{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:16px;text-align:center;box-shadow:var(--shadow)}
.score .n{font-size:2rem;font-weight:650;line-height:1.1;letter-spacing:-.02em}
.score .l{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;
  color:var(--muted);margin-top:5px}
.verdict{border-left:4px solid var(--accent);background:var(--soft);
  border-radius:0 8px 8px 0;padding:14px 18px;margin:14px 0}
.verdict.bad{border-left-color:var(--bad);background:rgba(179,18,59,.08)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600}
.finding{border-left:4px solid var(--line);padding:12px 16px;margin-bottom:10px;
  background:var(--panel);border-radius:0 8px 8px 0;border-top:1px solid var(--line);
  border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.68rem;
  font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#fff}
.q{display:inline-block;margin-left:6px;padding:1px 7px;border-radius:20px;font-size:.66rem;
  font-weight:600;background:var(--soft);color:var(--accent);border:1px solid var(--accent)}
.finding h4{margin:.5em 0 .3em;font-size:.98rem}
.finding p{margin:.3em 0;font-size:.9rem}
.finding .where{font-family:ui-monospace,Menlo,monospace;font-size:.8rem;color:var(--muted)}
.tblwrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.88rem;min-width:480px}
th,td{text-align:left;padding:8px 11px;border-bottom:1px solid var(--line)}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.7rem;
  font-weight:650;color:#fff;text-transform:uppercase}
.hide{display:none}
.err{color:var(--bad);font-weight:600}
.note{color:var(--muted);font-size:.86rem}
footer{margin-top:48px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--muted);font-size:.84rem}
</style>
</head><body><div class="wrap">

<h1>Quantum.Ready</h1>
<p class="sub">Scan a company's public estate for quantum-vulnerable cryptography,
certificate and TLS weaknesses, licence exposure, and compliance gaps.</p>

<div class="card">
  <form id="f">
    <div class="full">
      <label for="domain">Company domain</label>
      <input id="domain" placeholder="acme.co.uk" autocomplete="off" required>
    </div>
    <div>
      <label for="org">Organisation name</label>
      <input id="org" placeholder="optional" autocomplete="off">
    </div>
    <div>
      <label for="sector">Sector</label>
      <select id="sector"></select>
    </div>
    <div>
      <label for="shelf">Data shelf life (years)</label>
      <input id="shelf" type="number" min="1" max="100" value="10">
    </div>
    <div>
      <label for="migration">Migration time (years)</label>
      <input id="migration" type="number" min="1" max="50" value="5">
    </div>
    <div>
      <label for="scenario">Threat timeline</label>
      <select id="scenario">
        <option value="conservative">Conservative (2030)</option>
        <option value="central" selected>Central (2035)</option>
        <option value="optimistic">Optimistic (2040)</option>
      </select>
    </div>
    <div>
      <label for="hosts">Max hosts</label>
      <input id="hosts" type="number" min="1" max="30" value="8">
    </div>
    <div class="full row">
      <button id="go" type="submit">Run scan</button>
      <span id="hint" class="note"></span>
    </div>
  </form>
</div>

<div id="live" class="card hide">
  <div class="row" style="justify-content:space-between">
    <strong id="stage">Starting…</strong>
    <span id="pct" class="note">0%</span>
  </div>
  <div class="progress"><span id="bar"></span></div>
  <div id="log"></div>
</div>

<div id="out" class="hide"></div>

<footer>
Assesses the externally visible estate only. Internal systems, VPNs, code
signing and backups need a separate inventory — which is what the NCSC 2028
discovery phase asks for. Compliance mappings are for orientation, not legal advice.
</footer>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const SEV = {critical:"#b3123b",high:"#c2410c",medium:"#a16207",low:"#0e7490",info:"#4b5563"};
let sectors = {};

fetch("/api/sectors").then(r => r.json()).then(data => {
  sectors = data;
  const select = $("sector");
  Object.keys(data).sort().forEach(name => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name[0].toUpperCase() + name.slice(1) + " (" + data[name].years + "y)";
    if (name === "general") option.selected = true;
    select.appendChild(option);
  });
  syncShelf();
}).catch(() => {});

function syncShelf(){
  const entry = sectors[$("sector").value];
  if (entry) { $("shelf").value = entry.years; $("hint").textContent = entry.reason; }
}
$("sector").addEventListener("change", syncShelf);

$("f").addEventListener("submit", async event => {
  event.preventDefault();
  const domain = $("domain").value.trim();
  if (!domain) return;

  $("go").disabled = true;
  $("out").className = "hide";
  $("live").className = "card";
  $("log").innerHTML = "";
  $("bar").style.width = "0%";
  $("stage").textContent = "Starting…";

  let job;
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        domain,
        organisation: $("org").value.trim(),
        sector: $("sector").value,
        shelf_life: parseInt($("shelf").value, 10),
        migration_years: parseInt($("migration").value, 10),
        scenario: $("scenario").value,
        max_hosts: parseInt($("hosts").value, 10)
      })
    });
    job = await response.json();
    if (!response.ok) throw new Error(job.error || "could not start scan");
  } catch (err) {
    log("error: " + err.message, true);
    $("go").disabled = false;
    return;
  }

  const stream = new EventSource("/api/scan/events?id=" + encodeURIComponent(job.id));
  stream.onmessage = message => {
    const event = JSON.parse(message.data);
    if (event.type === "progress") {
      if (typeof event.progress === "number") {
        $("bar").style.width = event.progress + "%";
        $("pct").textContent = event.progress + "%";
      }
      $("stage").textContent = event.stage;
      log(event.message);
    } else if (event.type === "result") {
      render(event.data, job.id);
    } else if (event.type === "error") {
      log("error: " + event.message, true);
    } else if (event.type === "status" && (event.status === "done" || event.status === "error")) {
      stream.close();
      $("go").disabled = false;
    }
  };
  stream.onerror = () => { stream.close(); $("go").disabled = false; };
});

function log(text, isError){
  const line = document.createElement("div");
  line.textContent = text;
  if (isError) line.className = "err";
  const previous = $("log").lastElementChild;
  if (previous) previous.className = "";
  if (!isError) line.className = "now";
  $("log").appendChild(line);
  $("log").scrollTop = $("log").scrollHeight;
}

function render(data, jobId){
  const summary = data.summary, mosca = data.mosca;
  const tiles = [
    [summary.risk_score, "Security (" + summary.risk_grade + ")"],
    [summary.quantum_readiness_score, "Quantum readiness (" + summary.quantum_readiness_grade + ")"],
    [summary.counts.critical, "Critical"],
    [summary.counts.high, "High"],
    [summary.hosts_reachable + "/" + summary.hosts_assessed, "Hosts live"]
  ];

  let html = "<h2>Result</h2><div class='scores'>" + tiles.map(
    t => "<div class='score'><div class='n'>" + esc(t[0]) + "</div><div class='l'>" + esc(t[1]) + "</div></div>"
  ).join("") + "</div>";

  if (mosca) {
    html += "<div class='verdict " + (mosca.at_risk ? "bad" : "") + "'>" +
      "<div class='mono'>" + esc(mosca.formula) + " → " + esc(mosca.verdict) + "</div>" +
      "<p style='margin:.5em 0 0;font-size:.92rem'>" + esc(mosca.explanation) + "</p></div>";
  }

  const components = summary.quantum_readiness_components || {};
  if (Object.keys(components).length) {
    html += "<h2>Readiness breakdown</h2><div class='card tblwrap'><table><tbody>" +
      Object.keys(components).map(name =>
        "<tr><td>" + esc(name) + "</td><td style='text-align:right'>" +
        components[name].toFixed(1) + "</td></tr>").join("") +
      "</tbody></table><p class='note' style='margin:.8em 0 0'>" +
      esc(summary.quantum_readiness_narrative || "") + "</p></div>";
  }

  const findings = (data.findings || []).filter(f => f.severity !== "info");
  html += "<h2>Findings (" + findings.length + ")</h2>";
  if (!findings.length) html += "<div class='card'>No issues identified.</div>";
  findings.forEach(f => {
    html += "<div class='finding' style='border-left-color:" + SEV[f.severity] + "'>" +
      "<span class='badge' style='background:" + SEV[f.severity] + "'>" + esc(f.severity) + "</span>" +
      (f.quantum_relevant ? "<span class='q'>quantum</span>" : "") +
      "<h4>" + esc(f.title) + "</h4>" +
      "<p class='where'>" + esc(f.target) + "</p>" +
      "<p>" + esc(f.detail) + "</p>" +
      "<p><strong>Impact.</strong> " + esc(f.impact) + "</p>" +
      "<p><strong>Fix.</strong> " + esc(f.remediation) + "</p></div>";
  });

  if ((data.remediation || []).length) {
    html += "<h2>Do these first</h2><div class='card tblwrap'><table>" +
      "<thead><tr><th>#</th><th>Action</th><th>Effort</th><th>Phase</th></tr></thead><tbody>" +
      data.remediation.map(a => "<tr><td>" + a.priority + "</td><td><strong>" +
        esc(a.title) + "</strong><br><span class='note'>" + esc(a.how) + "</span></td><td>" +
        esc(a.effort) + "</td><td>" + esc(a.phase) + "</td></tr>").join("") +
      "</tbody></table></div>";
  }

  if ((data.licences || []).length) {
    html += "<h2>Components and licences</h2><div class='card tblwrap'><table>" +
      "<thead><tr><th>Component</th><th>Version</th><th>Licence</th><th>Risk</th></tr></thead><tbody>" +
      data.licences.map(l => "<tr><td>" + esc(l.component) + "</td><td>" +
        esc(l.version || "—") + "</td><td>" + esc(l.licence) + "</td><td><span class='pill' style='background:" +
        (SEV[l.risk] || "#4b5563") + "'>" + esc(l.risk) + "</span></td></tr>").join("") +
      "</tbody></table></div>";
  }

  if ((data.crypto_inventory || []).length) {
    const seen = new Set(); const rows = [];
    data.crypto_inventory.forEach(a => {
      const key = a.name + "|" + a.kind;
      if (seen.has(key)) return;
      seen.add(key);
      rows.push("<tr><td>" + esc(a.name) + "</td><td>" + esc(a.kind) + "</td><td>" +
        (a.classical_bits || "—") + "</td><td>" + a.quantum_bits + "</td><td><span class='pill' style='background:" +
        (a.quantum_safe ? "var(--ok)" : "var(--bad)") + "'>" +
        (a.quantum_safe ? "safe" : esc(a.broken_by || "weak")) + "</span></td></tr>");
    });
    html += "<h2>Cryptographic inventory</h2><div class='card tblwrap'><table>" +
      "<thead><tr><th>Algorithm</th><th>Use</th><th>Classical bits</th>" +
      "<th>Quantum bits</th><th>Status</th></tr></thead><tbody>" + rows.join("") +
      "</tbody></table></div>";
  }

  if ((data.compliance || []).length) {
    html += "<h2>Compliance</h2><div class='card tblwrap'><table>" +
      "<thead><tr><th>Framework</th><th>Status</th><th>Timeline</th></tr></thead><tbody>" +
      data.compliance.map(c => "<tr><td>" + esc(c.name) + "</td><td><span class='pill' style='background:" +
        (c.status === "pass" ? "var(--ok)" : c.status === "fail" ? "var(--bad)" : "var(--warn)") +
        "'>" + esc(c.status) + "</span></td><td class='note'>" + esc(c.deadline) +
        "</td></tr>").join("") + "</tbody></table></div>";
  }

  const notes = (data.notes || []).concat(data.errors || []);
  if (notes.length) {
    html += "<h2>Scan notes</h2><div class='card'><ul class='note' style='margin:0;padding-left:1.2em'>" +
      notes.map(n => "<li>" + esc(n) + "</li>").join("") + "</ul></div>";
  }

  const base = "/api/scan/result?id=" + encodeURIComponent(jobId) + "&format=";
  html += "<h2>Download</h2><div class='card row'>" +
    "<a href='" + base + "html' target='_blank'><button class='ghost' type='button'>HTML report</button></a>" +
    "<a href='" + base + "json' target='_blank'><button class='ghost' type='button'>JSON</button></a>" +
    "<a href='" + base + "markdown'><button class='ghost' type='button'>Markdown</button></a>" +
    "<a href='" + base + "cbom'><button class='ghost' type='button'>CycloneDX CBOM</button></a></div>";

  $("out").innerHTML = html;
  $("out").className = "";
}
</script>
</body></html>
"""
