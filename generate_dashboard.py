#!/usr/bin/env python3
"""Generate a self-contained static dashboard for GitHub Pages.

Reads the committed rule database metadata and emits a single ``index.html``
(with all data embedded inline + Chart.js from CDN) under ``site/``. The
GitHub Pages workflow regenerates and redeploys this on every push to main,
so the public dashboard always reflects the latest ruleset and validation
results.

Usage:
    python generate_dashboard.py [--out site]
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
META = PROJECT_ROOT / "database" / "metadata"

# Canonical MITRE tactic order (ATT&CK Enterprise kill-chain).
TACTIC_ORDER = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


def _load(path: Path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _val_stats(data: dict) -> dict:
    """Compute pass/fail/inconclusive summary from a per-rule results dict."""
    if not isinstance(data, dict) or not data:
        return {"total": 0, "passed": 0, "failed": 0, "inconclusive": 0, "pass_rate": 0.0}
    total = len(data)
    passed = sum(1 for r in data.values() if isinstance(r, dict) and r.get("passed"))
    inconclusive = sum(1 for r in data.values() if isinstance(r, dict) and r.get("inconclusive"))
    considered = total - inconclusive
    rate = (passed / considered * 100) if considered else 0.0
    return {
        "total": total,
        "passed": passed,
        "failed": considered - passed,
        "inconclusive": inconclusive,
        "pass_rate": round(rate, 1),
    }


def collect_stats() -> dict:
    """Aggregate every metric the dashboard renders into one dict."""
    index = _load(META / "rule_index.json", {})
    validation = _load(META / "validation_results.json", {})
    live = _load(META / "live_validation_results.json", {})
    changelog = _load(META / "changelog.json", [])

    by_tactic: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_level: dict[str, int] = {}
    provenance = {"evtx": 0, "sigma": 0}
    techniques: set[str] = set()
    mitre_ids: set[str] = set()

    for meta in index.values():
        if not isinstance(meta, dict):
            continue
        by_tactic[meta.get("tactic") or "unknown"] = by_tactic.get(meta.get("tactic") or "unknown", 0) + 1
        by_source[meta.get("source_category") or "unknown"] = (
            by_source.get(meta.get("source_category") or "unknown", 0) + 1
        )
        lv = str(meta.get("level", "?"))
        by_level[lv] = by_level.get(lv, 0) + 1
        provenance["sigma" if meta.get("sigma_id") else "evtx"] += 1
        if meta.get("technique_id"):
            techniques.add(meta["technique_id"])
        for mid in meta.get("mitre_ids", []) or []:
            mitre_ids.add(mid)

    # Order tactics by the kill chain, append any unknowns.
    ordered_tactics = {t: by_tactic[t] for t in TACTIC_ORDER if t in by_tactic}
    for t, c in by_tactic.items():
        if t not in ordered_tactics:
            ordered_tactics[t] = c

    levels_sorted = {k: by_level[k] for k in sorted(by_level, key=lambda x: int(x) if x.isdigit() else 0)}

    # Last 15 changelog entries (newest first).
    recent = changelog[-15:][::-1] if isinstance(changelog, list) else []

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "run_url": os.environ.get("DASHBOARD_RUN_URL", ""),
        "commit": os.environ.get("DASHBOARD_COMMIT", "")[:7],
        "total": len(index),
        "techniques": len(techniques),
        "mitre_ids": len(mitre_ids),
        "tactics_covered": len([t for t in ordered_tactics if t != "unknown"]),
        "by_tactic": ordered_tactics,
        "by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
        "by_level": levels_sorted,
        "provenance": provenance,
        "simulate": _val_stats(validation),
        "live": _val_stats(live),
        "recent_changes": recent,
    }


def render_html(stats: dict) -> str:
    """Render the full static HTML page with inlined data + Chart.js."""
    data_json = json.dumps(stats)
    run_link = (
        f'<a href="{stats["run_url"]}" target="_blank">build&nbsp;#{stats["commit"]}</a>'
        if stats["run_url"]
        else (f"build {stats['commit']}" if stats["commit"] else "local build")
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EVTX-Wazuh · Detection Coverage Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root{{
    --bg:#0b0f1a;--panel:#131a2b;--panel2:#1a2335;--line:#243049;--text:#e6ebf5;
    --muted:#8a97b1;--accent:#4f8cff;--accent2:#8957e5;--good:#2ea44f;--warn:#e3b341;--bad:#e5534b;--radius:16px;
  }}
  *{{box-sizing:border-box}}
  html{{scroll-behavior:smooth}}
  body{{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    background:radial-gradient(1200px 600px at 80% -10%,#1b2540 0%,transparent 60%),
    radial-gradient(900px 500px at -10% 0%,#21183a 0%,transparent 55%),var(--bg);
    color:var(--text);-webkit-font-smoothing:antialiased}}
  .wrap{{max-width:1180px;margin:0 auto;padding:2.5rem 1.25rem 4rem}}
  .badge{{display:inline-flex;align-items:center;gap:.5rem;font-size:.78rem;font-weight:600;
    color:var(--accent);background:rgba(79,140,255,.12);border:1px solid rgba(79,140,255,.3);
    border-radius:999px;padding:.35rem .7rem}}
  h1{{font-size:clamp(1.8rem,3vw,2.6rem);margin:.6rem 0 .3rem;line-height:1.1;
    background:linear-gradient(90deg,#fff 20%,var(--accent) 60%,var(--accent2) 100%);
    -webkit-background-clip:text;background-clip:text;color:transparent}}
  .sub{{color:var(--muted);margin:0;font-size:1.02rem}}
  .meta{{color:var(--muted);font-size:.82rem;margin-top:.5rem}}
  .meta a{{color:var(--accent);text-decoration:none}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1rem;margin:2rem 0}}
  .card{{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
    border-radius:var(--radius);padding:1.3rem 1.4rem;position:relative;overflow:hidden}}
  .card::after{{content:"";position:absolute;inset:0 0 auto auto;width:120px;height:120px;
    background:radial-gradient(circle at top right,rgba(79,140,255,.18),transparent 70%)}}
  .card .k{{font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}}
  .card .v{{font-size:2.1rem;font-weight:750;margin-top:.35rem}}
  .card .v small{{font-size:.85rem;color:var(--muted);font-weight:500}}
  .v.good{{color:#58d68a}}.v.warn{{color:var(--warn)}}.v.bad{{color:var(--bad)}}
  .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem;margin-bottom:1.25rem}}
  @media(max-width:820px){{.grid2{{grid-template-columns:1fr}}}}
  .panel{{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:1.3rem 1.4rem}}
  .panel h2{{margin:0 0 1rem;font-size:1.02rem;display:flex;align-items:center;gap:.5rem}}
  .panel h2 .dot{{width:9px;height:9px;border-radius:50%;background:var(--accent)}}
  .panel h2 .dot.alt{{background:var(--accent2)}}
  canvas{{max-height:300px}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th,td{{text-align:left;padding:.4rem .5rem;border-bottom:1px solid var(--line)}}
  th{{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:.72rem;letter-spacing:.05em}}
  td.act{{font-weight:600}}
  .add{{color:#58d68a}}.modify{{color:var(--warn)}}.remove{{color:var(--bad)}}
  .foot{{margin-top:2.5rem;padding-top:1.25rem;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}}
  .foot a{{color:var(--accent);text-decoration:none}}
  code{{background:var(--panel2);border:1px solid var(--line);padding:.1rem .4rem;border-radius:6px;color:var(--accent);font-size:.85em}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="badge">● Live coverage · auto-redeployed every pipeline run</span>
    <h1>EVTX-Wazuh Detection Coverage</h1>
    <p class="sub">MITRE ATT&amp;CK-mapped Wazuh rules from EVTX attack samples &amp; SigmaHQ.</p>
    <p class="meta">Generated {stats["generated_at"]} · {run_link}</p>
  </header>

  <section class="cards">
    <div class="card"><div class="k">Total rules</div><div class="v" id="c-total">0</div></div>
    <div class="card"><div class="k">MITRE techniques</div><div class="v" id="c-tech">0</div></div>
    <div class="card"><div class="k">Tactics covered</div><div class="v" id="c-tac">0<small> / 12</small></div></div>
    <div class="card"><div class="k">Offline sim pass</div><div class="v good" id="c-sim">0<small>%</small></div></div>
    <div class="card"><div class="k">Live logtest pass</div><div class="v" id="c-live">0<small>%</small></div></div>
  </section>

  <div class="grid2">
    <div class="panel"><h2><span class="dot"></span> Rules by tactic</h2><canvas id="tacticChart"></canvas></div>
    <div class="panel"><h2><span class="dot alt"></span> Rules by source</h2><canvas id="sourceChart"></canvas></div>
  </div>

  <div class="grid2">
    <div class="panel"><h2><span class="dot"></span> Severity level distribution</h2><canvas id="levelChart"></canvas></div>
    <div class="panel"><h2><span class="dot alt"></span> Rule provenance &amp; validation</h2><canvas id="provChart"></canvas></div>
  </div>

  <div class="panel">
    <h2><span class="dot"></span> Recent changes</h2>
    <table>
      <thead><tr><th>Time</th><th>Action</th><th>Rule</th><th>Version</th></tr></thead>
      <tbody id="changelog"></tbody>
    </table>
  </div>

  <div class="foot">
    EVTX-Wazuh-Rules · <a href="https://github.com/saifbelaarbi/EVTX-Wazuh-rules">GitHub</a> ·
    data from <code>database/metadata/</code> · rebuilt automatically on every push to <code>main</code>.
  </div>
</div>

<script>
const DATA = {data_json};
const fmt = new Intl.NumberFormat();
const C = {{accent:'#4f8cff',accent2:'#8957e5',good:'#2ea44f',warn:'#e3b341',bad:'#e5534b',muted:'#8a97b1',line:'#243049'}};
Chart.defaults.color = C.muted;
Chart.defaults.borderColor = C.line;
Chart.defaults.font.family = 'ui-sans-serif, system-ui, sans-serif';

// Stat cards
document.getElementById('c-total').textContent = fmt.format(DATA.total);
document.getElementById('c-tech').textContent = fmt.format(DATA.techniques);
document.getElementById('c-tac').innerHTML = DATA.tactics_covered + '<small> / 12</small>';
const sim = DATA.simulate.pass_rate, live = DATA.live.pass_rate;
const simEl = document.getElementById('c-sim'), liveEl = document.getElementById('c-live');
simEl.innerHTML = sim.toFixed(1) + '<small>%</small>';
liveEl.innerHTML = (DATA.live.total ? live.toFixed(1) : '—') + '<small>%</small>';
liveEl.className = 'v ' + (live>=90?'good':live>=50?'warn':'bad');

function grad(ctx, c1, c2){{const g=ctx.createLinearGradient(0,0,0,300);g.addColorStop(0,c1);g.addColorStop(1,c2);return g;}}
const titleCase = s => s.replace(/_/g,' ').replace(/\\b\\w/g,m=>m.toUpperCase());

// Rules by tactic (horizontal bar)
new Chart(document.getElementById('tacticChart'),{{
  type:'bar',
  data:{{labels:Object.keys(DATA.by_tactic).map(titleCase),
    datasets:[{{data:Object.values(DATA.by_tactic),backgroundColor:C.accent,borderRadius:6}}]}},
  options:{{indexAxis:'y',plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:C.line}}}},y:{{grid:{{display:false}}}}}}}}
}});

// Rules by source (doughnut)
new Chart(document.getElementById('sourceChart'),{{
  type:'doughnut',
  data:{{labels:Object.keys(DATA.by_source).map(titleCase),
    datasets:[{{data:Object.values(DATA.by_source),
      backgroundColor:[C.accent,C.accent2,C.good,C.warn,C.bad,'#37b6c4','#c47ae3','#6d7fa3']}}]}},
  options:{{plugins:{{legend:{{position:'right',labels:{{boxWidth:12,padding:10}}}}}}}}
}});

// Severity levels (bar)
new Chart(document.getElementById('levelChart'),{{
  type:'bar',
  data:{{labels:Object.keys(DATA.by_level).map(l=>'L'+l),
    datasets:[{{data:Object.values(DATA.by_level),
      backgroundColor:Object.keys(DATA.by_level).map(l=>{{const n=+l;return n>=12?C.bad:n>=10?C.warn:C.accent;}}),borderRadius:6}}]}},
  options:{{plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{display:false}}}},y:{{grid:{{color:C.line}}}}}}}}
}});

// Provenance + validation (stacked-ish bar)
new Chart(document.getElementById('provChart'),{{
  type:'bar',
  data:{{labels:['EVTX','Sigma','Sim pass','Sim fail','Live pass','Live fail'],
    datasets:[{{data:[DATA.provenance.evtx,DATA.provenance.sigma,
      DATA.simulate.passed,DATA.simulate.failed,DATA.live.passed,DATA.live.failed],
      backgroundColor:[C.accent,C.accent2,C.good,C.bad,C.good,C.bad],borderRadius:6}}]}},
  options:{{plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{display:false}}}},y:{{grid:{{color:C.line}}}}}}}}
}});

// Changelog table
const tbody = document.getElementById('changelog');
if(DATA.recent_changes.length===0){{
  tbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted)">No changelog entries yet.</td></tr>';
}} else {{
  for(const ch of DATA.recent_changes){{
    const ts = (ch.timestamp||'').replace('T',' ').slice(0,16);
    const act = (ch.action||'').toLowerCase();
    const ver = ch.new_version||ch.version||'';
    tbody.insertAdjacentHTML('beforeend',
      `<tr><td>${{ts}}</td><td class="act ${{act}}">${{act}}</td><td><code>${{ch.rule_id||''}}</code></td><td>v${{ver}}</td></tr>`);
  }}
}}
</script>
</body>
</html>
"""


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the static GitHub Pages dashboard.")
    ap.add_argument("--out", default="site", help="Output directory (default: site)")
    args = ap.parse_args()

    stats = collect_stats()
    out_dir = PROJECT_ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    html = render_html(stats)
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    # Also drop the raw stats JSON next to the page for programmatic consumers.
    (out_dir / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    # GitHub Pages: skip Jekyll processing.
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")

    print(f"Dashboard written to {out_dir / 'index.html'}")
    print(
        f"  {stats['total']} rules · {stats['techniques']} techniques · "
        f"sim {stats['simulate']['pass_rate']}% · live {stats['live']['pass_rate']}%"
    )


if __name__ == "__main__":
    main()
