"""Executive report — a self-contained, printable HTML briefing for a match.

Rolls the scorecard, business-impact cost, prioritised remediation and incident
summary into one branded page a CISO or investor can read or print to PDF. Pure
HTML string built from engine state; no external assets.
"""
from __future__ import annotations

import html
import time

from . import attack_map


def _usd(n) -> str:
    return "$" + format(int(n), ",") if n is not None else "–"


def _esc(x) -> str:
    return html.escape(str(x))


def _attack_summary(turns) -> list[tuple[str, str, int]]:
    agg: dict[str, dict] = {}
    for t in turns:
        if t.side != "red" or not t.success:
            continue
        for tech in attack_map.techniques_for(t.action):
            e = agg.setdefault(tech["id"], {"name": tech["name"], "tactic": tech["tactic"], "n": 0})
            e["n"] += 1
    return [(tid, f"{e['tactic']} — {e['name']}", e["n"])
            for tid, e in sorted(agg.items(), key=lambda kv: -kv[1]["n"])]


def build(seed, scenario, winner, reason, rounds, scorecard, exposure, cases, turns) -> str:
    red, blue = scorecard["red"], scorecard["blue"]
    bc = scorecard.get("business_cost", {})
    won = (winner or "in progress").upper()
    outcome_colour = "#ff2d55" if winner == "red" else "#3b9dff"
    fixes = exposure.get("top_fixes", [])[:5]
    plan = exposure.get("minimal_fix_plan", [])
    techs = _attack_summary(turns)

    def stat(label, value, note=""):
        return (f'<div class="stat"><div class="sv">{_esc(value)}</div>'
                f'<div class="sl">{_esc(label)}</div>'
                f'{f"<div class=sn>{_esc(note)}</div>" if note else ""}</div>')

    fix_rows = "".join(
        f'<tr><td><span class="tag">{_esc(f["action"])}</span> {_esc(f["label"])}</td>'
        f'<td class="num">−{f["paths_removed"]}</td>'
        f'<td class="num">{int(f["pct_removed"]*100)}%</td></tr>' for f in fixes) or \
        '<tr><td colspan="3">No single fix reduces exposure further.</td></tr>'
    plan_rows = "".join(f'<li>{_esc(p["label"])} <span class="muted">→ {p["paths_after"]} paths left</span></li>'
                        for p in plan) or "<li>Already at minimal exposure.</li>"
    tech_rows = "".join(f'<tr><td class="mono">{_esc(tid)}</td><td>{_esc(desc)}</td>'
                        f'<td class="num">{n}×</td></tr>' for tid, desc, n in techs) or \
        '<tr><td colspan="3">No attacker techniques recorded.</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Wargame — Executive Report (seed {_esc(seed)})</title>
<style>
  :root {{ --ink:#0a0e17; --muted:#64708a; --line:#e2e6ee; --red:#ff2d55; --blue:#2b7fd6; --gold:#b8860b; --green:#1f9d57; }}
  * {{ box-sizing:border-box; }}
  body {{ font:15px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif; color:var(--ink); max-width:860px; margin:0 auto; padding:40px 28px; }}
  header {{ border-bottom:3px solid var(--ink); padding-bottom:16px; margin-bottom:24px; }}
  h1 {{ font-size:24px; margin:0 0 4px; }} h2 {{ font-size:17px; margin:28px 0 10px; border-bottom:1px solid var(--line); padding-bottom:5px; }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .verdict {{ font-size:20px; font-weight:700; color:{outcome_colour}; margin:14px 0 6px; }}
  .stats {{ display:flex; flex-wrap:wrap; gap:14px; margin:14px 0; }}
  .stat {{ flex:1 1 120px; border:1px solid var(--line); border-radius:8px; padding:12px 14px; }}
  .sv {{ font-size:22px; font-weight:700; }} .sl {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }}
  .sn {{ font-size:11px; color:var(--muted); margin-top:2px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin:8px 0; }}
  th,td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-size:11px; text-transform:uppercase; }}
  .num {{ text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }}
  .mono {{ font-family:ui-monospace,Menlo,monospace; }}
  .tag {{ font:700 10px ui-monospace,monospace; background:#eef3fb; color:var(--blue); border-radius:3px; padding:1px 5px; }}
  .muted {{ color:var(--muted); }} .cost-total {{ font-size:18px; font-weight:700; color:var(--gold); }}
  ol {{ margin:4px 0 4px 20px; }} li {{ margin:3px 0; }}
  footer {{ margin-top:34px; padding-top:12px; border-top:1px solid var(--line); color:var(--muted); font-size:11px; }}
  @media print {{ body {{ padding:0; }} .stat {{ break-inside:avoid; }} h2 {{ break-after:avoid; }} }}
</style></head><body>
<header>
  <h1>⛩ AI Wargame — Executive Briefing</h1>
  <div class="sub">Sakura Logistics K.K. (simulation) · scenario: {_esc(scenario)} · seed {_esc(seed)} · generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</div>
</header>

<div class="verdict">{"🔴" if winner=="red" else "🔵"} {won} — {_esc(reason)}</div>
<div class="sub">{rounds} rounds played.</div>

<h2>Defensive performance</h2>
<div class="stats">
  {stat("BLUE grade", f"{blue['grade']} · {blue['score']}")}
  {stat("Mean time to detect", f"{blue['mttd_rounds'] if blue['mttd_rounds'] is not None else '–'}", "rounds")}
  {stat("Mean time to respond", f"{blue['mttr_rounds'] if blue['mttr_rounds'] is not None else '–'}", "rounds")}
  {stat("Exposure reduced", f"{int(blue['exposure_reduction']*100)}%")}
  {stat("False isolations", blue['false_isolations'], "wasted downtime")}
</div>
<div class="stats">
  {stat("Compromises detected", f"{blue['detected']}/{blue['detected']+blue['missed']}")}
  {stat("Incidents opened", cases.get("opened", 0))}
  {stat("Contained", cases.get("contained", 0))}
  {stat("False-positive cases", cases.get("closed_false_positive", 0))}
  {stat("Mean time to contain", cases.get("mean_time_to_contain", "–"), "rounds")}
</div>

<h2>Business impact</h2>
<table>
  <tr><td>Downtime (isolation / reimage)</td><td class="num">{_usd(bc.get("downtime_usd"))}</td></tr>
  <tr><td>Incident response ({bc.get("hosts_requiring_response", 0)} hosts)</td><td class="num">{_usd(bc.get("response_usd"))}</td></tr>
  <tr><td>Breach loss (objective reached)</td><td class="num">{_usd(bc.get("breach_usd"))}</td></tr>
  <tr><td class="cost-total">Total cost to the business</td><td class="num cost-total">{_usd(bc.get("total_usd"))}</td></tr>
</table>

<h2>Prioritised remediation</h2>
<div class="sub">Current exposure: <b>{exposure.get("current_exposure", 0)}</b> viable attack paths to the crown jewel.</div>
<table><tr><th>Fix</th><th class="num">Paths removed</th><th class="num">%</th></tr>{fix_rows}</table>
<div class="sub">Minimal fix plan ({len(plan)} steps → {exposure.get("residual_after_plan", 0)} residual):</div>
<ol>{plan_rows}</ol>

<h2>Attacker techniques (MITRE ATT&amp;CK)</h2>
<table><tr><th>Technique</th><th>Tactic / name</th><th class="num">Uses</th></tr>{tech_rows}</table>

<footer>Generated by AI Wargame — an autonomous red-vs-blue simulation. All figures are from a
simulated incident; costs are illustrative, anchored to public breach benchmarks. No real systems were involved.</footer>
</body></html>"""
