"""After-action report: LLM-generated, with a deterministic static fallback."""
from __future__ import annotations

import json
import logging

log = logging.getLogger("report")

REPORT_SYSTEM = """You are a senior incident responder writing the after-action report for a simulated cyber wargame at Sakura Logistics K.K.

You receive the complete turn log (JSON) and the per-round count of viable attack paths to the CrownJewel.

Write a markdown report with EXACTLY these sections:
## Outcome
(winner and why, 2 sentences)
## Timeline
(5-10 bullets, turn-numbered, only key events)
## MITRE ATT&CK Mapping
(table: turn | RED action | tactic | technique)
## Turning Points
(where the path count shifted and why)
## What BLUE Should Have Done Differently
(3 concrete recommendations)

Under 500 words. Be specific: name hosts, CVEs, and turns."""


def static_report(turns, metrics_history, winner, reason) -> str:
    red_actions = [t for t in turns if t.side == "red"]
    compromised_peak = max((m["compromised"] for m in metrics_history), default=0)
    lines = [
        "## Outcome",
        f"**{winner.upper()} wins** — {reason}. "
        f"Peak attacker footprint: {compromised_peak} host(s).",
        "",
        "## Timeline",
    ]
    for t in turns:
        if t.success and (t.side == "red" or t.action in ("ISOLATE", "DEPLOY_HONEYPOT")):
            mark = "✅" if t.success else "❌"
            lines.append(f"- Turn {t.n} (round {t.round}, {t.side.upper()}): {t.action} {mark} — {t.narration}")
    lines += [
        "",
        "## MITRE ATT&CK Mapping",
        "(LLM report unavailable — heuristic summary only)",
        "",
        "| Turn | RED action | Tactic |",
        "|---|---|---|",
    ]
    tactic = {"SCAN": "Discovery (T1046)", "EXPLOIT": "Initial Access / Execution (T1190)",
              "HARVEST_CREDS": "Credential Access (T1003)", "LATERAL_MOVE": "Lateral Movement (T1021)",
              "EXFILTRATE": "Exfiltration (T1041)"}
    for t in red_actions:
        lines.append(f"| {t.n} | {t.action} {json.dumps(t.args)} | {tactic.get(t.action, '-')} |")
    lines += [
        "",
        "## Turning Points",
        "Path-count history: " + ", ".join(str(m["paths"]) for m in metrics_history),
        "",
        "## What BLUE Should Have Done Differently",
        "- Investigate high-confidence alerts before isolating critical hosts.",
        "- Rotate privileged credentials earlier (k.sato, j.saito).",
        "- Patch the highest-severity vulns on the shortest path to the CrownJewel first.",
    ]
    return "\n".join(lines)


async def generate_report(settings, turns, metrics_history, winner, reason) -> str:
    if not settings.aiand_enabled:
        return static_report(turns, metrics_history, winner, reason)
    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(base_url=settings.AIAND_BASE_URL, api_key=settings.AIAND_API_KEY,
                             timeout=90.0, max_retries=0)
        log_data = [
            {"n": t.n, "round": t.round, "side": t.side, "action": t.action,
             "args": t.args, "success": t.success, "narration": t.narration}
            for t in turns
        ]
        user = json.dumps({"winner": winner, "reason": reason,
                           "turn_log": log_data,
                           "path_count_history": [m["paths"] for m in metrics_history]})
        resp = await client.chat.completions.create(
            model=settings.REPORT_MODEL, temperature=0.4, max_tokens=2500,
            messages=[{"role": "system", "content": REPORT_SYSTEM},
                      {"role": "user", "content": user}])
        md = (resp.choices[0].message.content or "").strip()
        return md if "## Outcome" in md else static_report(turns, metrics_history, winner, reason)
    except Exception as e:  # noqa: BLE001
        log.warning("LLM report failed (%s) — using static fallback", e)
        return static_report(turns, metrics_history, winner, reason)
