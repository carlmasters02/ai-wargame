"""After-action report: LLM-generated (streamed, with a model fallback chain) and a
deterministic, data-driven template when no model can answer.

`generate_report` returns {"markdown", "source", "model", "note"} so the UI can say
honestly whether a model wrote the report or the template did.
"""
from __future__ import annotations

import asyncio
import json
import logging

from . import attack_map

log = logging.getLogger("report")

REPORT_SYSTEM = """You are a senior incident responder writing the after-action report for a simulated cyber wargame at Sakura Logistics K.K.

You receive the complete turn log (JSON), the per-round count of viable attack paths to the CrownJewel, and engine facts about what was left unresolved at the end.

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
(3 concrete recommendations grounded in the unresolved facts)

Under 500 words. Be specific: name hosts, CVEs, and turns. Output only the report."""


def _technique_cell(action: str) -> tuple[str, str]:
    techs = attack_map.techniques_for(action)
    if not techs:
        return "-", "-"
    return techs[0]["tactic"], ", ".join(f"{t['id']} {t['name']}" for t in techs)


def _timeline(turns) -> list[str]:
    key = [t for t in turns if t.success and (t.side == "red" or t.action in
                                              ("ISOLATE", "REIMAGE", "DEPLOY_HONEYPOT", "ROTATE_CREDS"))]
    out = [f"- Turn {t.n} (round {t.round}, {t.side.upper()}): {t.action} — {t.narration}"
           for t in key[:12]]
    if len(key) > 12:
        out.append(f"- … {len(key) - 12} more key events in the match timeline")
    return out


def _attack_table(turns) -> list[str]:
    out = ["| Turn | RED action | Tactic | Technique |", "|---|---|---|---|"]
    for t in (t for t in turns if t.side == "red"):
        tactic, tech = _technique_cell(t.action)
        target = t.args.get("host") or t.args.get("user") or ""
        out.append(f"| {t.n} | {t.action} {target}{'' if t.success else ' (failed)'} | {tactic} | {tech} |")
    return out


def _turning_points(metrics_history) -> list[str]:
    swings = sorted(((abs(b["paths"] - a["paths"]), a, b)
                     for a, b in zip(metrics_history, metrics_history[1:])), key=lambda x: -x[0])[:3]
    out = [f"- Round {b['round']}: attack paths {a['paths']} → {b['paths']}" for d, a, b in swings if d]
    if not out:
        out = ["- The attack-path count stayed flat — neither side shifted the exposure."]
    paths = [m["paths"] for m in metrics_history]
    out.append(f"- Path-count range over the match: {min(paths, default=0)}–{max(paths, default=0)}")
    return out


def _recommendations(context: dict) -> list[str]:
    recs = [f"- Rotate {c['owner']}'s {c['kind']} (grants {c['grants']}): stolen and never rotated."
            for c in context.get("stolen_unrotated", [])[:2]]
    recs += [f"- Patch {v['cve']} on {v['host']}: exploited in round {v['round']} and still open."
             for v in context.get("exploited_unpatched", [])[:2]]
    if context.get("uninvestigated_alerts"):
        hosts = ", ".join(context["uninvestigated_alerts"][:3])
        recs.append(f"- Investigate high-confidence alerts sooner (never investigated: {hosts}).")
    if context.get("failed_isolations"):
        recs.append("- Investigate before isolating: hidden C2 beacons defeated "
                    f"{context['failed_isolations']} isolation attempt(s).")
    return recs[:4] or ["- BLUE left no obvious gaps; keep prioritising the shortest path to the crown jewel."]


def static_report(turns, metrics_history, winner, reason, context: dict | None = None) -> str:
    """Deterministic report built only from engine data — used when no model can answer."""
    peak = max((m["compromised"] for m in metrics_history), default=0)
    return "\n".join(
        ["## Outcome",
         f"**{winner.upper()} wins** — {reason}. Peak attacker footprint: {peak} host(s).",
         "", "## Timeline", *_timeline(turns),
         "", "## MITRE ATT&CK Mapping", "", *_attack_table(turns),
         "", "## Turning Points", *_turning_points(metrics_history),
         "", "## What BLUE Should Have Done Differently", *_recommendations(context or {})])


async def _stream_report(client, model: str, user: str, budget: float) -> str:
    """Stream so long reasoning never trips a read timeout; cap total wall time."""
    async def run() -> str:
        stream = await client.chat.completions.create(
            model=model, temperature=0.4, max_tokens=6000, stream=True,
            messages=[{"role": "system", "content": REPORT_SYSTEM},
                      {"role": "user", "content": user}])
        parts: list[str] = []
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                parts.append(chunk.choices[0].delta.content)
        return "".join(parts).strip()
    return await asyncio.wait_for(run(), timeout=budget)


async def generate_report(settings, turns, metrics_history, winner, reason,
                          context: dict | None = None) -> dict:
    template = {"markdown": static_report(turns, metrics_history, winner, reason, context),
                "source": "template", "model": None}
    if not settings.aiand_enabled:
        return template | {"note": "no AIAND_API_KEY configured"}
    from openai import AsyncOpenAI

    client = AsyncOpenAI(base_url=settings.AIAND_BASE_URL, api_key=settings.AIAND_API_KEY,
                         timeout=60.0, max_retries=0)
    user = json.dumps({
        "winner": winner, "reason": reason,
        "turn_log": [{"n": t.n, "round": t.round, "side": t.side, "action": t.action,
                      "args": t.args, "success": t.success, "narration": t.narration}
                     for t in turns],
        "path_count_history": [m["paths"] for m in metrics_history],
        "unresolved_at_end": context or {},
    }, ensure_ascii=False)
    models = list(dict.fromkeys(m for m in (settings.REPORT_MODEL, settings.ATTACKER_MODEL) if m))
    errors = []
    for model in models:
        try:
            md = await _stream_report(client, model, user, settings.REPORT_TIMEOUT)
            if "## Outcome" in md:
                return {"markdown": md, "source": "llm", "model": model, "note": ""}
            errors.append(f"{model}: missing required sections")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{model}: {type(e).__name__}")
            log.warning("LLM report via %s failed (%s)", model, e)
    return template | {"note": "LLM report unavailable (" + "; ".join(errors) + ")"}
