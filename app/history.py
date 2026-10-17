"""Match history — persist finished matches so outcomes can be tracked over time.

Each completed match appends a compact record to a JSON file (newest last, capped).
Useful for the model-evaluation story (how a model trends across many games) and
for showing a session's history in the UI. Append-only, best-effort: a write
failure never affects the game.
"""
from __future__ import annotations

import json
import logging
import os
import time

log = logging.getLogger("history")

MAX_RECORDS = 500


def _load(path: str) -> list[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def record(path: str, match: dict) -> None:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        hist = _load(path)
        hist.append(match)
        hist = hist[-MAX_RECORDS:]
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(hist, fh, indent=1)
        os.replace(tmp, path)
    except OSError as e:
        log.warning("match history write failed: %s", e)


def recent(path: str, limit: int = 50) -> dict:
    hist = _load(path)
    red = sum(1 for m in hist if m.get("winner") == "red")
    blue = sum(1 for m in hist if m.get("winner") == "blue")
    return {"count": len(hist), "red_wins": red, "blue_wins": blue,
            "matches": list(reversed(hist[-limit:]))}


def summarise(engine) -> dict:
    """Build the compact record for a finished match from engine state."""
    sc = engine.scorecard()
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": engine.spec.seed if engine.spec else None,
        "scenario": getattr(engine, "scenario", "baseline"),
        "winner": engine.winner,
        "reason": engine.win_reason,
        "rounds": engine.round,
        "red_model": engine.agents["red"].model if engine.agents.get("red")
        else ("human" if engine.control.get("red") == "human" else "heuristic"),
        "blue_model": engine.agents["blue"].model if engine.agents.get("blue")
        else ("human" if engine.control.get("blue") == "human" else "heuristic"),
        "players": dict(engine.control),
        "red_score": sc["red"]["score"], "red_grade": sc["red"]["grade"],
        "blue_score": sc["blue"]["score"], "blue_grade": sc["blue"]["grade"],
        "mttd": sc["blue"]["mttd_rounds"], "mttr": sc["blue"]["mttr_rounds"],
        "exposure_reduction": sc["blue"]["exposure_reduction"],
        "business_cost_usd": sc.get("business_cost", {}).get("total_usd"),
        "incidents": sc.get("cases", {}).get("opened", 0),
    }
