"""Match exports: ATT&CK Navigator layer JSON and a STIX 2.1 bundle.

Both are built from the engine's TurnRecord list, so they work for any
finished (or in-progress) match. The Navigator layer imports directly into
https://mitre-attack.github.io/attack-navigator/; the STIX bundle validates
against STIX 2.1 and imports into TIP tooling.
"""
from __future__ import annotations

import time
import uuid

from . import attack_map
from .models import TurnRecord


def _red_techniques(turns: list[TurnRecord]) -> dict[str, dict]:
    """technique id -> {count, hosts, name, tactic} for successful RED actions."""
    agg: dict[str, dict] = {}
    for t in turns:
        if t.side != "red" or not t.success:
            continue
        for tech in attack_map.techniques_for(t.action):
            e = agg.setdefault(tech["id"], {"count": 0, "hosts": set(),
                                            "name": tech["name"], "tactic": tech["tactic"]})
            e["count"] += 1
            if t.args.get("host"):
                e["hosts"].add(t.args["host"])
    return agg


def navigator_layer(turns: list[TurnRecord], seed: int, winner: str | None,
                    reason: str) -> dict:
    """ATT&CK Navigator layer format v4.5 (RED heatmap)."""
    agg = _red_techniques(turns)
    techniques = [
        {
            "techniqueID": tid,
            "tactic": None,  # tactic-agnostic: color the technique everywhere it appears
            "score": e["count"],
            "color": "#ff2d55",
            "comment": f"{e['count']}x — targets: {', '.join(sorted(e['hosts'])) or '-'}",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        }
        for tid, e in sorted(agg.items())
    ]
    return {
        "name": f"AI Wargame match (seed {seed}) — RED",
        "versions": {"attack": "16", "navigator": "5.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Autonomous RED agent techniques. Outcome: "
                       f"{(winner or 'in progress').upper()} — {reason}",
        "filters": {"platforms": ["Linux", "Windows", "Network", "PRE"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "sum",
                   "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#2b2f4a", "#ff2d55"],
                     "minValue": 0,
                     "maxValue": max((e["count"] for e in agg.values()), default=1)},
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#14172b",
        "selectTechniquesAcrossTactics": True,
    }


def _stix_id(type_: str) -> str:
    return f"{type_}--{uuid.uuid4()}"


def stix_bundle(turns: list[TurnRecord], seed: int, winner: str | None, reason: str) -> dict:
    """Minimal valid STIX 2.1 bundle describing the match."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    identity = {
        "type": "identity", "spec_version": "2.1", "id": _stix_id("identity"),
        "created": now, "modified": now,
        "name": "AI Wargame (Sakura Logistics K.K. simulation)",
        "identity_class": "organization",
    }
    objects: list[dict] = [identity]

    agg = _red_techniques(turns)
    for tid, e in sorted(agg.items()):
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1",
            "id": _stix_id("attack-pattern"),
            "created": now, "modified": now,
            "name": f"{e['name']} — observed {e['count']}x (seed {seed})",
            "description": f"Autonomous RED agent used {tid} {e['count']} time(s); "
                           f"targets: {', '.join(sorted(e['hosts'])) or '-'}.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid,
                 "url": attack_map.technique_url(tid)},
                {"source_name": "ai-wargame", "description":
                 f"Match seed {seed}; outcome {winner or 'in progress'}: {reason}"},
            ],
        })

    objects.append({
        "type": "note", "spec_version": "2.1", "id": _stix_id("note"),
        "created": now, "modified": now,
        "abstract": f"AI Wargame match seed {seed}",
        "content": f"Winner: {(winner or 'in progress').upper()}. {reason}. "
                   f"{len(turns)} actions recorded.",
        "authors": ["AI Wargame"],
        "object_refs": [o["id"] for o in objects],
    })
    return {"type": "bundle", "id": _stix_id("bundle"), "objects": objects}
