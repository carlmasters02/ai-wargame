"""Match exports: ATT&CK Navigator layer JSON and a STIX 2.1 bundle.

Both are built from the engine's TurnRecord list, so they work for any
finished (or in-progress) match.

- The Navigator layer follows layer format 4.5 and imports directly into
  https://mitre-attack.github.io/attack-navigator/.
- The STIX bundle does NOT mint its own attack-pattern objects. Each technique
  RED used becomes a `sighting` whose `sighting_of_ref` is MITRE's canonical
  attack-pattern id, so a threat-intel platform that already holds ATT&CK links
  the sighting to the existing technique instead of creating a duplicate.
  BLUE's mitigations are attached the same way (notes referencing MITRE's
  canonical course-of-action ids), and a `report` object ties the match together.
"""
from __future__ import annotations

import time
import uuid

from . import attack_map
from .models import TurnRecord

# stable namespace so the simulated organisation / tool identities keep the same
# STIX id across every export (TIPs then merge them instead of duplicating)
_NS = uuid.UUID("6f1c2a52-3c1e-4c55-9d0c-7a1e5b2f9e10")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _aggregate(turns: list[TurnRecord], side: str) -> dict[str, dict]:
    """technique id -> {count, hosts, name, tactic, stix_id, first, last} for successful actions."""
    agg: dict[str, dict] = {}
    for t in turns:
        if t.side != side or not t.success:
            continue
        for tech in attack_map.techniques_for(t.action):
            e = agg.setdefault(tech["id"], {"count": 0, "hosts": set(), "name": tech["name"],
                                            "tactic": tech["tactic"], "stix_id": tech.get("stix_id"),
                                            "first": t.ts, "last": t.ts})
            e["count"] += 1
            e["last"] = t.ts or e["last"]
            if t.args.get("host"):
                e["hosts"].add(t.args["host"])
    return agg


def navigator_layer(turns: list[TurnRecord], seed: int, winner: str | None,
                    reason: str) -> dict:
    """ATT&CK Navigator layer format v4.5 (RED heatmap)."""
    agg = _aggregate(turns, "red")
    techniques = [
        {
            # no "tactic" key: per the layer spec, omitting it applies the annotation
            # to the technique under every tactic it belongs to
            "techniqueID": tid,
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
        "metadata": [{"name": "seed", "value": str(seed)},
                     {"name": "outcome", "value": (winner or "in progress")}],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#14172b",
        "selectTechniquesAcrossTactics": True,
    }


def stix_bundle(turns: list[TurnRecord], seed: int, winner: str | None, reason: str) -> dict:
    """STIX 2.1 bundle: sightings of canonical ATT&CK techniques + mitigation notes + report."""
    now = _now()
    org = {
        "type": "identity", "spec_version": "2.1",
        "id": f"identity--{uuid.uuid5(_NS, 'organisation/sakura-logistics')}",
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": "Sakura Logistics K.K. (simulated)", "identity_class": "organization",
        "sectors": ["transportation"],
    }
    tool = {
        "type": "identity", "spec_version": "2.1",
        "id": f"identity--{uuid.uuid5(_NS, 'tool/ai-wargame')}",
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": "AI Wargame", "identity_class": "system",
        "description": "Autonomous red-vs-blue cyber wargame simulation (no real systems involved).",
    }
    objects: list[dict] = [org, tool]
    match_ref = {"source_name": "ai-wargame",
                 "description": f"Match seed {seed}; outcome {winner or 'in progress'}: {reason}"}

    for tid, e in sorted(_aggregate(turns, "red").items()):
        if not e["stix_id"]:
            continue
        s = {
            "type": "sighting", "spec_version": "2.1",
            "id": f"sighting--{uuid.uuid4()}", "created": now, "modified": now,
            "created_by_ref": tool["id"],
            "sighting_of_ref": e["stix_id"],
            "where_sighted_refs": [org["id"]],
            "count": e["count"],
            "description": f"{tid} {e['name']} observed {e['count']}x; "
                           f"targets: {', '.join(sorted(e['hosts'])) or '-'}.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid,
                 "url": attack_map.technique_url(tid)}, match_ref],
        }
        if e["first"] and e["last"]:
            s["first_seen"], s["last_seen"] = e["first"], e["last"]
        objects.append(s)

    for mid, e in sorted(_aggregate(turns, "blue").items()):
        if not e["stix_id"]:
            continue
        objects.append({
            "type": "note", "spec_version": "2.1",
            "id": f"note--{uuid.uuid4()}", "created": now, "modified": now,
            "created_by_ref": tool["id"],
            "abstract": f"Defender applied {mid} {e['name']} ({e['count']}x)",
            "content": f"BLUE applied mitigation {mid} {e['name']} {e['count']} time(s); "
                       f"hosts: {', '.join(sorted(e['hosts'])) or '-'}.",
            "object_refs": [e["stix_id"]],
            "external_references": [{"source_name": "mitre-attack", "external_id": mid,
                                     "url": attack_map.technique_url(mid)}],
        })

    objects.append({
        "type": "report", "spec_version": "2.1",
        "id": f"report--{uuid.uuid4()}", "created": now, "modified": now,
        "created_by_ref": tool["id"],
        "name": f"AI Wargame match — seed {seed}",
        "description": f"Winner: {(winner or 'in progress').upper()}. {reason}. "
                       f"{len(turns)} actions recorded.",
        "report_types": ["attack-pattern", "threat-actor"],
        "published": now,
        "object_refs": [o["id"] for o in objects],
    })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
