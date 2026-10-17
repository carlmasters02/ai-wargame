"""Scenario library — preset starting conditions for a match.

A scenario shapes the opening: the attacker's persona, a pre-existing foothold or
stolen credential, a planted zero-day, a misconfigured asset. Each is a realistic
incident archetype a SOC trains against, and makes the demo tell a specific story
instead of always starting from a clean perimeter.

Each scenario's `apply(engine)` runs right after the network loads and mutates the
live game state. Deterministic given the seed. `baseline` is the default (no change).
"""
from __future__ import annotations

from .models import Vuln


def _first(engine, pred):
    return next((h for h in engine.hosts.values() if pred(h)), None)


def _apply_baseline(engine):
    return "standard patient-APT intrusion from the perimeter"


def _apply_ransomware(engine):
    engine.red_persona = "ransomware"
    if engine.agents.get("red"):
        engine.agents["red"].set_persona("ransomware")
    # a noisy crew already has a toehold in the DMZ (phished/exploited their way in)
    h = _first(engine, lambda h: h.zone == "dmz" and h.kind in ("webserver", "appserver"))
    if h:
        engine._compromise(h.id)
    return "fast, loud ransomware crew with an initial DMZ foothold"


def _apply_insider(engine):
    # a disgruntled insider handed the attacker a privileged credential
    cred = next((c for c in engine.creds.values()
                 if engine.users[c.owner].privileged and not c.rotated), None)
    if cred:
        cred.stolen = True
    return "malicious insider has leaked a privileged credential to the attacker"


def _apply_zero_day(engine, count=2):
    # a wave of fresh zero-days drops before the game — nothing is patched for them
    planted = []
    for _ in range(count):
        cands = [h for h in engine.hosts.values()
                 if h.zone in ("corp", "servers") and not h.honeypot and not h.isolated
                 and not any(v.zero_day for v in engine._host_vulns(h.id))]
        if not cands:
            break
        h = engine.rng.choice(cands)
        engine._zd_count += 1
        vid = f"V-0DAY-{engine._zd_count:02d}"
        v = Vuln(id=vid, host=h.id, cve_label="CVE-2026-1337",
                 name="ZERO-DAY: SakuraRPC pre-auth RCE", severity=10,
                 exploitability=0.9, noise=0.08, zero_day=True)
        engine.vulns[vid] = v
        if h.discovered:
            h.vulns_revealed = True
        planted.append(h.id)
    return f"zero-day storm: unpatchable pre-auth RCE on {', '.join(planted) or 'no eligible host'}"


def _apply_cloud(engine):
    # a public-facing cloud bucket is misconfigured and already exposed
    h = _first(engine, lambda h: h.kind == "cloud_bucket")
    if h is None:
        h = _first(engine, lambda h: h.zone == "servers" and h.kind in ("fileserver", "database"))
    if h:
        h.discovered = True
        h.vulns_revealed = True
        engine._zd_count += 1
        vid = f"V-CLOUD-{engine._zd_count:02d}"
        engine.vulns[vid] = Vuln(id=vid, host=h.id, cve_label="CWE-284",
                                 name="Public cloud bucket — improper access control",
                                 severity=9, exploitability=0.9, noise=0.1)
        return f"misconfigured, internet-exposed data store on {h.id}"
    return "no cloud asset in this network — playing baseline"


def _apply_supply_chain(engine):
    # a trusted internal system (backup/update infra) shipped compromised
    h = _first(engine, lambda h: h.kind in ("backup",) and h.zone == "servers")
    if h is None:
        h = _first(engine, lambda h: h.kind == "fileserver")
    if h:
        engine._compromise(h.id)
        h.beacon = True
        return f"supply-chain compromise: trusted system {h.id} shipped with a backdoor"
    return "no suitable trusted system — playing baseline"


SCENARIOS: dict[str, dict] = {
    "baseline": {"label": "🎯 Baseline APT", "apply": _apply_baseline,
                 "desc": "Patient attacker from the perimeter (default)."},
    "ransomware": {"label": "🔥 Ransomware outbreak", "apply": _apply_ransomware,
                   "desc": "Fast, loud crew with a DMZ foothold."},
    "insider": {"label": "🕴 Insider threat", "apply": _apply_insider,
                "desc": "A leaked privileged credential."},
    "zero_day": {"label": "💥 Zero-day storm", "apply": _apply_zero_day,
                 "desc": "Unpatchable pre-auth RCEs planted inside."},
    "cloud_exposure": {"label": "☁ Cloud exposure", "apply": _apply_cloud,
                       "desc": "A misconfigured, internet-exposed data store."},
    "supply_chain": {"label": "📦 Supply-chain compromise", "apply": _apply_supply_chain,
                     "desc": "A trusted internal system ships backdoored."},
}


def apply(engine, name: str) -> str:
    """Apply a scenario to the freshly loaded engine state. Returns a narration."""
    spec = SCENARIOS.get(name) or SCENARIOS["baseline"]
    return spec["apply"](engine)
