"""LLM agent layer: persona prompts, strict JSON contract, repair ladder,
and deterministic heuristic fallback policies (also used by the smoke test).

Contract: the engine hands the model a numbered list of concrete legal actions;
the model answers with {"thought": str, "action_index": N} (RED) or
{"thought": str, "action_indices": [N, M]} (BLUE). Picking by index kills the
whole class of invalid-args failures.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re

from .models import ActionSpec

log = logging.getLogger("agents")

RED_SYSTEM = """You are RED, a patient APT operator infiltrating Sakura Logistics K.K., a Tokyo logistics company. Objective: exfiltrate the CrownJewel database (SKR-DB-PROD).

Rules:
- You receive your network view (JSON), stolen credentials, and a numbered list of legal actions. Pick exactly ONE by index.
- You only see discovered hosts. New neighbors become visible when you compromise a host, but their vulns stay hidden until you SCAN from an owned neighbor.
- Every action may raise a defender alert with probability = its noise. SCAN and LATERAL_MOVE are quiet; EXPLOIT noise depends on the vuln. Quiet is survival: if the defender isolates your host, you lose it.
- Prefer LATERAL_MOVE with stolen credentials over EXPLOIT. HARVEST_CREDS on owned hosts unlocks lateral paths. Servers and the domain controller hold the best creds. PHISH_USER can steal a user's creds from afar when you can't reach the host storing them.
- C2_BEACON plants persistence on an owned host: the next ISOLATE on it fails unless the defender investigated first. Plant beacons on your most valuable footholds.
- DEFENSE_EVASION wipes logs on an owned host: future actions involving it are much harder to detect. Use before loud moves (EXFILTRATE, HARVEST_CREDS).
- Vuln tags show real-world intel: EPSS = exploit probability, CISA-KEV = actively exploited in the wild.
- If the CrownJewel is owned, EXFILTRATE immediately.
- Beware suspiciously easy, high-value-looking hosts: they may be honeypots.

Respond with ONLY JSON: {"thought": "<=60 words", "action_index": N}"""

PERSONAS = {
    "apt": {"label": "Patient APT",
            "addon": ""},
    "ransomware": {"label": "Ransomware crew",
                   "addon": "\nPersona: you are a ransomware crew — fast and loud. Prefer EXPLOIT "
                            "over slow credential play, aim for high-criticality hosts, and "
                            "EXFILTRATE the moment you can. Never SCAN when a decent EXPLOIT is "
                            "available. Beacons and evasion are a waste of your time."},
    "ghost": {"label": "Ghost (max stealth)",
              "addon": "\nPersona: you are obsessively stealthy. Never take a noisy action "
                       "(EXPLOIT, HARVEST_CREDS, EXFILTRATE) on or from a host without "
                       "DEFENSE_EVASION first. Plant a C2_BEACON on every owned server. Prefer "
                       "SCAN and credential paths over brute-force exploitation."},
}


def build_system(side: str, persona: str = "apt") -> str:
    if side == "red":
        p = PERSONAS.get(persona, PERSONAS["apt"])
        return RED_SYSTEM + p["addon"]
    return BLUE_SYSTEM

BLUE_SYSTEM = """You are BLUE, SOC lead defending Sakura Logistics K.K. An APT is probing your network. Objective: keep the CrownJewel (SKR-DB-PROD) safe for all rounds, or fully evict the attacker.

Rules:
- You receive the full topology, unpatched vulns, your recent alert queue (with confidence), and a numbered legal-action list. You have 2 action points: return TWO different indices.
- You CANNOT see the attacker. ~15% of alerts are false positives. INVESTIGATE a host to learn the truth before isolating anything critical.
- ISOLATE evicts the attacker but costs business impact = criticality (x2 for servers/restricted zones). Never casually isolate the CrownJewel or domain controllers. The perimeter firewall CANNOT be isolated (company policy — it would take the business offline); defend it with PATCH + INVESTIGATE.
- PATCH kills a vuln forever, but change windows are limited: MAX ONE PATCH PER TURN (a second patch in the same turn fails). Spend your other action point on INVESTIGATE, ISOLATE, ROTATE_CREDS or DEPLOY_HONEYPOT.
- ROTATE_CREDS invalidates stolen credentials — rotate privileged users when alerts point near their assets.
- DEPLOY_HONEYPOT near the CrownJewel or DC gives a guaranteed high-confidence alert when touched.
- THREAT_HUNT sweeps an entire zone at once: reveals true compromise status of every un-investigated host there and burns hidden C2 beacons (attacker persistence that makes ISOLATE fail).
- If an ISOLATE reports a hidden C2 beacon re-established the foothold, INVESTIGATE that host to burn the beacon before isolating again.
- Think like the attacker: defend the shortest unpatched path to the CrownJewel first.

Respond with ONLY JSON: {"thought": "<=60 words", "action_indices": [N, M]}"""


def extract_json(text: str) -> dict:
    """Robustly pull the first JSON object out of LLM output."""
    text = text.strip()
    text = re.sub(r"^```(json)?|```$", "", text, flags=re.MULTILINE).strip()
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object found")
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(text[start:], start):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced braces")


class Agent:
    def __init__(self, side: str, model: str, settings, persona: str = "apt"):
        from openai import AsyncOpenAI

        self.side = side
        self.model = model
        self.persona = persona
        self.client = AsyncOpenAI(base_url=settings.AIAND_BASE_URL,
                                  api_key=settings.AIAND_API_KEY,
                                  timeout=20.0, max_retries=0)
        self.system = build_system(side, persona)
        self.temperature = 0.6 if side == "red" else 0.3

    def set_persona(self, persona: str):
        self.persona = persona
        self.system = build_system(self.side, persona)

    async def choose(self, engine, obs: dict, legal: list[ActionSpec], n_actions: int):
        """Returns (chosen ActionSpecs, thought, used_fallback)."""
        user_msg = json.dumps({
            "observation": obs,
            "legal_actions": [{"index": a.index, "description": a.description} for a in legal],
            "instruction": (f"Pick {'ONE action_index' if n_actions == 1 else 'TWO distinct action_indices'} "
                            f"from legal_actions. JSON only."),
        }, ensure_ascii=False)
        for attempt in range(2):
            try:
                return await asyncio.wait_for(self._call(user_msg, legal, n_actions), timeout=25)
            except Exception as e:  # noqa: BLE001
                log.warning("%s agent attempt %d failed: %s", self.side, attempt + 1, e)
        chosen = heuristic_choose(engine, self.side, legal, n_actions)
        return chosen, "[fallback: LLM unavailable — heuristic policy]", True

    async def _call(self, user_msg: str, legal: list[ActionSpec], n_actions: int):
        try:
            resp = await self.client.chat.completions.create(
                model=self.model, temperature=self.temperature, max_tokens=2000,
                messages=[{"role": "system", "content": self.system},
                          {"role": "user", "content": user_msg}],
                response_format={"type": "json_object"})
        except Exception:
            resp = await self.client.chat.completions.create(
                model=self.model, temperature=self.temperature, max_tokens=2000,
                messages=[{"role": "system", "content": self.system},
                          {"role": "user", "content": user_msg}])
        msg = resp.choices[0].message
        text = msg.content or ""
        if not text.strip():
            # heavy-reasoning models may put the decision in the reasoning trace
            text = getattr(msg, "reasoning_content", None) or ""
        data = extract_json(text)
        thought = str(data.get("thought", ""))[:400]
        raw = data.get("action_indices" if n_actions > 1 else "action_index")
        if isinstance(raw, int):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            raise ValueError("missing action index")
        by_index = {a.index: a for a in legal}
        picked: list[ActionSpec] = []
        for r in raw:
            r = max(0, min(int(r), len(legal) - 1))  # clamp (repair)
            a = by_index.get(r)
            if a and a not in picked:
                picked.append(a)
            if len(picked) == n_actions:
                break
        if not picked:
            raise ValueError("no valid action index")
        return picked, thought, False


# ------------------------------------------------------- heuristic policies

def heuristic_choose(engine, side: str, legal: list[ActionSpec], n_actions: int) -> list[ActionSpec]:
    return _heuristic_red(engine, legal) if side == "red" else _heuristic_blue(engine, legal)


def _zone(engine, hid: str) -> int:
    from .engine import ZONE_RANK
    return ZONE_RANK.get(engine.hosts[hid].zone, 0)


def _heuristic_red(engine, legal: list[ActionSpec]) -> list[ActionSpec]:
    if not legal:
        return []
    for a in legal:
        if a.action == "EXFILTRATE":
            return [a]
    lat = [a for a in legal if a.action == "LATERAL_MOVE"]
    if lat:
        return [max(lat, key=lambda a: (_zone(engine, a.args["host"]),
                                        engine.hosts[a.args["host"]].criticality))]
    harv = [a for a in legal if a.action == "HARVEST_CREDS"]
    if harv:
        return [max(harv, key=lambda a: engine.hosts[a.args["host"]].criticality)]
    exp = [a for a in legal if a.action == "EXPLOIT"]
    if exp:
        def k(a):
            v = engine.vulns[a.args["vuln"]]
            return (_zone(engine, a.args["host"]), v.exploitability, -v.noise)
        return [max(exp, key=k)]
    # phish privileged users when no exploit is on the table
    phish = [a for a in legal if a.action == "PHISH_USER" and "PRIVILEGED" in a.description]
    if phish and engine.rng.random() < 0.6:
        return [phish[0]]
    scans = [a for a in legal if a.action == "SCAN"]
    if scans:
        def sk(a):
            zones = [_zone(engine, n) for n in engine._neighbors(a.args["host"])
                     if not engine.hosts[n].vulns_revealed]
            return max(zones or [0])
        return [max(scans, key=sk)]
    # quiet turns: dig in — beacon the most valuable foothold, else wipe logs
    beac = [a for a in legal if a.action == "C2_BEACON"]
    if beac:
        return [max(beac, key=lambda a: engine.hosts[a.args["host"]].criticality)]
    ev = [a for a in legal if a.action == "DEFENSE_EVASION"]
    if ev:
        return [max(ev, key=lambda a: engine.hosts[a.args["host"]].criticality)]
    return [legal[0]]


def _heuristic_blue(engine, legal: list[ActionSpec]) -> list[ActionSpec]:
    picks: list[ActionSpec] = []

    def add(a):
        if a and all(p.description != a.description for p in picks) and len(picks) < 2:
            if a.action == "PATCH" and any(p.action == "PATCH" for p in picks):
                return  # one patch per turn
            picks.append(a)

    # 1. confirmed compromised -> isolate (cheap hosts) or patch (critical hosts)
    for h in engine.hosts.values():
        if h.investigated and h.compromised and not h.isolated:
            if h.criticality < 9:
                add(next((a for a in legal if a.action == "ISOLATE" and a.args["host"] == h.id), None))
            else:
                add(max((a for a in legal if a.action == "PATCH" and a.args["host"] == h.id),
                        key=lambda a: engine.vulns[a.args["vuln"]].severity, default=None))
    # 2. investigate highest-confidence alerted host
    for al in sorted(engine.alerts, key=lambda a: -a.confidence):
        if len(picks) >= 2:
            break
        add(next((a for a in legal if a.action == "INVESTIGATE" and a.args["host"] == al.host), None))
    # 3. patch highest-severity vuln on an alerted host
    alerted = {a.host for a in engine.alerts}
    add(max((a for a in legal if a.action == "PATCH" and a.args["host"] in alerted),
            key=lambda a: engine.vulns[a.args["vuln"]].severity, default=None))
    # 4. rotate a privileged user
    add(next((a for a in legal if a.action == "ROTATE_CREDS" and "PRIVILEGED" in a.description), None))
    # 5. early game: honeypot near the crown jewel
    if engine.round <= 4:
        add(next((a for a in legal if a.action == "DEPLOY_HONEYPOT"
                  and a.args["host"] == engine.cj), None))
    # 6. otherwise patch the global worst vuln on INTERNAL hosts first
    #    (internet-facing kit needs change control — defense in depth)
    if len(picks) < 2:
        internal = [a for a in legal if a.action == "PATCH"
                    and engine.hosts[a.args["host"]].zone in ("corp", "servers", "restricted")]
        add(internal[0] if internal else next((a for a in legal if a.action == "PATCH"), None))
    # 7. reactive hunting: sweep the zone of the highest-confidence alert, sometimes
    if len(picks) < 2 and engine.alerts and engine.rng.random() < 0.5:
        alert_zones = {engine.hosts[a.host].zone for a in engine.alerts
                       if a.host in engine.hosts}
        hunts = [a for a in legal if a.action == "THREAT_HUNT"
                 and a.args["zone"] in alert_zones]
        if hunts:
            depth = {"restricted": 4, "servers": 3, "corp": 2, "dmz": 1}
            add(max(hunts, key=lambda a: depth.get(a.args["zone"], 0)))
    if len(picks) < 2 and legal:
        add(legal[0])
    return picks
