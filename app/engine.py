"""Game engine — the single source of truth.

LLMs never touch the database. Each turn the engine builds the observation,
enumerates concrete legal actions, asks the agent to pick by index, validates,
resolves with seeded dice, mutates state, mirrors to Neo4j, logs a Turn node,
and emits WebSocket events.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
from collections import deque

from . import attack_map, generator, intel, queries
from .models import ActionSpec, Alert, Credential, GraphSpec, Host, TurnRecord, Vuln
from .paths import count_viable_paths

log = logging.getLogger("engine")

ZONE_RANK = {"internet": 0, "dmz": 1, "corp": 2, "servers": 3, "restricted": 4}

NOISE = {"SCAN": 0.15, "HARVEST_CREDS": 0.4, "LATERAL_MOVE": 0.2, "EXFILTRATE": 0.8,
         "PHISH_USER": 0.3, "C2_BEACON": 0.25, "DEFENSE_EVASION": 0.1}
EVASION_FACTOR = 0.4  # DEFENSE_EVASION multiplies future detection noise on that host
FALSE_POSITIVE_RATE = 0.15
MAX_HONEYPOTS = 3
ALERT_WINDOW = 8


class GameEngine:
    def __init__(self, settings, bus, mirror):
        self.s = settings
        self.bus = bus
        self.mirror = mirror
        self.state = "idle"  # idle|running|paused|game_over
        self.speed = 1.0
        self.turn_delay = 3.0
        self.reports_enabled = True  # headless benchmarks set False (skip LLM report)
        self.command_queue: asyncio.Queue = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._step = False
        self.agents = {"red": None, "blue": None}  # None -> heuristic policy
        self._clear()

    # ------------------------------------------------------------- state
    def _clear(self):
        self.spec: GraphSpec | None = None
        self.hosts: dict[str, Host] = {}
        self.edges: list = []
        self.adj: dict[str, list] = {}
        self.vulns: dict[str, Vuln] = {}
        self.creds: dict[str, Credential] = {}
        self.users: dict = {}
        self.cj: str = ""
        self.round = 1
        self.action_n = 0
        self.alerts: deque[Alert] = deque(maxlen=ALERT_WINDOW)
        self.all_alerts: list[Alert] = []
        self.turns: list[TurnRecord] = []
        self.metrics_history: list[dict] = []
        self.impact = 0.0
        self.ever_compromised = False
        self.honeypot_count = 0
        self.winner: str | None = None
        self.win_reason = ""
        self._patch_used_this_turn = False
        self.evasion: set[str] = set()  # hosts where RED wiped logs (detection noise reduced)
        self.red_persona = "apt"
        self.rng = random.Random(0)

    def load_spec(self, spec: GraphSpec):
        self._clear()
        self.spec = spec
        self.hosts = {h.id: h.model_copy() for h in spec.hosts}
        self.edges = [e.model_copy() for e in spec.edges]
        self.vulns = {v.id: v.model_copy() for v in spec.vulns}
        self.creds = {c.id: c.model_copy() for c in spec.creds}
        self.users = {u.id: u for u in spec.users}
        self.cj = spec.crown_jewel
        self.rng = random.Random(spec.seed)
        self.adj = {}
        for e in self.edges:
            self.adj.setdefault(e.src, []).append(e)

    # ------------------------------------------------------------ helpers
    def _neighbors(self, hid: str) -> list[str]:
        return [e.dst for e in self.adj.get(hid, [])
                if not e.blocked and not self.hosts[e.dst].isolated]

    def _host_vulns(self, hid: str) -> list[Vuln]:
        return [v for v in self.vulns.values() if v.host == hid]

    def _controlled(self, include_internet=True) -> list[Host]:
        return [h for h in self.hosts.values()
                if h.compromised and (include_internet or h.kind != "internet")]

    def _reachable_from_controlled(self) -> set[str]:
        reach = set()
        for h in self._controlled():
            reach.update(self._neighbors(h.id))
        return reach

    # -------------------------------------------------------- graph mirror
    async def reset(self, seed: int):
        await self.stop()
        spec, used_seed = generator.generate_with_guarantee(seed)
        self.load_spec(spec)
        if self.mirror.enabled:
            m = self.mirror
            m.write_blocking(queries.WIPE)
            m.write_blocking(queries.WRITE_HOSTS,
                             rows=[{"id": h.id, "props": h.model_dump()} for h in spec.hosts])
            m.write_blocking(queries.SET_CROWN_JEWEL, id=spec.crown_jewel)
            m.write_blocking(queries.WRITE_EDGES, rows=[e.model_dump() for e in spec.edges])
            m.write_blocking(queries.WRITE_VULNS,
                             rows=[{"host": v.host, "id": v.id,
                                    "props": v.model_dump(exclude={"host", "id"})} for v in spec.vulns])
            m.write_blocking(queries.WRITE_USERS,
                             rows=[{"id": u.id, "props": u.model_dump(exclude={"id"})} for u in spec.users])
            m.write_blocking(queries.WRITE_CREDS,
                             rows=[c.model_dump() | {"props": c.model_dump(
                                 exclude={"id", "stored_on", "grants", "owner"})} for c in spec.creds])
            m.write_blocking(queries.WRITE_ADMIN_OF,
                             rows=[{"u": u, "h": h} for u, h in generator.ADMIN_OF])
        self.bus.start_recording(tag=f"seed{used_seed}")
        await self._emit_snapshot()
        await self._emit_metrics()
        log.info("game reset with seed %d (%d hosts)", used_seed, len(self.hosts))

    def snapshot(self) -> dict:
        return {
            "nodes": [
                {"id": h.id, "name": h.name, "kind": h.kind, "zone": h.zone,
                 "os": h.os, "criticality": h.criticality, "compromised": h.compromised,
                 "isolated": h.isolated, "honeypot": h.honeypot,
                 "discovered": h.discovered, "crown": h.id == self.cj,
                 "beacon": h.beacon,
                 "vulns": [{"id": v.id, "cve": v.cve_label, "name": v.name, "sev": v.severity,
                            "patched": v.patched, "zero_day": v.zero_day,
                            "epss": v.epss, "kev": v.kev}
                           for v in self._host_vulns(h.id)]}
                for h in self.hosts.values()
            ],
            "links": [{"source": e.src, "target": e.dst, "port": e.port,
                       "protocol": e.protocol, "blocked": e.blocked} for e in self.edges],
            "crown_jewel": self.cj,
            "seed": self.spec.seed if self.spec else 0,
            "max_rounds": self.s.MAX_TURNS,
        }

    async def _emit_snapshot(self):
        await self.bus.emit("graph_snapshot", self.snapshot())

    async def _emit_patch(self, node_ids: set[str] | None = None,
                          new_nodes: list | None = None, new_links: list | None = None):
        payload = {"nodes": [], "links": [], "new_nodes": new_nodes or [], "new_links": new_links or []}
        for hid in (node_ids or set()):
            h = self.hosts.get(hid)
            if h:
                payload["nodes"].append(
                    {"id": h.id, "compromised": h.compromised, "isolated": h.isolated,
                     "honeypot": h.honeypot, "discovered": h.discovered,
                     "investigated": h.investigated, "beacon": h.beacon})
        payload["links"] = [{"source": e.src, "target": e.dst, "blocked": e.blocked}
                            for e in self.edges if e.blocked]
        if payload["nodes"] or payload["links"] or new_nodes or new_links:
            await self.bus.emit("graph_patch", payload)

    # ------------------------------------------------------------- metrics
    def compute_metrics(self) -> dict:
        paths, shortest, capped = count_viable_paths(
            list(self.hosts.values()), self.edges, list(self.vulns.values()),
            list(self.creds.values()), self.cj, maxlen=8, cap=250)
        return {
            "paths": paths, "capped": capped, "shortest_path_ids": shortest,
            "compromised": len(self._controlled(include_internet=False)),
            "impact": round(self.impact, 1), "alerts": len(self.all_alerts),
            "round": self.round, "max_rounds": self.s.MAX_TURNS,
        }

    async def _emit_metrics(self):
        m = self.compute_metrics()
        self.metrics_history.append({"round": m["round"], "paths": m["paths"],
                                     "compromised": m["compromised"], "impact": m["impact"]})
        await self.bus.emit("metrics", m)

    # ------------------------------------------------------------- control
    async def start(self):
        if self.state in ("idle", "game_over") or self._task is None or self._task.done():
            self.state = "running"
            self._task = asyncio.create_task(self._loop())
        else:
            self.state = "running"

    async def stop(self):
        self.state = "idle"
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._task = None

    def pause(self):
        if self.state == "running":
            self.state = "paused"

    def resume(self):
        if self.state == "paused":
            self.state = "running"

    def step(self):
        if self.state == "paused":
            self._step = True
            self.state = "running"

    def set_speed(self, x: float):
        self.speed = max(0.25, min(8.0, x))

    # -------------------------------------------------------------- loop
    async def _loop(self):
        try:
            while True:
                await self._drain_commands()
                if self.state == "paused":
                    await asyncio.sleep(0.1)
                    continue
                if self.state != "running":
                    break
                if self.round > self.s.MAX_TURNS:
                    await self._game_over("blue", f"{self.s.MAX_TURNS} rounds survived — BLUE held the line")
                    break
                await self._play_side("red")
                if self.winner:
                    break
                await self._between_turns()
                if self.state != "running":
                    continue
                await self._play_side("blue")
                if self.winner:
                    break
                self.round += 1
                await self._between_turns()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("game loop crashed")
            await self.bus.emit("error", {"message": "game loop error — see server log"})
        finally:
            self.state = "game_over" if self.winner else self.state

    async def _between_turns(self):
        if self._step:
            self._step = False
            self.state = "paused"
            return
        delay = self.turn_delay / self.speed
        end = delay
        while end > 0:
            if self.state != "running":
                return
            await asyncio.sleep(min(0.2, end))
            end -= 0.2
            await self._drain_commands()

    async def _drain_commands(self):
        while not self.command_queue.empty():
            cmd, kw = self.command_queue.get_nowait()
            try:
                if cmd == "zero_day":
                    await self._inject_zero_day()
                elif cmd == "insider":
                    await self._insider_threat()
                elif cmd == "model_swap":
                    agent = self.agents.get(kw["side"])
                    if agent:
                        agent.model = kw["model"]
                        await self.bus.emit("intervention",
                                            {"kind": "model_swap",
                                             "narration": f"{kw['side'].upper()} now runs on {kw['model']}"})
                elif cmd == "persona":
                    from .agents import PERSONAS
                    p = kw["persona"]
                    self.red_persona = p
                    agent = self.agents.get("red")
                    if agent:
                        agent.set_persona(p)
                    await self.bus.emit("intervention",
                                        {"kind": "persona",
                                         "narration": f"RED persona → "
                                                      f"{PERSONAS.get(p, {}).get('label', p)}"})
            except Exception:  # noqa: BLE001
                log.exception("command %s failed", cmd)

    # ---------------------------------------------------------- turn flow
    async def _play_side(self, side: str):
        from . import agents as agent_mod  # local import: no cycle

        self._patch_used_this_turn = False

        await self.bus.emit("turn_start", {"side": side, "round": self.round,
                                           "max_rounds": self.s.MAX_TURNS})
        legal = self.legal_red() if side == "red" else self.legal_blue()
        if not legal:
            await self.bus.emit("action_result", {
                "side": side, "action": "PASS", "args": {}, "success": True,
                "narration": f"{side.upper()} has no legal moves — passes.", "round": self.round})
            return
        n_actions = 1 if side == "red" else 2
        obs = self.build_observation(side)
        agent = self.agents[side]
        if agent is not None:
            chosen, thought, fallback = await agent.choose(self, obs, legal, n_actions)
        else:
            chosen = agent_mod.heuristic_choose(self, side, legal, n_actions)
            thought = "[heuristic policy — no LLM key configured]"
            fallback = True
        await self.bus.emit("agent_thought", {
            "side": side, "text": thought, "fallback": fallback,
            "model": agent.model if agent else "heuristic", "round": self.round})

        for spec in chosen:
            rec = await (self._resolve_red(spec) if side == "red" else self._resolve_blue(spec))
            await self.bus.emit("action_result", {
                "side": side, "action": rec.action, "args": rec.args, "success": rec.success,
                "narration": rec.narration, "round": self.round,
                "techniques": attack_map.techniques_for(rec.action)})
            await self._log_turn(rec)
            await self._emit_metrics()
            if self.winner:
                return
        if side == "blue":
            self._maybe_false_positive()
            self._check_eviction()

    async def _log_turn(self, rec: TurnRecord):
        self.turns.append(rec)
        self.mirror.write(queries.LOG_TURN, n=rec.n, round=rec.round, side=rec.side,
                          action=rec.action, args=json.dumps(rec.args), success=rec.success,
                          narration=rec.narration, thought=rec.thought, fallback=rec.fallback,
                          target=rec.args.get("host"))

    def _new_record(self, side, action, args) -> TurnRecord:
        self.action_n += 1
        return TurnRecord(n=self.action_n, round=self.round, side=side,
                          action=action, args=args, success=False,
                          techniques=[t["id"] for t in attack_map.techniques_for(action)])

    # ------------------------------------------------------- legal actions
    def legal_red(self) -> list[ActionSpec]:
        acts: list[ActionSpec] = []
        cj = self.hosts[self.cj]
        if cj.compromised:
            acts.append(ActionSpec(
                action="EXFILTRATE", args={"host": self.cj},
                description=f"EXFILTRATE the crown jewel {self.cj} — WIN THE GAME NOW"))
        reach = self._reachable_from_controlled()
        for hid in sorted(reach):
            t = self.hosts[hid]
            if t.compromised or t.isolated or not t.vulns_revealed:
                continue
            for v in self._host_vulns(hid):
                if not v.patched:
                    acts.append(ActionSpec(
                        action="EXPLOIT", args={"host": hid, "vuln": v.id},
                        description=f"EXPLOIT {hid} ({t.kind}/{t.zone}, crit {t.criticality}) via "
                                    f"{v.cve_label} {v.name} (sev {v.severity}, "
                                    f"exploit {v.exploitability}, noise {v.noise}){intel.tag(v)}"))
        for c in self.creds.values():
            t = self.hosts[c.grants]
            if c.stolen and not c.rotated and not t.compromised and not t.isolated \
                    and c.grants in reach and t.discovered:
                acts.append(ActionSpec(
                    action="LATERAL_MOVE", args={"host": c.grants, "cred": c.id},
                    description=f"LATERAL_MOVE to {c.grants} ({t.kind}/{t.zone}, crit {t.criticality}) "
                                f"with stolen {c.kind} of {self.users[c.owner].name} "
                                f"(quiet, always succeeds)"))
        for h in self._controlled(include_internet=False):
            unstolen = [c for c in self.creds.values() if c.stored_on == h.id and not c.stolen]
            if unstolen:
                grants = ", ".join(sorted({c.grants for c in unstolen}))
                acts.append(ActionSpec(
                    action="HARVEST_CREDS", args={"host": h.id},
                    description=f"HARVEST_CREDS on {h.id} — {len(unstolen)} credential(s) "
                                f"stored here (grant access to: {grants})"))
        for h in self._controlled():
            unrevealed = [n for n in self._neighbors(h.id) if not self.hosts[n].vulns_revealed]
            if unrevealed:
                acts.append(ActionSpec(
                    action="SCAN", args={"host": h.id},
                    description=f"SCAN from {h.id} — fingerprint vulns on ALL known hosts "
                                f"(new: {', '.join(sorted(unrevealed))}) (low noise)"))
        # PHISH_USER: target users whose creds sit on a discovered host
        for u in self.users.values():
            pending = [c for c in self.creds.values()
                       if c.owner == u.id and not c.stolen and not c.rotated
                       and self.hosts[c.stored_on].discovered]
            if pending:
                chance = 0.45 if u.privileged else 0.7
                acts.append(ActionSpec(
                    action="PHISH_USER", args={"user": u.id},
                    description=f"PHISH_USER {u.name} ({u.role}{' PRIVILEGED' if u.privileged else ''}) "
                                f"— targeted phishing, ~{chance:.0%} success, steals {len(pending)} "
                                f"cred(s) wherever stored (grants: "
                                f"{', '.join(sorted({c.grants for c in pending}))})"))
        # C2_BEACON: persistence on an owned host (survives one ISOLATE unless investigated)
        for h in self._controlled(include_internet=False):
            if not h.beacon:
                acts.append(ActionSpec(
                    action="C2_BEACON", args={"host": h.id},
                    description=f"C2_BEACON on {h.id} — plant persistence: the next ISOLATE fails "
                                f"to evict unless BLUE investigates this host first"))
        # DEFENSE_EVASION: wipe logs on an owned host (future detection noise ×0.4)
        for h in self._controlled(include_internet=False):
            if h.id not in self.evasion:
                acts.append(ActionSpec(
                    action="DEFENSE_EVASION", args={"host": h.id},
                    description=f"DEFENSE_EVASION on {h.id} — wipe logs/artifacts: future actions "
                                f"involving this host are much harder to detect"))
        for i, a in enumerate(acts):
            a.index = i
        return acts

    def legal_blue(self) -> list[ActionSpec]:
        acts: list[ActionSpec] = []
        # PATCH: top 12 unpatched by severity
        unpatched = sorted((v for v in self.vulns.values() if not v.patched),
                           key=lambda v: -v.severity)[:12]
        for v in unpatched:
            acts.append(ActionSpec(
                action="PATCH", args={"vuln": v.id, "host": v.host},
                description=f"PATCH {v.cve_label} on {v.host} (sev {v.severity}, {v.name}){intel.tag(v)}"))
        # ISOLATE: alerted or confirmed-compromised hosts
        flagged = {a.host for a in self.alerts}
        flagged |= {h.id for h in self.hosts.values() if h.investigated and h.compromised}
        for hid in sorted(flagged):
            h = self.hosts[hid]
            if h.isolated or h.kind in ("internet", "firewall") or h.honeypot:
                continue  # policy: isolating the perimeter firewall takes the company offline
            cost = self._isolate_cost(h)
            acts.append(ActionSpec(
                action="ISOLATE", args={"host": hid},
                description=f"ISOLATE {hid} ({h.kind}/{h.zone}, crit {h.criticality}) — "
                            f"evicts attacker, business impact +{cost}"))
        # ROTATE: users with unrotated creds, privileged first
        for u in sorted(self.users.values(), key=lambda u: not u.privileged):
            if any(c.owner == u.id and not c.rotated for c in self.creds.values()):
                acts.append(ActionSpec(
                    action="ROTATE_CREDS", args={"user": u.id},
                    description=f"ROTATE_CREDS for {u.name} ({u.role}"
                                f"{' PRIVILEGED' if u.privileged else ''}) — kills stolen creds"))
        # HONEYPOT: near crown jewel, alerted hosts, or high-crit servers
        if self.honeypot_count < MAX_HONEYPOTS:
            spots = [self.cj] + sorted(flagged)[:2] + ["SKR-DC-01", "SKR-DB-01"]
            for hid in dict.fromkeys(spots):
                h = self.hosts.get(hid)
                if not h or h.kind == "internet" or h.honeypot:
                    continue
                if any(self.hosts[n].honeypot for n in self._neighbors(hid)):
                    continue
                acts.append(ActionSpec(
                    action="DEPLOY_HONEYPOT", args={"host": hid},
                    description=f"DEPLOY_HONEYPOT near {hid} ({h.zone}) — "
                                f"guaranteed alert if attacker touches it"))
        # INVESTIGATE: alerted hosts first, then critical
        inv = [a.host for a in sorted(self.alerts, key=lambda a: -a.confidence)]
        inv += [h.id for h in sorted(self.hosts.values(), key=lambda h: -h.criticality)]
        for hid in dict.fromkeys(inv):
            h = self.hosts.get(hid)
            if h and not h.investigated and h.kind != "internet" and not h.honeypot:
                acts.append(ActionSpec(
                    action="INVESTIGATE", args={"host": hid},
                    description=f"INVESTIGATE {hid} ({h.kind}/{h.zone}, crit {h.criticality}) — "
                                f"reveals true compromise status"))
            if len([a for a in acts if a.action == "INVESTIGATE"]) >= 10:
                break
        # THREAT_HUNT: sweep a whole zone — reveals true status + burns C2 beacons
        for zone in ("dmz", "corp", "servers", "restricted"):
            hosts_in_zone = [h for h in self.hosts.values()
                             if h.zone == zone and not h.investigated and h.kind != "internet"]
            if hosts_in_zone:
                acts.append(ActionSpec(
                    action="THREAT_HUNT", args={"zone": zone},
                    description=f"THREAT_HUNT in {zone} zone — sweep {len(hosts_in_zone)} "
                                f"un-investigated host(s): reveals true compromise status "
                                f"and removes hidden C2 beacons"))
        for i, a in enumerate(acts):
            a.index = i
        return acts

    def _isolate_cost(self, h: Host) -> int:
        return h.criticality * (2 if h.zone in ("servers", "restricted") else 1)

    # -------------------------------------------------------- observations
    def build_observation(self, side: str) -> dict:
        return self._obs_red() if side == "red" else self._obs_blue()

    def _obs_red(self) -> dict:
        hosts = []
        for h in self.hosts.values():
            if not h.discovered and not h.compromised:
                continue
            if h.kind == "internet":
                continue
            entry = {"id": h.id, "kind": h.kind, "zone": h.zone,
                     "criticality": h.criticality, "owned": h.compromised,
                     "isolated": h.isolated}
            if h.compromised:
                entry["beacon"] = h.beacon
                entry["evasion"] = h.id in self.evasion
            if h.vulns_revealed or h.compromised:
                entry["vulns"] = [{"id": v.id, "cve": v.cve_label, "sev": v.severity,
                                   "exploit": v.exploitability, "noise": v.noise,
                                   "patched": v.patched, "epss": v.epss, "kev": v.kev}
                                  for v in self._host_vulns(h.id)]
            entry["neighbors"] = [{"id": n, "kind": self.hosts[n].kind, "zone": self.hosts[n].zone}
                                  for n in self._neighbors(h.id) if self.hosts[n].discovered]
            hosts.append(entry)
        stolen = [{"id": c.id, "kind": c.kind, "grants": c.grants, "rotated": c.rotated,
                   "owner": self.users[c.owner].name}
                  for c in self.creds.values() if c.stolen]
        return {"side": "red", "round": self.round,
                "turns_remaining": self.s.MAX_TURNS - self.round + 1,
                "score": self.compute_metrics(),
                "hosts": hosts, "stolen_creds": stolen,
                "hint": "EXPLOIT needs a revealed vuln (SCAN first). "
                        "LATERAL_MOVE needs a stolen unrotated credential."}

    def _obs_blue(self) -> dict:
        hosts = []
        for h in self.hosts.values():
            if h.kind == "internet":
                continue
            entry = {"id": h.id, "kind": h.kind, "zone": h.zone, "os": h.os,
                     "criticality": h.criticality, "isolated": h.isolated,
                     "honeypot": h.honeypot, "investigated": h.investigated,
                     "vulns": [{"id": v.id, "cve": v.cve_label, "sev": v.severity,
                                "patched": v.patched, "epss": v.epss, "kev": v.kev}
                               for v in self._host_vulns(h.id)]}
            if h.investigated:
                entry["confirmed_compromised"] = h.compromised
            hosts.append(entry)
        alerts = [{"round": a.turn, "host": a.host, "kind": a.kind,
                   "confidence": round(a.confidence, 2)}
                  for a in sorted(self.alerts, key=lambda a: -a.confidence)]
        return {"side": "blue", "round": self.round,
                "turns_remaining": self.s.MAX_TURNS - self.round + 1,
                "crown_jewel": self.cj,
                "score": {"paths_to_crown_jewel": self.compute_metrics()["paths"],
                          "business_impact": round(self.impact, 1),
                          "alerts_total": len(self.all_alerts)},
                "hosts": hosts, "alerts": alerts,
                "note": "~15% of alerts are FALSE POSITIVES. INVESTIGATE before you ISOLATE "
                        "critical hosts. You have 2 action points this turn."}

    # ---------------------------------------------------------- resolution
    def _compromise(self, hid: str) -> set[str]:
        """Mark host compromised; auto-discover its neighbors. Returns changed ids."""
        h = self.hosts[hid]
        h.compromised = True
        h.discovered = True
        changed = {hid}
        if h.kind != "internet":
            self.ever_compromised = True
        for n in self._neighbors(hid):
            if not self.hosts[n].discovered:
                self.hosts[n].discovered = True
                changed.add(n)
        return changed

    async def _resolve_red(self, spec: ActionSpec) -> TurnRecord:
        rec = self._new_record("red", spec.action, spec.args)
        changed: set[str] = set()
        noise = 0.0
        target = self.hosts.get(spec.args.get("host", ""))

        if spec.action == "SCAN":
            hid = spec.args["host"]
            rec.success = True
            changed.add(hid)
            revealed = 0
            for nh in self.hosts.values():  # foothold = network-wide fingerprint of known hosts
                if nh.discovered and not nh.vulns_revealed:
                    nh.vulns_revealed = True
                    changed.add(nh.id)
                    revealed += 1
            noise = NOISE["SCAN"]
            rec.narration = (f"RED scans from {hid} — fingerprints vulns on {revealed} known host(s)"
                             if revealed else f"RED scans from {hid} — nothing new to fingerprint")

        elif spec.action == "EXPLOIT":
            v = self.vulns[spec.args["vuln"]]
            hid = spec.args["host"]
            rec.success = self.rng.random() < v.exploitability
            noise = v.noise
            if rec.success:
                changed |= self._compromise(hid)
                rec.narration = (f"RED exploits {v.cve_label} ({v.name}) on {hid} — shell obtained, "
                                 f"neighbors now visible")
            else:
                rec.narration = f"RED's {v.cve_label} exploit against {hid} FAILED — exploit crashed"

        elif spec.action == "HARVEST_CREDS":
            hid = spec.args["host"]
            got = [c for c in self.creds.values() if c.stored_on == hid and not c.stolen]
            for c in got:
                c.stolen = True
                self.mirror.write(queries.SET_CRED, id=c.id, props={"stolen": True})
            rec.success = bool(got)
            noise = NOISE["HARVEST_CREDS"]
            grants = ", ".join(sorted({c.grants for c in got}))
            rec.narration = (f"RED harvests {len(got)} credential(s) from {hid} "
                             f"(grants: {grants})" if got else f"RED finds no credentials on {hid}")

        elif spec.action == "LATERAL_MOVE":
            c = self.creds[spec.args["cred"]]
            hid = spec.args["host"]
            rec.success = True
            noise = NOISE["LATERAL_MOVE"]
            changed |= self._compromise(hid)
            rec.narration = (f"RED pivots to {hid} using stolen {c.kind} of "
                             f"{self.users[c.owner].name} — quiet and clean")

        elif spec.action == "PHISH_USER":
            u = self.users[spec.args["user"]]
            noise = NOISE["PHISH_USER"]
            chance = 0.45 if u.privileged else 0.7
            rec.success = self.rng.random() < chance
            if rec.success:
                got = [c for c in self.creds.values()
                       if c.owner == u.id and not c.stolen and not c.rotated]
                for c in got:
                    c.stolen = True
                    self.mirror.write(queries.SET_CRED, id=c.id, props={"stolen": True})
                grants = ", ".join(sorted({c.grants for c in got}))
                rec.narration = (f"RED's phishing email lands: {u.name} ({u.role}) hands over "
                                 f"{len(got)} credential(s) (grants: {grants})")
            else:
                rec.narration = (f"RED phishes {u.name} ({u.role}) — they report the email "
                                 f"to IT instead. No creds.")
            # phishing flows through the mail gateway: that's where sensors see it
            mail = self.hosts.get("SKR-MAIL-01")
            target = mail if mail and mail.discovered else None

        elif spec.action == "C2_BEACON":
            h = self.hosts[spec.args["host"]]
            h.beacon = True
            changed.add(h.id)
            self.mirror.write(queries.SET_HOST, id=h.id, props={"beacon": True})
            rec.success = True
            noise = NOISE["C2_BEACON"]
            rec.narration = (f"RED plants a C2 beacon on {h.id} — persistence established, "
                             f"will survive an ISOLATE unless investigated")

        elif spec.action == "DEFENSE_EVASION":
            h = self.hosts[spec.args["host"]]
            self.evasion.add(h.id)
            rec.success = True
            noise = NOISE["DEFENSE_EVASION"]
            rec.narration = (f"RED wipes logs and artifacts on {h.id} — "
                             f"future activity there is much harder to detect")

        elif spec.action == "EXFILTRATE":
            rec.success = True
            noise = NOISE["EXFILTRATE"]
            rec.narration = f"RED is EXFILTRATING the crown jewel {self.cj}!"
            await self._game_over("red", f"crown jewel {self.cj} exfiltrated in round {self.round}")

        if target and target.honeypot and spec.action in ("EXPLOIT", "LATERAL_MOVE"):
            await self._raise_alert(target.id, "honeypot", 0.97)
        else:
            await self._roll_detection(target.id if target else "", noise,
                                       spec.action.lower())
        for hid in changed:
            h = self.hosts[hid]
            self.mirror.write(queries.SET_HOST, id=hid,
                              props={"compromised": h.compromised, "discovered": h.discovered,
                                     "vulns_revealed": h.vulns_revealed})
        await self._emit_patch(changed)
        return rec

    async def _resolve_blue(self, spec: ActionSpec) -> TurnRecord:
        rec = self._new_record("blue", spec.action, spec.args)
        changed: set[str] = set()
        rec.success = True

        if spec.action == "PATCH":
            if self._patch_used_this_turn:
                rec.success = False
                rec.narration = "PATCH rejected — change window exhausted (max 1 patch per turn)"
                return rec
            self._patch_used_this_turn = True
            v = self.vulns[spec.args["vuln"]]
            v.patched = True
            self.mirror.write(queries.SET_VULN, id=v.id, props={"patched": True})
            rec.narration = f"BLUE patches {v.cve_label} on {v.host}"

        elif spec.action == "ISOLATE":
            h = self.hosts[spec.args["host"]]
            was_compromised = h.compromised
            cost = self._isolate_cost(h)
            if h.beacon and not h.investigated:
                # hidden C2 beacon re-establishes the foothold: isolation breaks, attacker stays
                h.beacon = False
                self.impact += cost
                changed.add(h.id)
                self.mirror.write(queries.SET_HOST, id=h.id, props={"beacon": False})
                rec.narration = (f"BLUE tries to isolate {h.id} (impact +{cost}) — but a hidden "
                                 f"C2 beacon re-established the attacker's foothold! ISOLATION "
                                 f"FAILED. Investigate the host to burn persistence.")
            else:
                h.isolated = True
                h.compromised = False
                self.impact += cost
                changed.add(h.id)
                for e in self.edges:
                    if e.src == h.id or e.dst == h.id:
                        e.blocked = True
                        self.mirror.write(queries.SET_EDGE_BLOCKED, src=e.src, dst=e.dst,
                                          blocked=True)
                self.mirror.write(queries.SET_HOST, id=h.id,
                                  props={"isolated": True, "compromised": False})
                rec.narration = (f"BLUE isolates {h.id} (impact +{cost})"
                                 + (" — attacker EVICTED from the host" if was_compromised else ""))

        elif spec.action == "ROTATE_CREDS":
            u = self.users[spec.args["user"]]
            n = 0
            for c in self.creds.values():
                if c.owner == u.id and not c.rotated:
                    c.rotated = True
                    n += 1
                    self.mirror.write(queries.SET_CRED, id=c.id, props={"rotated": True})
            rec.narration = f"BLUE rotates {n} credential(s) for {u.name} ({u.role})"

        elif spec.action == "DEPLOY_HONEYPOT":
            near = spec.args["host"]
            self.honeypot_count += 1
            hid = f"SKR-HP-{self.honeypot_count:02d}"
            zone = self.hosts[near].zone
            hp = Host(id=hid, name=hid, kind="webserver", zone=zone, os="Ubuntu 22.04",
                      criticality=3, honeypot=True)
            self.hosts[hid] = hp
            vid = f"V-HP-{self.honeypot_count:02d}"
            self.vulns[vid] = Vuln(id=vid, host=hid, cve_label="CVE-2021-44228",
                                   name="Log4Shell RCE (decoy)", severity=10,
                                   exploitability=0.9, noise=0.05)
            e = {"src": near, "dst": hid, "port": 443, "protocol": "tcp", "blocked": False}
            from .models import Edge
            edge = Edge(**e)
            self.edges.append(edge)
            self.adj.setdefault(near, []).append(edge)
            self.mirror.write(queries.ADD_HONEYPOT, near=near, id=hid, props=hp.model_dump())
            rec.narration = f"BLUE deploys honeypot {hid} near {near} — tripwire armed"
            await self.bus.emit("graph_patch", {
                "nodes": [], "links": [],
                "new_nodes": [{"id": hid, "name": hid, "kind": "webserver", "zone": zone,
                               "os": hp.os, "criticality": 3, "compromised": False,
                               "isolated": False, "honeypot": True, "discovered": False,
                               "crown": False}],
                "new_links": [{"source": near, "target": hid, "port": 443,
                               "protocol": "tcp", "blocked": False}]})
            return rec

        elif spec.action == "INVESTIGATE":
            h = self.hosts[spec.args["host"]]
            h.investigated = True
            changed.add(h.id)
            props = {"investigated": True}
            verdict = "COMPROMISED — attacker present!" if h.compromised else "clean"
            if h.beacon:
                h.beacon = False
                props["beacon"] = False
                verdict += " Hidden C2 beacon FOUND and removed — persistence burned."
            self.mirror.write(queries.SET_HOST, id=h.id, props=props)
            rec.narration = f"BLUE investigates {h.id}: {verdict}"

        elif spec.action == "THREAT_HUNT":
            zone = spec.args["zone"]
            swept = [h for h in self.hosts.values()
                     if h.zone == zone and not h.investigated and h.kind != "internet"]
            found, burned = [], 0
            for h in swept:
                h.investigated = True
                changed.add(h.id)
                props = {"investigated": True}
                if h.compromised:
                    found.append(h.id)
                if h.beacon:
                    h.beacon = False
                    burned += 1
                    props["beacon"] = False
                self.mirror.write(queries.SET_HOST, id=h.id, props=props)
            rec.narration = (f"BLUE threat-hunts the {zone} zone: {len(swept)} host(s) swept, "
                             f"{len(found)} compromised ({', '.join(sorted(found)) or 'none'})"
                             + (f", {burned} C2 beacon(s) burned" if burned else ""))

        await self._emit_patch(changed)
        return rec

    # ----------------------------------------------------------- detection
    async def _raise_alert(self, host: str, kind: str, confidence: float,
                           true_positive: bool = True):
        a = Alert(turn=self.round, host=host, kind=kind,
                  confidence=round(confidence, 2), true_positive=true_positive)
        self.alerts.append(a)
        self.all_alerts.append(a)
        await self.bus.emit("alert", {"host": host, "kind": kind,
                                      "confidence": round(confidence, 2)})

    async def _roll_detection(self, host: str, noise: float, kind: str):
        if host in self.evasion:
            noise *= EVASION_FACTOR
        if host and self.rng.random() < noise:
            conf = min(0.95, noise + self.rng.random() * 0.35)
            await self._raise_alert(host, kind, conf)

    def _maybe_false_positive(self):
        if self.rng.random() < FALSE_POSITIVE_RATE:
            clean = [h for h in self.hosts.values()
                     if not h.compromised and h.kind != "internet"]
            if clean:
                h = self.rng.choice(clean)
                conf = 0.25 + self.rng.random() * 0.3
                a = Alert(turn=self.round, host=h.id, kind="false_positive",
                          confidence=round(conf, 2), true_positive=False)
                self.alerts.append(a)
                self.all_alerts.append(a)
                # fire-and-forget emit; called from sync context in _play_side loop
                asyncio.get_running_loop().create_task(
                    self.bus.emit("alert", {"host": h.id, "kind": "anomaly",
                                            "confidence": round(conf, 2)}))

    # -------------------------------------------------------- interventions
    async def _inject_zero_day(self):
        cands = [h for h in self.hosts.values()
                 if h.zone in ("corp", "servers") and not h.honeypot
                 and not any(v.zero_day for v in self._host_vulns(h.id))]
        if not cands:
            return
        h = self.rng.choice(cands)
        vid = f"V-0DAY-{self.action_n}"
        v = Vuln(id=vid, host=h.id, cve_label="CVE-2026-1337",
                 name="ZERO-DAY: SakuraRPC pre-auth RCE", severity=10,
                 exploitability=0.9, noise=0.08, zero_day=True)
        self.vulns[vid] = v
        if h.discovered:
            h.vulns_revealed = True  # threat intel leak: RED hears about it
        self.mirror.write(queries.WRITE_VULNS,
                          rows=[{"host": h.id, "id": vid,
                                 "props": v.model_dump(exclude={"host", "id"})}])
        await self.bus.emit("intervention", {
            "kind": "zero_day",
            "narration": f"⚠ JUDGE INTERVENTION: zero-day CVE-2026-1337 dropped on {h.id} "
                         f"(exploit 0.9, near-silent)"})
        await self._emit_metrics()

    async def _insider_threat(self):
        priv = [c for c in self.creds.values()
                if self.users[c.owner].privileged and not c.stolen and not c.rotated]
        if not priv:  # fall back: refresh + steal any rotated/regular cred so the button always lands
            others = [c for c in self.creds.values() if not c.stolen]
            if not others:
                return
            c = self.rng.choice(others)
            c.rotated = False
        else:
            c = self.rng.choice(priv)
        c.stolen = True
        self.mirror.write(queries.SET_CRED, id=c.id, props={"stolen": True})
        await self.bus.emit("intervention", {
            "kind": "insider",
            "narration": f"⚠ JUDGE INTERVENTION: insider hands RED the {c.kind} of "
                         f"{self.users[c.owner].name} (grants {c.grants})"})
        await self._emit_metrics()

    # ------------------------------------------------------------ game over
    def _check_eviction(self):
        if self.ever_compromised and not self._controlled(include_internet=False):
            asyncio.get_running_loop().create_task(
                self._game_over("blue", "RED fully evicted — zero hosts under attacker control"))

    async def _game_over(self, winner: str, reason: str):
        if self.winner:
            return
        self.winner = winner
        self.win_reason = reason
        self.state = "game_over"
        await self.bus.emit("game_over", {"winner": winner, "reason": reason,
                                          "rounds": self.round,
                                          "score": self.compute_metrics()})
        if self.reports_enabled:
            asyncio.get_running_loop().create_task(self._emit_report())
        else:
            self.bus.stop_recording()

    async def _emit_report(self):
        from .report import generate_report
        try:
            md = await generate_report(self.s, self.turns, self.metrics_history,
                                       self.winner, self.win_reason)
        except Exception:  # noqa: BLE001
            log.exception("report failed")
            md = ""
        await self.bus.emit("report", {"markdown": md})
        self.bus.stop_recording()
