"""SOC-style scorecards for a finished match.

Everything here is computed from the recorded match data (turn log, alert log,
per-round path-count history) plus the engine's ground truth about which hosts
RED actually held. These are the numbers a SOC is measured on, so they double as
the model-evaluation metrics: how fast a defender detects and responds, how often
it disrupts the business chasing ghosts, and how much exposure it removes.

Pure functions, no engine mutation — safe to call after a match or in a benchmark.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .models import Alert, TurnRecord

RED_COMPROMISE = ("EXPLOIT", "LATERAL_MOVE", "PHISH_USER")  # actions that can take a host
BLUE_EVICT = ("ISOLATE", "REIMAGE")


@dataclass
class BlueScore:
    detected: int = 0                 # compromised hosts BLUE confirmed (investigate/hunt/evict)
    missed: int = 0                   # compromised hosts never confirmed
    mttd_rounds: float | None = None  # mean rounds from compromise to confirmation
    mttr_rounds: float | None = None  # mean rounds from confirmation to eviction
    evictions: int = 0
    false_isolations: int = 0         # ISOLATE/REIMAGE of a host RED did not hold (wasted downtime)
    business_impact: float = 0.0
    exposure_peak: int = 0            # worst true path count during the match
    exposure_final: int = 0
    exposure_reduction: float = 0.0   # fraction of peak exposure removed by the end

    def grade(self) -> str:
        return _grade(self.score())

    def score(self) -> float:
        """0-100 composite: detection coverage, speed, precision, exposure control."""
        total = self.detected + self.missed
        coverage = self.detected / total if total else 1.0
        speed = 1.0 if self.mttd_rounds is None else max(0.0, 1 - self.mttd_rounds / 6)
        evict_total = self.evictions + self.false_isolations
        precision = self.evictions / evict_total if evict_total else 1.0
        return round(100 * (0.35 * coverage + 0.2 * speed + 0.2 * precision
                            + 0.25 * self.exposure_reduction), 1)


@dataclass
class RedScore:
    hosts_compromised: int = 0        # distinct hosts taken (peak breadth)
    objective: bool = False           # exfiltrated the crown jewel
    rounds_to_objective: int | None = None
    actions: int = 0
    alerts_raised: int = 0            # true-positive alerts caused by RED
    stealth: float = 0.0              # successful actions per alert raised (higher = quieter)
    reached_restricted: bool = False

    def grade(self) -> str:
        return _grade(self.score())

    def score(self) -> float:
        speed = 0.0 if not self.objective or self.rounds_to_objective is None \
            else max(0.0, 1 - self.rounds_to_objective / 20)
        reach = min(1.0, self.hosts_compromised / 6)
        quiet = min(1.0, self.stealth / 4)
        return round(100 * (0.5 * (1.0 if self.objective else 0.0)
                            + 0.2 * speed + 0.2 * reach + 0.1 * quiet), 1)


@dataclass
class CostScore:
    """Per-side model cost: only populated for LLM sides (heuristic leaves None)."""
    decisions: int = 0
    fallbacks: int = 0
    avg_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    total_tokens: int | None = None
    avg_tokens: float | None = None
    fallback_rate: float = 0.0


@dataclass
class Scorecard:
    winner: str | None
    reason: str
    rounds: int
    red: RedScore = field(default_factory=RedScore)
    blue: BlueScore = field(default_factory=BlueScore)
    red_cost: CostScore = field(default_factory=CostScore)
    blue_cost: CostScore = field(default_factory=CostScore)

    def to_dict(self) -> dict:
        return asdict(self) | {
            "red": asdict(self.red) | {"score": self.red.score(), "grade": self.red.grade()},
            "blue": asdict(self.blue) | {"score": self.blue.score(), "grade": self.blue.grade()},
            "red_cost": asdict(self.red_cost), "blue_cost": asdict(self.blue_cost),
        }


def _grade(score: float) -> str:
    for cut, g in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= cut:
            return g
    return "F"


def _mean(xs):
    return round(sum(xs) / len(xs), 2) if xs else None


def _percentile(xs, p):
    if not xs:
        return None
    s = sorted(xs)
    k = max(0, min(len(s) - 1, int(round((p / 100) * (len(s) - 1)))))
    return float(s[k])


def _cost(turns: list[TurnRecord], side: str) -> CostScore:
    side_turns = [t for t in turns if t.side == side]
    # one decision per side-turn (a round); BLUE resolves 2 actions under one decision
    rounds = sorted({t.round for t in side_turns})
    decisions = len(rounds)
    fallback_rounds = {t.round for t in side_turns if t.fallback}
    fallbacks = len(fallback_rounds)
    # latency/tokens are stamped once per decision (identical on a round's actions) — dedupe by round
    seen = {}
    for t in side_turns:
        if t.latency_ms is not None and t.round not in seen:
            seen[t.round] = t
    model_turns = list(seen.values())
    lat = [t.latency_ms for t in model_turns]
    toks = [t.tokens for t in model_turns if t.tokens is not None]
    return CostScore(
        decisions=decisions, fallbacks=fallbacks,
        avg_latency_ms=_mean(lat), p95_latency_ms=_percentile(lat, 95),
        total_tokens=sum(toks) if toks else None, avg_tokens=_mean(toks),
        fallback_rate=round(fallbacks / decisions, 3) if decisions else 0.0)


def build(turns: list[TurnRecord], alerts: list[Alert], metrics_history: list[dict],
          winner: str | None, reason: str, rounds: int,
          host_criticality: dict[str, int] | None = None) -> Scorecard:
    host_criticality = host_criticality or {}

    # --- when was each host first compromised (ground truth from the turn log) ---
    first_compromise: dict[str, int] = {}
    for t in turns:
        if t.side == "red" and t.success and t.action in RED_COMPROMISE:
            hid = t.meta.get("target") or t.args.get("host")
            if hid and hid not in first_compromise:
                first_compromise[hid] = t.round

    # --- when did BLUE first *confirm* each compromised host ---
    confirmed: dict[str, int] = {}
    for t in turns:
        if t.side != "blue" or not t.success:
            continue
        for hid in t.meta.get("confirmed_hosts", []):
            if hid in first_compromise and hid not in confirmed:
                confirmed[hid] = t.round

    # --- when did BLUE evict each host; count false isolations ---
    evicted: dict[str, int] = {}
    false_iso = 0
    for t in turns:
        if t.side == "blue" and t.success and t.action in BLUE_EVICT:
            hid = t.args.get("host")
            if t.meta.get("was_compromised"):
                evicted.setdefault(hid, t.round)
            else:
                false_iso += 1

    red = RedScore()
    red.hosts_compromised = len(first_compromise)
    red.actions = sum(1 for t in turns if t.side == "red")
    red.alerts_raised = sum(1 for a in alerts if a.true_positive)
    red_success = sum(1 for t in turns if t.side == "red" and t.success)
    red.stealth = round(red_success / red.alerts_raised, 2) if red.alerts_raised else float(red_success)
    red.reached_restricted = any(c >= 10 for h, c in host_criticality.items() if h in first_compromise)
    exfil = next((t for t in turns if t.action == "EXFILTRATE" and t.success), None)
    if exfil:
        red.objective = True
        red.rounds_to_objective = exfil.round

    blue = BlueScore()
    blue.detected = len(confirmed)
    blue.missed = len(first_compromise) - len(confirmed)
    blue.evictions = len(evicted)
    blue.false_isolations = false_iso
    blue.business_impact = round(metrics_history[-1]["impact"], 1) if metrics_history else 0.0
    blue.mttd_rounds = _mean([confirmed[h] - first_compromise[h] for h in confirmed])
    blue.mttr_rounds = _mean([evicted[h] - confirmed[h] for h in evicted if h in confirmed])
    paths = [m["paths"] for m in metrics_history] or [0]
    blue.exposure_peak, blue.exposure_final = max(paths), paths[-1]
    blue.exposure_reduction = round((blue.exposure_peak - blue.exposure_final) / blue.exposure_peak, 3) \
        if blue.exposure_peak else 0.0

    return Scorecard(winner=winner, reason=reason, rounds=rounds, red=red, blue=blue,
                     red_cost=_cost(turns, "red"), blue_cost=_cost(turns, "blue"))
