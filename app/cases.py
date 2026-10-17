"""SOC case (incident) management.

Real analysts don't act on loose alerts — they open a case, investigate it, and
drive it to a resolution. This tracks that lifecycle: alerts on a host roll up
into one open case; investigating sets it to triage; isolating/reimaging contains
it; an investigation that comes back clean closes it as a false positive.

The CaseBook lives on the engine and is updated as alerts fire and BLUE acts.
Serialised for the UI it exposes only what an analyst would see (status, severity,
alert count) — never the engine-only true/false-positive verdict while the case
is open.
"""
from __future__ import annotations

from .models import Case

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _severity(confidence: float, criticality: int) -> str:
    score = confidence * 0.6 + (criticality / 10) * 0.4
    if score >= 0.75:
        return "critical"
    if score >= 0.55:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


class CaseBook:
    def __init__(self):
        self.cases: dict[str, Case] = {}   # case id -> Case
        self._open_by_host: dict[str, str] = {}  # host -> open case id
        self._n = 0

    def reset(self):
        self.__init__()

    def on_alert(self, host: str, round_: int, confidence: float, criticality: int,
                 true_positive: bool) -> Case:
        """An alert fired on a host: open a case or fold into the open one."""
        cid = self._open_by_host.get(host)
        case = self.cases.get(cid) if cid else None
        if case is None or case.status in ("contained", "closed"):
            self._n += 1
            cid = f"INC-{self._n:03d}"
            case = Case(id=cid, host=host, opened_round=round_)
            self.cases[cid] = case
            self._open_by_host[host] = cid
        case.alerts += 1
        case.max_confidence = max(case.max_confidence, round(confidence, 2))
        sev = _severity(case.max_confidence, criticality)
        if SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(case.severity):
            case.severity = sev
        # accumulate verdict: a case is a true positive if any contributing alert is real
        case.true_positive = bool(case.true_positive) or true_positive
        return case

    def on_investigate(self, host: str, round_: int, compromised: bool) -> Case | None:
        case = self._current(host)
        if not case:
            return None
        if case.detected_round is None:
            case.detected_round = round_
        if compromised:
            case.status = "investigating"
            case.resolution = "confirmed compromised"
        else:
            case.status = "closed"
            case.closed_round = round_
            case.resolution = "investigated — no compromise (false positive)"
            self._open_by_host.pop(host, None)
        return case

    def on_contained(self, host: str, round_: int, action: str) -> Case | None:
        case = self._current(host)
        if not case:
            return None
        case.status = "contained"
        case.contained_round = round_
        if case.detected_round is None:
            case.detected_round = round_
        case.resolution = f"contained via {action}"
        self._open_by_host.pop(host, None)
        return case

    def _current(self, host: str) -> Case | None:
        cid = self._open_by_host.get(host)
        return self.cases.get(cid) if cid else None

    # ---- serialisation ----
    def public(self) -> list[dict]:
        """Case board as an analyst sees it — no engine-only verdict on open cases."""
        out = []
        for c in sorted(self.cases.values(), key=lambda c: -c.opened_round):
            d = {"id": c.id, "host": c.host, "status": c.status, "severity": c.severity,
                 "opened_round": c.opened_round, "alerts": c.alerts,
                 "max_confidence": c.max_confidence, "resolution": c.resolution}
            out.append(d)
        return out

    def summary(self) -> dict:
        cases = list(self.cases.values())
        contained = [c for c in cases if c.contained_round is not None]
        ttc = [c.contained_round - c.opened_round for c in contained]
        return {
            "opened": len(cases),
            "contained": len(contained),
            "closed_false_positive": sum(1 for c in cases if c.status == "closed"),
            "open": sum(1 for c in cases if c.status in ("open", "investigating")),
            "mean_time_to_contain": round(sum(ttc) / len(ttc), 2) if ttc else None,
            "critical": sum(1 for c in cases if c.severity == "critical"),
        }
