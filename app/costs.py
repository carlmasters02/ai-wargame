"""Business-impact cost model — translates a match into dollars.

Security spend is justified in money, not game points, so every match also
produces a cost breakdown a finance team would recognise:

  - downtime:  hosts taken offline. ISOLATE cuts a host off for the rest of the
    incident (ongoing lost productivity); REIMAGE is one maintenance window.
  - response:  incident-response effort per compromised host (triage, forensics).
  - breach:    the cost of the attacker reaching the objective — the crown-jewel
    exfiltration models a data-breach loss.

All figures are illustrative but anchored to public benchmarks (e.g. IBM's
Cost of a Data Breach), so the relative numbers are defensible in a pitch.
Computed from the recorded match, never during play, so it changes nothing about
game balance.
"""
from __future__ import annotations

from .models import TurnRecord

ROUND_HOURS = 4                 # a round is roughly half a business day
HOURLY_PER_CRITICALITY = 2_500  # $/hour of downtime per criticality point
ZONE_MULT = {"restricted": 1.6, "servers": 1.4, "corp": 1.0, "dmz": 0.8, "internet": 0.5}
RESPONSE_PER_HOST = 18_000      # IR effort to triage/clean one compromised host
BREACH_BASE = 4_450_000         # crown-jewel exfiltration ~ IBM avg data-breach cost
REIMAGE_WINDOW_HOURS = ROUND_HOURS


def _hourly(host: dict) -> float:
    return host["criticality"] * HOURLY_PER_CRITICALITY * ZONE_MULT.get(host["zone"], 1.0)


def breakdown(turns: list[TurnRecord], hosts: dict[str, dict], total_rounds: int,
              winner: str | None) -> dict:
    """hosts: {id: {"criticality": int, "zone": str}}. Returns a USD cost breakdown."""
    downtime = 0.0
    response_hosts: set[str] = set()

    for t in turns:
        h = hosts.get(t.args.get("host", ""))
        if t.side == "red" and t.success and t.meta.get("target"):
            response_hosts.add(t.meta["target"])
        if not (t.side == "blue" and t.success and h):
            continue
        if t.action == "ISOLATE":
            # offline from this round to the end of the incident (ongoing lost productivity)
            downtime += _hourly(h) * ROUND_HOURS * max(1, total_rounds - t.round + 1)
        elif t.action == "REIMAGE":
            downtime += _hourly(h) * REIMAGE_WINDOW_HOURS  # one maintenance window

    response = len(response_hosts) * RESPONSE_PER_HOST
    breach = BREACH_BASE if winner == "red" else 0.0
    total = downtime + response + breach
    return {
        "downtime_usd": round(downtime),
        "response_usd": round(response),
        "breach_usd": round(breach),
        "total_usd": round(total),
        "hosts_requiring_response": len(response_hosts),
    }
