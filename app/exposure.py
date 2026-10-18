"""Exposure analysis — prioritised remediation ("which fixes cut the most risk").

Given the current network, this measures how many viable attack paths to the
crown jewel each candidate fix would remove, then ranks them — the core of a
continuous-threat-exposure-management (CTEM) product. It also greedily builds a
minimal fix set that drives exposure toward zero, so a defender (or a CISO) sees
the shortest list of actions that most reduces risk.

Candidate fixes considered:
  - PATCH an unpatched vulnerability
  - ROTATE a user's credentials (removes stolen-credential paths)
  - ISOLATE / REIMAGE-equivalent: take a compromised host out of the attack graph

Pure analysis over copies of the game state — it never mutates the live match.
"""
from __future__ import annotations

from copy import deepcopy

from .paths import count_viable_paths

# Work bounds: every candidate fix costs one path count, so a large imported network
# could otherwise pin the CPU. Generated networks stay far below both.
COUNT_BUDGET = 5_000      # DFS expansions per path count
MAX_EVALS = 150           # path counts per analysis (normal play peaks ~75)


def _count(hosts, edges, vulns, creds, cj, potential=False) -> int:
    return count_viable_paths(hosts, edges, vulns, creds, cj, maxlen=8, cap=250,
                              potential=potential, budget=COUNT_BUDGET)[0]


def _candidates(hosts, vulns, creds, potential=False):
    """Yield (kind, label, apply_fn) for every fix worth evaluating. In potential mode
    (static snapshot / identity graph) any unrotated credential is a candidate, since any
    grant is a reachable hop; otherwise only credentials known to be stolen."""
    host_by = {h.id: h for h in hosts}
    for v in vulns:
        if not v.patched and host_by.get(v.host) and not host_by[v.host].isolated:
            yield ("PATCH", f"Patch {v.cve_label} on {v.host}", ("vuln", v.id))
    owners = {c.owner for c in creds
              if not c.rotated and (potential or c.stolen)}
    for owner in sorted(owners):
        yield ("ROTATE_CREDS", f"Rotate credentials for {owner}", ("owner", owner))
    for h in hosts:
        if h.compromised and h.kind not in ("internet",) and not h.isolated:
            yield ("ISOLATE", f"Isolate/reimage {h.id}", ("host", h.id))


def _apply(target, hosts, vulns, creds):
    kind, key = target
    if kind == "vuln":
        for v in vulns:
            if v.id == key:
                v.patched = True
    elif kind == "owner":
        for c in creds:
            if c.owner == key:
                c.rotated = True
    elif kind == "host":
        for h in hosts:
            if h.id == key:
                h.isolated = True
                h.compromised = False


def analyse(hosts, edges, vulns, creds, cj, top: int = 8, potential: bool = False) -> dict:
    # potential=True (gen_mode): count attack paths an attacker COULD take (any credential
    # grant is a hop) — the right view for a static network snapshot / identity graph.
    base = _count(hosts, edges, vulns, creds, cj, potential)
    evals = 1
    ranked = []
    for action, label, target in _candidates(hosts, vulns, creds, potential):
        if evals >= MAX_EVALS:
            break
        evals += 1
        h2, v2, c2 = deepcopy(hosts), deepcopy(vulns), deepcopy(creds)
        _apply(target, h2, v2, c2)
        after = _count(h2, edges, v2, c2, cj, potential)
        removed = base - after
        if removed > 0:
            ranked.append({"action": action, "label": label,
                           "paths_removed": removed, "paths_after": after,
                           "pct_removed": round(removed / base, 3) if base else 0.0})
    ranked.sort(key=lambda r: -r["paths_removed"])

    # greedy minimal fix set: repeatedly apply the single fix that removes the most,
    # until exposure hits zero or no fix helps
    h2, v2, c2 = deepcopy(hosts), deepcopy(vulns), deepcopy(creds)
    plan, cur = [], base
    while cur > 0:
        best = None
        for action, label, target in _candidates(h2, v2, c2, potential):
            if evals >= MAX_EVALS:
                break
            evals += 1
            hh, vv, cc = deepcopy(h2), deepcopy(v2), deepcopy(c2)
            _apply(target, hh, vv, cc)
            after = _count(hh, edges, vv, cc, cj, potential)
            if best is None or after < best[0]:
                best = (after, action, label, target)
        if best is None or best[0] >= cur:
            break
        cur = best[0]
        _apply(best[3], h2, v2, c2)
        plan.append({"action": best[1], "label": best[2], "paths_after": cur})
        if len(plan) >= 12:
            break

    return {"current_exposure": base, "top_fixes": ranked[:top],
            "minimal_fix_plan": plan,
            "residual_after_plan": plan[-1]["paths_after"] if plan else base}
