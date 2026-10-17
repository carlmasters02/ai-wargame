"""Viable attack-path metric (pure Python, O(35 nodes) — instant).

A path is viable if:
  - every traversed edge is unblocked,
  - no traversed host is isolated or a honeypot,
  - every host after the start is "breachable":
      compromised OR has an unpatched vuln OR reachable via a credential grant
      (runtime: the credential must be stolen and unrotated; gen_mode: any grant).

Used by the generator (guarantee check, gen_mode=True) and the engine
(per-turn metric, gen_mode=False).
"""
from __future__ import annotations

from collections import deque

from .models import Credential, Edge, Host, Vuln


def _index(hosts, edges, vulns, creds):
    hmap = {h.id: h for h in hosts}
    vulns_by_host: dict[str, list[Vuln]] = {}
    for v in vulns:
        vulns_by_host.setdefault(v.host, []).append(v)
    creds_by_grant: dict[str, list[Credential]] = {}
    for c in creds:
        creds_by_grant.setdefault(c.grants, []).append(c)
    adj: dict[str, list[str]] = {}
    for e in edges:
        if e.blocked:
            continue
        a, b = hmap.get(e.src), hmap.get(e.dst)
        if not a or not b:
            continue
        if a.isolated or b.isolated or a.honeypot or b.honeypot:
            continue
        adj.setdefault(e.src, []).append(e.dst)
    return hmap, vulns_by_host, creds_by_grant, adj


def _breachable(hid, hmap, vulns_by_host, creds_by_grant, gen_mode, potential=False) -> bool:
    h = hmap[hid]
    if h.compromised:
        return True
    if any(not v.patched for v in vulns_by_host.get(hid, [])):
        return True
    for c in creds_by_grant.get(hid, []):
        # gen_mode: any grant. potential: any grant that hasn't been rotated (a snapshot view).
        # runtime: only a credential the attacker has actually stolen and that isn't rotated.
        if gen_mode or (potential and not c.rotated) or (c.stolen and not c.rotated):
            return True
    return False


def count_viable_paths(
    hosts: list[Host],
    edges: list[Edge],
    vulns: list[Vuln],
    creds: list[Credential],
    cj: str,
    maxlen: int = 8,
    cap: int = 250,
    gen_mode: bool = False,
    potential: bool = False,
) -> tuple[int, list[str], bool]:
    """Returns (path_count, shortest_path_ids, capped)."""
    hmap, vbh, cbg, adj = _index(hosts, edges, vulns, creds)

    def breachable(hid: str) -> bool:
        return _breachable(hid, hmap, vbh, cbg, gen_mode, potential)

    starts = [
        h.id
        for h in hosts
        if (h.compromised or h.kind == "internet") and not h.isolated and not h.honeypot
    ]
    starts = list(dict.fromkeys(starts))
    if cj not in hmap or not starts:
        return 0, [], False

    # --- shortest viable path (BFS) ---
    shortest: list[str] = []
    for s in starts:
        q = deque([(s, [s])])
        seen = {s}
        while q:
            node, path = q.popleft()
            if len(path) - 1 >= maxlen:
                continue
            for nxt in adj.get(node, []):
                if nxt in seen or not breachable(nxt):
                    continue
                np = path + [nxt]
                if nxt == cj:
                    if not shortest or len(np) < len(shortest):
                        shortest = np
                    q.clear()
                    break
                seen.add(nxt)
                q.append((nxt, np))

    # --- count all simple viable paths (DFS, capped) ---
    count = 0
    capped = False
    for s in starts:
        stack = [(s, (s,))]
        while stack:
            node, path = stack.pop()
            if len(path) - 1 >= maxlen:
                continue
            for nxt in adj.get(node, []):
                if nxt in path or not breachable(nxt):
                    continue
                if nxt == cj:
                    count += 1
                    if count >= cap:
                        capped = True
                        return count, shortest, capped
                else:
                    stack.append((nxt, path + (nxt,)))

    return count, shortest, capped
