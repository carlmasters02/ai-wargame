"""Digital twin — import a real network and play the wargame on it.

Turns an organisation's own inventory into a GraphSpec the engine can load, so
the exposure analysis and the red-vs-blue match run on *their* topology, not the
synthetic one. Two ground-truth sources teams already have:

  - CSV asset inventory  (import_csv)   — hosts, connections and known CVEs
  - Nmap XML scan        (import_nmap)  — hosts and the services between them

Imported networks skip the synthetic generator's path guarantee (a real network
is whatever it is). Credentials/users aren't inferred, so the imported game is
driven by exploitation and the exposure analysis; add a CSV creds section to
model credential reuse.

CSV format (one section per block, blank-line separated, '#'-comments ignored):

    # hosts: id,kind,zone,criticality,crown
    SRV-DB-01,database,restricted,10,yes
    WEB-01,webserver,dmz,4,no
    # edges: src,dst
    WEB-01,SRV-DB-01
    # vulns: host,cve,severity,exploitability
    WEB-01,CVE-2021-44228,10,0.8
"""
from __future__ import annotations

import csv
import re
from defusedxml import ElementTree as ET  # hardened against XXE / billion-laughs

from . import intel
from .models import Credential, Edge, GraphSpec, Host, User, Vuln

VALID_KINDS = {"internet", "firewall", "webserver", "workstation", "fileserver", "appserver",
               "database", "domain_controller", "backup", "cloud_bucket", "server"}
VALID_ZONES = {"internet", "dmz", "corp", "servers", "restricted"}

# Size limits: imports are untrusted and every host/edge feeds per-turn path analysis.
MAX_HOSTS = 250
MAX_EDGES = 20_000
MAX_VULNS = 2_000
_UNSAFE = re.compile(r"[^A-Za-z0-9._:@-]")


def _ident(raw, limit: int = 64) -> str:
    """Imported names reach the UI, the reports and the LLM prompts: keep them short and
    to a conservative charset so an import can't smuggle markup or prompt text."""
    return _UNSAFE.sub("_", str(raw).strip())[:limit]


def _check(items, limit: int, what: str) -> None:
    if len(items) > limit:
        raise ImportError(f"too many {what} (max {limit})")


class ImportError(ValueError):
    pass


def _finalise(hosts, edges, vulns, crown) -> GraphSpec:
    unique: dict[str, Host] = {}
    for h in hosts:
        if h.id:
            unique.setdefault(h.id, h)  # first definition of a duplicated id wins
    hosts = list(unique.values())
    if not hosts:
        raise ImportError("no hosts found")
    _check(hosts, MAX_HOSTS, "hosts")
    _check(edges, MAX_EDGES, "edges")
    _check(vulns, MAX_VULNS, "vulnerabilities")
    ids = {h.id for h in hosts}
    if crown not in ids:
        # default crown jewel: highest-criticality host
        crown = max(hosts, key=lambda h: h.criticality).id
    edges = [e for e in edges if e.src in ids and e.dst in ids and e.src != e.dst]
    # ensure an internet beachhead exists and reaches the perimeter
    if not any(h.kind == "internet" for h in hosts):
        hosts.insert(0, Host(id="INTERNET", name="INTERNET", kind="internet",
                             zone="internet", criticality=1))
        # beachheads: perimeter (dmz) OR workstations (phishing) — the realistic entry points
        perimeter = [h for h in hosts if (h.zone == "dmz" or h.kind == "workstation")
                     and h.kind != "internet"]
        for h in (perimeter or [h for h in hosts if h.kind != "internet"][:1]):
            edges.append(Edge(src="INTERNET", dst=h.id))
    vulns = [v for v in vulns if v.host in ids]
    for v in vulns:
        intel.enrich(v)
    spec = GraphSpec(seed=-1, hosts=hosts, edges=edges, vulns=vulns, creds=[], users=[],
                     crown_jewel=crown)
    # fog of war: internet is the beachhead; its neighbours are discovered + fingerprinted
    hmap = {h.id: h for h in hosts}
    for h in hosts:
        if h.kind == "internet":
            h.compromised = h.discovered = True
    for e in edges:
        if hmap[e.src].kind == "internet":
            hmap[e.dst].discovered = True
            hmap[e.dst].vulns_revealed = True
    return spec


def import_csv(text: str) -> GraphSpec:
    hosts: list[Host] = []
    edges: list[Edge] = []
    vulns: list[Vuln] = []
    crown = ""
    section = None
    n = 0
    for raw in text.splitlines():
        # section headers may be written as "# hosts:" or "hosts:" — detect before stripping comments
        hdr = raw.strip().lstrip("#").strip().lower()
        if hdr.startswith(("hosts:", "host:")):
            section = "hosts"; continue
        if hdr.startswith(("edges:", "edge:")):
            section = "edges"; continue
        if hdr.startswith(("vulns:", "vuln:")):
            section = "vulns"; continue
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        cells = next(csv.reader([line]))
        cells = [c.strip() for c in cells]
        if section == "hosts":
            hid = _ident(cells[0])
            kind = (cells[1] if len(cells) > 1 and cells[1] else "server").lower()
            if kind not in VALID_KINDS:
                kind = "server"
            zone = (cells[2] if len(cells) > 2 and cells[2] else "corp").lower()
            if zone not in VALID_ZONES:
                zone = "corp"
            crit = int(cells[3]) if len(cells) > 3 and cells[3].isdigit() else 5
            hosts.append(Host(id=hid, name=hid, kind=kind, zone=zone,
                              criticality=max(1, min(10, crit))))
            if len(cells) > 4 and cells[4].lower() in ("yes", "true", "crown", "1"):
                crown = hid
            _check(hosts, MAX_HOSTS, "hosts")
        elif section == "edges" and len(cells) >= 2:
            edges.append(Edge(src=_ident(cells[0]), dst=_ident(cells[1])))
            _check(edges, MAX_EDGES, "edges")
        elif section == "vulns" and len(cells) >= 2:
            n += 1
            sev = int(cells[2]) if len(cells) > 2 and cells[2].isdigit() else 7
            try:
                expl = float(cells[3]) if len(cells) > 3 and cells[3] else sev / 14.0
            except ValueError:
                expl = sev / 14.0
            label = _ident(cells[1], 40)
            vulns.append(Vuln(id=f"V-IMP-{n:03d}", host=_ident(cells[0]), cve_label=label,
                              name=label, severity=max(1, min(10, sev)),
                              exploitability=round(max(0.05, min(0.95, expl)), 2), noise=0.4))
            _check(vulns, MAX_VULNS, "vulnerabilities")
    if not any(s for s in (hosts,)):
        raise ImportError("CSV had no 'hosts:' section")
    return _finalise(hosts, edges, vulns, crown)


_ZONE_BY_PORTHINT = {443: "dmz", 80: "dmz", 25: "dmz"}


def _port(p) -> int | None:
    try:
        return int(p.get("portid"))
    except (TypeError, ValueError):
        return None


def import_nmap(xml_text: str) -> GraphSpec:
    try:
        root = ET.fromstring(xml_text)
    except Exception as e:  # defusedxml raises on malicious + malformed XML
        raise ImportError(f"invalid Nmap XML: {e}")
    hosts: list[Host] = []
    edges: list[Edge] = []
    vulns: list[Vuln] = []
    n = 0
    host_ids: list[str] = []
    for h in root.findall("host"):
        state = h.find("status")
        if state is not None and state.get("state") == "down":
            continue
        addr = next((a.get("addr") for a in h.findall("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), None)
        name_el = h.find("hostnames/hostname")
        hid = _ident((name_el.get("name") if name_el is not None else None) or addr or "")
        if not hid:
            continue
        ports = [p for p in h.findall("ports/port") if _port(p) is not None]
        open_ports = [_port(p) for p in ports
                      if (p.find("state") is not None and p.find("state").get("state") == "open")]
        zone = "dmz" if any(p in open_ports for p in (80, 443, 25)) else "corp"
        kind = ("webserver" if any(p in open_ports for p in (80, 443)) else
                "database" if any(p in open_ports for p in (1433, 3306, 5432)) else
                "domain_controller" if 88 in open_ports else "server")
        crit = 8 if kind in ("database", "domain_controller") else 4
        hosts.append(Host(id=hid, name=hid, kind=kind, zone=zone, criticality=crit))
        _check(hosts, MAX_HOSTS, "hosts")
        host_ids.append(hid)
        for p in ports:
            svc = p.find("service")
            if svc is not None and svc.get("state") != "closed" and \
                    (p.find("state") is not None and p.find("state").get("state") == "open"):
                # a reachable service is a potential exploitation surface
                n += 1
                vulns.append(Vuln(id=f"V-IMP-{n:03d}", host=hid,
                                  cve_label=f"SERVICE-{_port(p)}",
                                  name=f"{_ident(svc.get('name', 'service'), 32)} on port {_port(p)}",
                                  severity=6, exploitability=0.4, noise=0.4))
                _check(vulns, MAX_VULNS, "vulnerabilities")
    # Nmap gives no topology; wire a flat reachable mesh from the perimeter inward
    dmz = [h.id for h in hosts if h.zone == "dmz"]
    inner = [h.id for h in hosts if h.zone != "dmz"]
    _check(range(len(dmz) * len(inner)), MAX_EDGES, "edges")
    for d in dmz:
        for i in inner:
            edges.append(Edge(src=d, dst=i))
    return _finalise(hosts, edges, vulns, "")


# -------------------------------------------------------- BloodHound (identity paths)
def _bh_kind(name: str) -> str:
    n = name.upper()
    if any(t in n for t in ("DC", "DOMAIN")):
        return "domain_controller"
    if any(t in n for t in ("SQL", "DB")):
        return "database"
    if any(t in n for t in ("FILE", "FS", "SHARE")):
        return "fileserver"
    if any(t in n for t in ("WEB", "WWW", "IIS")):
        return "webserver"
    if any(t in n for t in ("WS", "WKS", "PC", "LAPTOP", "DESK")):
        return "workstation"
    return "server"


def import_bloodhound(text: str) -> GraphSpec:
    """Import a BloodHound-style identity graph into attacker-reachable paths.

    Models Active Directory privilege escalation the way BloodHound does: a user
    with a *session* on computer A whose account is *admin to* computer B creates a
    path A -> B (own A, steal the session's credential, admin onto B). Accepts a
    simplified combined JSON:

        {"computers": [{"name": "DC01", "crown": false,
                        "sessions": ["alice"], "admins": ["bob"]}],
         "users":     [{"name": "alice", "admin_to": ["FILE01", "DC01"]}]}

    and makes a best effort at a SharpHound computers collection (Properties.name +
    Sessions/LocalAdmins). Unknown fields are ignored.
    """
    import json

    try:
        data = json.loads(text)
    except ValueError as e:
        raise ImportError(f"invalid BloodHound JSON: {e}")
    if not isinstance(data, dict):
        raise ImportError("BloodHound JSON must be an object")

    computers = data.get("computers") or data.get("data") or []
    users_raw = data.get("users") or []
    # user -> set of computers they are admin to
    admin_to: dict[str, set[str]] = {}
    for u in users_raw:
        name = _ident(str(u.get("name") or u.get("Properties", {}).get("name") or "")
                      .split("@")[0].upper())
        if name:
            admin_to.setdefault(name, set()).update(
                _ident(str(c).split("@")[0].split(".")[0].upper()) for c in (u.get("admin_to") or []))

    hosts: list[Host] = []
    id_vulns: list[Vuln] = []
    sessions: dict[str, list[str]] = {}   # computer -> users with a session there
    local_admins: dict[str, list[str]] = {}
    seen: set[str] = set()
    crown = ""

    def _short(n):
        return _ident(str(n).split("@")[0].split(".")[0].upper())

    for c in computers:
        name = c.get("name") or c.get("Properties", {}).get("name") or c.get("ObjectIdentifier")
        if not name:
            continue
        cid = _short(name)
        if not cid or cid in seen:
            continue
        seen.add(cid)
        _check(seen, MAX_HOSTS, "computers")
        kind = _bh_kind(cid)
        crit = {"domain_controller": 9, "database": 8, "fileserver": 7}.get(kind, 4)
        zone = "corp" if kind == "workstation" else "servers"
        hosts.append(Host(id=cid, name=cid, kind=kind, zone=zone, criticality=crit))
        if kind == "workstation":
            n_v = len(id_vulns)
            id_vulns.append(Vuln(id=f"V-BH-PHISH-{n_v:03d}", host=cid, cve_label="T1566",
                                 name="Phishing / endpoint initial access", severity=6,
                                 exploitability=0.6, noise=0.3))
        if c.get("crown"):
            crown = cid
        sess = c.get("sessions")
        if sess is None:
            sess = [s.get("UserName") or s.get("UserSID") for s in
                    (c.get("Sessions", {}).get("Results") or [])]
        sessions[cid] = [_short(s) for s in sess if s]
        adm = c.get("admins")
        if adm is None:
            adm = [a.get("ObjectIdentifier") for a in (c.get("LocalAdmins", {}).get("Results") or [])]
        local_admins[cid] = [_short(a) for a in adm if a]

    if not hosts:
        raise ImportError("no computers found in BloodHound export")

    host_ids = {h.id for h in hosts}
    edges: list[Edge] = []
    creds: list[Credential] = []
    pair_seen: set[tuple[str, str]] = set()
    n = 0
    # identity edges: a session user who can admin another box -> reachable credential path
    for comp, users in sessions.items():
        for user in users:
            for target in sorted(admin_to.get(user, set())):
                if target in host_ids and target != comp and (comp, target) not in pair_seen:
                    pair_seen.add((comp, target))
                    edges.append(Edge(src=comp, dst=target, port=445, protocol="smb"))
                    _check(edges, MAX_EDGES, "edges")
                    n += 1
                    creds.append(Credential(id=f"C-BH-{n:03d}", kind="session",
                                            owner=user, stored_on=comp, grants=target))
    # local-admin edges without a session still imply reachability (lateral surface)
    for comp, admins in local_admins.items():
        for user in admins:
            for target in sorted(admin_to.get(user, set())):
                if target in host_ids and target != comp and (comp, target) not in pair_seen:
                    pair_seen.add((comp, target))
                    edges.append(Edge(src=comp, dst=target, port=445, protocol="smb"))

    spec = _finalise(hosts, edges, id_vulns, crown)
    # attach identity credentials + the users that own them
    spec.creds = creds
    owners = {c.owner for c in creds}
    spec.users = [User(id=u, name=u, role="AD account", privileged=True) for u in sorted(owners)]
    return spec
