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
import io
from defusedxml import ElementTree as ET  # hardened against XXE / billion-laughs

from . import intel
from .models import Edge, GraphSpec, Host, Vuln

VALID_KINDS = {"internet", "firewall", "webserver", "workstation", "fileserver", "appserver",
               "database", "domain_controller", "backup", "cloud_bucket", "server"}
VALID_ZONES = {"internet", "dmz", "corp", "servers", "restricted"}


class ImportError(ValueError):
    pass


def _finalise(hosts, edges, vulns, crown) -> GraphSpec:
    if not hosts:
        raise ImportError("no hosts found")
    ids = {h.id for h in hosts}
    if crown not in ids:
        # default crown jewel: highest-criticality host
        crown = max(hosts, key=lambda h: h.criticality).id
    edges = [e for e in edges if e.src in ids and e.dst in ids and e.src != e.dst]
    # ensure an internet beachhead exists and reaches the perimeter
    if not any(h.kind == "internet" for h in hosts):
        hosts.insert(0, Host(id="INTERNET", name="INTERNET", kind="internet",
                             zone="internet", criticality=1))
        perimeter = [h for h in hosts if h.zone in ("dmz", "internet") and h.kind != "internet"]
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
            hid = cells[0]
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
        elif section == "edges" and len(cells) >= 2:
            edges.append(Edge(src=cells[0], dst=cells[1]))
        elif section == "vulns" and len(cells) >= 2:
            n += 1
            sev = int(cells[2]) if len(cells) > 2 and cells[2].isdigit() else 7
            try:
                expl = float(cells[3]) if len(cells) > 3 and cells[3] else sev / 14.0
            except ValueError:
                expl = sev / 14.0
            vulns.append(Vuln(id=f"V-IMP-{n:03d}", host=cells[0], cve_label=cells[1],
                              name=cells[1], severity=max(1, min(10, sev)),
                              exploitability=round(max(0.05, min(0.95, expl)), 2), noise=0.4))
    if not any(s for s in (hosts,)):
        raise ImportError("CSV had no 'hosts:' section")
    return _finalise(hosts, edges, vulns, crown)


_ZONE_BY_PORTHINT = {443: "dmz", 80: "dmz", 25: "dmz"}


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
        hid = (name_el.get("name") if name_el is not None else None) or addr
        if not hid:
            continue
        ports = h.findall("ports/port")
        open_ports = [int(p.get("portid")) for p in ports
                      if (p.find("state") is not None and p.find("state").get("state") == "open")]
        zone = "dmz" if any(p in open_ports for p in (80, 443, 25)) else "corp"
        kind = ("webserver" if any(p in open_ports for p in (80, 443)) else
                "database" if any(p in open_ports for p in (1433, 3306, 5432)) else
                "domain_controller" if 88 in open_ports else "server")
        crit = 8 if kind in ("database", "domain_controller") else 4
        hosts.append(Host(id=hid, name=hid, kind=kind, zone=zone, criticality=crit))
        host_ids.append(hid)
        for p in ports:
            svc = p.find("service")
            if svc is not None and svc.get("state") != "closed" and \
                    (p.find("state") is not None and p.find("state").get("state") == "open"):
                # a reachable service is a potential exploitation surface
                n += 1
                vulns.append(Vuln(id=f"V-IMP-{n:03d}", host=hid,
                                  cve_label=f"SERVICE-{p.get('portid')}",
                                  name=f"{svc.get('name', 'service')} on port {p.get('portid')}",
                                  severity=6, exploitability=0.4, noise=0.4))
    # Nmap gives no topology; wire a flat reachable mesh from the perimeter inward
    dmz = [h.id for h in hosts if h.zone == "dmz"]
    inner = [h.id for h in hosts if h.zone != "dmz"]
    for d in dmz:
        for i in inner:
            edges.append(Edge(src=d, dst=i))
    return _finalise(hosts, edges, vulns, "")
