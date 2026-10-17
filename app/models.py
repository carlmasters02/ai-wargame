from __future__ import annotations

from pydantic import BaseModel


# ---------- Graph entities ----------

class Host(BaseModel):
    id: str
    name: str
    kind: str            # internet|firewall|webserver|workstation|fileserver|appserver|database|domain_controller|backup|cloud_bucket
    zone: str            # internet|dmz|corp|servers|restricted
    os: str = "linux"
    criticality: int = 5
    compromised: bool = False
    isolated: bool = False
    honeypot: bool = False
    discovered: bool = False
    investigated: bool = False
    vulns_revealed: bool = False  # RED has scanned this host's vuln details
    beacon: bool = False          # RED C2 persistence: survives ISOLATE unless investigated


class Edge(BaseModel):
    src: str
    dst: str
    port: int = 443
    protocol: str = "tcp"
    blocked: bool = False


class Vuln(BaseModel):
    id: str
    host: str
    cve_label: str
    name: str
    severity: int            # 1-10
    exploitability: float    # 0.0-1.0
    noise: float             # 0.0-1.0
    patched: bool = False
    zero_day: bool = False
    epss: float | None = None  # EPSS exploit probability (0-1), from FIRST.org
    kev: bool = False          # on CISA's Known Exploited Vulnerabilities catalog


class Credential(BaseModel):
    id: str
    kind: str               # password|ssh_key|token|kerberos_ticket
    owner: str              # user id
    stored_on: str          # host id
    grants: str             # host id
    rotated: bool = False
    stolen: bool = False


class User(BaseModel):
    id: str
    name: str
    role: str
    privileged: bool = False


class GraphSpec(BaseModel):
    seed: int
    hosts: list[Host]
    edges: list[Edge]
    vulns: list[Vuln]
    creds: list[Credential]
    users: list[User]
    crown_jewel: str


# ---------- Game entities ----------

class ActionSpec(BaseModel):
    index: int = 0
    action: str
    args: dict = {}
    description: str = ""


class Alert(BaseModel):
    turn: int
    host: str
    kind: str               # scan|exploit|harvest|lateral|exfil|honeypot|false_positive
    confidence: float
    true_positive: bool     # engine-only; NEVER serialized to BLUE


class TurnRecord(BaseModel):
    n: int                  # global action counter
    round: int
    side: str
    action: str
    args: dict = {}
    success: bool
    narration: str = ""
    thought: str = ""
    fallback: bool = False
    techniques: list[str] = []  # MITRE ATT&CK / mitigation IDs for this action
