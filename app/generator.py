"""Seeded procedural generator for the Sakura Logistics K.K. network.

Deterministic from seed. Builds a layered topology
internet -> firewall -> dmz -> corp -> servers -> restricted with deliberate
misconfigurations and credential-reuse chains, then verifies with the path
metric that >= 3 distinct attack paths (length 4-8) exist from the internet
to the CrownJewel. Reseeds (seed+1) if the guarantee fails.
"""
from __future__ import annotations

import random

from . import intel
from .models import Credential, Edge, GraphSpec, Host, User, Vuln
from .paths import count_viable_paths

CVE_POOL = {
    "edge": [
        ("CVE-2024-3400", "PAN-OS GlobalProtect Command Injection", 10),
        ("CVE-2023-27997", "FortiOS SSL-VPN Heap Overflow", 10),
        ("CVE-2024-21887", "Ivanti Connect Secure Command Injection", 9),
        ("CVE-2023-4966", "Citrix Bleed Session Hijack", 9),
        ("CVE-2023-20198", "Cisco IOS XE Web UI PrivEsc", 10),
    ],
    "web": [
        ("CVE-2021-44228", "Log4Shell RCE", 10),
        ("CVE-2023-34362", "MOVEit Transfer SQLi", 9),
        ("CVE-2023-22515", "Confluence Broken Access Control", 10),
        ("CVE-2021-26084", "Confluence OGNL Injection", 9),
        ("CVE-2023-50164", "Struts2 File Upload RCE", 9),
        ("CVE-2023-42793", "TeamCity Auth Bypass RCE", 9),
        ("CVE-2024-23897", "Jenkins Arbitrary File Read", 9),
    ],
    "windows": [
        ("CVE-2020-1472", "Zerologon", 10),
        ("CVE-2021-34527", "PrintNightmare", 8),
        ("CVE-2024-38077", "Windows RDL RCE", 9),
        ("CVE-2023-36884", "Office HTML RCE", 8),
        ("CVE-2024-21413", "Outlook Moniker RCE", 9),
        ("CVE-2023-23397", "Outlook NTLM Leak", 9),
        ("CVE-2023-36802", "Windows MSKV PrivEsc", 7),
        ("CVE-2019-0708", "BlueKeep RDP RCE", 9),
    ],
    "linux": [
        ("CVE-2024-6387", "regreSSHion OpenSSH RCE", 8),
        ("CVE-2023-38408", "OpenSSH Agent Forwarding RCE", 9),
        ("CVE-2022-47966", "ManageEngine SAML RCE", 9),
        ("CVE-2024-40711", "Veeam Backup RCE", 9),
        ("CVE-2024-28995", "SolarWinds Serv-U Path Traversal", 8),
        ("CVE-2022-41040", "ProxyNotShell Exchange SSRF", 8),
        ("CVE-2021-26855", "ProxyLogon Exchange SSRF", 9),
        ("CVE-2017-0144", "EternalBlue SMB RCE", 9),
        ("CVE-2023-0669", "GoAnywhere MFT RCE", 7),
    ],
}

KIND_POOL = {
    "firewall": ["edge"],
    "webserver": ["web", "linux"],
    "appserver": ["web", "linux"],
    "workstation": ["windows"],
    "domain_controller": ["windows"],
    "fileserver": ["windows", "linux"],
    "database": ["linux", "windows"],
    "backup": ["linux"],
    "cloud_bucket": ["linux"],
    "internet": [],
}

OS_BY_KIND = {
    "internet": "-",
    "firewall": "FortiOS 7.4",
    "webserver": "Ubuntu 22.04",
    "appserver": "Ubuntu 22.04",
    "workstation": "Windows 11 23H2",
    "domain_controller": "Windows Server 2022",
    "fileserver": "Windows Server 2019",
    "database": "Windows Server 2022",
    "backup": "Veeam B&R 12",
    "cloud_bucket": "AWS S3",
}

USERS = [
    ("U-01", "k.sato", "Domain Admin", True),
    ("U-02", "y.tanaka", "SysAdmin", True),
    ("U-03", "m.kobayashi", "IT Support", True),
    ("U-04", "j.saito", "Backup Admin", True),
    ("U-05", "h.suzuki", "HR Manager", False),
    ("U-06", "t.yamamoto", "Finance Lead", False),
    ("U-07", "a.watanabe", "Developer", False),
    ("U-08", "r.nakamura", "Sales Rep", False),
]

ADMIN_OF = [
    ("U-01", "SKR-DC-01"), ("U-01", "SKR-DB-PROD"),
    ("U-02", "SKR-APP-01"), ("U-02", "SKR-APP-02"),
    ("U-03", "SKR-FS-01"),
    ("U-04", "SKR-BKP-01"), ("U-04", "SKR-BKP-02"),
]


def _mk_vuln(rng: random.Random, vid: str, host: str, kind: str, quiet: bool = False) -> Vuln:
    pools = KIND_POOL.get(kind, ["linux"])
    cve, name, sev = rng.choice(CVE_POOL[rng.choice(pools)])
    exploitability = max(0.05, min(0.95, rng.gauss(sev / 14.0, 0.15)))
    noise = max(0.05, min(0.90, rng.gauss(0.45, 0.15)))
    if quiet or rng.random() < 0.15:  # a few quiet "gems"
        noise = round(noise * 0.3, 2)
    v = Vuln(
        id=vid, host=host, cve_label=cve, name=name, severity=sev,
        exploitability=round(exploitability, 2), noise=round(noise, 2),
    )
    intel.enrich(v)  # attach real-world EPSS/KEV (deterministic committed cache)
    return v


def generate(seed: int) -> GraphSpec:
    rng = random.Random(seed)
    hosts: list[Host] = []
    edges: list[Edge] = []
    vulns: list[Vuln] = []
    creds: list[Credential] = []
    users = [User(id=u, name=n, role=r, privileged=p) for u, n, r, p in USERS]
    seen_pairs: set[tuple[str, str]] = set()

    def H(hid, kind, zone, crit):
        hosts.append(Host(id=hid, name=hid, kind=kind, zone=zone,
                          os=OS_BY_KIND.get(kind, "linux"), criticality=crit))

    def E(src, dst, port=443, proto="tcp"):
        if (src, dst) in seen_pairs or src == dst:
            return
        seen_pairs.add((src, dst))
        edges.append(Edge(src=src, dst=dst, port=port, protocol=proto))

    # --- core topology ---
    H("INTERNET", "internet", "internet", 1)
    H("SKR-FW-01", "firewall", "dmz", 9)
    H("SKR-WEB-01", "webserver", "dmz", 4)
    H("SKR-WEB-02", "webserver", "dmz", 4)
    H("SKR-MAIL-01", "appserver", "dmz", 5)
    H("SKR-APP-01", "appserver", "corp", 6)
    ws_ids = [f"SKR-WS-{i:03d}" for i in range(1, 9)]
    for w in ws_ids:
        H(w, "workstation", "corp", 3)
    H("SKR-DC-01", "domain_controller", "servers", 9)
    H("SKR-FS-01", "fileserver", "servers", 7)
    H("SKR-DB-01", "database", "servers", 8)
    H("SKR-APP-02", "appserver", "servers", 6)
    H("SKR-BKP-01", "backup", "servers", 7)
    H("SKR-DB-PROD", "database", "restricted", 10)
    H("SKR-BKP-02", "backup", "restricted", 8)

    # --- seed-dependent extras ---
    extra_ws = rng.randint(2, 6)
    for i in range(9, 9 + extra_ws):
        H(f"SKR-WS-{i:03d}", "workstation", "corp", rng.randint(2, 4))
        ws_ids.append(f"SKR-WS-{i:03d}")
    if rng.random() < 0.5:
        H("SKR-S3-01", "cloud_bucket", "servers", 6)
        E("SKR-APP-01", "SKR-S3-01", 443, "https")  # misconfig: bucket reachable from corp
    if rng.random() < 0.3:
        H("SKR-FS-02", "fileserver", "servers", 6)
        E("SKR-APP-01", "SKR-FS-02", 445, "smb")

    # --- edges: layered ---
    E("INTERNET", "SKR-FW-01", 443)
    for d in ("SKR-WEB-01", "SKR-WEB-02"):
        E("SKR-FW-01", d, 443, "https")
    E("SKR-FW-01", "SKR-MAIL-01", 25, "smtp")
    E("SKR-WEB-01", "SKR-APP-01", 8443)
    E("SKR-WEB-02", "SKR-APP-01", 8443)
    E("SKR-MAIL-01", "SKR-APP-01", 1433)
    for w in ws_ids:
        E(w, "SKR-APP-01", 445, "smb")
        if rng.random() < 0.3:
            E(w, "SKR-DC-01", 88, "kerberos")
    E("SKR-APP-01", "SKR-DB-01", 1433)
    E("SKR-APP-01", "SKR-FS-01", 445, "smb")
    E("SKR-APP-01", "SKR-DC-01", 88, "kerberos")
    E("SKR-APP-01", "SKR-APP-02", 8443)
    E("SKR-APP-02", "SKR-DB-01", 1433)
    E("SKR-FS-01", "SKR-BKP-01", 445, "smb")
    E("SKR-BKP-01", "SKR-DC-01", 9389, "adws")
    E("SKR-DC-01", "SKR-DB-PROD", 88, "kerberos")
    E("SKR-DB-01", "SKR-DB-PROD", 1433, "replication")
    E("SKR-DB-PROD", "SKR-BKP-02", 445, "smb")

    # --- deliberate misconfigurations ---
    pivot_ws = rng.choice(ws_ids)
    E(pivot_ws, "SKR-FS-01", 445, "smb")          # corp workstation straight into servers zone
    E("SKR-APP-01", "SKR-BKP-01", 445, "smb")      # backup reachable from corp
    E("SKR-WEB-02", "SKR-DB-01", 1433)             # DMZ host reaches internal DB

    # random intra-corp chatter
    for _ in range(rng.randint(2, 5)):
        a, b = rng.sample(ws_ids, 2)
        E(a, b, 445, "smb")

    # --- vulnerabilities ---
    n = 0
    for h in hosts:
        if h.kind == "internet":
            continue
        count = {"firewall": 2, "webserver": rng.randint(1, 2)}.get(
            h.kind, 1 if rng.random() < 0.85 else 2)
        for _ in range(count):
            v = _mk_vuln(rng, f"V-{n:03d}", h.id, h.kind)
            if h.kind == "firewall":
                # perimeter bugs: exploitable but NOT top of BLUE's global patch list
                v.severity = rng.randint(7, 8)
                v.exploitability = round(rng.uniform(0.65, 0.85), 2)
                v.noise = round(rng.uniform(0.25, 0.45), 2)
            vulns.append(v)
            n += 1
    # the crown jewel is hard but not impossible (hand-tuned odds, real intel labels)
    cj_vuln = Vuln(id=f"V-{n:03d}", host="SKR-DB-PROD", cve_label="CVE-2020-1472",
                   name="Zerologon", severity=10, exploitability=0.35, noise=0.5)
    intel.enrich(cj_vuln, blend=False)
    vulns.append(cj_vuln)
    n += 1

    # --- credential-reuse chains (grants target is always a network neighbor) ---
    def C(cid, kind, owner, stored, grants):
        creds.append(Credential(id=cid, kind=kind, owner=owner, stored_on=stored, grants=grants))

    C("C-01", "ssh_key", "U-07", "SKR-WEB-01", "SKR-APP-01")          # web -> app
    C("C-02", "token", "U-02", "SKR-APP-01", "SKR-DB-01")             # app -> db
    C("C-03", "password", "U-03", pivot_ws, "SKR-FS-01")              # ws -> fileserver
    C("C-04", "ssh_key", "U-04", "SKR-FS-01", "SKR-BKP-01")           # fs -> backup
    C("C-05", "password", "U-01", "SKR-BKP-01", "SKR-DC-01")          # backup -> DC (!)
    C("C-06", "kerberos_ticket", "U-01", "SKR-DC-01", "SKR-DB-PROD")  # DC -> crown jewel
    C("C-07", "password", "U-05", "SKR-MAIL-01", rng.choice(ws_ids))  # phish-y mail cred
    C("C-08", "ssh_key", "U-02", "SKR-APP-02", "SKR-DB-01")
    for i, w in enumerate(rng.sample(ws_ids, min(3, len(ws_ids)))):
        C(f"C-09-{i}", "password", rng.choice(["U-06", "U-08"]), w, w)  # decoys

    # invariant: every credential's GRANTS target must be reachable from where it is stored
    for c in creds:
        if c.stored_on != c.grants and (c.stored_on, c.grants) not in seen_pairs:
            E(c.stored_on, c.grants, 445, "smb")

    spec = GraphSpec(seed=seed, hosts=hosts, edges=edges, vulns=vulns,
                     creds=creds, users=users, crown_jewel="SKR-DB-PROD")

    # initial fog of war: INTERNET is RED's beachhead; its neighbors are known,
    # and their vulns are already revealed (public-facing services are fingerprintable).
    hmap = {h.id: h for h in hosts}
    hmap["INTERNET"].compromised = True
    hmap["INTERNET"].discovered = True
    for e in edges:
        if e.src == "INTERNET":
            hmap[e.dst].discovered = True
            hmap[e.dst].vulns_revealed = True

    return spec


def path_guarantee_count(spec: GraphSpec) -> int:
    count, _, _ = count_viable_paths(
        spec.hosts, spec.edges, spec.vulns, spec.creds,
        spec.crown_jewel, maxlen=8, cap=100, gen_mode=True,
    )
    return count


def generate_with_guarantee(seed: int, required: int = 3, max_tries: int = 50) -> tuple[GraphSpec, int]:
    s = seed
    for _ in range(max_tries):
        spec = generate(s)
        if path_guarantee_count(spec) >= required:
            return spec, s
        s += 1
    raise RuntimeError(f"could not generate a valid network after {max_tries} seeds from {seed}")
