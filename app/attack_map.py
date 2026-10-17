"""MITRE ATT&CK mapping for game actions.

RED actions map to ATT&CK Enterprise techniques; BLUE actions map to ATT&CK
Mitigations (M1xxx) / D3FEND-style counters. Attached to every action_result
event so the frontend heatmap and the export layer work for live games AND
offline replays with no extra event types.
"""
from __future__ import annotations

ACTION_TECHNIQUES: dict[str, list[dict]] = {
    # ---- RED (ATT&CK Enterprise techniques) ----
    "SCAN": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "EXPLOIT": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "HARVEST_CREDS": [
        {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    ],
    "LATERAL_MOVE": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    ],
    "EXFILTRATE": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    # ---- BLUE (ATT&CK Mitigations / D3FEND counters) ----
    "PATCH": [
        {"id": "M1051", "name": "Update Software", "tactic": "Mitigation"},
    ],
    "ISOLATE": [
        {"id": "M1030", "name": "Network Segmentation", "tactic": "Mitigation"},
    ],
    "ROTATE_CREDS": [
        {"id": "M1026", "name": "Privileged Account Management", "tactic": "Mitigation"},
    ],
    "INVESTIGATE": [
        {"id": "M1047", "name": "Audit", "tactic": "Mitigation"},
    ],
    "DEPLOY_HONEYPOT": [
        {"id": "D3-DE", "name": "Decoy Environment", "tactic": "Deception"},
    ],
}

# column order for the frontend heatmap
TACTIC_ORDER = [
    "Discovery", "Initial Access", "Credential Access", "Defense Evasion",
    "Lateral Movement", "Exfiltration", "Mitigation", "Deception",
]

ATTACK_URL = "https://attack.mitre.org/techniques/{id}/"
MITIGATION_URL = "https://attack.mitre.org/mitigations/{id}/"


def techniques_for(action: str) -> list[dict]:
    return ACTION_TECHNIQUES.get(action, [])


def technique_url(tid: str) -> str:
    return MITIGATION_URL.format(id=tid) if tid.startswith("M") else ATTACK_URL.format(id=tid)
