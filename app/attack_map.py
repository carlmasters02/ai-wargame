"""MITRE ATT&CK mapping for game actions.

RED actions map to ATT&CK Enterprise techniques; BLUE actions map to ATT&CK
Mitigations (M1xxx) / D3FEND-style counters. `stix_id` is MITRE's canonical STIX
object id (enterprise-attack bundle), so STIX exports reference the official
objects instead of minting duplicates. Attached to every action_result
event so the frontend heatmap and the export layer work for live games AND
offline replays with no extra event types.
"""
from __future__ import annotations

ACTION_TECHNIQUES: dict[str, list[dict]] = {
    # ---- RED (ATT&CK Enterprise techniques) ----
    "SCAN": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "stix_id": "attack-pattern--e3a12395-188d-4051-9a16-ea8e14d07b88"},
    ],
    "EXPLOIT": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "stix_id": "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c"},
    ],
    "HARVEST_CREDS": [
        {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "stix_id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22"},
    ],
    "LATERAL_MOVE": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "stix_id": "attack-pattern--54a649ff-439a-41a4-9856-8d144a2551ba"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "stix_id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81"},
    ],
    "EXFILTRATE": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "stix_id": "attack-pattern--92d7da27-2d91-488e-a00c-059dc162766d"},
    ],
    "PHISH_USER": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "stix_id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"},
    ],
    "C2_BEACON": [
        {"id": "T1071", "name": "Application Layer Protocol (C2)", "tactic": "Command and Control", "stix_id": "attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6"},
    ],
    "DEFENSE_EVASION": [
        {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion", "stix_id": "attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69"},
    ],
    # ---- BLUE (ATT&CK Mitigations / D3FEND counters) ----
    "PATCH": [
        {"id": "M1051", "name": "Update Software", "tactic": "Mitigation", "stix_id": "course-of-action--e5d930e9-775a-40ad-9bdb-b941d8dfe86b"},
    ],
    "ISOLATE": [
        {"id": "M1030", "name": "Network Segmentation", "tactic": "Mitigation", "stix_id": "course-of-action--86598de0-b347-4928-9eb0-0acbfc21908c"},
    ],
    "ROTATE_CREDS": [
        {"id": "M1026", "name": "Privileged Account Management", "tactic": "Mitigation", "stix_id": "course-of-action--9bb9e696-bff8-4ae1-9454-961fc7d91d5f"},
    ],
    "INVESTIGATE": [
        {"id": "M1047", "name": "Audit", "tactic": "Mitigation", "stix_id": "course-of-action--cc2399fd-3cd3-4319-8d0a-fbd6420cdaf8"},
    ],
    "DEPLOY_HONEYPOT": [
        {"id": "D3-DE", "name": "Decoy Environment", "tactic": "Deception"},
    ],
    "REIMAGE": [
        {"id": "M1053", "name": "Data Backup (restore known-good image)", "tactic": "Mitigation", "stix_id": "course-of-action--3efe43d1-6f3f-4fcb-ab39-4a730971f70b"},
    ],
    "THREAT_HUNT": [
        {"id": "M1047", "name": "Audit (threat hunt sweep)", "tactic": "Mitigation", "stix_id": "course-of-action--cc2399fd-3cd3-4319-8d0a-fbd6420cdaf8"},
    ],
}

# column order for the frontend heatmap
TACTIC_ORDER = [
    "Discovery", "Initial Access", "Credential Access", "Defense Evasion",
    "Command and Control", "Lateral Movement", "Exfiltration", "Mitigation", "Deception",
]

ATTACK_URL = "https://attack.mitre.org/techniques/{id}/"
MITIGATION_URL = "https://attack.mitre.org/mitigations/{id}/"


def techniques_for(action: str) -> list[dict]:
    return ACTION_TECHNIQUES.get(action, [])


def technique_url(tid: str) -> str:
    return MITIGATION_URL.format(id=tid) if tid.startswith("M") else ATTACK_URL.format(id=tid)
