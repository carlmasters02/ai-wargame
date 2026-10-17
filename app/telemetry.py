"""SOC telemetry layer: realistic log events and detection rules.

Real defenders don't get a labelled "alert" — they get a firehose of log events
from different sensors (Windows Security, Sysmon, firewall, proxy, mail gateway,
IDS/EDR) and a set of detection rules that turn a few of those events into
alerts. BLUE triages the stream; most events are benign.

Each RED action maps to the log events it would generate on real infrastructure,
tagged with the MITRE ATT&CK data source. A detection rule converts an event
into an alert with a confidence; whether it actually fires is still the engine's
seeded detection roll (so game balance is preserved), but now an alert carries
the sensor, the signature and the rule that caught it — and BLUE can also see the
raw events that did NOT trip a rule, exactly like a real log search.
"""
from __future__ import annotations

# action -> the log event a real sensor would record. Fields:
#   source:    the sensor / log source
#   signature: a human-readable event signature (what shows up in the SIEM)
#   data_source: MITRE ATT&CK data source (DS####) the detection draws on
#   benign_rate: how often normal business activity produces a look-alike event
#                (drives realistic false positives)
ACTION_EVENTS: dict[str, dict] = {
    "SCAN": {
        "source": "IDS", "signature": "Horizontal port sweep from internal host",
        "data_source": "DS0029", "data_source_name": "Network Traffic", "benign_rate": 0.30,
    },
    "EXPLOIT": {
        "source": "EDR", "signature": "Exploit behaviour / anomalous child process",
        "data_source": "DS0009", "data_source_name": "Process", "benign_rate": 0.10,
    },
    "HARVEST_CREDS": {
        "source": "Sysmon", "signature": "LSASS process access (Sysmon EID 10)",
        "data_source": "DS0009", "data_source_name": "Process", "benign_rate": 0.08,
    },
    "LATERAL_MOVE": {
        "source": "Windows Security", "signature": "Remote logon with explicit creds (EID 4624/4648)",
        "data_source": "DS0028", "data_source_name": "Logon Session", "benign_rate": 0.35,
    },
    "PHISH_USER": {
        "source": "Mail Gateway", "signature": "Suspicious inbound mail / credential-harvest link",
        "data_source": "DS0017", "data_source_name": "Email Gateway", "benign_rate": 0.25,
    },
    "C2_BEACON": {
        "source": "Proxy", "signature": "Periodic beaconing to low-reputation host",
        "data_source": "DS0029", "data_source_name": "Network Traffic", "benign_rate": 0.15,
    },
    "DEFENSE_EVASION": {
        "source": "Windows Security", "signature": "Security/audit log cleared (EID 1102)",
        "data_source": "DS0015", "data_source_name": "Application Log", "benign_rate": 0.02,
    },
    "EXFILTRATE": {
        "source": "Proxy", "signature": "Large outbound transfer to external host",
        "data_source": "DS0029", "data_source_name": "Network Traffic", "benign_rate": 0.12,
    },
    "HONEYPOT": {
        "source": "Deception", "signature": "Decoy asset interaction (high fidelity)",
        "data_source": "DS0029", "data_source_name": "Network Traffic", "benign_rate": 0.0,
    },
}

# which benign look-alike signatures normal activity can throw (for false positives)
BENIGN_EVENTS = [
    ("Windows Security", "Scheduled service logon (EID 4624 type 5)", "DS0028", "Logon Session"),
    ("IDS", "Vulnerability scanner sweep (authorised)", "DS0029", "Network Traffic"),
    ("Proxy", "Backup job outbound transfer", "DS0029", "Network Traffic"),
    ("EDR", "Admin tool flagged as dual-use (PsExec)", "DS0009", "Process"),
    ("Sysmon", "Credential manager access by IT tooling", "DS0009", "Process"),
    ("Mail Gateway", "Marketing bulk mail quarantined", "DS0017", "Email Gateway"),
]


def event_for(action: str, host: str) -> dict | None:
    """The telemetry event a successful/attempted RED action records on `host`."""
    spec = ACTION_EVENTS.get(action)
    if not spec or not host:
        return None
    return {"source": spec["source"], "signature": spec["signature"], "host": host,
            "data_source": spec["data_source"], "data_source_name": spec["data_source_name"]}


def benign_event(host: str, pick) -> dict:
    """A benign look-alike event on a clean host (false-positive source). `pick` = rng.choice."""
    source, signature, ds, ds_name = pick(BENIGN_EVENTS)
    return {"source": source, "signature": signature, "host": host,
            "data_source": ds, "data_source_name": ds_name}
