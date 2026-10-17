"""Real-world CVE intel: EPSS exploit probability + CISA KEV flags.

Loads data/cve_intel.json (committed; refresh with scripts/fetch_intel.py).
Enrichment is deterministic — the cache is fixed, so seeded games and smoke
tests remain reproducible. If the cache is missing, enrichment is a no-op and
the game plays exactly as before.
"""
from __future__ import annotations

import json
import logging
import os

from .models import Vuln

log = logging.getLogger("intel")

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "cve_intel.json")

_cache: dict | None = None


def _load() -> dict:
    global _cache
    if _cache is None:
        try:
            with open(_PATH, encoding="utf-8") as fh:
                _cache = json.load(fh).get("cves", {})
            log.info("CVE intel loaded: %d entries (data/cve_intel.json)", len(_cache))
        except OSError:
            log.warning("data/cve_intel.json missing — run scripts/fetch_intel.py; "
                        "EPSS/KEV enrichment disabled")
            _cache = {}
    return _cache


def intel_status() -> dict:
    """Small status blob for the /api/state endpoint."""
    try:
        with open(_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return {"available": True, "fetched_at": data.get("fetched_at"),
                "cves": len(data.get("cves", {}))}
    except OSError:
        return {"available": False}


def lookup(cve: str) -> dict | None:
    return _load().get(cve)


def enrich(v: Vuln, blend: bool = True) -> None:
    """Attach EPSS/KEV to a vuln and blend EPSS into its exploitability.

    Blend: 80% authored value + 20% EPSS, clamped. Hand-tuned vulns (the crown
    jewel Zerologon, judge-injected zero-days) pass blend=False — their
    authored difficulty stays, but they still get EPSS/KEV labels.
    """
    info = _load().get(v.cve_label)
    if not info:
        return
    if info.get("epss") is not None:
        v.epss = round(info["epss"], 4)
        if blend:
            blended = 0.8 * v.exploitability + 0.2 * v.epss
            v.exploitability = round(max(0.05, min(0.95, blended)), 2)
    v.kev = bool(info.get("kev"))


def tag(v: Vuln) -> str:
    """Short human tag for action descriptions / LLM observations."""
    bits = []
    if v.epss is not None:
        bits.append(f"EPSS {v.epss:.0%}")
    if v.kev:
        bits.append("CISA-KEV")
    return f" [{', '.join(bits)}]" if bits else ""
