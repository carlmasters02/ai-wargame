"""Fetch real-world threat intel for every CVE in the generator pool.

Sources (both free, no API key):
  - EPSS  (FIRST.org)  — probability a CVE is exploited in the wild in 30 days
  - CISA KEV           — vulnerabilities with confirmed active exploitation

Writes data/cve_intel.json, which is COMMITTED to the repo so game generation
stays deterministic and demos work offline. Re-run to refresh.

Usage: .venv/bin/python scripts/fetch_intel.py
"""
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.generator import CVE_POOL  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "data", "cve_intel.json")

# CVEs used outside the pool (crown jewel + judge interventions)
EXTRA_CVES = ["CVE-2020-1472", "CVE-2021-44228"]

EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ai-wargame-intel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def main() -> int:
    pool_cves = sorted({cve for pool in CVE_POOL.values() for cve, _, _ in pool})
    all_cves = sorted(set(pool_cves) | set(EXTRA_CVES))
    print(f"enriching {len(all_cves)} CVEs ({len(pool_cves)} pool + {len(EXTRA_CVES)} scripted)")

    # EPSS supports comma-separated batches; keep batches modest for URL length
    epss: dict[str, dict] = {}
    for i in range(0, len(all_cves), 30):
        batch = all_cves[i:i + 30]
        data = fetch_json(EPSS_URL.format(cves=",".join(batch)))
        for row in data.get("data", []):
            epss[row["cve"]] = {"epss": float(row["epss"]),
                                "percentile": float(row["percentile"])}
        print(f"  EPSS batch {i // 30 + 1}: {len(batch)} CVEs")
        time.sleep(1)  # be polite

    kev_data = fetch_json(KEV_URL, timeout=60)
    kev_set = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    print(f"  CISA KEV catalog: {len(kev_set)} CVEs total")

    intel = {}
    for cve in all_cves:
        e = epss.get(cve, {})
        intel[cve] = {
            "epss": e.get("epss"),
            "epss_percentile": e.get("percentile"),
            "kev": cve in kev_set,
        }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    payload = {"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "sources": {"epss": "https://api.first.org/data/v1/epss",
                           "kev": KEV_URL},
               "cves": intel}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)

    kev_hits = [c for c, v in intel.items() if v["kev"]]
    top = sorted(intel.items(), key=lambda kv: -(kv[1]["epss"] or 0))[:5]
    print(f"\nwrote {OUT}")
    print(f"KEV-listed in pool: {len(kev_hits)}: {', '.join(kev_hits) or 'none'}")
    print("highest EPSS:", ", ".join(f"{c}={v['epss']:.0%}" for c, v in top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
