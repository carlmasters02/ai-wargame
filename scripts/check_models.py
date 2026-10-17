"""P0 checkpoint: confirm ai& model IDs + Neo4j connectivity.

Usage: .venv/bin/python scripts/check_models.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()


def main() -> int:
    ok = True

    # --- Neo4j ---
    uri = os.getenv("NEO4J_URI", "")
    pw = os.getenv("NEO4J_PASSWORD", "")
    if uri and pw:
        try:
            from neo4j import GraphDatabase

            d = GraphDatabase.driver(uri, auth=(os.getenv("NEO4J_USER") or os.getenv("NEO4J_USERNAME") or "neo4j", pw))
            d.verify_connectivity()
            print(f"[neo4j] CONNECTED  {uri}")
            d.close()
        except Exception as e:  # noqa: BLE001
            print(f"[neo4j] FAILED     {e}")
            ok = False
    else:
        print("[neo4j] SKIP       NEO4J_URI/NEO4J_PASSWORD not set (offline graph mode will be used)")

    # --- ai& models ---
    base = os.getenv("AIAND_BASE_URL", "")
    key = os.getenv("AIAND_API_KEY", "")
    if base and key:
        try:
            from openai import OpenAI

            client = OpenAI(base_url=base, api_key=key, timeout=20)
            models = [m.id for m in client.models.list()]
            print(f"[ai&]   {len(models)} models available:")
            for m in models:
                print(f"          - {m}")
            for env_name in ("ATTACKER_MODEL", "DEFENDER_MODEL", "REPORT_MODEL"):
                want = os.getenv(env_name, "")
                hit = want in models
                ok = ok and hit
                print(f"[ai&]   {env_name}={want!r} -> {'OK' if hit else 'NOT FOUND, pick one of the IDs above'}")
        except Exception as e:  # noqa: BLE001
            print(f"[ai&]   FAILED     {e}")
            ok = False
    else:
        print("[ai&]   SKIP       AIAND_BASE_URL/AIAND_API_KEY not set (heuristic policies will be used)")

    print("\nRESULT:", "ALL OK" if ok else "NEEDS ATTENTION (see above)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
