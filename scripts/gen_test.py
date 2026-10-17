"""P1 checkpoint: generate seeds 0..19 offline, verify the path guarantee,
and (if Neo4j creds are set) write one graph to Aura and cross-check in Cypher.

Usage: .venv/bin/python scripts/gen_test.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()


def main() -> int:
    from app import generator

    failures = 0
    for seed in range(20):
        spec = generator.generate(seed)
        n = generator.path_guarantee_count(spec)
        zones = {}
        for h in spec.hosts:
            zones[h.zone] = zones.get(h.zone, 0) + 1
        status = "OK " if n >= 3 else "FAIL"
        if n < 3:
            failures += 1
        print(f"[{status}] seed={seed:2d} hosts={len(spec.hosts):2d} edges={len(spec.edges):2d} "
              f"vulns={len(spec.vulns):2d} creds={len(spec.creds):2d} qualifying_paths={n:3d} zones={zones}")

    # reseed loop sanity
    t0 = time.time()
    spec, used = generator.generate_with_guarantee(42)
    print(f"\ngenerate_with_guarantee(42) -> seed {used} in {time.time()-t0:.3f}s, "
          f"paths={generator.path_guarantee_count(spec)}")

    # optional: write to Aura and cross-check with Cypher
    uri, pw = os.getenv("NEO4J_URI", ""), os.getenv("NEO4J_PASSWORD", "")
    if uri and pw:
        from app import db, queries, schema

        if db.init_driver(uri, os.getenv("NEO4J_USER", "neo4j"), pw):
            schema.apply_constraints(db.run_sync)
            t0 = time.time()
            db.run_sync(queries.WIPE)
            db.run_sync(queries.WRITE_HOSTS, rows=[{"id": h.id, "props": h.model_dump()} for h in spec.hosts])
            db.run_sync(queries.SET_CROWN_JEWEL, id=spec.crown_jewel)
            db.run_sync(queries.WRITE_EDGES, rows=[e.model_dump() for e in spec.edges])
            db.run_sync(queries.WRITE_VULNS, rows=[{"host": v.host, "id": v.id, "props": v.model_dump(exclude={"host", "id"})} for v in spec.vulns])
            db.run_sync(queries.WRITE_USERS, rows=[{"id": u.id, "props": u.model_dump(exclude={"id"})} for u in spec.users])
            db.run_sync(queries.WRITE_CREDS, rows=[c.model_dump() | {"props": c.model_dump(exclude={"id", "stored_on", "grants", "owner"})} for c in spec.creds])
            db.run_sync(queries.WRITE_ADMIN_OF, rows=[{"u": u, "h": h} for u, h in generator.ADMIN_OF])
            print(f"Aura write: {time.time()-t0:.2f}s")
            n = db.run_sync(queries.GUARANTEE)[0]["n"]
            print(f"Cypher guarantee check: {n} (expected >= 3) -> {'OK' if n >= 3 else 'FAIL'}")
    else:
        print("\nNeo4j creds not set — skipped Aura write/cross-check (offline mode).")

    print("\nRESULT:", "FAIL" if failures else "ALL OK")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
