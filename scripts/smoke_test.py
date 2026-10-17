"""P3 checkpoint: full headless games with heuristic policies only.

Usage: .venv/bin/python scripts/smoke_test.py [seed ...]
"""
import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.db import Mirror
from app.engine import GameEngine
from app.events import Broadcaster


async def play(seed: int, quiet: bool = True) -> dict:
    bus = Broadcaster(record_dir=os.path.join(tempfile.gettempdir(), "ai_wargame", "replays_test"))
    engine = GameEngine(settings, bus, Mirror(enabled=False))
    engine.turn_delay = 0.0
    t0 = time.time()
    await engine.reset(seed)

    # security invariant: BLUE observation must never leak ground truth
    obs_blue = engine.build_observation("blue")
    blob = json.dumps(obs_blue)
    assert '"compromised": true' not in blob.lower(), "BLUE observation leaks compromised flag!"

    await engine.start()
    while engine.state in ("running", "paused") and not engine.winner:
        await asyncio.sleep(0.05)
        if time.time() - t0 > 120:
            raise TimeoutError("game did not finish in 120s")
    dt = time.time() - t0
    m = engine.compute_metrics()
    red_turns = [t for t in engine.turns if t.side == "red"]
    summary = {
        "seed": engine.spec.seed, "winner": engine.winner, "reason": engine.win_reason,
        "rounds": engine.round, "actions": len(engine.turns), "time_s": round(dt, 2),
        "paths_final": m["paths"], "impact": m["impact"], "alerts": len(engine.all_alerts),
        "red_actions": [f"{t.action}({t.args.get('host', '')})" for t in red_turns],
    }
    if not quiet:
        for t in engine.turns:
            print(f"  [{t.round:2d}|{t.side:4s}] {t.action:15s} {t.args} -> "
                  f"{'OK' if t.success else 'FAIL'} {t.narration}")
    return summary


async def main(seeds):
    results = []
    for s in seeds:
        r = await play(s)
        print(f"seed {r['seed']:3d}: {r['winner'].upper():4s} wins in round {r['rounds']:2d} "
              f"({r['actions']:3d} actions, {r['time_s']:5.2f}s) — {r['reason']}")
        print(f"          RED: {' -> '.join(r['red_actions'][:14])}")
        results.append(r)

    # determinism check: same seed, same outcome
    a = await play(seeds[0])
    b = await play(seeds[0])
    same = a["winner"] == b["winner"] and a["rounds"] == b["rounds"]
    print(f"\ndeterminism: {'OK' if same else 'FAIL'} (seed {seeds[0]}: "
          f"{a['winner']}/{a['rounds']} vs {b['winner']}/{b['rounds']})")
    ok = all(r["winner"] for r in results) and same
    print("RESULT:", "ALL OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    seeds = [int(x) for x in sys.argv[1:]] or [1, 2, 3]
    raise SystemExit(asyncio.run(main(seeds)))
