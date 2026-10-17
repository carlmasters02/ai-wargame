"""P7: score seeds for demo drama and print the best candidates.

Usage: .venv/bin/python scripts/find_seed.py [n_seeds]
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.db import Mirror
from app.engine import GameEngine
from app.events import Broadcaster


async def play(seed: int):
    replay_dir = os.path.join(tempfile.gettempdir(), "ai_wargame", "find_seed")
    engine = GameEngine(settings, Broadcaster(record_dir=replay_dir), Mirror(False))
    engine.turn_delay = 0.0
    await engine.reset(seed)
    await engine.start()
    while engine.state in ("running", "paused") and not engine.winner:
        await asyncio.sleep(0.02)
    hist = [m["paths"] for m in engine.metrics_history]
    swings = sum(abs(b - a) for a, b in zip(hist, hist[1:]))
    peak_comp = max((m["compromised"] for m in engine.metrics_history), default=0)
    # drama scoring
    score = swings * 2 + peak_comp * 5
    if engine.winner == "red":
        score += 60
    if 10 <= engine.round <= 18:      # decided mid-late: best pacing
        score += 40
    if engine.winner == "blue" and engine.round > settings.MAX_TURNS:
        score += 10
    return {"seed": engine.spec.seed, "winner": engine.winner, "rounds": engine.round,
            "swings": swings, "peak_comp": peak_comp, "score": score}


async def main(n: int):
    results = [await play(s) for s in range(n)]
    results.sort(key=lambda r: -r["score"])
    print(f"{'seed':>5} {'winner':>6} {'rounds':>6} {'swings':>6} {'peak':>4} {'score':>6}")
    for r in results[:10]:
        print(f"{r['seed']:>5} {r['winner']:>6} {r['rounds']:>6} {r['swings']:>6} "
              f"{r['peak_comp']:>4} {r['score']:>6}")


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 40))
