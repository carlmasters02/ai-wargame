"""Benchmark harness: play N headless matches per (RED, BLUE) pairing and
produce a leaderboard (JSON + Markdown) in benchmarks/.

Heuristic policies run offline and fast (~50ms/match). With AIAND_API_KEY set,
pass --red/--blue model IDs to benchmark LLM agents; matches then run with a
concurrency limit and record per-match fallback rates.

Usage:
  .venv/bin/python scripts/benchmark.py                          # 10 heuristic matches
  .venv/bin/python scripts/benchmark.py -n 30 --out benchmarks/leaderboard
  .venv/bin/python scripts/benchmark.py --red deepseek-ai/deepseek-v4-pro \
      --blue moonshotai/kimi-k3 -n 4 --concurrency 2
"""
import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings  # noqa: E402
from app.db import Mirror  # noqa: E402
from app.engine import GameEngine  # noqa: E402
from app.events import Broadcaster  # noqa: E402

REPLAY_DIR = "/tmp/opencode/bench_replays"


async def play(seed: int, red_model: str | None, blue_model: str | None,
               timeout: float = 600) -> dict:
    engine = GameEngine(settings, Broadcaster(record_dir=REPLAY_DIR), Mirror(False))
    engine.turn_delay = 0.0
    engine.reports_enabled = False
    if settings.aiand_enabled and (red_model or blue_model):
        from app.agents import Agent
        if red_model:
            engine.agents["red"] = Agent("red", red_model, settings)
        if blue_model:
            engine.agents["blue"] = Agent("blue", blue_model, settings)
    await engine.reset(seed)
    t0 = time.time()
    await engine.start()
    while engine.state in ("running", "paused") and not engine.winner:
        await asyncio.sleep(0.02)
        if time.time() - t0 > timeout:
            return {"seed": seed, "winner": "timeout", "rounds": engine.round}
    m = engine.compute_metrics()
    return {
        "seed": engine.spec.seed, "winner": engine.winner, "reason": engine.win_reason,
        "rounds": engine.round, "actions": len(engine.turns),
        "fallbacks": sum(1 for t in engine.turns if t.fallback),
        "paths_final": m["paths"], "impact": m["impact"],
        "alerts": len(engine.all_alerts), "time_s": round(time.time() - t0, 2),
    }


def aggregate(pair: str, results: list[dict]) -> dict:
    valid = [r for r in results if r["winner"] in ("red", "blue")]
    red_wins = sum(1 for r in valid if r["winner"] == "red")
    n = len(valid)
    return {
        "pairing": pair,
        "matches": len(results), "finished": n, "timeouts": len(results) - n,
        "red_win_rate": round(red_wins / n, 3) if n else None,
        "blue_win_rate": round((n - red_wins) / n, 3) if n else None,
        "avg_rounds": round(sum(r["rounds"] for r in valid) / n, 1) if n else None,
        "avg_fallbacks_per_match": round(sum(r["fallbacks"] for r in valid) / n, 1) if n else None,
        "results": results,
    }


def to_markdown(board: dict) -> str:
    lines = ["# AI Wargame — Benchmark Leaderboard", "",
             f"_{board['generated_at']} — MAX_TURNS={settings.MAX_TURNS}_", "",
             "| RED vs BLUE | matches | RED win % | BLUE win % | avg rounds | fallbacks/match |",
             "|---|---|---|---|---|---|"]
    for p in board["pairings"]:
        rw = f"{p['red_win_rate'] * 100:.0f}%" if p["red_win_rate"] is not None else "-"
        bw = f"{p['blue_win_rate'] * 100:.0f}%" if p["blue_win_rate"] is not None else "-"
        lines.append(f"| {p['pairing']} | {p['finished']}/{p['matches']} | {rw} | {bw} | "
                     f"{p['avg_rounds'] or '-'} | {p['avg_fallbacks_per_match'] or 0} |")
    return "\n".join(lines) + "\n"


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--matches", type=int, default=10)
    ap.add_argument("--seed-start", type=int, default=1000)
    ap.add_argument("--red", default=None, help="RED model id (default: heuristic)")
    ap.add_argument("--blue", default=None, help="BLUE model id (default: heuristic)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--out", default="benchmarks/leaderboard")
    args = ap.parse_args()

    pair = f"{args.red or 'heuristic'} vs {args.blue or 'heuristic'}"
    seeds = [args.seed_start + i for i in range(args.matches)]
    print(f"benchmark: {pair} — {len(seeds)} matches (seeds {seeds[0]}..{seeds[-1]})")
    if (args.red or args.blue) and not settings.aiand_enabled:
        print("WARNING: AIAND_API_KEY not set — LLM sides will fall back to heuristics")

    sem = asyncio.Semaphore(args.concurrency)

    async def guarded(seed):
        async with sem:
            r = await play(seed, args.red, args.blue)
            print(f"  seed {r['seed']}: {r['winner'].upper():7s} round {r.get('rounds', '-'):>3} "
                  f"({r.get('actions', 0)} actions, {r.get('fallbacks', 0)} fallbacks, "
                  f"{r.get('time_s', 0)}s)")
            return r

    t0 = time.time()
    results = await asyncio.gather(*(guarded(s) for s in seeds))
    board = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "wall_time_s": round(time.time() - t0, 1),
             "pairings": [aggregate(pair, list(results))]}

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out + ".json", "w") as fh:
        json.dump(board, fh, indent=2)
    with open(args.out + ".md", "w") as fh:
        fh.write(to_markdown(board))
    p = board["pairings"][0]
    print(f"\nRED win rate: {p['red_win_rate']} over {p['finished']} matches "
          f"({board['wall_time_s']}s wall) → {args.out}.json/.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
