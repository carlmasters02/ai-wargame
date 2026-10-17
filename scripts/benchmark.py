"""Benchmark harness and model-evaluation tournament.

Two modes:

  Single pairing (RED vs BLUE):
    python scripts/benchmark.py                                  # heuristic baseline
    python scripts/benchmark.py --red deepseek-ai/deepseek-v4-pro \
        --blue moonshotai/kimi-k3 -n 8 --concurrency 2

  Round-robin tournament (every model plays every other as both RED and BLUE,
  producing a single Elo rating per model plus SOC scorecards):
    python scripts/benchmark.py --models deepseek-ai/deepseek-v4-pro,moonshotai/kimi-k3,openai/gpt-oss-120b \
        -n 6 --concurrency 3

Writes benchmarks/leaderboard.{json,md}: win rates with Wilson 95% intervals,
SOC scorecards (MTTD/MTTR, false-isolation rate, exposure reduction, RED/BLUE
composite scores), model cost (latency/tokens/fallbacks), and Elo ratings.
"""
import argparse
import asyncio
import itertools
import json
import math
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings  # noqa: E402
from app.db import Mirror  # noqa: E402
from app.engine import GameEngine  # noqa: E402
from app.events import Broadcaster  # noqa: E402

REPLAY_DIR = os.path.join(tempfile.gettempdir(), "ai_wargame", "bench_replays")
HEURISTIC = "heuristic"


# ------------------------------------------------------------------ one match
async def play(seed: int, red_model: str | None, blue_model: str | None,
               timeout: float = 600) -> dict:
    engine = GameEngine(settings, Broadcaster(record_dir=REPLAY_DIR), Mirror(False))
    engine.turn_delay = 0.0
    engine.reports_enabled = False
    if settings.aiand_enabled:
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
            await engine.stop()
            return {"seed": seed, "winner": "timeout", "rounds": engine.round}
    return {"seed": engine.spec.seed, "winner": engine.winner, "reason": engine.win_reason,
            "rounds": engine.round, "actions": len(engine.turns),
            "time_s": round(time.time() - t0, 2),
            "scorecard": engine.scorecard()}


# ------------------------------------------------------------------ statistics
def _wilson(k: int, n: int) -> tuple[float, float, float]:
    """Wilson 95% confidence interval for a proportion (point, low, high)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    z, p = 1.96, k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(p, 3), round(max(0, centre - half), 3), round(min(1, centre + half), 3))


def _mean_ci(xs: list[float]) -> dict | None:
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    m = sum(xs) / len(xs)
    if len(xs) < 2:
        return {"mean": round(m, 2), "ci95": 0.0, "n": len(xs)}
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return {"mean": round(m, 2), "ci95": round(1.96 * math.sqrt(var / len(xs)), 2), "n": len(xs)}


def _sc(results, path):
    """Pull a nested scorecard field from every finished result."""
    out = []
    for r in results:
        sc = r.get("scorecard")
        if not sc:
            continue
        cur = sc
        for key in path:
            cur = cur.get(key) if isinstance(cur, dict) else None
            if cur is None:
                break
        out.append(cur)
    return out


def aggregate(pair: str, results: list[dict]) -> dict:
    valid = [r for r in results if r["winner"] in ("red", "blue")]
    n = len(valid)
    red_wins = sum(1 for r in valid if r["winner"] == "red")
    rwr = _wilson(red_wins, n)
    return {
        "pairing": pair, "matches": len(results), "finished": n,
        "timeouts": len(results) - n,
        "red_win_rate": rwr[0], "red_win_ci95": [rwr[1], rwr[2]],
        "blue_win_rate": round(1 - rwr[0], 3) if n else None,
        "avg_rounds": _mean_ci([r["rounds"] for r in valid]),
        "red_score": _mean_ci(_sc(valid, ["red", "score"])),
        "blue_score": _mean_ci(_sc(valid, ["blue", "score"])),
        "mttd_rounds": _mean_ci(_sc(valid, ["blue", "mttd_rounds"])),
        "mttr_rounds": _mean_ci(_sc(valid, ["blue", "mttr_rounds"])),
        "false_isolations": _mean_ci(_sc(valid, ["blue", "false_isolations"])),
        "exposure_reduction": _mean_ci(_sc(valid, ["blue", "exposure_reduction"])),
        "red_stealth": _mean_ci(_sc(valid, ["red", "stealth"])),
        "red_latency_ms": _mean_ci(_sc(valid, ["red_cost", "avg_latency_ms"])),
        "blue_latency_ms": _mean_ci(_sc(valid, ["blue_cost", "avg_latency_ms"])),
        "red_avg_tokens": _mean_ci(_sc(valid, ["red_cost", "avg_tokens"])),
        "blue_avg_tokens": _mean_ci(_sc(valid, ["blue_cost", "avg_tokens"])),
        "fallback_rate": _mean_ci(_sc(valid, ["blue_cost", "fallback_rate"])
                                  + _sc(valid, ["red_cost", "fallback_rate"])),
        # compact per-match rows (full scorecards stay in the live game_over event, not on disk)
        "results": [_compact(r) for r in results],
    }


def _compact(r: dict) -> dict:
    sc = r.get("scorecard") or {}
    row = {"seed": r.get("seed"), "winner": r.get("winner"), "rounds": r.get("rounds"),
           "time_s": r.get("time_s")}
    if sc:
        row.update(red_score=sc["red"]["score"], blue_score=sc["blue"]["score"],
                   mttd=sc["blue"]["mttd_rounds"], exposure_reduction=sc["blue"]["exposure_reduction"])
    return row


def elo(matches: list[tuple[str, str, str]], k: float = 24.0, base: float = 1500.0) -> dict:
    """matches = [(red_model, blue_model, winner_side)]. Every model plays both sides
    across the round-robin, so role advantage averages out of the single rating."""
    r: dict[str, float] = {}
    for red, blue, _ in matches:
        r.setdefault(red, base)
        r.setdefault(blue, base)
    for red, blue, winner in matches:
        exp_red = 1 / (1 + 10 ** ((r[blue] - r[red]) / 400))
        s_red = 1.0 if winner == "red" else 0.0
        r[red] += k * (s_red - exp_red)
        r[blue] += k * ((1 - s_red) - (1 - exp_red))
    return {m: round(v) for m, v in sorted(r.items(), key=lambda kv: -kv[1])}


# ------------------------------------------------------------------ markdown
def _cell(m):
    if not m:
        return "-"
    return f"{m['mean']}±{m['ci95']}" if m.get("ci95") else f"{m['mean']}"


def to_markdown(board: dict) -> str:
    lines = ["# AI Wargame — Benchmark Leaderboard", "",
             f"_{board['generated_at']} — MAX_TURNS={settings.MAX_TURNS}, "
             f"{board['wall_time_s']}s wall_", ""]
    if board.get("elo"):
        lines += ["## Elo ratings (round-robin, both sides)", "",
                  "| Rank | Model | Elo |", "|---|---|---|"]
        for i, (m, e) in enumerate(board["elo"].items(), 1):
            lines.append(f"| {i} | {m} | {e} |")
        lines.append("")
    lines += ["## Pairings", "",
              "| RED vs BLUE | matches | RED win % (95% CI) | RED score | BLUE score | "
              "MTTD | MTTR | false-iso | exposure↓ | BLUE tok |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for p in board["pairings"]:
        ci = f"{p['red_win_rate']*100:.0f}% [{p['red_win_ci95'][0]*100:.0f}–{p['red_win_ci95'][1]*100:.0f}]" \
            if p["red_win_rate"] is not None else "-"
        lines.append(
            f"| {p['pairing']} | {p['finished']}/{p['matches']} | {ci} | "
            f"{_cell(p['red_score'])} | {_cell(p['blue_score'])} | {_cell(p['mttd_rounds'])} | "
            f"{_cell(p['mttr_rounds'])} | {_cell(p['false_isolations'])} | "
            f"{_cell(p['exposure_reduction'])} | {_cell(p['blue_avg_tokens'])} |")
    lines += ["", "_MTTD/MTTR in rounds (lower is better); exposure↓ is the fraction of peak "
              "attack-paths BLUE removed; scores are 0–100 SOC composites._", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ driver
async def _run(seeds, pairings, concurrency):
    sem = asyncio.Semaphore(concurrency)

    async def one(seed, red, blue):
        async with sem:
            r = await play(seed, None if red == HEURISTIC else red,
                           None if blue == HEURISTIC else blue)
            r["red_model"], r["blue_model"] = red, blue
            w = r["winner"]
            print(f"  [{red} vs {blue}] seed {r['seed']}: {str(w).upper():7s} "
                  f"r{r.get('rounds','-')} ({r.get('time_s',0)}s)")
            return r

    tasks = [one(s, red, blue) for (red, blue) in pairings for s in seeds]
    return await asyncio.gather(*tasks)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--matches", type=int, default=10)
    ap.add_argument("--seed-start", type=int, default=1000)
    ap.add_argument("--red", default=None, help="RED model id (single-pairing mode)")
    ap.add_argument("--blue", default=None, help="BLUE model id (single-pairing mode)")
    ap.add_argument("--models", default=None,
                    help="comma-separated model ids for a round-robin tournament")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--out", default="benchmarks/leaderboard")
    args = ap.parse_args()

    seeds = [args.seed_start + i for i in range(args.matches)]
    if (args.red or args.blue or args.models) and not settings.aiand_enabled:
        print("WARNING: AIAND_API_KEY not set — LLM sides fall back to heuristics")

    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
        pairings = [(a, b) for a, b in itertools.permutations(models, 2)]
        print(f"tournament: {len(models)} models, {len(pairings)} pairings × {len(seeds)} seeds")
    else:
        pairings = [(args.red or HEURISTIC, args.blue or HEURISTIC)]
        print(f"benchmark: {pairings[0][0]} vs {pairings[0][1]} × {len(seeds)} seeds")

    t0 = time.time()
    results = await _run(seeds, pairings, args.concurrency)
    by_pair: dict[tuple, list] = {}
    for r in results:
        by_pair.setdefault((r["red_model"], r["blue_model"]), []).append(r)

    board = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wall_time_s": round(time.time() - t0, 1),
        "pairings": [aggregate(f"{red} vs {blue}", rs) for (red, blue), rs in by_pair.items()],
    }
    if args.models:
        board["elo"] = elo([(r["red_model"], r["blue_model"], r["winner"])
                            for r in results if r["winner"] in ("red", "blue")])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out + ".json", "w") as fh:
        json.dump(board, fh, indent=2)
    with open(args.out + ".md", "w") as fh:
        fh.write(to_markdown(board))
    print(f"\nwrote {args.out}.json/.md ({board['wall_time_s']}s wall)")
    if board.get("elo"):
        print("Elo:", board["elo"])
    else:
        p = board["pairings"][0]
        print(f"RED win rate: {p['red_win_rate']} [{p['red_win_ci95'][0]}–{p['red_win_ci95'][1]}] "
              f"over {p['finished']} matches")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
