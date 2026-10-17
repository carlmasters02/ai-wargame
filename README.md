# ⛩ AI Wargame — Autonomous Red vs. Blue on a Live Graph

Two LLM agents fight a turn-based cyber wargame over a procedurally generated
corporate network ("Sakura Logistics K.K.") that lives in **Neo4j Aura**.
**RED** (DeepSeek via ai&) attacks with fog of war; **BLUE** (Kimi via ai&)
defends using only a noisy alert queue. The headline metric — *viable attack
paths to the crown jewel* — is recomputed every turn and charted live.

Pure simulation: vulnerabilities are abstract game objects with CVE-style
labels. No real exploit code, no real scanning, no real network interaction.

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env   # fill in NEO4J_* and AIAND_*
.venv/bin/python scripts/check_models.py   # confirms ai& model IDs + Aura connectivity
```

**Neo4j gotcha:** in the Aura credentials file, `NEO4J_USERNAME` is the
**instance ID** (e.g. `a1b2c3d4`), *not* `neo4j`. Copy all three fields from
that file (`NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`) into `.env`.

## Run

```bash
.venv/bin/uvicorn app.main:app --port 8000
# open http://localhost:8000  →  press ▶ START
```

Without `AIAND_API_KEY` both sides play with built-in heuristic policies
(fully playable offline demo). Without `NEO4J_*` the game runs in offline
graph mode (Neo4j mirroring skipped). Both models are pre-warmed at startup
so the first turn of a demo is never a cold call.

## How a match works

- RED gets 1 action/turn (SCAN, EXPLOIT, HARVEST_CREDS, LATERAL_MOVE,
  EXFILTRATE). BLUE gets 2 action points/turn (PATCH, ISOLATE, ROTATE_CREDS,
  DEPLOY_HONEYPOT, INVESTIGATE).
- RED sees only discovered hosts (fog of war); BLUE sees the full topology but
  never the true compromised flags — only a noisy alert queue (~15% false
  positives). INVESTIGATE reveals a host's true status.
- House rules that keep games dramatic: **max 1 PATCH per turn** (change
  window), and the **perimeter firewall can't be isolated** (would take the
  business offline) — BLUE must defend it with patching and monitoring.
- Win conditions: RED wins by exfiltrating the crown jewel; BLUE wins by
  fully evicting RED or surviving `MAX_TURNS` (20) rounds.

## Real-world threat intel

Every CVE in the pool is enriched with **live data**: EPSS exploit probability
(FIRST.org) and CISA Known-Exploited-Vulnerabilities flags
(`scripts/fetch_intel.py` → committed cache `data/cve_intel.json`, so games
stay deterministic and demos work offline). EPSS is blended into exploit
success odds, shown in host tooltips (hover any node) and in the LLM action
menus — the agents literally reason over the same intel a real SOC uses.
25 of the 29 pooled CVEs are on CISA's KEV list.

## MITRE ATT&CK, live and exportable

Every action is tagged with its ATT&CK technique (RED) or mitigation (BLUE) and
accumulates into a **live ATT&CK heatmap** under the graph. When the match ends,
export the fight as a real artifact:

- **🗺 ATT&CK LAYER** — Navigator layer JSON (`/api/export/navigator`), imports
  straight into https://mitre-attack.github.io/attack-navigator/
- **📦 STIX BUNDLE** — STIX 2.1 bundle (`/api/export/stix`) with attack-pattern
  objects + external references, importable into TIP tooling

## Judge controls (bottom bar)

START / PAUSE / STEP, speed slider, **INJECT ZERO-DAY**, **INSIDER THREAT**,
seed + RESET, per-side **model dropdowns** (see below), and a GOD VIEW /
RED VIEW fog-of-war toggle above the map.

## Model switching — yes, it's live

The dropdowns list every model on the ai& account (fetched from
`GET /models` at startup) and take effect on the **next turn, mid-game, no
restart** — the feed labels each card with the model that produced it.
`.env` only sets the *starting* models. If a model can't answer in time, the
game silently falls back to a heuristic policy (tagged `[fallback]` in the
feed) and never stalls.

Demo-safe models (fast + clean JSON): `deepseek-ai/deepseek-v4-pro`,
`moonshotai/kimi-k3`, `openai/gpt-oss-120b` (tested live, mid-game swaps
verified). Avoid `zai-org/glm-5.3` for live play — it reasons too long and
keeps hitting the token/time budget (you'll see `[fallback]` cards).

## Endgame

When the winner banner appears you can open the **📋 After-Action Report**
(LLM-written: outcome, timeline, MITRE ATT&CK mapping, turning points,
recommendations) or the **🕒 Match Timeline** (every action, alert, and judge
intervention in order with match stats). Close the banner to inspect the
final graph; both views stay available from the docked buttons bottom-right.

## Offline replay (venue Wi-Fi insurance)

Every match is recorded to `replays/*.jsonl`. A golden match is committed:

```bash
.venv/bin/python -m app.replay replays/golden.jsonl --speed 2 --port 8000
```

The frontend cannot tell the difference. `--speed` scales the original pacing
(2× turns a ~5 min match into ~2.5 min).

## Demo script (3 min)

1. (15s) "Every company's network is a graph. Attackers think in graphs;
   defenders think in lists. We made two AIs fight on the graph."
2. (60s) START the golden-seed match. Toggle RED VIEW (fog of war) ↔ GOD VIEW.
   Point at the attack-path counter + sparkline.
3. (30s) Judge clicks INJECT ZERO-DAY → path count spikes → BLUE reacts.
4. (45s) RED vs BLUE reasoning side by side; swap a model live
   (ai& = one-line model change).
5. (30s) Game over → MATCH TIMELINE to narrate the fight, then the
   after-action report with MITRE ATT&CK mapping.

## Architecture

```
app/
  main.py       FastAPI: static, /ws, REST controls (all mutations via engine command queue)
  engine.py     game loop, legal actions, resolution, detection, win checks (single writer)
  generator.py  seeded procedural network + path-guarantee check (>= 3 paths, len 4-8)
  paths.py      viable-attack-path metric (pure Python, capped DFS + BFS shortest)
  queries.py    all Cypher (schema writes, Cypher metric variants, Turn log)
  agents.py     LLM agents (action-by-index JSON contract, repair ladder, heuristics)
  report.py     after-action report (LLM with static fallback)
  events.py     WS broadcaster + JSONL match recorder
  replay.py     offline replay server
  intel.py      EPSS/KEV enrichment (deterministic committed cache)
  attack_map.py action → MITRE ATT&CK technique/mitigation mapping
  export.py     ATT&CK Navigator layer + STIX 2.1 bundle builders
scripts/
  check_models.py   P0 gate: ai& model IDs + Neo4j connectivity
  gen_test.py       P1 gate: 20 seeds × guarantee check (+ Aura write & Cypher cross-check)
  smoke_test.py     P3 gate: full headless heuristic games + BLUE fog-of-war leak test
  find_seed.py      P7: drama-scored seed picker
  fetch_intel.py    refresh data/cve_intel.json from FIRST.org EPSS + CISA KEV
```

Golden seed: **6** — the committed `replays/golden.jsonl` is a full LLM match
on this seed (DeepSeek RED vs Kimi BLUE, ~20 rounds, BLUE holds the line,
full after-action report included). Run `scripts/find_seed.py` to scout other
dramatic seeds.

## Troubleshooting

- **`Neo.ClientError.Security.Unauthorized` on startup** — almost always the
  username: on Aura it's the instance ID from the credentials file, not
  `neo4j`. If that's right, reset the password (console → instance → ⋯ →
  Reset Password). The game still runs in offline graph mode meanwhile.
- **Kimi returns empty responses** — kimi-k3 is a reasoning model; it needs
  `max_tokens` headroom for reasoning + answer (handled in `app/agents.py`).
- **A model keeps showing `[fallback]` cards** — it's too slow or not
  answering with JSON; pick another from the dropdown (see "Model switching").
