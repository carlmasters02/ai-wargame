# ⛩ AI Wargame — Autonomous Red vs. Blue on a Live Graph

Two AI agents fight a turn-based cyber wargame over a procedurally generated
corporate network, **Sakura Logistics K.K.** **RED** (default: DeepSeek) is an
attacker trying to steal the company's crown-jewel database. **BLUE** (default:
Kimi) is the security team trying to stop it. You watch the fight live on an
interactive network map, step in as the "judge" with surprise events, swap the
AI models mid-game, and export the match as real MITRE ATT&CK / STIX artifacts.

> **Pure simulation.** Vulnerabilities are abstract game objects that carry
> real CVE labels and real-world threat intel. There is no exploit code, no
> scanning, and no real network traffic of any kind.

**Contents**

1. [Quick start](#1-quick-start)
2. [Configuration](#2-configuration)
3. [The dashboard](#3-the-dashboard)
4. [Reading the network map](#4-reading-the-network-map)
5. [Controls](#5-controls)
6. [How a match works](#6-how-a-match-works)
7. [The AI agents](#7-the-ai-agents)
8. [The network generator](#8-the-network-generator)
9. [Real-world threat intel](#9-real-world-threat-intel)
10. [MITRE ATT&CK heatmap and exports](#10-mitre-attck-heatmap-and-exports)
11. [Endgame: report and timeline](#11-endgame-report-and-timeline)
12. [Campaign mode and benchmarks](#12-campaign-mode-and-benchmarks)
13. [Replays and offline demos](#13-replays-and-offline-demos)
14. [Neo4j integration (optional)](#14-neo4j-integration-optional)
15. [API reference](#15-api-reference)
16. [Scripts](#16-scripts)
17. [Project layout](#17-project-layout)
18. [Demo script (3 minutes)](#18-demo-script-3-minutes)
19. [Troubleshooting](#19-troubleshooting)

---

## 1. Quick start

Requires **Python 3.10+**.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env          # optional: add API keys (see below)
.venv/bin/uvicorn app.main:app --port 8000
```

Or with Docker:

```bash
docker build -t ai-wargame .
docker run -p 8000:8000 --env-file .env ai-wargame
```

Run the tests with `pip install -r requirements-dev.txt && pytest`.

Open **http://localhost:8000** and press **▶ START**.

No keys are needed to try it. Without an AI API key both sides play with
built-in heuristic policies (a fully playable offline game), and without Neo4j
credentials the game simply skips mirroring the board to a database.

---

## 2. Configuration

All settings live in `.env` (copy `.env.example`). Every value is optional.

| Variable | Default | What it does |
|---|---|---|
| `AIAND_API_KEY` | *(empty)* | Key for the ai& inference API (OpenAI-compatible). Empty → both sides use heuristic policies. |
| `AIAND_BASE_URL` | `https://api.aiand.example/v1` | API base URL. Any OpenAI-compatible endpoint works. |
| `ATTACKER_MODEL` | `deepseek-chat` | Starting model for RED. |
| `DEFENDER_MODEL` | `kimi-k2` | Starting model for BLUE. |
| `REPORT_MODEL` | `kimi-k2` | Model that writes the after-action report. |
| `REPORT_TIMEOUT` | `180` | Seconds per model for the streamed after-action report. |
| `WARGAME_TOKEN` | *(empty)* | If set, every control endpoint requires it (header `X-Wargame-Token`, or `?token=` in the page URL). Spectating never does. Set this before exposing the server. |
| `MODEL_PROVIDERS` | `{}` | JSON provider map for cross-provider benchmarking (see §12). A model id `openai:gpt-4o` routes to the named provider; a bare id uses ai&. |
| `NEO4J_URI` | *(empty)* | Neo4j Aura URI, e.g. `neo4j+s://xxxx.databases.neo4j.io`. |
| `NEO4J_USER` (or `NEO4J_USERNAME`) | `neo4j` | On Aura this is the **instance ID**, not `neo4j`. |
| `NEO4J_PASSWORD` | *(empty)* | Neo4j password. |
| `GAME_SEED` | `42` | Network seed loaded at startup. |
| `MAX_TURNS` | `20` | Number of rounds BLUE must survive. |
| `PATH_METRIC_IMPL` | `python` | Reserved. The engine currently always uses the Python path metric. |

Recommended live-demo models (fast, reliable JSON): `deepseek-ai/deepseek-v4-pro`,
`moonshotai/kimi-k3`, `openai/gpt-oss-120b`. Avoid `zai-org/glm-5.3` for live
play: it reasons too long and keeps hitting the time budget.

Check that your model IDs and Neo4j connection work before a demo:

```bash
.venv/bin/python scripts/check_models.py
```

---

## 3. The dashboard

```
┌──────────────────────────── TOP BAR: round · attack paths · sparkline · stats ─────────────────────────┐
│ RED PANEL            │                 NETWORK MAP                 │ BLUE PANEL                         │
│ RED's reasoning and  │   live graph of the company network         │ ALERT QUEUE (what BLUE can see)    │
│ actions, newest      │   [GOD VIEW | RED VIEW]  (top-right)        │ BLUE's reasoning and actions       │
│ first                │   MITRE ATT&CK heatmap bar  (bottom)        │                                    │
└──────────────────────┴─────────────────────────────────────────────┴────────────────────────────────────┘
  CONTROLS: start · pause · step · speed · judge buttons · seed/reset · campaign · 🏆 · models · persona
```

**Top bar**

| Stat | Meaning |
|---|---|
| **ROUND** | Current round / `MAX_TURNS`. |
| **ATTACK PATHS TO CROWN JEWEL** | The headline metric: how many viable routes RED currently has to the crown jewel (see [§6.7](#67-the-attack-path-metric)). Shows `250+` when capped. The sparkline beside it charts this number over the match. |
| **HOSTS PWNED** | Hosts RED controls right now (the internet itself isn't counted). |
| **BUSINESS IMPACT** | Total cost of BLUE's isolations. Cutting hosts off the network hurts the business. |
| **ALERTS** | Every alert raised so far, including false positives. |

**Side panels.** Each turn adds a card: the agent's thought (💭), then each
action with ✔/✘ and a one-line result. Cards show which model produced them,
a **FALLBACK** badge when the heuristic policy played instead of the AI, and
ATT&CK technique chips. Judge events appear as grey system cards in both feeds.
The **ALERT QUEUE** shows BLUE's last 8 alerts with a confidence bar;
honeypot hits are highlighted.

---

## 4. Reading the network map

### Node colours = network zones

The network is layered from the internet inward:

| Colour | Zone | Hosts |
|---|---|---|
| Grey | **Internet** | `INTERNET`, RED's starting point. |
| Orange | **DMZ** (public-facing) | `SKR-FW-01` firewall, `SKR-WEB-01/02` web servers, `SKR-MAIL-01` mail server. |
| Blue | **Corp** (office) | `SKR-APP-01` app server, `SKR-WS-0xx` employee workstations. |
| Purple | **Servers** | `SKR-DC-01` domain controller, `SKR-FS-01/02` file servers, `SKR-DB-01` database, `SKR-APP-02`, `SKR-BKP-01` backup, sometimes `SKR-S3-01` cloud bucket. |
| Red | **Restricted** | `SKR-DB-PROD` (the crown jewel), `SKR-BKP-02`. |

### Markers

| What you see | Meaning |
|---|---|
| **Solid pulsing red glow** | **Compromised.** RED controls this host right now. |
| **Gold ring + glow, larger node** | **The crown jewel** (`SKR-DB-PROD`). RED wins by exfiltrating it. |
| **Thin pulsing red ring + thick glowing red links** | The **shortest viable attack path** from RED's position to the crown jewel. |
| **Magenta diamond** (GOD VIEW only) | A **honeypot** BLUE deployed (`SKR-HP-01`…). Hidden in RED VIEW because RED doesn't know it's fake. |
| **Dark grey node with dashed grey ring** | **Isolated.** BLUE cut it off the network. |
| **Faded, see-through node** (GOD VIEW only) | RED hasn't discovered this host yet. |
| **Dashed grey link** | Connection blocked by an isolation. |
| **Red dots travelling along a link** | RED just moved laterally with stolen credentials. |

### GOD VIEW vs RED VIEW

The toggle in the top-right of the map switches perspective. **GOD VIEW** shows
the whole network, honeypots included. **RED VIEW** shows only what the
attacker has discovered: the fog of war RED is actually playing under.

### Hover tooltips

Hover over a node's **dot** to see its kind, zone, OS, criticality, status
flags (compromised, isolated, honeypot, 📡 C2 beacon, 👑 crown jewel) and every
vulnerability with its CVE, severity, **EPSS** exploit probability and badges
for **CISA KEV** and **ZERO-DAY**. Patched vulns are struck through.

---

## 5. Controls

### Bottom bar

| Control | What it does |
|---|---|
| **▶ START** | Starts (or resumes) the match. Does nothing on a finished match; press RESET first. |
| **⏸ PAUSE / ▶ RESUME** | Pauses once the current turn finishes; the label follows the server's real state. |
| **⏭ STEP** | Plays exactly **one side's turn** (RED's 1 action, or BLUE's 2) and then pauses. Works from idle, paused, or running. Alternates RED → BLUE → RED… |
| **SPEED** slider | 0.5× to 6× pacing between turns (base delay 3 s). |
| **💣 INJECT ZERO-DAY** | Judge event: drops `CVE-2026-1337` (exploit 0.9, near-silent) on a random clean corp/servers host. If RED already knows that host, it hears about the bug immediately. The attack-path count usually spikes. |
| **🕴 INSIDER THREAT** | Judge event: an insider hands RED one credential, preferring a privileged user's. |
| **SEED** + **↺ RESET** | Generates a fresh network from that seed and resets the match. Also aborts a running campaign. |
| **Campaign selector** | SINGLE MATCH / BEST OF 3 / BEST OF 5. See [§12](#12-campaign-mode-and-benchmarks). |
| **🏆** | Opens the benchmark leaderboard. |
| **RED / BLUE model dropdowns** | Every model on your ai& account. Takes effect on the **next turn, mid-game, no restart**. Disabled in heuristic mode. |
| **RED persona dropdown** | Patient APT / Ransomware crew / Ghost. See [§7.3](#73-red-personas). Disabled in heuristic mode. |

Judge buttons, model swaps and persona changes work at any time: during a
match, while paused, or before START.

### Endgame buttons

When a match ends a banner announces the winner with buttons for the
**📋 AFTER-ACTION REPORT**, **🕒 MATCH TIMELINE**, **🗺 ATT&CK LAYER** and
**📦 STIX BUNDLE**. Close the banner (**✕ CLOSE**) to inspect the final map;
the same four buttons stay docked bottom-right.

---

## 6. How a match works

### 6.1 Turn structure

A match is up to `MAX_TURNS` (default 20) **rounds**. Each round, **RED takes
1 action**, then **BLUE takes 2 actions**. Each turn the engine:

1. builds the side's **observation** (what that side is allowed to know),
2. lists every **legal action** as a numbered menu,
3. asks the agent (AI or heuristic) to pick by number,
4. resolves the action with seeded dice and updates the network,
5. rolls for **detection**, recomputes the **attack-path metric**, and
   streams everything to the browser.

### 6.2 Win conditions

| Winner | How |
|---|---|
| **RED** | Exfiltrates the crown jewel `SKR-DB-PROD`. |
| **BLUE** | Evicts RED and keeps the attacker out for 3 consecutive rounds (so RED can't just walk back in through an unpatched door), **or** survives all `MAX_TURNS` rounds. |

### 6.3 RED's actions

RED starts at `INTERNET` and only knows the firewall in front of it.

| Action | Effect | Detection noise |
|---|---|---|
| **SCAN** | From an owned host: reveals the vulnerabilities of every host RED has discovered. | 0.15 |
| **EXPLOIT** | Attacks a revealed vuln on a reachable host. Success chance = the vuln's exploitability. Success compromises the host and reveals its neighbours (their vulns stay hidden until a SCAN). | per vuln |
| **HARVEST_CREDS** | Steals every credential stored on an owned host. | 0.40 |
| **LATERAL_MOVE** | Uses a stolen, unrotated credential to take over the host it grants. **Always succeeds**, quietly. | 0.20 |
| **PHISH_USER** | Independent initial access: a spearphish reaches any employee by email (no network position needed), 45% success on privileged users / 70% on regular ones. Steals all their credentials and, on success, lands a foothold on the victim's endpoint — so RED can enter the corp zone without breaching the perimeter. Detection rolls at the mail gateway. | 0.30 |
| **C2_BEACON** | Plants persistence on an owned host: the **next ISOLATE on it fails** (and still costs BLUE the impact) unless BLUE investigates first. | 0.25 |
| **DEFENSE_EVASION** | Wipes logs on an owned host: detection noise for actions targeting it ×0.4 from now on. | 0.10 |
| **EXFILTRATE** | Only once the crown jewel is owned. **RED wins.** | 0.80 |

### 6.4 BLUE's actions

| Action | Effect |
|---|---|
| **PATCH** | Permanently fixes a vuln (menu shows the 12 most severe). **Max one PATCH per turn** (change window); a second one fails. |
| **ISOLATE** | Cuts a flagged host off the network and evicts RED from it. Costs business impact = criticality, ×2 in servers/restricted zones. The perimeter firewall **can't** be isolated (it would take the business offline). |
| **REIMAGE** | Restores a **confirmed-compromised** host from a known-good backup: evicts the attacker and wipes persistence while the host stays online (cost = criticality). It does **not** fix vulns, so patch the entry point too. This is how BLUE cleans the firewall. |
| **ROTATE_CREDS** | Invalidates every credential of a user, killing any RED has stolen. |
| **DEPLOY_HONEYPOT** | Adds a decoy host beside a chosen host (near the crown jewel, an alerted host, the DC or DB-01; max 3 per match). It's reachable from that host **and** from everything upstream of it. Touching it gives BLUE a guaranteed 97%-confidence alert, and RED gets no foothold. |
| **INVESTIGATE** | Reveals a host's true status right now, and burns any C2 beacon on it. |
| **THREAT_HUNT** | Investigates every not-recently-checked host in a whole zone at once and burns their beacons. |

### 6.5 Fog of war

- **RED** sees only hosts it has discovered. Compromising a host reveals its
  neighbours; their vulnerabilities stay hidden until a SCAN.
- **BLUE** sees the full topology and every unpatched vuln, but **never** sees
  which hosts are compromised. It works from the alert queue and investigations.
  Its exposure score is an **estimate** — attack paths from the internet and
  *confirmed* footholds, assuming any unrotated credential may already be stolen
  — so it never silently reacts to a RED action that raised no alert.
- **Investigations are snapshots.** A host found clean can be compromised a
  round later. A verdict goes stale after 3 rounds, or as soon as a newer alert
  hits that host; then BLUE may investigate again.

### 6.6 Alerts and false positives

Every RED action rolls for detection: an alert fires with probability equal to
the action's noise (×0.4 on hosts where RED wiped logs), with a confidence
score. After each BLUE turn there's a 15% chance of a **false positive** on a
clean host. False positives look exactly like real alerts (same alert types),
so BLUE has to investigate to tell them apart.

### 6.7 SOC telemetry and detection

Instead of abstract "alerts", RED's actions generate realistic **log events** on
the sensors a real network runs — Windows Security (logons), Sysmon (LSASS
access), EDR (exploit behaviour), the firewall/proxy (beaconing, exfil), the
mail gateway (phishing) and an IDS (scans) — each tagged with its **MITRE
ATT&CK data source** (DS####). A detection rule turns a fraction of those events
into **alerts** carrying the sensor and the signature that caught them; the rest
stay in the raw SIEM stream. Normal business activity throws benign look-alike
events (a backup job's outbound transfer, an authorised scanner) that sometimes
trip a rule — the false positives an analyst has to rule out. BLUE sees both the
alert queue and the recent-events stream and triages like a real SOC: correlate
an EDR hit with a follow-on remote logon, confirm with INVESTIGATE, then act.

### 6.8 SOC cases (incident workflow)

Alerts don't float free — they roll up into **cases** (incidents), the way a SOC
triages. The first alert on a host opens a case (`INC-001`…); more alerts fold in
and raise its severity (low → critical, from confidence × asset criticality).
INVESTIGATE or THREAT_HUNT moves it to *investigating* or **closes** it as a false
positive; ISOLATE/REIMAGE marks it *contained*. The **📁 case board** shows the
live queue, and the scorecard reports cases opened/contained, false positives, and
**mean time to contain** — the metrics a SOC is actually measured on. `GET /api/cases`.

### 6.9 The attack-path metric

After every action the engine counts **viable attack paths** from RED's
positions (the internet plus every compromised host) to the crown jewel, up
to 8 hops, capped at 250. A path is viable when:

- every link on it is unblocked,
- no host on it is isolated or a honeypot,
- every host after the start is *breachable*: already compromised, has an
  unpatched vuln, or is granted by a credential RED has stolen and BLUE hasn't
  rotated.

It's a live read of how exposed the company is: patching, rotating and
isolating push it down; exploits, stolen creds and zero-days push it up. The
shortest such path is highlighted in red on the map.

---

## 7. The AI agents

### 7.1 How they decide

Each turn an agent receives its observation (JSON) plus a **numbered list of
concrete legal actions**, and answers with JSON:

```json
{"thought": "<= 60 words", "action_index": 3}          // RED
{"thought": "<= 60 words", "action_indices": [0, 7]}   // BLUE
```

Picking by number means the model can never invent an illegal move. The answer
parser tolerates code fences and stray text, and falls back to reading the
model's reasoning trace if the reply is empty.

### 7.2 Fallback and timing

Each side gets a hard **30-second budget** per turn (up to two attempts). If
the model is too slow or answers garbage, the built-in heuristic policy plays
that turn instead, the card shows a **FALLBACK** badge, and the game never
stalls. With no API key, both sides are heuristic for the whole match.

### 7.3 RED personas

Changeable from the footer dropdown at any time (LLM games only):

| Persona | Play style |
|---|---|
| 🥷 **Patient APT** (default) | Quiet credential play, careful exploitation. |
| 🔥 **Ransomware crew** | Fast and loud: exploits over credentials, goes straight for high-value hosts, ignores beacons and evasion. |
| 👻 **Ghost** | Obsessively stealthy: wipes logs before every noisy move and beacons every owned server. |

### 7.4 Model switching

The model dropdowns list every model on the ai& account (fetched at startup)
and switch on the next turn, mid-game, with no restart. The panel header and
each feed card show which model produced it. `.env` only sets the starting
models.

---

### 7.5 Human vs AI

Either side can be played by a person instead of a model: the footer **RED: AI /
You** and **BLUE: AI / You** selectors switch control live. On your turn a **YOUR
MOVE** panel shows the exact same numbered legal-action menu the AI gets — with
the CVE, EPSS and KEV detail — and you pick 1 action (RED) or 2 (BLUE). Your
turn is scored identically to a model's (it shows up tagged `human` in the
scorecard and timeline), so you can measure yourself against the AI, or play BLUE
against an AI attacker as hands-on SOC training. The game waits for your move; the
AI opponent plays automatically between your turns.

## 8. The network generator

Every network is generated deterministically from its **seed**: the same seed
always gives the same company and, with heuristic agents, the same match.

- A layered topology: internet → firewall → DMZ → corp → servers → restricted,
  with 10–14 workstations and an optional cloud bucket and second file server.
- **Deliberate misconfigurations**: a workstation with a direct line into the
  servers zone, backups reachable from corp, a DMZ host that can reach an
  internal database.
- **Credential-reuse chains**: an SSH key on a web server opens the app server,
  a backup admin's password on the backup server opens the domain controller,
  a Kerberos ticket on the DC opens the crown jewel, plus decoys.
- Vulnerabilities drawn from a pool of 29 real CVEs (Log4Shell, Zerologon,
  Citrix Bleed, regreSSHion, …) matched to each host type.
- A **guarantee check** ensures at least 3 distinct attack paths of 4–8 hops
  exist from the internet to the crown jewel; otherwise it moves to the next
  seed.

---

## 9. Real-world threat intel

Every CVE in the pool carries live intel from two free sources:

- **EPSS** (FIRST.org): the probability a CVE gets exploited in the wild in the
  next 30 days. Blended 20% into each vuln's exploit odds.
- **CISA KEV**: whether the CVE is on the Known Exploited Vulnerabilities list
  (25 of the 29 are).

The data is cached in `data/cve_intel.json`, which is committed so games stay
deterministic and demos work offline. Refresh it with
`.venv/bin/python scripts/fetch_intel.py`. The intel shows in host tooltips and
in the agents' action menus, so the AIs reason over the same signals a real SOC
uses.

---

## 10. MITRE ATT&CK heatmap and exports

Every action is tagged with an ATT&CK technique (RED, e.g. `T1190` Exploit
Public-Facing Application) or mitigation (BLUE, e.g. `M1051` Update Software).
The **heatmap bar** under the map groups them by tactic and counts uses live.

When a match ends you can export it from the banner (the endpoints also work
mid-match):

- **🗺 ATT&CK LAYER**: a Navigator layer JSON (`/api/export/navigator`) of
  RED's successful techniques. Import it at
  https://mitre-attack.github.io/attack-navigator/.
- **📦 STIX BUNDLE**: a STIX 2.1 bundle (`/api/export/stix`) with
  attack-pattern objects and references, importable into threat-intel tooling.

---

## 11. Endgame: report and timeline

- **📋 After-action report**: streamed from `REPORT_MODEL` (falling back to the
  attacker model, then a deterministic template) from the full turn log:
  outcome, timeline, ATT&CK mapping table, turning points and recommendations
  grounded in what was left unresolved (stolen-but-unrotated creds, exploited-
  but-unpatched vulns, un-investigated alerts). The report header always says
  whether a model or the template wrote it. It opens a couple of seconds after
  the match ends.
- **🕒 Match timeline**: every action, alert and judge intervention in order,
  with match stats (actions per side, alerts, interventions).

---

## 12. Campaign mode and benchmarks

**Campaign mode.** Choose BEST OF 3 or BEST OF 5 in the footer, then press
START. When a game ends, the next one starts automatically 6 seconds later on
the next seed, with a live series scoreboard (`GAME 2/3 · 🔴 1 — 0 🔵`). The
series ends with a champion card. RESET aborts the series.

**Benchmarks.** `scripts/benchmark.py` plays N headless matches per RED/BLUE
pairing and writes `benchmarks/leaderboard.{json,md}` (win rates, average
rounds, fallback rate). The 🏆 button shows the latest board.

```bash
.venv/bin/python scripts/benchmark.py -n 30                       # heuristic baseline (~1 s)
.venv/bin/python scripts/benchmark.py --red deepseek-ai/deepseek-v4-pro \
    --blue moonshotai/kimi-k3 -n 4 --concurrency 2                # LLM vs LLM
```

Options: `-n/--matches`, `--seed-start` (default 1000), `--red`, `--blue`
(model IDs; omit for heuristic), `--concurrency` (default 4), `--out`.

Every match produces a **SOC scorecard** (the 📊 button, or `game_over.scorecard`):

| Metric | Side | Meaning |
|---|---|---|
| **MTTD** | BLUE | mean rounds to detect a compromise |
| **MTTR** | BLUE | rounds from detection to eviction |
| **false isolations** | BLUE | hosts cut off / reimaged that RED never held (wasted downtime) |
| **exposure reduced** | BLUE | fraction of peak attack-paths removed by the end |
| **detected / missed** | BLUE | compromise coverage |
| **objective, rounds-to-objective** | RED | did it reach the crown jewel, how fast |
| **stealth** | RED | successful actions per alert raised |
| **model cost** | both | avg latency, tokens and fallback rate per decision |

Each side also gets a 0–100 composite **score and grade (A–F)**.

Every match also prices the incident in **dollars** — downtime from isolating or
reimaging hosts, incident-response effort per compromised host, and a breach
loss if RED reached the objective (anchored to public breach benchmarks). This
surfaces the "won, but at what cost" trade-off: a defender that isolates
everything wins the round but can run up seven figures in downtime.

**Cross-provider benchmarking.** Set `MODEL_PROVIDERS` and prefix a model id
with its provider (`openai:gpt-4o`, `anthropic:claude-...`); a bare id uses ai&.
RED and BLUE can run on different providers in the same match.

**Tournament mode** plays every model against every other as both RED and BLUE
and computes a single Elo rating (role advantage averages out):

```bash
python scripts/benchmark.py --models deepseek-ai/deepseek-v4-pro,moonshotai/kimi-k3,openai:gpt-4o     -n 6 --concurrency 3
```

**Balance baseline** (heuristic vs heuristic, 100 matches, seeds 2000–2099):
**RED 10% [5–17% 95% CI] / BLUE 90%**, BLUE score 80±2, MTTD 1.2 rounds,
exposure reduced 98% — a competitive baseline with two realistic entry vectors
(perimeter exploitation and spearphishing) and a defender that can genuinely
evict. LLM pairings vary with model quality, which is the point.

---

## 13. Replays and offline demos

Every live match is recorded to `replays/match_<time>_seed<N>.jsonl`
(git-ignored). The replay server streams a recording over the exact same
WebSocket contract, so the browser can't tell the difference: insurance if the
venue Wi-Fi dies.

```bash
.venv/bin/python -m app.replay replays/golden.jsonl --speed 2 --port 8000
```

`--speed` scales the original pacing (2× turns a ~5-minute match into ~2.5).
In replay mode the control buttons are no-ops and exports are unavailable.

The committed **`replays/golden.jsonl`** is a full LLM match on seed 6
(DeepSeek RED vs Kimi BLUE, 20 rounds, BLUE holds the line, report included).
It was recorded on an earlier build, before phishing, C2 beacons, evasion and
threat hunting existed, so those actions don't appear in it.

---

## 14. Neo4j integration (optional)

With `NEO4J_*` set, the network lives in **Neo4j** as the game board: hosts,
connections, vulns, users and credentials as nodes and relationships, plus a
`:Turn` node for every action linked to the host it affected. The engine stays
authoritative in memory and mirrors each change to Neo4j in the background, so
database latency never slows the game.

> ⚠ **RESET wipes the entire database** (`MATCH (n) DETACH DELETE n`) before
> writing the new network. Use a dedicated Aura instance.

For a database showcase, `app/queries.py` holds Cypher versions of the
attack-path metric (`METRIC_PATHS`, `SHORTEST_PATH`) you can paste into the
Aura browser during a match.

---

## 13a. Digital twin — import a real network

Play the wargame and run the exposure analysis on **your own** network, not just
the synthetic one. The **⬆ IMPORT** button loads:

- a **CSV asset inventory** (hosts, connections, known CVEs — `examples/sample_network.csv`
  shows the format), or
- an **Nmap XML** scan (hosts and the services between them).

Imported networks skip the synthetic path guarantee (a real network is whatever
it is), an internet beachhead is added automatically, and fog of war is seeded
from the perimeter. `POST /api/import` takes `{"format": "csv"|"nmap", "content": "..."}`.
Untrusted XML is parsed with `defusedxml` (XXE / billion-laughs safe). Once
imported, press ▶ START to watch the AIs fight over your topology, or 🎯 for the
prioritised fix plan for *your* exposure.

## 14a. Exposure analysis (prioritised remediation)

The **🎯** button answers the question a CISO actually asks: *of everything we
could fix, what cuts the most risk?* It measures how many viable attack paths to
the crown jewel each candidate fix (patch a vuln, rotate a user's credentials,
isolate/reimage a compromised host) removes **right now**, ranks them, and builds
a greedy **minimal fix plan** that drives exposure toward zero — a prioritised
remediation backlog. Available any time via `GET /api/exposure`. This is the core
of a continuous-threat-exposure-management (CTEM) workflow, run on the live graph.

## 15. API reference

### REST

| Method | Path | Body | Purpose |
|---|---|---|---|
| POST | `/api/start` | | Start / resume. |
| POST | `/api/pause` | | Pause. |
| POST | `/api/resume` | | Resume. |
| POST | `/api/step` | | Play one side's turn, then pause. |
| POST | `/api/speed` | `{"x": 2.0}` | Set speed (0.25–8). |
| POST | `/api/reset` | `{"seed": 6}` | New network + new match. |
| POST | `/api/intervene/zero_day` | | Judge: inject a zero-day. |
| POST | `/api/intervene/insider` | | Judge: insider threat. |
| POST | `/api/model` | `{"side": "red", "model": "…"}` | Swap a side's model. |
| POST | `/api/persona` | `{"persona": "apt"\|"ransomware"\|"ghost"}` | Change RED's persona. |

All `POST` endpoints require the `X-Wargame-Token` header when `WARGAME_TOKEN`
is set; `GET` endpoints and `/ws` never do.
| GET | `/api/models` | | Available and current models. |
| GET | `/api/state` | | State, round, winner, metrics, intel status. |
| GET | `/api/export/navigator` | | ATT&CK Navigator layer. |
| GET | `/api/export/stix` | | STIX 2.1 bundle. |
| GET | `/api/benchmarks` | | Latest leaderboard JSON. |

### WebSocket `/ws`

The server pushes `{"type": …, "payload": …}` events:

| Event | When |
|---|---|
| `graph_snapshot` | On connect and on reset: the full network. |
| `graph_patch` | Host flags, new honeypots, blocked links, updated vulns. |
| `metrics` | After every action: paths, shortest path, stats. |
| `status` | On connect: models, state, speed, persona. |
| `control` | Whenever the run state changes (running / paused / game over). |
| `turn_start` | A side's turn begins. |
| `agent_thought` | The agent's reasoning, model used, fallback flag. |
| `action_result` | Each resolved action with narration and ATT&CK techniques. |
| `alert` | A new alert in BLUE's queue. |
| `intervention` | Judge event, model swap or persona change. |
| `game_over` | Winner, reason, rounds. |
| `report` | The after-action report (markdown). |
| `error` | The game loop crashed; see the server log. |

---

## 16. Scripts

| Script | Purpose |
|---|---|
| `scripts/check_models.py` | Confirms your ai& model IDs answer and Neo4j connects. Run before any demo. |
| `scripts/smoke_test.py [seeds…]` | Full headless heuristic games, a determinism check and a BLUE fog-of-war leak check. |
| `scripts/gen_test.py` | Generates seeds 0–19 and verifies the path guarantee (plus a Neo4j/Cypher cross-check if configured). |
| `scripts/find_seed.py [n]` | Plays `n` seeds and ranks them by drama, to pick a good demo seed. |
| `scripts/fetch_intel.py` | Refreshes `data/cve_intel.json` from EPSS and CISA KEV. |
| `scripts/benchmark.py` | Headless leaderboard; see [§12](#12-campaign-mode-and-benchmarks). |

---

## 16a. Development & tests

```bash
pip install -r requirements-dev.txt
pytest                         # 47 unit + integration tests (engine, fog of war, exports, API)
python scripts/smoke_test.py   # headless games + determinism + fog-of-war leak check
```

CI (`.github/workflows/ci.yml`) runs the tests, smoke games, the generator
guarantee and a benchmark on every push across Python 3.11–3.13. Runtime
dependencies are pinned in `requirements.txt`; test-only ones in
`requirements-dev.txt`.

The test suite enforces the invariants that matter for credibility — RED never
sees undiscovered hosts, BLUE never sees compromise truth or reacts to silent
actions, false positives are indistinguishable from real alerts, STIX exports
reference MITRE's canonical object ids, and the control token gates mutations.

## 17. Project layout

```
app/
  main.py        FastAPI app: static files, /ws, REST controls
  engine.py      game loop, legal actions, resolution, detection, win checks (single source of truth)
  agents.py      LLM agents (prompts, personas, JSON contract, fallback) + heuristic policies
  generator.py   seeded procedural network + attack-path guarantee
  paths.py       viable-attack-path metric (pure Python)
  models.py      data models: hosts, edges, vulns, credentials, actions, alerts, turns
  intel.py       EPSS/KEV enrichment from the committed cache
  attack_map.py  action → MITRE ATT&CK technique / mitigation mapping
  export.py      ATT&CK Navigator layer + STIX 2.1 bundle builders
  report.py      after-action report (LLM, with static fallback)
  events.py      WebSocket broadcaster + JSONL match recorder
  replay.py      offline replay server
  db.py          Neo4j driver + background mirror
  queries.py     all Cypher
  config.py      settings from .env
static/          index.html, app.js, style.css, vendored force-graph / Chart.js / marked
data/            cve_intel.json (committed threat-intel cache)
replays/         golden.jsonl + recorded matches
benchmarks/      leaderboard.json / .md
scripts/         see §16
```

---

## 18. Demo script (3 minutes)

1. **(15 s)** "Every company's network is a graph. Attackers think in graphs;
   defenders think in lists. We made two AIs fight on the graph."
2. **(60 s)** START on seed 6. Toggle RED VIEW (fog of war) ↔ GOD VIEW. Point
   at the attack-path counter and sparkline; hover a host to show real EPSS/KEV
   intel.
3. **(30 s)** The judge clicks **INJECT ZERO-DAY**: the path count spikes and
   BLUE reacts.
4. **(45 s)** Read RED's and BLUE's reasoning side by side; swap a model live
   from the dropdown.
5. **(30 s)** Game over: open the **MATCH TIMELINE** to narrate the fight, then
   the **after-action report**, then download the ATT&CK layer.

---

## 19. Troubleshooting

- **`Neo.ClientError.Security.Unauthorized` on startup.** Almost always the
  username: on Aura it's the instance ID from the credentials file, not
  `neo4j`. If that's right, reset the password in the Aura console. The game
  keeps running in offline graph mode meanwhile.
- **Cards keep showing FALLBACK.** The model is too slow or not answering with
  JSON. Pick another from the dropdown (see [§2](#2-configuration)).
- **Kimi returns empty responses.** kimi-k3 is a reasoning model and needs
  token headroom for reasoning plus the answer; `app/agents.py` already allows
  for it.
- **Personas or model dropdowns are greyed out.** No `AIAND_API_KEY` is set, so
  both sides are heuristic.
- **START does nothing after a match.** The match is finished; press RESET (or
  pick a new seed) to start another.
- **A hover tooltip doesn't appear.** Point at the node's dot rather than its
  label. Tooltips for nodes in the lower part of the map can be hidden behind
  the ATT&CK bar.
