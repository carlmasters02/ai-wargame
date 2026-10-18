"""FastAPI app: static frontend, one WebSocket, REST controls.

Graph-mutating judge commands go through the engine's command queue while a match
runs (single-writer rule); control flags (pause/resume/step/speed) and model or
persona swaps are safe to apply directly.

If WARGAME_TOKEN is set, every state-changing endpoint requires it (header
`X-Wargame-Token`). Spectating — the page, /ws and GET endpoints — never does.
Without a token the server only answers requests addressed to localhost (see Guard).
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import math
import os
import re
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .agents import PERSONAS, Agent
from .scenarios import SCENARIOS
from .config import settings
from .db import Mirror, init_driver
from .engine import GameEngine
from .events import Broadcaster
from . import exec_report, export, importer
from .intel import intel_status

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("main")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

bus = Broadcaster(record_dir=os.path.join(BASE, "replays"))
engine: GameEngine | None = None
available_models: list[str] = []


LOOPBACK = {"localhost", "127.0.0.1", "::1"}
MAX_BODY = 2_500_000  # bytes; the largest legitimate body is a 2 MB network import
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
     b"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
     b"frame-ancestors 'none'; form-action 'self'"),
]


def _loopback_client(scope) -> bool:
    try:
        ip = ipaddress.ip_address((scope.get("client") or ("",))[0])
    except ValueError:
        return False  # unix socket / unknown peer: fail closed
    return ip.is_loopback or bool(getattr(ip, "ipv4_mapped", None) and ip.ipv4_mapped.is_loopback)


def _hostname(netloc: str) -> str:
    try:
        return urlsplit("//" + netloc).hostname or ""
    except ValueError:
        return ""


class Guard:
    """Runs in front of every HTTP and WebSocket request.

    - Open mode (no WARGAME_TOKEN) serves only loopback connections addressed to a
      loopback Host name: a network client is refused even if it forges `Host`, and a
      DNS-rebinding page can't drive a local server. Proxied requests are refused too.
    - State changes and WebSocket upgrades from another site's page (Origin != Host)
      are refused: no CSRF, no cross-site WebSocket hijacking.
    - Every HTTP response gets security headers (CSP, nosniff, no framing, no referrer).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        host, origin = headers.get("host", ""), headers.get("origin")
        reason = None
        if not settings.WARGAME_TOKEN and (
                _hostname(host) not in LOOPBACK or not _loopback_client(scope)
                or any(h in headers for h in ("x-forwarded-for", "forwarded", "x-real-ip"))):
            reason = "this server has no WARGAME_TOKEN, so it only serves localhost"
        elif origin is not None and (scope["type"] == "websocket"
                                     or scope["method"] not in SAFE_METHODS):
            try:
                same = urlsplit(origin).netloc == host
            except ValueError:
                same = False
            if not same:
                reason = "cross-origin request refused"
        if reason:
            if scope["type"] == "websocket":
                await receive()  # websocket.connect
                await send({"type": "websocket.close", "code": 1008})
                return
            return await JSONResponse({"error": reason}, status_code=403)(scope, receive, send)
        if scope["type"] == "websocket":
            return await self.app(scope, receive, send)

        async def send_secured(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + SECURITY_HEADERS
            await send(message)
        return await self.app(scope, receive, send_secured)


def require_token(request: Request) -> None:
    """Gate state-changing endpoints behind WARGAME_TOKEN when one is configured.
    Header only: a token in the URL would land in access logs and browser history."""
    if not settings.WARGAME_TOKEN:
        return
    given = request.headers.get("x-wargame-token") or ""
    if not hmac.compare_digest(given.encode(), settings.WARGAME_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="valid X-Wargame-Token required")


async def _body(request: Request) -> dict:
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY:
            raise HTTPException(status_code=413, detail="request body too large")
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:  # non-JSON body
        return {}
    return data if isinstance(data, dict) else {}


def _status_payload() -> dict:
    return {"state": engine.state, "llm": settings.aiand_enabled,
            "speed": engine.speed, "persona": engine.red_persona,
            "auth": bool(settings.WARGAME_TOKEN),
            "models": {side: (a.model if a else "heuristic") for side, a in engine.agents.items()},
            "players": engine.control, "available_models": available_models,
            "scenario": engine.scenario,
            "scenarios": [{"id": k, "label": v["label"], "desc": v["desc"]} for k, v in SCENARIOS.items()],
            "config": dict(engine.config)}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global engine
    neo4j_ok = init_driver(settings.NEO4J_URI, settings.NEO4J_USER, settings.NEO4J_PASSWORD) \
        if settings.neo4j_enabled else False
    engine = GameEngine(settings, bus, Mirror(enabled=neo4j_ok))
    if settings.aiand_enabled:
        engine.agents["red"] = Agent("red", settings.ATTACKER_MODEL, settings,
                                     persona=engine.red_persona)
        engine.agents["blue"] = Agent("blue", settings.DEFENDER_MODEL, settings)
        await _fetch_models()
        await _prewarm()
    else:
        log.warning("AIAND_API_KEY not set — both sides will use heuristic policies")
    if settings.WARGAME_TOKEN:
        log.info("control endpoints require WARGAME_TOKEN (open the page with #token=...)")
    engine.history_path = os.path.join(BASE, "data", "match_history.json")
    await engine.reset(settings.GAME_SEED)
    log.info("ready. open http://localhost:8000")
    yield
    await engine.stop()
    await engine.mirror.flush()


def create_app() -> FastAPI:
    # no auto-generated /docs, /redoc, /openapi.json: the API is documented in the README
    # (and Swagger UI's CDN assets would be blocked by the CSP anyway)
    app = FastAPI(title="AI Wargame", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(Guard)
    app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
    guarded = [Depends(require_token)]

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(BASE, "static", "index.html"))

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        if not await bus.connect(websocket):
            return
        try:
            await websocket.send_json({"type": "graph_snapshot", "payload": engine.snapshot()})
            await websocket.send_json({"type": "metrics", "payload": engine.compute_metrics()})
            await websocket.send_json({"type": "status", "payload": _status_payload()})
            if engine.winner:
                await websocket.send_json({"type": "game_over", "payload": {
                    "winner": engine.winner, "reason": engine.win_reason,
                    "rounds": engine.round, "score": engine.compute_metrics(),
                    "scorecard": engine.scorecard()}})
                if engine.last_report is not None:
                    await websocket.send_json({"type": "report", "payload": engine.last_report})
            while True:
                await websocket.receive_text()  # keepalive; client sends nothing meaningful
        except WebSocketDisconnect:
            pass
        finally:
            bus.disconnect(websocket)

    # ---- controls ----
    @app.post("/api/start", dependencies=guarded)
    async def start():
        await engine.start()
        await engine.emit_state()
        return {"state": engine.state}

    @app.post("/api/pause", dependencies=guarded)
    async def pause():
        engine.pause()
        await engine.emit_state()
        return {"state": engine.state}

    @app.post("/api/resume", dependencies=guarded)
    async def resume():
        engine.resume()
        await engine.emit_state()
        return {"state": engine.state}

    @app.post("/api/step", dependencies=guarded)
    async def step():
        if engine.winner:
            return {"state": engine.state}
        if engine.state == "idle":
            await engine.start()
            engine.pause()
        engine.step()
        await engine.emit_state()
        return {"state": engine.state}

    @app.post("/api/speed", dependencies=guarded)
    async def speed(request: Request):
        try:
            x = float((await _body(request)).get("x", 1.0))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="x must be a number")
        if not math.isfinite(x):
            raise HTTPException(status_code=400, detail="x must be finite")
        engine.set_speed(x)
        return {"speed": engine.speed}

    @app.post("/api/reset", dependencies=guarded)
    async def reset(request: Request):
        body = await _body(request)
        try:
            seed = int(body.get("seed", settings.GAME_SEED))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="seed must be an integer")
        scenario = body.get("scenario")
        if scenario is not None and scenario not in SCENARIOS:
            raise HTTPException(status_code=400, detail=f"unknown scenario {scenario!r}")
        await engine.reset(seed, scenario=scenario)
        return {"seed": engine.spec.seed, "hosts": len(engine.hosts),
                "scenario": engine.scenario, "scenario_note": engine._scenario_note}

    @app.post("/api/import", dependencies=guarded)
    async def import_network(request: Request):
        body = await _body(request)
        fmt = (body.get("format") or "csv").lower()
        content = body.get("content") or ""
        if not isinstance(content, str) or not content.strip():
            return JSONResponse({"error": "content (CSV or Nmap XML text) required"}, status_code=400)
        if len(content) > 2_000_000:
            return JSONResponse({"error": "import too large (max 2 MB)"}, status_code=413)
        try:
            if fmt == "nmap":
                spec = importer.import_nmap(content)
            elif fmt in ("bloodhound", "bh", "json"):
                spec = importer.import_bloodhound(content)
            else:
                spec = importer.import_csv(content)
        except importer.ImportError as e:
            return JSONResponse({"error": f"import failed: {e}"}, status_code=400)
        except (ValueError, TypeError, AttributeError, KeyError):  # malformed structure
            return JSONResponse({"error": "import failed: malformed input"}, status_code=400)
        await engine.load_network(spec)
        return {"hosts": len(engine.hosts), "crown_jewel": engine.cj,
                "edges": len(engine.edges), "vulns": len(engine.vulns),
                "exposure": engine.compute_metrics()["paths"]}

    # ---- judge interventions ----
    @app.post("/api/intervene/zero_day", dependencies=guarded)
    async def zero_day():
        await engine.submit("zero_day", {})
        return {"queued": True}

    @app.post("/api/intervene/insider", dependencies=guarded)
    async def insider():
        await engine.submit("insider", {})
        return {"queued": True}

    @app.post("/api/model", dependencies=guarded)
    async def model_swap(request: Request):
        body = await _body(request)
        side, model = body.get("side"), body.get("model")
        if side not in ("red", "blue") or not isinstance(model, str) \
                or not re.fullmatch(r"[A-Za-z0-9._:/@-]{1,128}", model):
            return JSONResponse({"error": "side + model required"}, status_code=400)
        if engine.agents[side] is None:
            return JSONResponse({"error": "LLM not configured (heuristic mode)"}, status_code=409)
        routed = ":" in model and model.split(":", 1)[0] in settings.providers
        if not routed and available_models and model not in available_models:
            return JSONResponse({"error": f"unknown model {model!r}"}, status_code=400)
        await engine.run_command("model_swap", {"side": side, "model": model})  # no graph mutation
        return {"queued": True}

    @app.post("/api/persona", dependencies=guarded)
    async def persona(request: Request):
        p = (await _body(request)).get("persona")
        if p not in PERSONAS:
            return JSONResponse({"error": f"persona must be one of {sorted(PERSONAS)}"},
                                status_code=400)
        await engine.run_command("persona", {"persona": p})  # no graph mutation
        return {"queued": True, "label": PERSONAS[p]["label"]}

    @app.post("/api/control", dependencies=guarded)
    async def control(request: Request):
        body = await _body(request)
        side, who = body.get("side"), body.get("who")
        if side not in ("red", "blue") or who not in ("auto", "human"):
            return JSONResponse({"error": "side in {red,blue}, who in {auto,human}"},
                                status_code=400)
        engine.set_control(side, who)
        await engine.emit_state()
        return {"players": engine.control}

    @app.post("/api/act", dependencies=guarded)
    async def act(request: Request):
        body = await _body(request)
        raw = body.get("indices", [])
        if not isinstance(raw, list):
            return JSONResponse({"error": "indices must be a list of integers"}, status_code=400)
        try:
            indices = [int(i) for i in raw]
        except (TypeError, ValueError):
            return JSONResponse({"error": "indices must be integers"}, status_code=400)
        ok, msg = engine.submit_human_action(indices)
        return JSONResponse({"ok": ok, "detail": msg}, status_code=200 if ok else 409)

    # ---- read-only ----
    @app.get("/api/models")
    async def models():
        return {"models": available_models,
                "current": {side: (a.model if a else None) for side, a in engine.agents.items()}}

    @app.get("/api/exposure")
    async def exposure_report():
        return engine.exposure_analysis()

    @app.get("/api/cases")
    async def cases_report():
        return {"cases": engine.casebook.public(), "summary": engine.casebook.summary()}

    @app.post("/api/config", dependencies=guarded)
    async def set_config(request: Request):
        body = await _body(request)
        cfg = engine.set_config(**{k: body[k] for k in
                                   ("difficulty", "max_turns", "false_positive_rate") if k in body})
        await engine.emit_state()
        return cfg

    @app.get("/api/history")
    async def match_history():
        from . import history
        return history.recent(engine.history_path or
                              os.path.join(BASE, "data", "match_history.json"))

    @app.get("/api/state")
    async def state():
        return {"state": engine.state, "round": engine.round, "winner": engine.winner,
                "metrics": engine.compute_metrics(), "intel": intel_status()}

    # ---- exports (ATT&CK Navigator layer + STIX 2.1 bundle) ----
    @app.get("/api/export/navigator")
    async def export_navigator():
        if not engine.turns:
            return JSONResponse({"error": "no match data yet"}, status_code=404)
        layer = export.navigator_layer(engine.turns, engine.spec.seed if engine.spec else 0,
                                       engine.winner, engine.win_reason)
        return JSONResponse(layer, headers={
            "Content-Disposition": "attachment; filename=attack_navigator_layer.json"})

    @app.get("/api/export/stix")
    async def export_stix():
        if not engine.turns:
            return JSONResponse({"error": "no match data yet"}, status_code=404)
        bundle = export.stix_bundle(engine.turns, engine.spec.seed if engine.spec else 0,
                                    engine.winner, engine.win_reason)
        return JSONResponse(bundle, headers={
            "Content-Disposition": "attachment; filename=match_stix_bundle.json"})

    @app.get("/api/report/executive")
    async def executive_report():
        if not engine.turns:
            return JSONResponse({"error": "no match data yet"}, status_code=404)
        html_doc = exec_report.build(
            engine.spec.seed if engine.spec else 0, engine.scenario, engine.winner,
            engine.win_reason, engine.round, engine.scorecard(), engine.exposure_analysis(),
            engine.casebook.summary(), engine.turns)
        return HTMLResponse(html_doc)

    @app.get("/api/benchmarks")
    async def benchmarks():
        path = os.path.join(BASE, "benchmarks", "leaderboard.json")
        if not os.path.exists(path):
            return JSONResponse({"error": "no benchmark run yet — see scripts/benchmark.py"},
                                status_code=404)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    return app


async def _fetch_models():
    global available_models
    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(base_url=settings.AIAND_BASE_URL, api_key=settings.AIAND_API_KEY,
                             timeout=15)
        page = await client.models.list()
        available_models = sorted(m.id for m in page.data)
        log.info("ai& models: %s", available_models)
    except Exception as e:  # noqa: BLE001
        log.warning("could not list ai& models: %s", e)
        available_models = sorted({settings.ATTACKER_MODEL, settings.DEFENDER_MODEL,
                                   settings.REPORT_MODEL})


async def _prewarm():
    """Kill LLM cold-start latency before the demo."""
    for side, agent in engine.agents.items():
        if agent is None:
            continue
        try:
            client, model = agent._resolve()
            await client.chat.completions.create(
                model=model, max_tokens=1,
                messages=[{"role": "user", "content": "ping"}])
            log.info("prewarmed %s model %s", side, agent.model)
        except Exception as e:  # noqa: BLE001
            log.warning("prewarm failed for %s: %s", side, e)


app = create_app()
