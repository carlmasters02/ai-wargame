"""FastAPI app: static frontend, one WebSocket, REST controls.

All graph mutations go through the engine's command queue (single-writer rule);
control flags (pause/resume/step/speed) are safe to set directly.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .agents import Agent
from .config import settings
from .db import Mirror, init_driver
from .engine import GameEngine
from .events import Broadcaster
from . import export
from .intel import intel_status

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("main")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

bus = Broadcaster(record_dir=os.path.join(BASE, "replays"))
engine: GameEngine | None = None
available_models: list[str] = []


def create_app() -> FastAPI:
    app = FastAPI(title="AI Wargame")
    app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")

    @app.on_event("startup")
    async def startup():
        global engine, available_models
        neo4j_ok = init_driver(settings.NEO4J_URI, settings.NEO4J_USER, settings.NEO4J_PASSWORD) \
            if settings.neo4j_enabled else False
        engine = GameEngine(settings, bus, Mirror(enabled=neo4j_ok))
        if settings.aiand_enabled:
            engine.agents["red"] = Agent("red", settings.ATTACKER_MODEL, settings)
            engine.agents["blue"] = Agent("blue", settings.DEFENDER_MODEL, settings)
            await _fetch_models()
            await _prewarm()
        else:
            log.warning("AIAND_API_KEY not set — both sides will use heuristic policies")
        await engine.reset(settings.GAME_SEED)
        log.info("ready. open http://localhost:8000")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(BASE, "static", "index.html"))

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await bus.connect(websocket)
        try:
            await websocket.send_json({"type": "graph_snapshot", "payload": engine.snapshot()})
            await websocket.send_json({"type": "metrics", "payload": engine.compute_metrics()})
            await websocket.send_json({"type": "status", "payload": {
                "state": engine.state, "llm": settings.aiand_enabled,
                "models": {"red": engine.agents["red"].model if engine.agents["red"] else "heuristic",
                           "blue": engine.agents["blue"].model if engine.agents["blue"] else "heuristic"},
                "available_models": available_models}})
            if engine.winner:
                await websocket.send_json({"type": "game_over", "payload": {
                    "winner": engine.winner, "reason": engine.win_reason,
                    "rounds": engine.round, "score": engine.compute_metrics()}})
            while True:
                await websocket.receive_text()  # keepalive; client sends nothing meaningful
        except WebSocketDisconnect:
            pass
        finally:
            bus.disconnect(websocket)

    # ---- controls ----
    @app.post("/api/start")
    async def start():
        await engine.start()
        return {"state": engine.state}

    @app.post("/api/pause")
    async def pause():
        engine.pause()
        return {"state": engine.state}

    @app.post("/api/resume")
    async def resume():
        engine.resume()
        return {"state": engine.state}

    @app.post("/api/step")
    async def step():
        if engine.state in ("idle", "game_over"):
            await engine.start()
            engine.pause()
        engine.step()
        return {"state": "step"}

    @app.post("/api/speed")
    async def speed(body: dict):
        engine.set_speed(float(body.get("x", 1.0)))
        return {"speed": engine.speed}

    @app.post("/api/reset")
    async def reset(body: dict = {}):
        seed = int(body.get("seed", settings.GAME_SEED))
        await engine.reset(seed)
        return {"seed": engine.spec.seed, "hosts": len(engine.hosts)}

    # ---- judge interventions ----
    @app.post("/api/intervene/zero_day")
    async def zero_day():
        await engine.command_queue.put(("zero_day", {}))
        return {"queued": True}

    @app.post("/api/intervene/insider")
    async def insider():
        await engine.command_queue.put(("insider", {}))
        return {"queued": True}

    @app.post("/api/model")
    async def model_swap(body: dict):
        side, model = body.get("side"), body.get("model")
        if side not in ("red", "blue") or not model:
            return JSONResponse({"error": "side + model required"}, status_code=400)
        if engine.agents[side] is None:
            return JSONResponse({"error": "LLM not configured (heuristic mode)"}, status_code=409)
        await engine.command_queue.put(("model_swap", {"side": side, "model": model}))
        return {"queued": True}

    @app.get("/api/models")
    async def models():
        return {"models": available_models,
                "current": {"red": engine.agents["red"].model if engine.agents["red"] else None,
                            "blue": engine.agents["blue"].model if engine.agents["blue"] else None}}

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
        available_models = list({settings.ATTACKER_MODEL, settings.DEFENDER_MODEL,
                                 settings.REPORT_MODEL})


async def _prewarm():
    """Kill LLM cold-start latency before the demo."""
    for side, agent in engine.agents.items():
        if agent is None:
            continue
        try:
            await agent.client.chat.completions.create(
                model=agent.model, max_tokens=1,
                messages=[{"role": "user", "content": "ping"}])
            log.info("prewarmed %s model %s", side, agent.model)
        except Exception as e:  # noqa: BLE001
            log.warning("prewarm failed for %s: %s", side, e)


app = create_app()
