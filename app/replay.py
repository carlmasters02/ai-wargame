"""Replay server: stream a recorded match (replays/*.jsonl) over the same
WebSocket contract. The frontend cannot tell the difference — this is the
offline fallback if venue Wi-Fi dies.

Usage: .venv/bin/python -m app.replay replays/match_xxx.jsonl [--speed 2]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_events(path: str):
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def create_replay_app(path: str, speed: float) -> FastAPI:
    events = load_events(path)
    app = FastAPI(title="AI Wargame — REPLAY")
    app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(BASE, "static", "index.html"))

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_json({"type": "status", "payload": {
            "state": "replay", "llm": False,
            "models": {"red": "recorded", "blue": "recorded"}, "available_models": []}})
        t_prev = 0.0
        try:
            for ev in events:
                dt = max(0.0, (ev.get("dt", 0.0) - t_prev)) / speed
                t_prev = ev.get("dt", 0.0)
                if dt:
                    await asyncio.sleep(min(dt, 5.0))
                await websocket.send_json({"type": ev["type"], "payload": ev["payload"]})
            # keep the socket open so the frontend stays interactive
            while True:
                await websocket.receive_text()
        except (WebSocketDisconnect, RuntimeError):
            pass

    @app.post("/api/{path:path}")
    async def noop(path: str):
        return {"replay": True}

    return app


def main():
    p = argparse.ArgumentParser()
    p.add_argument("file")
    p.add_argument("--speed", type=float, default=2.0)
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    print(f"REPLAY MODE: {args.file} at {args.speed}x -> http://localhost:{args.port}")
    uvicorn.run(create_replay_app(args.file, args.speed), host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
