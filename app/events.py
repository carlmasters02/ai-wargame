"""WebSocket broadcaster + match recorder.

Every event emitted during a live game is appended to a JSONL replay file
(replays/match_*.jsonl). app/replay.py can stream such a file back over the
same WS contract, so a recorded match is a perfect offline fallback.
"""
from __future__ import annotations

import json
import logging
import os
import time

log = logging.getLogger("events")


class Broadcaster:
    def __init__(self, record_dir: str = "replays"):
        self.clients: set = set()
        self.record_dir = record_dir
        self._fh = None
        self._t0 = None

    async def connect(self, ws) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws) -> None:
        self.clients.discard(ws)

    def start_recording(self, tag: str = "") -> None:
        self.stop_recording()
        try:
            os.makedirs(self.record_dir, exist_ok=True)
            name = f"match_{time.strftime('%Y%m%d_%H%M%S')}{'_' + tag if tag else ''}.jsonl"
            self._fh = open(os.path.join(self.record_dir, name), "a", encoding="utf-8")
            self._t0 = time.monotonic()
            log.info("recording match to %s", name)
        except OSError as e:
            log.warning("recording disabled: %s", e)
            self._fh = None

    def stop_recording(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None

    async def emit(self, type_: str, payload: dict) -> None:
        msg = json.dumps({"type": type_, "payload": payload}, ensure_ascii=False, default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(msg)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
        if self._fh:
            dt = round(time.monotonic() - self._t0, 3) if self._t0 else 0.0
            self._fh.write(json.dumps({"dt": dt, "type": type_, "payload": payload},
                                      ensure_ascii=False, default=str) + "\n")
            self._fh.flush()
