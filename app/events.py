"""WebSocket broadcaster + match recorder.

Every event emitted during a live game is appended to a JSONL replay file
(replays/match_*.jsonl). app/replay.py can stream such a file back over the
same WS contract, so a recorded match is a perfect offline fallback.
"""
from __future__ import annotations

import asyncio
import glob
import json
import logging
import os
import time

log = logging.getLogger("events")

KEEP_RECORDINGS = 50  # newest match_*.jsonl files kept; older ones are pruned
MAX_CLIENTS = 100     # /ws is unauthenticated (spectating), so bound it
SEND_TIMEOUT = 5.0    # seconds; a client that stops reading is dropped, not waited on

class Broadcaster:
    def __init__(self, record_dir: str = "replays", keep: int = KEEP_RECORDINGS):
        self.clients: set = set()
        self.record_dir = record_dir
        self.keep = keep
        self._fh = None
        self._t0 = None

    @property
    def recording(self) -> bool:
        return self._fh is not None

    async def connect(self, ws) -> bool:
        if len(self.clients) >= MAX_CLIENTS:
            await ws.close(code=1013)  # try again later
            return False
        await ws.accept()
        self.clients.add(ws)
        return True

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
            self._prune()
        except OSError as e:
            log.warning("recording disabled: %s", e)
            self._fh = None

    def _prune(self) -> None:
        files = sorted(glob.glob(os.path.join(self.record_dir, "match_*.jsonl")), key=os.path.getmtime)
        for f in files[:-self.keep] if self.keep else []:
            try:
                os.remove(f)
            except OSError:
                pass

    def record(self, type_: str, payload: dict) -> None:
        """Write an event to the replay file only (not broadcast to live clients)."""
        if self._fh:
            dt = round(time.monotonic() - self._t0, 3) if self._t0 else 0.0
            self._fh.write(json.dumps({"dt": dt, "type": type_, "payload": payload},
                                      ensure_ascii=False, default=str) + "\n")
            self._fh.flush()

    def stop_recording(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None

    async def emit(self, type_: str, payload: dict) -> None:
        msg = json.dumps({"type": type_, "payload": payload}, ensure_ascii=False, default=str)

        async def send(ws):
            try:
                await asyncio.wait_for(ws.send_text(msg), SEND_TIMEOUT)
            except Exception:  # noqa: BLE001 — closed, broken or too slow
                self.disconnect(ws)

        await asyncio.gather(*(send(ws) for ws in list(self.clients)))
        self.record(type_, payload)
