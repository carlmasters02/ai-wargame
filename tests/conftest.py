"""Shared fixtures. Tests never call a real model or database: the API key and
Neo4j URI are forced empty before any app module reads settings."""
import asyncio
import os
import sys

os.environ["AIAND_API_KEY"] = ""
os.environ["NEO4J_URI"] = ""
os.environ["WARGAME_TOKEN"] = ""
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import Mirror  # noqa: E402
from app.engine import GameEngine  # noqa: E402
from app.events import Broadcaster  # noqa: E402


class RecordingBus(Broadcaster):
    """Broadcaster that keeps every emitted event in memory instead of sending it."""

    def __init__(self, record_dir):
        super().__init__(record_dir=str(record_dir))
        self.events: list[tuple[str, dict]] = []

    async def emit(self, type_, payload):
        self.events.append((type_, payload))
        self.record(type_, payload)

    def of(self, type_):
        return [p for t, p in self.events if t == type_]


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def make_engine(tmp_path):
    """make_engine(seed=6, delay=0.0) -> (engine, bus), reset and ready (inside a fresh loop)."""
    def factory(seed=6, delay=0.0):
        bus = RecordingBus(tmp_path / "replays")
        eng = GameEngine(settings, bus, Mirror(False))
        eng.turn_delay = delay
        eng.reports_enabled = False
        return eng, bus
    return factory


async def play_out(eng, timeout=60.0):
    """Start and wait until the match is no longer running."""
    await eng.start()
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while eng.state == "running":
        assert loop.time() < end, "match did not finish"
        await asyncio.sleep(0)


async def wait_not_running(eng, timeout=10.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        await asyncio.sleep(0.01)
        if eng.state != "running":
            return
    raise AssertionError("engine still running")
