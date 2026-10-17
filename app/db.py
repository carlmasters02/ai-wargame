"""Neo4j driver + non-blocking mirror.

The engine is authoritative in-memory; every mutation is mirrored to Neo4j
("the game board") via fire-and-forget writes on a thread, so Aura latency
can never stall the game loop. If credentials are missing or Aura is
unreachable, the game still runs in offline mode.
"""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("db")

_driver = None


def init_driver(uri: str, user: str, password: str) -> bool:
    global _driver
    try:
        from neo4j import GraphDatabase

        _driver = GraphDatabase.driver(uri, auth=(user, password), max_connection_pool_size=10)
        _driver.verify_connectivity()
        log.info("Neo4j connected: %s", uri)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("Neo4j unavailable (%s) — running in OFFLINE graph mode", e)
        _driver = None
        return False


def get_driver():
    return _driver


def run_sync(cypher: str, **params) -> list[dict]:
    if _driver is None:
        return []
    with _driver.session() as s:
        return [dict(r) for r in s.run(cypher, **params)]


class Mirror:
    """Queues Cypher writes to Neo4j without ever blocking the event loop."""

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self._pending: set[asyncio.Task] = set()  # strong refs: tasks can't be GC'd mid-write

    def write(self, cypher: str, **params) -> None:
        if not self.enabled:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self._write_async(cypher, params))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def flush(self) -> None:
        """Wait for every queued write (call before WIPE so stale writes can't land after it)."""
        while self._pending:
            await asyncio.gather(*list(self._pending), return_exceptions=True)

    async def write_now(self, cypher: str, **params) -> list[dict]:
        """Awaited write on a worker thread — ordered, but never blocks the event loop."""
        if not self.enabled:
            return []
        try:
            return await asyncio.to_thread(run_sync, cypher, **params)
        except Exception as e:  # noqa: BLE001
            log.warning("mirror write failed: %s", e)
            return []

    async def _write_async(self, cypher: str, params: dict) -> None:
        try:
            await asyncio.to_thread(run_sync, cypher, **params)
        except Exception as e:  # noqa: BLE001
            log.warning("mirror write failed: %s", e)

