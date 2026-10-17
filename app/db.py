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

    def write(self, cypher: str, **params) -> None:
        if not self.enabled:
            return
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._write_async(cypher, params))
        except RuntimeError:
            pass

    async def _write_async(self, cypher: str, params: dict) -> None:
        try:
            await asyncio.to_thread(run_sync, cypher, **params)
        except Exception as e:  # noqa: BLE001
            log.warning("mirror write failed: %s", e)

    def write_blocking(self, cypher: str, **params) -> list[dict]:
        if not self.enabled:
            return []
        try:
            return run_sync(cypher, **params)
        except Exception as e:  # noqa: BLE001
            log.warning("mirror blocking write failed: %s", e)
            return []
