import os
import time

from app.events import Broadcaster
from conftest import run


def test_recording_starts_with_the_match_not_on_reset(make_engine, tmp_path):
    async def go():
        eng, bus = make_engine(); await eng.reset(6)
        assert not bus.recording
        await eng.start(); await eng.stop()
        return bus
    bus = run(go())
    files = os.listdir(tmp_path / "replays")
    assert len(files) == 1
    first = open(tmp_path / "replays" / files[0]).readline()
    assert '"graph_snapshot"' in first  # a replay always opens on the full board


def test_old_recordings_are_pruned(tmp_path):
    bus = Broadcaster(record_dir=str(tmp_path), keep=3)
    for i in range(6):
        p = tmp_path / f"match_old_{i}.jsonl"; p.write_text("{}\n")
        os.utime(p, (time.time() - 100 + i, time.time() - 100 + i))
    bus.start_recording("x"); bus.stop_recording()
    assert len(list(tmp_path.glob("match_*.jsonl"))) == 3
