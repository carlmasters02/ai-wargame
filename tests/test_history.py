import os

from app import history
from conftest import play_out, run


def test_record_and_recent(tmp_path):
    p = str(tmp_path / "h.json")
    for w in ("blue", "red", "blue"):
        history.record(p, {"winner": w, "seed": 1, "scenario": "baseline"})
    r = history.recent(p)
    assert r["count"] == 3 and r["blue_wins"] == 2 and r["red_wins"] == 1
    assert r["matches"][0]["winner"] == "blue"  # newest first


def test_record_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "MAX_RECORDS", 5)
    p = str(tmp_path / "h.json")
    for i in range(12):
        history.record(p, {"winner": "blue", "seed": i})
    r = history.recent(p)
    assert r["count"] == 5 and r["matches"][0]["seed"] == 11  # kept the newest 5


def test_corrupt_history_is_ignored(tmp_path):
    p = str(tmp_path / "h.json")
    open(p, "w").write("{ not json")
    assert history.recent(p)["count"] == 0
    history.record(p, {"winner": "red"})  # recovers
    assert history.recent(p)["count"] == 1


def test_match_is_recorded_on_game_over(make_engine, tmp_path):
    async def go():
        eng, _ = make_engine()
        eng.history_enabled = True
        eng.history_path = str(tmp_path / "h.json")
        await eng.reset(8, scenario="ransomware")
        await play_out(eng)
        r = history.recent(eng.history_path)
        assert r["count"] == 1
        m = r["matches"][0]
        assert m["scenario"] == "ransomware" and m["winner"] in ("red", "blue")
        assert "blue_grade" in m and "business_cost_usd" in m
    run(go())
