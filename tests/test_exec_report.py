from fastapi.testclient import TestClient

import app.main as main
from conftest import play_out, run


def test_executive_report_renders_html(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8, scenario="ransomware"); await play_out(eng)
        from app import exec_report
        doc = exec_report.build(8, eng.scenario, eng.winner, eng.win_reason, eng.round,
                                eng.scorecard(), eng.exposure_analysis(),
                                eng.casebook.summary(), eng.turns)
        assert doc.startswith("<!doctype html>")
        for section in ("Executive Briefing", "Defensive performance", "Business impact",
                        "Prioritised remediation", "MITRE ATT&amp;CK"):
            assert section in doc
        assert "5a6party" not in doc  # no leftover CSS typo
    run(go())


def test_exec_endpoint_renders_after_a_match(tmp_path, monkeypatch):
    monkeypatch.setattr(main.bus, "record_dir", str(tmp_path))
    with TestClient(main.app) as c:
        assert c.get("/api/report/executive").status_code == 404  # no match yet
        c.post("/api/reset", json={"seed": 8})
        c.post("/api/step")  # one turn is enough for turns to be non-empty
        import time as _t; _t.sleep(4)
        r = c.get("/api/report/executive")
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
        assert "Executive Briefing" in r.text
