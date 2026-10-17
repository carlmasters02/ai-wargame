from app.config import settings
from app.report import generate_report, static_report
from conftest import play_out, run


def test_template_report_is_data_driven(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8); await play_out(eng)
        ctx = eng.report_context()
        md = static_report(eng.turns, eng.metrics_history, eng.winner, eng.win_reason, ctx)
        for section in ("## Outcome", "## Timeline", "## MITRE ATT&CK Mapping",
                        "## Turning Points", "## What BLUE Should Have Done Differently"):
            assert section in md
        assert "k.sato, j.saito" not in md  # no hard-coded names
        if any(t.action == "PHISH_USER" for t in eng.turns):
            assert "T1566" in md
        out = await generate_report(settings, eng.turns, eng.metrics_history, eng.winner, eng.win_reason, ctx)
        assert out["source"] == "template" and out["note"] and out["model"] is None
    run(go())
