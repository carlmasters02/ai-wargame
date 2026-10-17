from app.cases import CaseBook
from app.models import ActionSpec
from conftest import play_out, run


def test_alert_opens_case_and_escalates_severity():
    cb = CaseBook()
    c = cb.on_alert("H1", 1, 0.4, criticality=3, true_positive=True)
    assert c.id == "INC-001" and c.status == "open" and c.alerts == 1
    c2 = cb.on_alert("H1", 2, 0.9, criticality=10, true_positive=True)
    assert c2.id == c.id and c2.alerts == 2 and c2.severity == "critical"


def test_investigate_confirms_or_closes():
    cb = CaseBook()
    cb.on_alert("H1", 1, 0.5, 8, True)
    c = cb.on_investigate("H1", 2, compromised=True)
    assert c.status == "investigating" and c.detected_round == 2
    cb.on_alert("H2", 1, 0.3, 4, False)
    c2 = cb.on_investigate("H2", 2, compromised=False)
    assert c2.status == "closed" and "false positive" in c2.resolution


def test_containment_and_summary():
    cb = CaseBook()
    cb.on_alert("H1", 1, 0.6, 8, True)
    cb.on_investigate("H1", 2, True)
    c = cb.on_contained("H1", 4, "ISOLATE")
    assert c.status == "contained" and c.contained_round == 4
    s = cb.summary()
    assert s["opened"] == 1 and s["contained"] == 1 and s["mean_time_to_contain"] == 3.0


def test_reopen_after_containment():
    cb = CaseBook()
    cb.on_alert("H1", 1, 0.5, 5, True); cb.on_contained("H1", 2, "ISOLATE")
    c2 = cb.on_alert("H1", 5, 0.5, 5, True)   # new activity after containment -> new case
    assert c2.id == "INC-002"


def test_cases_tracked_in_a_real_match(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8); await play_out(eng)
        s = eng.casebook.summary()
        assert s["opened"] > 0
        assert s["opened"] == s["contained"] + s["closed_false_positive"] + s["open"]
        assert "cases" in eng.scorecard()
        # BLUE observation exposes open cases but never the verdict
        import json
        obs = eng.build_observation("blue")
        assert "open_cases" in obs
        assert '"true_positive"' not in json.dumps(obs)
    run(go())
