from app import scoring
from app.models import Alert, TurnRecord
from conftest import play_out, run


def _t(n, rnd, side, action, success=True, **meta):
    return TurnRecord(n=n, round=rnd, side=side, action=action, success=success, meta=meta)


def test_mttd_mttr_and_false_isolation():
    turns = [
        _t(1, 1, "red", "EXPLOIT", target="H1"),          # H1 compromised round 1
        _t(2, 2, "red", "LATERAL_MOVE", target="H2"),     # H2 compromised round 2
        _t(3, 3, "blue", "INVESTIGATE", confirmed_hosts=["H1"]),  # detect H1 at round 3 (mttd 2)
        _t(4, 4, "blue", "ISOLATE", was_compromised=True),       # evict H1 (mttr 1)
        _t(5, 5, "blue", "ISOLATE", was_compromised=False),      # false isolation
    ]
    turns[3].args = {"host": "H1"}
    hist = [{"round": 1, "paths": 10, "impact": 0}, {"round": 5, "paths": 4, "impact": 6}]
    sc = scoring.build(turns, [], hist, "blue", "x", 5,
                       {"H1": {"criticality": 8, "zone": "servers"}, "H2": {"criticality": 5, "zone": "corp"}})
    assert sc.blue.detected == 1 and sc.blue.missed == 1
    assert sc.blue.mttd_rounds == 2.0 and sc.blue.mttr_rounds == 1.0
    assert sc.blue.false_isolations == 1 and sc.blue.evictions == 1
    assert sc.blue.exposure_reduction == 0.6


def test_red_objective_and_stealth():
    turns = [
        _t(1, 1, "red", "EXPLOIT", target="H1"),
        _t(2, 2, "red", "LATERAL_MOVE", target="H2"),
        _t(3, 3, "red", "EXFILTRATE"),
    ]
    alerts = [Alert(turn=1, host="H1", kind="exploit", confidence=0.6, true_positive=True)]
    sc = scoring.build(turns, alerts, [{"round": 1, "paths": 5, "impact": 0}], "red", "x", 3)
    assert sc.red.objective and sc.red.rounds_to_objective == 3
    assert sc.red.hosts_compromised == 2 and sc.red.stealth == 3.0  # 3 successes / 1 alert


def test_grades_and_bounds():
    assert scoring._grade(95) == "A" and scoring._grade(0) == "F"
    for s in (scoring.RedScore(objective=True, rounds_to_objective=1, hosts_compromised=6, stealth=4),
              scoring.BlueScore(detected=5, missed=0, mttd_rounds=0, exposure_reduction=1.0)):
        assert 0 <= s.score() <= 100


def test_cost_counts_per_decision_not_per_action():
    # BLUE: 2 actions per round share one decision; latency stamped once per round
    turns = [
        TurnRecord(n=1, round=1, side="blue", action="PATCH", success=True,
                   fallback=False, latency_ms=800, tokens=1200, model="m"),
        TurnRecord(n=2, round=1, side="blue", action="INVESTIGATE", success=True,
                   fallback=False, latency_ms=800, tokens=1200, model="m"),
        TurnRecord(n=3, round=2, side="blue", action="PATCH", success=True,
                   fallback=True, latency_ms=None, tokens=None, model="m"),
    ]
    c = scoring._cost(turns, "blue")
    assert c.decisions == 2 and c.fallbacks == 1 and c.fallback_rate == 0.5
    assert c.avg_latency_ms == 800.0 and c.total_tokens == 1200  # one decision, not two


def test_scorecard_from_a_real_match(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8); await play_out(eng)
        sc = eng.scorecard()
        assert sc["winner"] in ("red", "blue")
        assert 0 <= sc["red"]["score"] <= 100 and sc["red"]["grade"] in "ABCDF"
        assert sc["blue_cost"]["fallback_rate"] == 1.0  # pure heuristic match
    run(go())


def test_business_cost_model():
    from app import costs
    turns = [
        _t(1, 1, "red", "EXPLOIT", target="H1"),
        _t(2, 2, "red", "EXFILTRATE"),
        _t(3, 3, "blue", "ISOLATE", was_compromised=True),
    ]
    turns[2].args = {"host": "H1"}
    hosts = {"H1": {"criticality": 10, "zone": "restricted"}}
    bc = costs.breakdown(turns, hosts, total_rounds=5, winner="red")
    assert bc["breach_usd"] == costs.BREACH_BASE          # RED reached the objective
    assert bc["response_usd"] == costs.RESPONSE_PER_HOST  # one host compromised
    assert bc["downtime_usd"] > 0                         # isolated for 3 rounds
    assert bc["total_usd"] == bc["breach_usd"] + bc["response_usd"] + bc["downtime_usd"]
    # a BLUE win incurs no breach cost
    assert costs.breakdown(turns, hosts, 5, "blue")["breach_usd"] == 0
