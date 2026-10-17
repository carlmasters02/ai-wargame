from app.scenarios import SCENARIOS
from conftest import play_out, run


def test_all_scenarios_load_and_are_playable(make_engine):
    async def go():
        eng, _ = make_engine()
        for name in SCENARIOS:
            await eng.reset(6, scenario=name)
            assert eng.scenario == name
            assert eng.compute_metrics()["paths"] >= 0
            await play_out(eng)
            assert eng.winner in ("red", "blue")
    run(go())


def test_ransomware_sets_persona_and_foothold(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6, scenario="ransomware")
        assert eng.red_persona == "ransomware"
        assert any(h.compromised for h in eng.hosts.values() if h.zone == "dmz")
    run(go())


def test_insider_pre_steals_a_privileged_credential(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6, scenario="insider")
        assert any(c.stolen and eng.users[c.owner].privileged for c in eng.creds.values())
    run(go())


def test_zero_day_storm_plants_unpatchable_rce(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6, scenario="zero_day")
        zds = [v for v in eng.vulns.values() if v.zero_day]
        assert len(zds) >= 1 and all(not v.patched and v.exploitability >= 0.85 for v in zds)
    run(go())


def test_unknown_scenario_falls_back_to_baseline(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6, scenario="nonsense")
        assert eng.scenario == "baseline"
    run(go())


def test_scenario_persists_across_plain_reset(make_engine):
    async def go():
        eng, _ = make_engine()
        await eng.reset(6, scenario="ransomware")
        await eng.reset(7)  # campaign-style reset with no scenario arg keeps it
        assert eng.scenario == "ransomware" and eng.red_persona == "ransomware"
    run(go())
