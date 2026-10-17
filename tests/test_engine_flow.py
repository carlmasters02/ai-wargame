from app.engine import EVICTION_HOLD
from app.models import ActionSpec
from conftest import play_out, run, wait_not_running


def test_step_alternates_sides(make_engine):
    async def go():
        eng, _ = make_engine(delay=0.2); await eng.reset(6)
        await eng.start(); eng.pause(); eng.step(); await wait_not_running(eng)
        for _ in range(3):
            eng.step(); await wait_not_running(eng)
        assert [t.side for t in eng.turns] == ["red", "blue", "blue", "red", "blue", "blue"]
        assert eng.state == "paused"
        await eng.stop()
    run(go())


def test_pause_between_turns_does_not_skip_blue(make_engine):
    async def go():
        import asyncio
        eng, _ = make_engine(delay=1.0); await eng.reset(6); await eng.start()
        while not eng.turns:
            await asyncio.sleep(0.01)
        eng.pause(); await asyncio.sleep(0.3); eng.resume()
        while len(eng.turns) < 2:
            await asyncio.sleep(0.01)
        assert [t.side for t in eng.turns[:2]] == ["red", "blue"]
        await eng.stop()
    run(go())


def test_finished_match_cannot_be_restarted(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8); await play_out(eng)
        n = len(eng.turns)
        await eng.start(); eng.step()
        import asyncio; await asyncio.sleep(0.2)
        assert len(eng.turns) == n and eng.state == "game_over"
    run(go())


def test_rounds_never_exceed_max(make_engine):
    async def go():
        eng, bus = make_engine()
        for seed in range(1, 12):
            await eng.reset(seed); await play_out(eng)
            assert bus.of("game_over")[-1]["rounds"] <= eng.s.MAX_TURNS
    run(go())


def test_reset_clears_queued_commands(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        await eng.command_queue.put(("zero_day", {}))
        await eng.reset(7)
        assert eng.command_queue.empty()
    run(go())


def test_judge_events_apply_when_idle_and_ids_are_unique(make_engine):
    async def go():
        eng, bus = make_engine(); await eng.reset(6)
        await eng.submit("zero_day", {}); await eng.submit("zero_day", {})
        zd = [v for v in eng.vulns.values() if v.zero_day]
        assert len(zd) == 2 and len({v.id for v in zd}) == 2
        assert all(not eng.hosts[v.host].compromised and not eng.hosts[v.host].isolated for v in zd)
        assert any(any(x["zero_day"] for n in p["nodes"] for x in n["vulns"]) for p in bus.of("graph_patch"))
    run(go())


def test_honeypot_trips_without_giving_a_foothold(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        await eng._resolve_blue(ActionSpec(action="DEPLOY_HONEYPOT", args={"host": eng.cj}))
        hp = "SKR-HP-01"
        assert {e.src for e in eng.edges if e.dst == hp} >= {eng.cj, "SKR-DC-01", "SKR-DB-01"}
        eng.hosts[hp].vulns_revealed = True
        vid = next(v.id for v in eng.vulns.values() if v.host == hp)
        rec = await eng._resolve_red(ActionSpec(action="EXPLOIT", args={"host": hp, "vuln": vid}))
        assert not rec.success and not eng.hosts[hp].compromised
        assert eng.alerts[-1].kind == "honeypot" and eng.alerts[-1].confidence >= 0.95
    run(go())


def test_beacon_blocks_isolation_even_after_old_investigation(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        h = eng.hosts["SKR-APP-01"]
        await eng._resolve_blue(ActionSpec(action="INVESTIGATE", args={"host": h.id}))
        h.compromised, h.beacon = True, True
        await eng._resolve_blue(ActionSpec(action="ISOLATE", args={"host": h.id}))
        assert not h.isolated and h.compromised and not h.beacon and h.verdict is True
    run(go())


def test_reimage_cleans_the_firewall(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        fw = eng.hosts["SKR-FW-01"]
        fw.compromised, fw.beacon = True, True
        await eng._resolve_blue(ActionSpec(action="INVESTIGATE", args={"host": fw.id}))
        legal = eng.legal_blue()
        assert any(a.action == "REIMAGE" and a.args["host"] == fw.id for a in legal)
        assert any(a.action == "PATCH" and a.args["host"] == fw.id for a in legal)  # flagged host's vulns listed
        assert not any(a.action == "ISOLATE" and a.args["host"] == fw.id for a in legal)
        await eng._resolve_blue(ActionSpec(action="REIMAGE", args={"host": fw.id}))
        assert not fw.compromised and not fw.beacon and not fw.isolated and eng.impact == fw.criticality
    run(go())


def test_eviction_must_hold(make_engine):
    async def go():
        eng, bus = make_engine(); await eng.reset(6)
        eng.ever_compromised = True
        for i in range(1, EVICTION_HOLD):
            await eng._check_eviction()
            assert not eng.winner
        await eng._check_eviction()
        assert eng.winner == "blue" and "locked out" in eng.win_reason
    run(go())


def test_eviction_counter_resets_when_red_returns(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        eng.ever_compromised = True
        await eng._check_eviction()
        eng.hosts["SKR-FW-01"].compromised = True
        await eng._check_eviction()
        assert eng._clean_turns == 0 and not eng.winner
    run(go())


def test_one_patch_per_turn(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        a, b = [x for x in eng.legal_blue() if x.action == "PATCH"][:2]
        assert (await eng._resolve_blue(a)).success
        assert not (await eng._resolve_blue(b)).success
    run(go())


def test_phishing_is_an_independent_entry_vector(make_engine):
    """A spearphish must be available from turn 1 (email reaches employees regardless of
    network position) and a successful one lands a foothold on the victim's endpoint."""
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        phish = [a for a in eng.legal_red() if a.action == "PHISH_USER"]
        assert phish, "phishing should be available before any host is breached"
        endpoint_opts = [a for a in phish if "foothold" in a.description]
        assert endpoint_opts, "at least one user should map to a compromisable endpoint"
        a = endpoint_opts[0]
        endpoint = eng._phish_endpoint(a.args["user"])
        eng.rng.seed(0)
        # force success to assert the foothold mechanic deterministically
        import app.engine as E
        saved = E.random.Random.random
        E.random.Random.random = lambda self: 0.0
        try:
            await eng._resolve_red(a)
        finally:
            E.random.Random.random = saved
        assert eng.hosts[endpoint].compromised
    run(go())


def test_human_turn_waits_and_resolves(make_engine):
    import asyncio

    async def go():
        eng, bus = make_engine(delay=0.0); eng.control["blue"] = "human"
        await eng.reset(6); await eng.start()
        # wait until BLUE's human turn is pending
        for _ in range(2000):
            await asyncio.sleep(0.005)
            if eng._human_future and not eng._human_future.done():
                break
        assert eng._human_future is not None and eng._human_legal
        offered = [p for p in bus.of("your_turn") if p["side"] == "blue"]
        assert offered and offered[0]["n_actions"] == 2
        ok, _ = eng.submit_human_action([eng._human_legal[0].index, eng._human_legal[1].index])
        assert ok
        await asyncio.sleep(0.02)
        assert any(t.side == "blue" and t.model == "human" for t in eng.turns)
        await eng.stop()
    run(go())
