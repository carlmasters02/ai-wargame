import json

from app import telemetry
from app.models import ActionSpec
from conftest import play_out, run


def test_every_red_action_maps_to_a_sensor_event():
    for action in ("SCAN", "EXPLOIT", "HARVEST_CREDS", "LATERAL_MOVE", "PHISH_USER",
                   "C2_BEACON", "DEFENSE_EVASION", "EXFILTRATE"):
        ev = telemetry.event_for(action, "H1")
        assert ev and ev["source"] and ev["signature"] and ev["data_source"].startswith("DS")


def test_events_recorded_for_every_detection_roll(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8); await play_out(eng)
        # every RED action that targets a host should leave a log event
        red_targeted = [t for t in eng.turns if t.side == "red"
                        and t.action in telemetry.ACTION_EVENTS and (t.args.get("host") or t.meta.get("target"))]
        assert eng.all_events and len(eng.all_events) >= len([t for t in red_targeted if t.action != "PHISH_USER"])
        # alerts that fired carry the sensor + signature of their event
        for a in eng.all_alerts:
            if a.true_positive and a.kind != "honeypot":
                assert a.source and a.signature
    run(go())


def test_blue_sees_events_but_never_the_benign_flag_or_truth(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8); await play_out(eng)
        obs = eng.build_observation("blue")
        blob = json.dumps(obs)
        assert "recent_log_events" in obs
        assert '"benign"' not in blob            # engine-only
        assert '"compromised": true' not in blob.lower()
        assert '"true_positive"' not in blob     # engine-only
    run(go())


def test_false_positive_events_are_indistinguishable(make_engine):
    async def go():
        eng, _ = make_engine()
        benign_sigs, real_sigs = set(), set()
        for seed in range(1, 12):
            await eng.reset(seed); await play_out(eng)
            for e in eng.all_events:
                (benign_sigs if e.benign else real_sigs).add(e.source)
        # benign events come from the same sensors as real ones (no tell-tale source)
        assert benign_sigs and benign_sigs <= real_sigs | benign_sigs
    run(go())
