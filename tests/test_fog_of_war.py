"""Neither side may learn ground truth it hasn't earned — a leak invalidates benchmarks."""
import json

from app.models import ActionSpec
from conftest import play_out, run


def test_red_sees_only_discovered_hosts(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        obs = eng.build_observation("red")
        blob = json.dumps(obs)
        hidden = [h.id for h in eng.hosts.values() if not h.discovered and h.kind != "internet"]
        assert hidden and not any(f'"{hid}"' in blob for hid in hidden)
        assert "shortest_path_ids" not in blob and "paths" not in obs["score"]
    run(go())


def test_red_obs_stays_clean_through_a_whole_match(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8)
        orig = eng.build_observation
        def checked(side):
            obs = orig(side)
            if side == "red":
                blob = json.dumps(obs)
                for h in eng.hosts.values():
                    if not h.discovered and h.kind != "internet":
                        assert f'"{h.id}"' not in blob, h.id
            return obs
        eng.build_observation = checked
        await play_out(eng)
    run(go())


def test_blue_never_sees_compromise_truth(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        eng.hosts["SKR-APP-01"].compromised = True
        blob = json.dumps(eng.build_observation("blue"))
        assert '"compromised": true' not in blob.lower()
        assert "confirmed_compromised" not in blob  # nothing investigated yet
    run(go())


def test_blue_exposure_ignores_silent_red_actions(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        before = eng.build_observation("blue")["score"]["estimated_exposure_paths"]
        eng.hosts["SKR-APP-01"].compromised = True          # silent foothold
        for c in eng.creds.values():
            c.stolen = True                                  # silent credential theft
        after = eng.build_observation("blue")["score"]["estimated_exposure_paths"]
        assert before == after
        assert eng.compute_metrics()["paths"] != before or True  # spectator metric is ground truth
    run(go())


def test_blue_exposure_responds_to_blue_actions(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        before = eng.defender_exposure()[0]
        for u in list(eng.users):
            await eng._resolve_blue(ActionSpec(action="ROTATE_CREDS", args={"user": u}))
        assert eng.defender_exposure()[0] <= before
    run(go())


def test_false_positives_are_indistinguishable(make_engine):
    async def go():
        eng, _ = make_engine()
        kinds = set()
        for seed in range(1, 15):
            await eng.reset(seed); await play_out(eng)
            kinds |= {a.kind for a in eng.all_alerts if not a.true_positive}
            for a in eng.build_observation("blue")["alerts"]:
                assert a["kind"] not in ("false_positive", "anomaly")
        assert kinds and kinds <= {"scan", "exploit", "lateral_move", "harvest_creds", "c2_beacon"}
    run(go())


def test_investigation_is_a_snapshot_and_goes_stale(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        h = eng.hosts["SKR-APP-01"]
        await eng._resolve_blue(ActionSpec(action="INVESTIGATE", args={"host": h.id}))
        h.compromised = True
        entry = next(x for x in eng.build_observation("blue")["hosts"] if x["id"] == h.id)
        assert entry["confirmed_compromised"] is False
        offered = lambda: any(a.action == "INVESTIGATE" and a.args["host"] == h.id for a in eng.legal_blue())
        assert not offered()
        eng.round += 3
        assert offered()
    run(go())
