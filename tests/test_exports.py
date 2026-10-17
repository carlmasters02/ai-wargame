import pytest

from app import attack_map, export
from conftest import play_out, run


@pytest.fixture
def finished(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(8); await play_out(eng)
        return eng
    return run(go())


def test_navigator_layer_follows_spec(finished):
    layer = export.navigator_layer(finished.turns, 8, finished.winner, finished.win_reason)
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    assert layer["techniques"]
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T") and "tactic" not in t


def test_stix_bundle_parses_strictly_and_uses_canonical_ids(finished):
    stix2 = pytest.importorskip("stix2")
    bundle = export.stix_bundle(finished.turns, 8, finished.winner, finished.win_reason)
    parsed = stix2.parse(bundle, allow_custom=False)
    canonical = {t["stix_id"] for techs in attack_map.ACTION_TECHNIQUES.values() for t in techs
                 if t.get("stix_id")}
    sightings = [o for o in parsed.objects if o.type == "sighting"]
    assert sightings and all(s.sighting_of_ref in canonical for s in sightings)
    assert not any(o.type == "attack-pattern" for o in parsed.objects)  # no duplicates minted


def test_stix_identities_are_stable(finished):
    a = export.stix_bundle(finished.turns, 8, finished.winner, finished.win_reason)
    b = export.stix_bundle(finished.turns, 8, finished.winner, finished.win_reason)
    ids = lambda bundle: sorted(o["id"] for o in bundle["objects"] if o["type"] == "identity")
    assert ids(a) == ids(b)


def test_every_red_action_has_a_technique():
    for action in ("SCAN", "EXPLOIT", "HARVEST_CREDS", "LATERAL_MOVE", "EXFILTRATE",
                   "PHISH_USER", "C2_BEACON", "DEFENSE_EVASION"):
        assert attack_map.techniques_for(action)[0]["stix_id"].startswith("attack-pattern--")
