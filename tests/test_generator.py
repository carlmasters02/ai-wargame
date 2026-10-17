from app import generator
from app.generator import CVE_POOL


def test_same_seed_same_network():
    a, b = generator.generate(123), generator.generate(123)
    assert a.model_dump() == b.model_dump()


def test_different_seeds_differ():
    assert generator.generate(1).model_dump() != generator.generate(2).model_dump()


def test_path_guarantee_holds_across_seeds():
    for seed in range(40):
        spec, used = generator.generate_with_guarantee(seed)
        assert generator.path_guarantee_count(spec) >= 3, seed


def test_vulns_come_from_the_real_cve_pool():
    pool = {cve for entries in CVE_POOL.values() for cve, _, _ in entries}
    spec = generator.generate(7)
    for v in spec.vulns:
        assert v.cve_label in pool
        assert 0.05 <= v.exploitability <= 0.95
        assert 0.0 <= v.noise <= 0.9


def test_crown_jewel_is_fixed_and_hard():
    spec = generator.generate(9)
    cj = [v for v in spec.vulns if v.host == spec.crown_jewel]
    assert spec.crown_jewel == "SKR-DB-PROD"
    assert [v.cve_label for v in cj] == ["CVE-2020-1472"]
    assert cj[0].exploitability == 0.35


def test_every_credential_grant_is_reachable():
    spec = generator.generate(11)
    pairs = {(e.src, e.dst) for e in spec.edges}
    for c in spec.creds:
        assert c.stored_on == c.grants or (c.stored_on, c.grants) in pairs, c.id


def test_initial_fog_of_war():
    spec = generator.generate(5)
    known = {h.id for h in spec.hosts if h.discovered}
    assert known == {"INTERNET", "SKR-FW-01"}
