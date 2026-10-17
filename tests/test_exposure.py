from app import exposure
from app.models import Credential, Edge, Host, Vuln
from conftest import run


def _net():
    hosts = [Host(id="I", name="I", kind="internet", zone="internet", compromised=True),
             Host(id="A", name="A", kind="webserver", zone="dmz"),
             Host(id="B", name="B", kind="appserver", zone="corp"),
             Host(id="J", name="J", kind="database", zone="restricted", criticality=10)]
    edges = [Edge(src="I", dst="A"), Edge(src="A", dst="B"), Edge(src="A", dst="J"), Edge(src="B", dst="J")]
    vulns = [Vuln(id="vA", host="A", cve_label="X", name="x", severity=9, exploitability=.5, noise=.2),
             Vuln(id="vB", host="B", cve_label="Y", name="y", severity=9, exploitability=.5, noise=.2),
             Vuln(id="vJ", host="J", cve_label="Z", name="z", severity=10, exploitability=.3, noise=.5)]
    return hosts, edges, vulns, []


def test_patching_the_chokepoint_removes_all_paths():
    hosts, edges, vulns, creds = _net()
    rep = exposure.analyse(hosts, edges, vulns, creds, "J")
    assert rep["current_exposure"] == 2
    top = rep["top_fixes"][0]
    # A and J are both full chokepoints here; the best fix removes every path
    assert top["action"] == "PATCH" and top["paths_removed"] == 2 and top["pct_removed"] == 1.0


def test_minimal_fix_plan_drives_exposure_to_zero():
    hosts, edges, vulns, creds = _net()
    rep = exposure.analyse(hosts, edges, vulns, creds, "J")
    assert rep["residual_after_plan"] == 0 and len(rep["minimal_fix_plan"]) >= 1


def test_does_not_mutate_inputs():
    hosts, edges, vulns, creds = _net()
    exposure.analyse(hosts, edges, vulns, creds, "J")
    assert not any(v.patched for v in vulns) and not any(h.isolated for h in hosts)


def test_rotation_candidate_appears_when_creds_stolen():
    hosts, edges, vulns, creds = _net()
    vulns[2].patched = True  # J only reachable via a credential now
    creds = [Credential(id="c", kind="pw", owner="u", stored_on="B", grants="J", stolen=True)]
    rep = exposure.analyse(hosts, edges, vulns, creds, "J")
    assert any(f["action"] == "ROTATE_CREDS" for f in rep["top_fixes"])


def test_engine_exposure_endpoint(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        rep = eng.exposure_analysis()
        assert rep["current_exposure"] > 0 and rep["top_fixes"]
    run(go())
