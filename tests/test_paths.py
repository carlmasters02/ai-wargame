from app.models import Credential, Edge, Host, Vuln
from app.paths import count_viable_paths


def _graph():
    hosts = [Host(id="I", name="I", kind="internet", zone="internet", compromised=True),
             Host(id="A", name="A", kind="webserver", zone="dmz"),
             Host(id="B", name="B", kind="appserver", zone="corp"),
             Host(id="J", name="J", kind="database", zone="restricted")]
    edges = [Edge(src="I", dst="A"), Edge(src="A", dst="B"), Edge(src="A", dst="J"), Edge(src="B", dst="J")]
    vulns = [Vuln(id="v1", host="A", cve_label="X", name="x", severity=9, exploitability=.5, noise=.2),
             Vuln(id="v2", host="B", cve_label="X", name="x", severity=9, exploitability=.5, noise=.2),
             Vuln(id="v3", host="J", cve_label="X", name="x", severity=9, exploitability=.5, noise=.2)]
    return hosts, edges, vulns


def test_counts_all_simple_paths_and_shortest():
    hosts, edges, vulns = _graph()
    n, shortest, capped = count_viable_paths(hosts, edges, vulns, [], "J")
    assert (n, shortest, capped) == (2, ["I", "A", "J"], False)


def test_patching_and_isolation_cut_paths():
    hosts, edges, vulns = _graph()
    vulns[2].patched = True  # J no longer breachable
    assert count_viable_paths(hosts, edges, vulns, [], "J")[0] == 0
    vulns[2].patched = False
    hosts[1].isolated = True  # A isolated: every path dies
    assert count_viable_paths(hosts, edges, vulns, [], "J")[0] == 0


def test_stolen_credentials_make_hosts_breachable():
    hosts, edges, vulns = _graph()
    vulns[2].patched = True
    cred = Credential(id="c", kind="password", owner="u", stored_on="B", grants="J")
    assert count_viable_paths(hosts, edges, vulns, [cred], "J")[0] == 0
    cred.stolen = True
    assert count_viable_paths(hosts, edges, vulns, [cred], "J")[0] == 2
    cred.rotated = True
    assert count_viable_paths(hosts, edges, vulns, [cred], "J")[0] == 0


def test_dense_graph_is_bounded_by_budget():
    # a 40-node mesh with an unreachable crown jewel used to enumerate ~40^8 simple paths
    n = 40
    hosts = [Host(id="I", name="I", kind="internet", zone="internet", compromised=True),
             Host(id="J", name="J", kind="database", zone="restricted")]
    hosts += [Host(id=f"H{i}", name=f"H{i}", kind="server", zone="corp") for i in range(n)]
    edges = [Edge(src="I", dst=f"H{i}") for i in range(n)]
    edges += [Edge(src=f"H{i}", dst=f"H{j}") for i in range(n) for j in range(n) if i != j]
    vulns = [Vuln(id=f"v{i}", host=f"H{i}", cve_label="X", name="x", severity=9,
                  exploitability=.5, noise=.2) for i in range(n)]
    count, _, capped = count_viable_paths(hosts, edges, vulns, [], "J", budget=10_000)
    assert count == 0 and capped
