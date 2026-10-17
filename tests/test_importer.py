import os

import pytest

from app import importer
from conftest import play_out, run

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "examples", "sample_network.csv")


def test_csv_import_round_trips_to_a_playable_spec():
    spec = importer.import_csv(open(SAMPLE).read())
    assert spec.crown_jewel == "CUSTOMER-DB"
    assert any(h.kind == "internet" and h.compromised for h in spec.hosts)  # beachhead added
    assert spec.vulns and all(v.host in {h.id for h in spec.hosts} for v in spec.vulns)
    # internet's neighbours are discovered (fog of war seeded)
    hmap = {h.id: h for h in spec.hosts}
    inet = next(h for h in spec.hosts if h.kind == "internet")
    nbrs = [e.dst for e in spec.edges if e.src == inet.id]
    assert nbrs and all(hmap[n].discovered for n in nbrs)


def test_csv_defaults_crown_to_highest_criticality():
    spec = importer.import_csv("hosts:\nA,server,corp,3\nB,database,restricted,10\nedges:\nA,B")
    assert spec.crown_jewel == "B"


def test_empty_or_bad_csv_raises():
    with pytest.raises(importer.ImportError):
        importer.import_csv("just,some,garbage\nwith,no,sections")


def test_imported_network_is_playable(make_engine):
    async def go():
        eng, _ = make_engine()
        spec = importer.import_csv(open(SAMPLE).read())
        await eng.load_network(spec)
        assert eng.cj == "CUSTOMER-DB" and eng.compute_metrics()["paths"] > 0
        rep = eng.exposure_analysis()
        assert rep["top_fixes"] and rep["current_exposure"] > 0
        await play_out(eng)
        assert eng.winner in ("red", "blue")
    run(go())


def test_nmap_import_is_xxe_safe():
    # a billion-laughs / XXE payload must not expand or read files — defusedxml rejects it
    evil = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;">]><nmaprun><host><status state="up"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>')
    with pytest.raises(importer.ImportError):
        importer.import_nmap(evil)


def test_nmap_import_basic():
    xml = ('<nmaprun><host><status state="up"/>'
           '<address addr="10.0.0.5" addrtype="ipv4"/>'
           '<ports><port portid="443"><state state="open"/>'
           '<service name="https"/></port></ports></host>'
           '<host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>'
           '<ports><port portid="1433"><state state="open"/>'
           '<service name="ms-sql"/></port></ports></host></nmaprun>')
    spec = importer.import_nmap(xml)
    ids = {h.id for h in spec.hosts}
    assert "10.0.0.5" in ids and "10.0.0.9" in ids
    assert any(h.kind == "database" for h in spec.hosts)
