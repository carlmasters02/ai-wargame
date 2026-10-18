import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.main as main
from app.config import settings


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main.bus, "record_dir", str(tmp_path))
    with TestClient(main.app, base_url="http://localhost", client=("127.0.0.1", 50000)) as c:
        yield c


def test_websocket_opens_with_full_state(client):
    with client.websocket_connect("ws://localhost/ws") as ws:
        kinds = [ws.receive_json()["type"] for _ in range(3)]
    assert kinds == ["graph_snapshot", "metrics", "status"]


def test_controls_and_validation(client):
    assert client.post("/api/reset", json={"seed": 6}).json()["seed"] == 6
    assert client.post("/api/speed", json={"x": "fast"}).status_code == 400
    assert client.post("/api/speed", json={"x": "nan"}).status_code == 400
    assert client.post("/api/reset", json={"seed": "abc"}).status_code == 400
    assert client.post("/api/persona", json={"persona": "nope"}).status_code == 400
    assert client.post("/api/model", json={"side": "red", "model": "x"}).status_code == 409  # heuristic mode
    assert client.post("/api/intervene/zero_day").status_code == 200
    assert client.get("/api/export/navigator").status_code == 404  # no actions yet


def test_token_guards_mutations_but_not_spectating(client, monkeypatch):
    monkeypatch.setattr(settings, "WARGAME_TOKEN", "s3cret")
    assert client.post("/api/start").status_code == 401
    assert client.post("/api/start", headers={"X-Wargame-Token": "wrong"}).status_code == 401
    assert client.post("/api/pause", headers={"X-Wargame-Token": "s3cret"}).status_code == 200
    assert client.get("/api/state").status_code == 200
    assert client.get("/").status_code == 200


def test_control_and_human_action_validation(client):
    assert client.post("/api/control", json={"side": "blue", "who": "human"}).json()["players"]["blue"] == "human"
    assert client.post("/api/control", json={"side": "blue", "who": "robot"}).status_code == 400
    # no human turn is pending yet -> 409
    r = client.post("/api/act", json={"indices": [0, 1]})
    assert r.status_code == 409 and r.json()["ok"] is False
    assert client.post("/api/act", json={"indices": "nope"}).status_code == 400
    client.post("/api/control", json={"side": "blue", "who": "auto"})


def test_reset_with_scenario(client):
    r = client.post("/api/reset", json={"seed": 6, "scenario": "ransomware"})
    assert r.status_code == 200 and r.json()["scenario"] == "ransomware"
    assert client.post("/api/reset", json={"seed": 6, "scenario": "bogus"}).status_code == 400
    client.post("/api/reset", json={"seed": 6, "scenario": "baseline"})


def test_config_endpoint(client):
    r = client.post("/api/config", json={"difficulty": "hard", "max_turns": 15})
    assert r.status_code == 200 and r.json()["difficulty"] == "hard" and r.json()["max_turns"] == 15
    client.post("/api/config", json={"difficulty": "normal", "max_turns": 20})


def test_guard_blocks_rebinding_csrf_and_oversized_bodies(client, monkeypatch):
    # open mode: only loopback Host names are served (DNS rebinding / accidental exposure)
    assert client.get("/api/state", headers={"host": "evil.example"}).status_code == 403
    # a foreign page can't drive the server, but the app's own page can
    assert client.post("/api/pause", headers={"origin": "http://evil.example"}).status_code == 403
    assert client.post("/api/pause", headers={"origin": "http://localhost"}).status_code == 200
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("ws://localhost/ws", headers={"origin": "http://evil.example"}) as ws:
            ws.receive_json()
    # bodies are capped before parsing
    big = '{"format": "csv", "content": "' + "x" * (main.MAX_BODY + 10) + '"}'
    assert client.post("/api/import", content=big,
                       headers={"content-type": "application/json"}).status_code == 413
    # security headers on every response
    h = client.get("/").headers
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    # with a token: any Host is served, and the token is only accepted as a header
    monkeypatch.setattr(settings, "WARGAME_TOKEN", "s3cret")
    assert client.get("/api/state", headers={"host": "wargame.example"}).status_code == 200
    assert client.post("/api/pause?token=s3cret").status_code == 401


def test_open_mode_refuses_network_clients_even_with_forged_host(tmp_path, monkeypatch):
    monkeypatch.setattr(main.bus, "record_dir", str(tmp_path))
    with TestClient(main.app, base_url="http://localhost", client=("192.168.1.50", 50000)) as lan:
        assert lan.post("/api/pause").status_code == 403          # Host: localhost, LAN peer
        assert lan.get("/api/state").status_code == 403
        monkeypatch.setattr(settings, "WARGAME_TOKEN", "s3cret")  # with a token, LAN is fine
        assert lan.post("/api/pause", headers={"X-Wargame-Token": "s3cret"}).status_code == 200
        monkeypatch.setattr(settings, "WARGAME_TOKEN", "")
    with TestClient(main.app, base_url="http://localhost", client=("::ffff:127.0.0.1", 1)) as v6:
        assert v6.get("/api/state").status_code == 200            # IPv4-mapped loopback
        # a local reverse proxy forwarding remote traffic must use a token
        assert v6.get("/api/state", headers={"x-forwarded-for": "203.0.113.9"}).status_code == 403
