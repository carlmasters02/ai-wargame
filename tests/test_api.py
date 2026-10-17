import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.config import settings


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main.bus, "record_dir", str(tmp_path))
    with TestClient(main.app) as c:
        yield c


def test_websocket_opens_with_full_state(client):
    with client.websocket_connect("/ws") as ws:
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
