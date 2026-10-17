import types

import pytest

from app.agents import Agent, extract_json
from app.config import settings
from app.models import ActionSpec
from conftest import run


@pytest.mark.parametrize("text,expected", [
    ('{"thought": "x", "action_index": 2}', 2),
    ('```json\n{"thought": "x", "action_index": 1}\n```', 1),
    ('Sure! Here you go: {"thought": "a {brace} in text", "action_index": 0} hope that helps', 0),
])
def test_extract_json(text, expected):
    assert extract_json(text)["action_index"] == expected


def test_extract_json_rejects_garbage():
    with pytest.raises(ValueError):
        extract_json("no json here")


class FakeCompletions:
    def __init__(self, replies):
        self.replies = list(replies)

    async def create(self, **_kw):
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        msg = types.SimpleNamespace(content=reply, reasoning_content=None)
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])


def _agent(replies, side="blue"):
    a = Agent.__new__(Agent)
    a.side, a.model, a.persona, a.temperature, a.system = side, "fake-model", "apt", 0.3, "sys"
    fake = types.SimpleNamespace(chat=types.SimpleNamespace(completions=FakeCompletions(replies)))
    a._resolve = lambda: (fake, "fake-model")  # bypass real client/provider resolution
    return a


LEGAL = [ActionSpec(index=i, action="PATCH", args={"vuln": f"V{i}", "host": "H"}, description=f"a{i}")
         for i in range(4)]


def test_out_of_range_indices_are_ignored_not_guessed():
    picked, _, fb = run(_agent(['{"thought": "t", "action_indices": [99, 2]}'])._call("m", LEGAL, 2))
    assert [a.index for a in picked] == [2] and not fb


def test_all_invalid_indices_raise_for_retry():
    with pytest.raises(ValueError):
        run(_agent(['{"thought": "t", "action_indices": [99, -5]}'])._call("m", LEGAL, 2))


def test_choose_falls_back_to_heuristic_on_failure(make_engine):
    async def go():
        eng, _ = make_engine(); await eng.reset(6)
        legal = eng.legal_blue()
        agent = _agent([RuntimeError("down"), RuntimeError("still down")])
        chosen, thought, fallback, tel = await agent.choose(eng, eng.build_observation("blue"), legal, 2)
        assert fallback and chosen and "fallback" in thought
        assert tel["tokens"] is None and tel["latency_ms"] is not None
    run(go())


def test_provider_resolution(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("MODEL_PROVIDERS",
                       '{"openai": {"base_url": "https://api.openai.com/v1", "api_key": "sk-x"}}')
    monkeypatch.setenv("AIAND_BASE_URL", "https://gw/v1")
    monkeypatch.setenv("AIAND_API_KEY", "gw-key")
    s = Settings()
    assert s.resolve_model("deepseek/x") == ("https://gw/v1", "gw-key", "deepseek/x")
    assert s.resolve_model("openai:gpt-4o") == ("https://api.openai.com/v1", "sk-x", "gpt-4o")
    # unconfigured prefix falls back to the gateway with the id intact
    assert s.resolve_model("groq:llama")[0] == "https://gw/v1"


def test_bad_provider_json_is_ignored(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("MODEL_PROVIDERS", "not json")
    assert Settings().providers == {}
