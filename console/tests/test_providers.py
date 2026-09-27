import json

import pytest

from app import assistant, providers
from app.manager import MASK
from tests.test_core import repo  # noqa: F401  (fixture: db init)

MESSAGES = [
    {"role": "system", "content": "sys"},
    {"role": "user", "content": "hi"},
    {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "name": "search_events", "args": {"q": "wget"}},
        {"id": "c2", "name": "list_xpods", "args": {}}]},
    {"role": "tool", "tool_call_id": "c1", "name": "search_events", "content": "{\"r\":1}"},
    {"role": "tool", "tool_call_id": "c2", "name": "list_xpods", "content": "{\"r\":2}"},
    {"role": "assistant", "content": "done"},
]


def test_to_openai_shapes():
    out = providers._to_openai(MESSAGES)
    asst = next(m for m in out if m["role"] == "assistant" and m.get("tool_calls"))
    assert asst["tool_calls"][0]["id"] == "c1"
    assert json.loads(asst["tool_calls"][0]["function"]["arguments"]) == {"q": "wget"}
    tools = [m for m in out if m["role"] == "tool"]
    assert tools[0]["tool_call_id"] == "c1" and tools[1]["tool_call_id"] == "c2"


def test_to_anthropic_shapes():
    system, msgs = providers._to_anthropic(MESSAGES)
    assert system == "sys"
    assert all(m["role"] != "system" for m in msgs)
    # assistant tool_use turn
    asst = next(m for m in msgs if m["role"] == "assistant" and isinstance(m["content"], list)
                and any(b.get("type") == "tool_use" for b in m["content"]))
    uses = [b for b in asst["content"] if b["type"] == "tool_use"]
    assert [b["id"] for b in uses] == ["c1", "c2"]
    # the two consecutive tool results are merged into ONE user turn
    merged = [m for m in msgs if m["role"] == "user" and isinstance(m["content"], list)
              and m["content"] and m["content"][0].get("type") == "tool_result"]
    assert len(merged) == 1 and len(merged[0]["content"]) == 2
    assert [b["tool_use_id"] for b in merged[0]["content"]] == ["c1", "c2"]


def test_to_ollama_shapes():
    out = providers._to_ollama(MESSAGES)
    asst = next(m for m in out if m["role"] == "assistant" and m.get("tool_calls"))
    assert asst["tool_calls"][0]["function"]["name"] == "search_events"
    assert asst["tool_calls"][0]["function"]["arguments"] == {"q": "wget"}


def test_unknown_provider_raises():
    with pytest.raises(providers.ProviderError):
        list(providers.stream({"provider": "bogus", "model": "x"}, [], []))


# ------------------------------------------------------------------ settings

def test_settings_default_local(repo):  # noqa: F811
    s = assistant.get_settings()
    assert s["provider"] == "local"
    assert assistant.active_config()["provider"] == "local"


def test_settings_switch_and_key_masking(repo):  # noqa: F811
    assistant.set_settings({"provider": "anthropic", "model_anthropic": "claude-opus-5",
                            "key_anthropic": "sk-ant-secret"}, "admin")
    s = assistant.get_settings()
    assert s["provider"] == "anthropic" and s["models"]["anthropic"] == "claude-opus-5"
    assert s["keys_set"]["anthropic"] is True
    assert "sk-ant-secret" not in json.dumps(s)          # key never returned
    ac = assistant.active_config()
    assert ac["provider"] == "anthropic" and ac["api_key"] == "sk-ant-secret"

    # MASK leaves the key unchanged; empty string clears it
    assistant.set_settings({"key_anthropic": MASK}, "admin")
    assert assistant.active_config()["api_key"] == "sk-ant-secret"
    assistant.set_settings({"key_anthropic": ""}, "admin")
    assert assistant.active_config()["api_key"] == ""


def test_settings_invalid_provider(repo):  # noqa: F811
    with pytest.raises(ValueError):
        assistant.set_settings({"provider": "grok"}, "admin")
