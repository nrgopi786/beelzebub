"""LLM provider adapters for the assistant: local Ollama, OpenAI, or Anthropic (Claude).

The assistant keeps one provider-agnostic message format; each adapter converts it to the
provider's wire format at request time and streams back a normalized result. All three expose
`stream(cfg, messages, tools)`, a generator that yields ("token", text) chunks and *returns*
(content, tool_calls) where tool_calls is [{"id", "name", "args": dict}].

Internal message format:
  {"role": "system"|"user"|"assistant"|"tool", "content": str,
   "tool_calls": [{"id","name","args"}]?, "tool_call_id": str?, "name": str?}
"""
import json
import urllib.error
import urllib.request

from . import config

MAX_TOKENS = 4096


class ProviderError(RuntimeError):
    pass


# --------------------------------------------------------------------------- Ollama (local)

def _stream_ollama(cfg, messages, tools):
    body = {"model": cfg["model"], "messages": _to_ollama(messages), "tools": tools,
            "stream": True, "options": {"temperature": 0.1}}
    req = urllib.request.Request(config.LLM_URL + "/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    content, calls = "", []
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            for line in r:
                if not line.strip():
                    continue
                chunk = json.loads(line)
                if chunk.get("error"):
                    raise ProviderError(chunk["error"])
                msg = chunk.get("message") or {}
                if msg.get("content"):
                    content += msg["content"]
                    yield ("token", msg["content"])
                for tc in msg.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    args = fn.get("arguments")
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except ValueError:
                            args = {}
                    calls.append({"id": tc.get("id") or f"call_{len(calls)}", "name": fn.get("name", ""),
                                  "args": args or {}})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ProviderError(str(exc)) from None
    return content, calls


def _to_ollama(messages):
    out = []
    for m in messages:
        if m["role"] == "assistant" and m.get("tool_calls"):
            out.append({"role": "assistant", "content": m.get("content", ""),
                        "tool_calls": [{"function": {"name": c["name"], "arguments": c["args"]}}
                                       for c in m["tool_calls"]]})
        elif m["role"] == "tool":
            out.append({"role": "tool", "content": m["content"]})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    return out


# --------------------------------------------------------------------------- OpenAI

def _stream_openai(cfg, messages, tools):
    try:
        from openai import OpenAI
    except ImportError:
        raise ProviderError("openai package not installed") from None
    if not cfg.get("api_key"):
        raise ProviderError("no OpenAI API key configured")
    client = OpenAI(api_key=cfg["api_key"], timeout=120)
    content, acc = "", {}
    try:
        stream = client.chat.completions.create(
            model=cfg["model"], messages=_to_openai(messages), tools=tools,
            temperature=0.1, stream=True)
        for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if getattr(delta, "content", None):
                content += delta.content
                yield ("token", delta.content)
            for tc in getattr(delta, "tool_calls", None) or []:
                a = acc.setdefault(tc.index, {"id": "", "name": "", "args": ""})
                if tc.id:
                    a["id"] = tc.id
                if tc.function and tc.function.name:
                    a["name"] += tc.function.name
                if tc.function and tc.function.arguments:
                    a["args"] += tc.function.arguments
    except Exception as exc:  # openai raises many typed errors
        raise ProviderError(str(exc)) from None
    calls = []
    for i, a in sorted(acc.items()):
        try:
            args = json.loads(a["args"] or "{}")
        except ValueError:
            args = {}
        calls.append({"id": a["id"] or f"call_{i}", "name": a["name"], "args": args})
    return content, calls


def _to_openai(messages):
    out = []
    for m in messages:
        if m["role"] == "assistant" and m.get("tool_calls"):
            out.append({"role": "assistant", "content": m.get("content") or None,
                        "tool_calls": [{"id": c["id"], "type": "function",
                                        "function": {"name": c["name"], "arguments": json.dumps(c["args"])}}
                                       for c in m["tool_calls"]]})
        elif m["role"] == "tool":
            out.append({"role": "tool", "tool_call_id": m.get("tool_call_id", ""), "content": m["content"]})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    return out


# --------------------------------------------------------------------------- Anthropic (Claude)

def _stream_anthropic(cfg, messages, tools):
    try:
        from anthropic import Anthropic
    except ImportError:
        raise ProviderError("anthropic package not installed") from None
    if not cfg.get("api_key"):
        raise ProviderError("no Anthropic API key configured")
    client = Anthropic(api_key=cfg["api_key"], timeout=120)
    system, msgs = _to_anthropic(messages)
    atools = [{"name": t["function"]["name"], "description": t["function"]["description"],
               "input_schema": t["function"]["parameters"]} for t in tools]
    content, calls = "", []
    try:
        with client.messages.stream(model=cfg["model"], max_tokens=MAX_TOKENS, system=system,
                                    tools=atools, messages=msgs) as stream:
            for text in stream.text_stream:
                content += text
                yield ("token", text)
            final = stream.get_final_message()
        for block in final.content:
            if block.type == "tool_use":
                calls.append({"id": block.id, "name": block.name,
                              "args": block.input if isinstance(block.input, dict) else {}})
    except Exception as exc:
        raise ProviderError(str(exc)) from None
    return content, calls


def _to_anthropic(messages):
    system = ""
    msgs = []
    for m in messages:
        role = m["role"]
        if role == "system":
            system = m.get("content", "")
        elif role == "assistant":
            blocks = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for c in m.get("tool_calls") or []:
                blocks.append({"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]})
            msgs.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
        elif role == "tool":
            block = {"type": "tool_result", "tool_use_id": m.get("tool_call_id", ""), "content": m["content"]}
            # Merge consecutive tool results into one user turn (parallel tool calls).
            if msgs and msgs[-1]["role"] == "user" and isinstance(msgs[-1]["content"], list) \
                    and msgs[-1]["content"] and msgs[-1]["content"][0].get("type") == "tool_result":
                msgs[-1]["content"].append(block)
            else:
                msgs.append({"role": "user", "content": [block]})
        else:
            msgs.append({"role": "user", "content": m.get("content", "")})
    return system, msgs


# --------------------------------------------------------------------------- dispatch

_ADAPTERS = {"local": _stream_ollama, "openai": _stream_openai, "anthropic": _stream_anthropic}


def stream(cfg, messages, tools):
    adapter = _ADAPTERS.get(cfg["provider"])
    if not adapter:
        raise ProviderError(f"unknown provider {cfg['provider']}")
    return adapter(cfg, messages, tools)
