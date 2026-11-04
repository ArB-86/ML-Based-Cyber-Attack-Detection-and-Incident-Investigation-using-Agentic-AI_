import json

import pytest

from attack_graph import ollama_reasoner


def test_reasoner_posts_context_and_decodes_json(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434/")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen-test:latest")
    monkeypatch.setenv("OLLAMA_NUM_CTX", "16384")

    captured = {}

    def fake_request(url, payload=None, *, timeout=900):
        captured["url"] = url
        captured["payload"] = payload
        captured["timeout"] = timeout
        return {
            "message": {
                "content": json.dumps({
                    "tool_calls": [],
                    "findings": [],
                    "finding_disposition": "no_additional_findings_supported",
                    "finding_disposition_reason": (
                        "No extra claim is supported by the supplied evidence."
                    ),
                    "narrative": "Evidence requires analyst validation.",
                })
            }
        }

    monkeypatch.setattr(ollama_reasoner, "_request_json", fake_request)
    result = ollama_reasoner.reasoner({"task": "final synthesis", "incident": {"incident_id": "INC-1"}})

    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["payload"]["model"] == "qwen-test:latest"
    schema = captured["payload"]["format"]
    assert isinstance(schema, dict)
    assert schema["properties"]["tool_calls"]["maxItems"] == 0
    assert schema["required"] == [
        "tool_calls",
        "findings",
        "finding_disposition",
        "finding_disposition_reason",
        "narrative",
    ]
    assert captured["payload"]["stream"] is False
    assert captured["payload"]["options"]["num_ctx"] == 16384
    assert "INC-1" in captured["payload"]["messages"][1]["content"]
    assert result["narrative"] == "Evidence requires analyst validation."


def test_reasoner_rejects_non_json_model_content(monkeypatch):
    monkeypatch.setattr(
        ollama_reasoner,
        "_request_json",
        lambda *args, **kwargs: {"message": {"content": "Not JSON"}},
    )
    with pytest.raises(RuntimeError, match="not valid JSON"):
        ollama_reasoner.reasoner({"task": "test"})


def test_check_ollama_requires_configured_model(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "qwen-missing")
    monkeypatch.setattr(
        ollama_reasoner,
        "_request_json",
        lambda *args, **kwargs: {"models": [{"name": "llama3:latest"}]},
    )
    with pytest.raises(RuntimeError, match="not installed"):
        ollama_reasoner.check_ollama()


def test_reasoner_uses_bounded_default_context_and_output_budget(monkeypatch):
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)
    monkeypatch.delenv("OLLAMA_NUM_PREDICT", raising=False)
    captured = {}

    def fake_request(url, payload=None, *, timeout=900):
        captured["payload"] = payload
        return {"message": {"content": '{"tool_calls": [], "findings": [], "narrative": "ok"}'}}

    monkeypatch.setattr(ollama_reasoner, "_request_json", fake_request)
    ollama_reasoner.reasoner({"task": "small test"})

    assert captured["payload"]["options"]["num_ctx"] == 8192
    assert captured["payload"]["options"]["num_predict"] == 2048
