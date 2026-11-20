"""Model providers and the fallback chain, against a fake HTTP layer (no network)."""
import json

import pytest
import requests

from agent import config, llm, providers
from agent.schemas import ChunkReview

ANSWER = {"suspicious": True, "confidence": "high", "category": "data_exfiltration",
          "evidence_lines": ["sock.connect(...)"], "explanation": "Opens a socket at import time."}


class FakeResponse:
    def __init__(self, status: int, doc: dict):
        self.status_code, self._doc, self.text = status, doc, json.dumps(doc)

    def json(self):
        return self._doc

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


def completion(content: str) -> FakeResponse:
    return FakeResponse(200, {"choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                              "usage": {"prompt_tokens": 10, "completion_tokens": 5}})


@pytest.fixture
def http(monkeypatch):
    """Records every POST; `http.replies` is a list of responses (or exceptions) handed out in order."""
    class Http:
        calls: list = []
        replies: list = []

    def post(url, json=None, headers=None, timeout=None):
        Http.calls.append({"url": url, "body": json, "headers": headers or {}})
        reply = Http.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(providers.requests, "post", post)
    for k in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "MOONSHOT_API_KEY",
              "KIMI_API_KEY", "MISTRAL_API_KEY", "DEEPSEEK_MODEL", "OPENAI_COMPATIBLE_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    providers.reset()
    yield Http
    providers.reset()


def use(monkeypatch, chain: str):
    monkeypatch.setattr(config, "LLM_PROVIDER", chain)
    providers.reset()


@pytest.mark.parametrize("name,url,key_env", [
    ("openai", "https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "GEMINI_API_KEY"),
    ("deepseek", "https://api.deepseek.com/chat/completions", "DEEPSEEK_API_KEY"),
    ("kimi", "https://api.moonshot.ai/v1/chat/completions", "MOONSHOT_API_KEY"),
    ("mistral", "https://api.mistral.ai/v1/chat/completions", "MISTRAL_API_KEY"),
])
def test_hosted_providers_speak_chat_completions(http, monkeypatch, name, url, key_env):
    monkeypatch.setenv(key_env, "sk-test")
    use(monkeypatch, name)
    http.replies = [completion(json.dumps(ANSWER))]
    answer, model = llm.complete("sys", "diff", ChunkReview)
    call = http.calls[-1]
    assert answer.category == "data_exfiltration" and model.startswith(name + ":")
    assert call["url"] == url and call["headers"]["Authorization"] == "Bearer sk-test"
    fmt = call["body"]["response_format"]
    if providers.PRESETS[name].json_mode == "object":     # no json_schema support: schema goes in the prompt
        assert fmt == {"type": "json_object"} and '"suspicious"' in call["body"]["messages"][0]["content"]
    else:
        assert fmt["type"] == "json_schema" and fmt["json_schema"]["schema"]["title"] == "ChunkReview"


def test_model_and_url_overrides_and_fenced_json(http, monkeypatch):
    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "http://vllm:8000/v1/")
    monkeypatch.setenv("OPENAI_COMPATIBLE_MODEL", "qwen2.5-14b")
    use(monkeypatch, "vllm")
    http.replies = [completion("```json\n" + json.dumps(ANSWER) + "\n```")]
    answer, model = llm.complete("sys", "diff", ChunkReview)
    assert model == "openai-compatible:qwen2.5-14b" and answer.suspicious
    assert http.calls[-1]["url"] == "http://vllm:8000/v1/chat/completions"
    assert "Authorization" not in http.calls[-1]["headers"]          # local servers need no key


def test_json_schema_rejected_falls_back_to_json_mode(http, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    use(monkeypatch, "gemini")
    http.replies = [FakeResponse(400, {"error": "response_format json_schema not supported"}),
                    completion(json.dumps(ANSWER)), completion(json.dumps(ANSWER))]
    llm.complete("sys", "diff", ChunkReview)
    llm.complete("sys", "diff", ChunkReview)
    assert [c["body"]["response_format"]["type"] for c in http.calls] == ["json_schema", "json_object", "json_object"]


def test_chain_falls_through_to_next_provider(http, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    use(monkeypatch, "ollama, openai, deepseek")       # ollama down, openai has no key
    http.replies = [requests.ConnectionError("refused"), completion(json.dumps(ANSWER))]
    answer, model = llm.complete("sys", "diff", ChunkReview)
    assert model == "deepseek:deepseek-chat"
    assert llm.describe().startswith("ollama:") and "→ deepseek:deepseek-chat" in llm.describe()


def test_all_providers_down_raises_with_every_reason(http, monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "k")
    use(monkeypatch, "openai,kimi")
    http.replies = [FakeResponse(401, {"error": "bad key"})]
    with pytest.raises(llm.LLMUnavailable) as exc:
        llm.complete("sys", "diff", ChunkReview)
    assert "openai: no API key" in str(exc.value) and "credentials rejected (401)" in str(exc.value)


def test_unknown_provider_is_a_config_error(monkeypatch):
    use(monkeypatch, "skynet")
    with pytest.raises(ValueError, match="unknown LLM provider"):
        llm.complete("sys", "diff", ChunkReview)


def test_live_answer_is_cached_under_the_model_that_gave_it(http, monkeypatch, tmp_path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(config, "LLM_MODE", "live")
    use(monkeypatch, "deepseek")
    http.replies = [completion("not json"), completion(json.dumps(ANSWER))]   # invalid once, then retried
    answer, source = llm.ask("vet", "k1", "sys", "diff", ChunkReview)
    assert source == "live" and answer.suspicious
    assert json.loads((tmp_path / "vet" / "k1.json").read_text())["model"] == "deepseek:deepseek-chat"
