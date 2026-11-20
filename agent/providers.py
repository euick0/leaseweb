"""Model providers: one structured call in, one validated answer out.

Every provider implements `chat(system, user, schema, timeout) -> answer` and
raises LLMUnavailable when it cannot answer (down, no key, refused) or
pydantic's ValidationError when it answers with the wrong shape. Retry, cache
and fallback live above this, in agent/llm.py.

  ollama        open-weight model on our own hardware (the default)
  anthropic     Claude, through the Anthropic SDK (`uv sync --extra anthropic`)
  openai, gemini, deepseek, kimi, mistral
                hosted APIs speaking the OpenAI chat-completions protocol
  openai-compatible
                any other server speaking that protocol (vLLM, llama.cpp,
                LM Studio, OpenRouter, ...): set OPENAI_COMPATIBLE_BASE_URL

Each provider reads <NAME>_MODEL, <NAME>_BASE_URL and <NAME>_API_KEY from the
environment (name upper-cased, "-" as "_"); the defaults are in PRESETS.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse
from typing import Optional, Protocol, Type, TypeVar

import requests
from pydantic import BaseModel

from . import config, overrides

T = TypeVar("T", bound=BaseModel)


class LLMUnavailable(RuntimeError):
    pass


class Provider(Protocol):
    name: str
    model: str

    def chat(self, system: str, user: str, schema: Type[T], timeout: float) -> T: ...


def _env(name: str, key: str) -> Optional[str]:
    return os.environ.get(f"{name.upper().replace('-', '_')}_{key}") or None


def _schema_instruction(schema: Type[BaseModel]) -> str:
    return ("\n\nAnswer with one JSON object, and nothing else, that matches this JSON schema:\n"
            + json.dumps(schema.model_json_schema()))


def _strip_fences(text: str) -> str:
    m = re.fullmatch(r"\s*```(?:json)?\s*(.*?)\s*```\s*", text, re.S)
    return m.group(1) if m else text


# ------------------------------------------------------------------ ollama

class Ollama:
    name = "ollama"

    def __init__(self):
        self.model = overrides.model("ollama") or config.OLLAMA_MODEL
        self.url = config.OLLAMA_URL

    def chat(self, system: str, user: str, schema: Type[T], timeout: float) -> T:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "format": schema.model_json_schema(),
            "stream": False,
            "options": {"temperature": 0, "num_ctx": 16384},
        }
        try:
            resp = requests.post(f"{self.url}/api/chat", json=body, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LLMUnavailable(str(exc)) from exc
        content = resp.json().get("message", {}).get("content", "")
        return schema.model_validate_json(content)


# ------------------------------------------------------- openai-compatible

@dataclass(frozen=True)
class Preset:
    base_url: Optional[str]
    model: Optional[str]
    key_envs: tuple[str, ...]
    # "schema": response_format json_schema; "object": json_object plus the schema in the prompt
    json_mode: str = "schema"
    temperature: Optional[float] = 0


# Default models are a starting point; check the provider's model list and
# override with <NAME>_MODEL.
PRESETS: dict[str, Preset] = {
    # GPT-5-class reasoning models only accept the default temperature
    "openai": Preset("https://api.openai.com/v1", "gpt-5-mini", ("OPENAI_API_KEY",), temperature=None),
    "gemini": Preset("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash",
                     ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    "deepseek": Preset("https://api.deepseek.com", "deepseek-chat", ("DEEPSEEK_API_KEY",), json_mode="object"),
    "kimi": Preset("https://api.moonshot.ai/v1", "kimi-k2-0905-preview", ("MOONSHOT_API_KEY", "KIMI_API_KEY"),
                   json_mode="object"),
    "mistral": Preset("https://api.mistral.ai/v1", "mistral-small-latest", ("MISTRAL_API_KEY",)),
    "openai-compatible": Preset(None, None, ("OPENAI_COMPATIBLE_API_KEY",)),
}
ALIASES = {"moonshot": "kimi", "google": "gemini", "claude": "anthropic", "vllm": "openai-compatible"}


class OpenAICompatible:
    """Chat completions over plain HTTP, so no SDK per provider."""

    def __init__(self, name: str, preset: Preset):
        self.name = name
        self.base_url = (_env(name, "BASE_URL") or preset.base_url or "").rstrip("/")
        self.model = overrides.model(name) or _env(name, "MODEL") or preset.model or ""
        self.api_key = next((os.environ[k] for k in preset.key_envs if os.environ.get(k)), None)
        self.json_mode = _env(name, "JSON_MODE") or preset.json_mode
        self.temperature = preset.temperature

    def _post(self, body: dict, timeout: float) -> requests.Response:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            return requests.post(f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            raise LLMUnavailable(f"not reachable: {exc}") from exc

    def _body(self, system: str, user: str, schema: Type[BaseModel]) -> dict:
        if self.json_mode == "schema":
            fmt = {"type": "json_schema",
                   "json_schema": {"name": schema.__name__, "schema": schema.model_json_schema(), "strict": False}}
        else:
            fmt = {"type": "json_object"}
            system += _schema_instruction(schema)
        body = {"model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": fmt}
        if self.temperature is not None:
            body["temperature"] = self.temperature
        return body

    def chat(self, system: str, user: str, schema: Type[T], timeout: float) -> T:
        if not self.base_url or not self.model:
            raise LLMUnavailable(f"set {self.name.upper().replace('-', '_')}_BASE_URL and _MODEL")
        if not self.api_key and self.name != "openai-compatible":
            raise LLMUnavailable(f"no API key (set {PRESETS[self.name].key_envs[0]})")
        resp = self._post(self._body(system, user, schema), timeout)
        if resp.status_code == 400 and self.json_mode == "schema":
            # server does not take json_schema: fall back to JSON mode for the rest of the process
            print(f"[llm] {self.name} rejected json_schema, using json_object: {resp.text[:200]}", flush=True)
            self.json_mode = "object"
            resp = self._post(self._body(system, user, schema), timeout)
        if resp.status_code in (401, 403):
            raise LLMUnavailable(f"credentials rejected ({resp.status_code})")
        if resp.status_code >= 400:
            raise LLMUnavailable(f"API error {resp.status_code}: {resp.text[:300]}")
        choice = (resp.json().get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        if msg.get("refusal"):
            raise LLMUnavailable(f"model declined: {msg['refusal'][:200]}")
        usage = resp.json().get("usage") or {}
        print(f"[llm] {self.name}:{self.model} in={usage.get('prompt_tokens')} out={usage.get('completion_tokens')} "
              f"finish={choice.get('finish_reason')}", flush=True)
        return schema.model_validate_json(_strip_fences(msg.get("content") or ""))


# --------------------------------------------------------------- anthropic

class Anthropic:
    """Claude with structured output: the SDK validates the answer against the schema.
    Server-side fallback re-runs a declined request on another model; a refusal that
    survives the fallback counts as "model unavailable", like a down Ollama."""
    name = "anthropic"

    def __init__(self):
        self.model = overrides.model("anthropic") or config.ANTHROPIC_MODEL

    def chat(self, system: str, user: str, schema: Type[T], timeout: float) -> T:
        try:
            import anthropic
        except ImportError as exc:
            raise LLMUnavailable("anthropic SDK not installed: uv sync --extra anthropic") from exc

        client = anthropic.Anthropic(timeout=timeout, max_retries=2)
        try:
            resp = client.beta.messages.parse(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_format=schema,
                output_config={"effort": config.ANTHROPIC_EFFORT},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.BadRequestError as exc:
            raise LLMUnavailable(f"bad request: {exc.message}") from exc
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise LLMUnavailable(f"Anthropic credentials rejected: {exc.message}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMUnavailable(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMUnavailable(f"Anthropic API not reachable: {exc}") from exc
        u = resp.usage
        print(f"[llm] {resp.model} in={u.input_tokens} out={u.output_tokens} stop={resp.stop_reason}", flush=True)
        if resp.stop_reason == "refusal":
            raise LLMUnavailable(f"model declined ({getattr(resp.stop_details, 'category', None)})")
        if resp.parsed_output is None:
            raise LLMUnavailable(f"no structured answer (stop_reason {resp.stop_reason})")
        return resp.parsed_output


# ----------------------------------------------------------------- registry

_instances: dict[str, Provider] = {}     # kept so a json_schema → json_object downgrade sticks


def get(name: str) -> Provider:
    name = ALIASES.get(name.strip().lower(), name.strip().lower())
    if name not in _instances:
        if name == "ollama":
            _instances[name] = Ollama()
        elif name == "anthropic":
            _instances[name] = Anthropic()
        elif name in PRESETS:
            _instances[name] = OpenAICompatible(name, PRESETS[name])
        else:
            raise ValueError(f"unknown LLM provider {name!r}; "
                             f"known: ollama, anthropic, {', '.join(PRESETS)}")
    return _instances[name]


def chain() -> list[Provider]:
    """The providers in LLM_PROVIDER (or chosen in the dashboard), in the order they are
    tried ("ollama,deepseek")."""
    return [get(n) for n in overrides.llm_providers()]


def hosted(p: Provider) -> bool:
    """True when a call to this provider leaves our own infrastructure: anything that is
    not a loopback or private address, or a bare or internal host name."""
    url = getattr(p, "url", None) or getattr(p, "base_url", None)
    host = (urlparse(url).hostname or "") if url else ""
    if not host:
        return True                       # SDK-managed endpoint (Anthropic) or nothing configured
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_loopback or ip.is_private)
    except ValueError:
        return "." in host and not host.endswith((".local", ".internal", ".lan", ".svc", ".cluster.local"))


def reset() -> None:
    _instances.clear()
