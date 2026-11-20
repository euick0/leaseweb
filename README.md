# PatchPilot

One advisory in, one proven decision per workload out, across a fleet on several clouds. See `PLAN.md` for the why.

## On a laptop (no Docker, Kubernetes or model)

```
uv sync
uv run scripts/run_local_demo.py      # http://localhost:8000
uv run pytest                         # 37 tests, ~70 s
```

The fleet is the fake in `tests/fakes.py`: `billing-py` really runs, the Java services are simulated. Model answers come from `agent/cache/`; hand-written ones are labelled `seed` until a live run replaces them.

## On the hackathon server

```
scripts/setup_server.sh               # tools, base images, artifacts, model
scripts/cluster_up.sh                 # registry + k3d clusters pp-hyperscaler and pp-eu, deploys v1
scripts/run_agent.sh                  # API + dashboard on :8000 (LLM_MODE=cache for the stage)
scripts/reset_demo.sh                 # between rehearsals
```

Fallback without Kubernetes: `scripts/compose_up.sh`, then `PP_FLEET=fleet.compose.yaml scripts/run_agent.sh`.

## Model providers

`LLM_PROVIDER` picks the model, or a fallback chain tried in order:

```
LLM_PROVIDER=ollama                                    # default: open-weight model on our own hardware
LLM_PROVIDER=deepseek DEEPSEEK_API_KEY=...             # one hosted API
LLM_PROVIDER=ollama,mistral,openai                     # local first, then hosted
uv run scripts/llm_smoke.py                            # one live triage + one diff review
```

| Provider | Key | Default model (`<NAME>_MODEL` overrides) |
|----------|-----|-------------------------------------------|
| `ollama` | none (`OLLAMA_URL`) | `qwen2.5:14b` |
| `openai` | `OPENAI_API_KEY` | `gpt-5-mini` |
| `anthropic` | `ANTHROPIC_API_KEY`, needs `uv sync --extra anthropic` | `claude-opus-5-5` |
| `gemini` | `GEMINI_API_KEY` | `gemini-2.5-flash` |
| `deepseek` | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| `kimi` | `MOONSHOT_API_KEY` | `kimi-k2-0905-preview` |
| `mistral` | `MISTRAL_API_KEY` | `mistral-small-latest` |
| `openai-compatible` | optional; set `OPENAI_COMPATIBLE_BASE_URL` | set `OPENAI_COMPATIBLE_MODEL` (vLLM, llama.cpp, OpenRouter, ...) |

All but `anthropic` use plain HTTP chat completions (`agent/providers.py`), so no extra SDKs. Every cached answer records the `provider:model` that gave it, and the dashboard header shows the active chain.

## Layout

| Path | What |
|------|------|
| `agent/pipeline.py` | discover → inventory → match → triage → rank → vet → policy → act |
| `agent/drivers/` | `Source` (git), `Ecosystem` (maven, pypi), `Target` (kubernetes, compose) |
| `agent/vetter.py`, `agent/probes.py`, `agent/mitigation.py`, `agent/policy.py` | the deterministic checks |
| `agent/static/index.html` | dashboard |
| `fleet/repos/` | the three demo services; `state/repos/` holds their live git copies |
| `scenarios/` | advisories: `log4shell`, `trojan`, `zeroday`, `badupdate` |
| `acme-libs/` | demo libraries, including the backdoored `acme-authutils` 1.0.1 (never installed) |
| `deploy/` | Kubernetes manifests and Compose files |
