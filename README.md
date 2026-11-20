# PatchPilot

One advisory in, one proven decision per workload out, across a fleet on several clouds. See `PLAN.md` for the why.

## On a laptop (no Docker, Kubernetes or model)

```
uv sync
uv run scripts/run_local_demo.py      # prints the dashboard link with its token
uv run pytest                         # 76 tests, ~2 min
```

The fleet is the fake in `tests/fakes.py`: `billing-py` really runs, the Java services are simulated. Model answers come from `agent/cache/`; hand-written ones are labelled `seed` until a live run replaces them.

A `seed` answer never counts as a review. Until a live run has written real answers to `agent/cache/`, every fix that needs a model review comes out `unreviewed` and waits for approval instead of patching on its own. One live run fixes that (about 30 diff reviews for log4shell, so give it time):

```
PP_DEMO=1 VET_BUDGET_SECONDS=900 scripts/run_agent.sh     # trigger each scenario once, then commit agent/cache/
```

## On the hackathon server

```
scripts/setup_server.sh               # tools, base images, artifacts, model
scripts/cluster_up.sh                 # registry + k3d clusters pp-hyperscaler and pp-eu, deploys v1
PP_DEMO=1 scripts/run_agent.sh        # API + dashboard on 127.0.0.1:8000 (LLM_MODE=cache for the stage)
PP_API_TOKEN=... scripts/reset_demo.sh   # between rehearsals
```

## Access

Every `/api` call needs a bearer token. Set `PP_API_TOKENS=eric:<token>,maria:<token>` (the name is recorded on every approval) or `PP_API_TOKEN=<token>`; with neither, a token is generated and printed at startup. Open the dashboard as `http://localhost:8000/#token=<token>` once; the browser keeps it.

The agent listens on 127.0.0.1. Reach it from elsewhere with `ssh -L 8000:localhost:8000 <server>`, or set `PP_HOST=0.0.0.0` once tokens are configured. The scenario buttons and `/api/reset` exist only with `PP_DEMO=1`.

Fallback without Kubernetes: `scripts/compose_up.sh`, then `PP_FLEET=fleet.compose.yaml scripts/run_agent.sh`.

## Model providers

`LLM_PROVIDER` picks the model, or a fallback chain tried in order:

```
LLM_PROVIDER=ollama                                    # default: open-weight model on our own hardware
LLM_PROVIDER=deepseek DEEPSEEK_API_KEY=...             # one hosted API
LLM_PROVIDER=ollama,mistral,openai                     # local first, then hosted (needs allow_hosted_llm: true)
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

Hosted providers are off by default: `policy.yaml` says `allow_hosted_llm: false`, and with a hosted provider in `LLM_PROVIDER` the agent refuses to start. A provider counts as ours when its URL is a loopback or private address or an internal host name. With `allow_hosted_llm: true`, prompts to hosted APIs are redacted (`agent/redact.py`) and counted, and the dashboard badge shows how many went out.

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
