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

## For companies: fill in the puzzle pieces

PatchPilot is built from pieces. Everything company-specific is a blank to fill in; nothing in the code changes.

```
cp patchpilot.example.yaml patchpilot.yaml   # the pieces: fill in the lines marked FILL IN
cp .env.example .env                         # the secrets (never committed)
# fleet.yaml: your repositories (sources) and clusters / Docker hosts (targets)
uv run python -m agent.doctor                # lists what is still missing, piece by piece
scripts/run_agent.sh
```

| Piece | Built-in choices | You fill in |
|-------|------------------|-------------|
| `auth` | `none`, `token`, `proxy` (SSO) | one token per person, or your SSO header; `approvers` |
| `forge` | `local`, `github`, `gitlab` | a token; `deploy: false` to let your CI/CD roll out the verified fix |
| `feed` | `files`, `osv` | how often to check, minimum severity |
| `notify` | `slack`, `teams`, `webhook`, `email` | webhook URLs / SMTP |
| `llm` | `ollama`, `openai`, `anthropic`, `gemini`, `deepseek`, `kimi`, `mistral`, `openai-compatible` | an API key, or your own model server |
| sources / targets (`fleet.yaml`) | git; `kubernetes`, `compose` | repository URLs; kube contexts |
| `policy.yaml` | auto / approval / block per verdict | your rules |

What each piece does:

- **Login and audit:** with `auth` on, every API call needs a user. Only `approvers` may approve, reject, trigger or reset, and every such action is kept in an audit log (`/api/audit`) that a demo reset does not clear.
- **Pull requests, not pushes to main:** with `github` or `gitlab`, the repository is cloned on first use, synced before every change, and a verified fix becomes a pull/merge request carrying the evidence (vet verdict, exploit probe before → after). With `deploy: false`, PatchPilot verifies the fix on a canary and stops there: your pipeline deploys on merge.
- **Advisories without copying files:** `osv` checks every package the fleet runs on a schedule. The dashboard's *Add advisory* box takes any CVE or GHSA id.
- **Notifications:** sent when an approval is waiting or an action fails, with a link straight to the decision.

Missing a piece? Any slot also takes your own class as `kind: "module:Class"`, with the module placed in `plugins/`. `plugins/README.md` lists what each slot expects, and `plugins/example_jira.py` is a complete example.

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
