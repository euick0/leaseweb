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
| `auth` | `token` (default), `proxy` (SSO), `none` | one token per person, or your SSO header; `approvers` |
| `forge` | `local`, `github`, `gitlab` | a token; `deploy: false` to let your CI/CD roll out the verified fix |
| `feed` | `files`, `osv` | how often to check, minimum severity |
| `notify` | `slack`, `teams`, `webhook`, `email` | webhook URLs / SMTP |
| `llm` | `ollama`, `openai`, `anthropic`, `gemini`, `deepseek`, `kimi`, `mistral`, `openai-compatible` | an API key, or your own model server |
| sources / targets (`fleet.yaml`) | git; `kubernetes`, `compose` | repository URLs; kube contexts |
| `policy.yaml` | auto / approval / block per verdict | your rules |

What each piece does:

- **Login and audit:** every API call needs a user (a token by default, see above). Only `approvers` may approve, reject, trigger or reset, and every such action is kept in an audit log (`/api/audit`) that a demo reset does not clear.
- **Pull requests, not pushes to main:** with `github` or `gitlab`, the repository is cloned on first use, synced before every change, and a verified fix becomes a pull/merge request carrying the evidence (vet verdict, exploit probe before → after). With `deploy: false`, PatchPilot verifies the fix on a canary and stops there: your pipeline deploys on merge.
- **Advisories without copying files:** `osv` checks every package the fleet runs on a schedule. The dashboard's *Add advisory* box takes any CVE or GHSA id.
- **Notifications:** sent when an approval is waiting or an action fails, with a link straight to the decision.

Missing a piece? Any slot also takes your own class as `kind: "module:Class"`, with the module placed in `plugins/`. `plugins/README.md` lists what each slot expects, and `plugins/example_jira.py` is a complete example.

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
