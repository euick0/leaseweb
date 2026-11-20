# PatchPilot

One advisory in, one proven decision per workload out, across a fleet on several clouds. See `PLAN.md` for the why.

## On a laptop (no Docker, Kubernetes or model)

```
uv sync
uv run scripts/run_local_demo.py      # http://localhost:8000
uv run pytest                         # 26 tests, ~30 s
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
