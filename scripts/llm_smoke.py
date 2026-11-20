#!/usr/bin/env python3
"""One live triage call and one live diff review against the configured model,
bypassing the cache, to check the setup and see the real token use.

  LLM_PROVIDER=anthropic uv run scripts/llm_smoke.py
  uv run scripts/llm_smoke.py                       # Ollama
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import config, llm, triage, vetter  # noqa: E402
from agent.drivers.pypi import PypiEcosystem  # noqa: E402
from agent.schemas import ChunkReview, Component, Match, Workload  # noqa: E402

adv = json.loads((ROOT / "scenarios/trojan.json").read_text())
wl = Workload(id="eu/shop/billing-py", name="billing-py", target="eu", target_kind="kubernetes",
              provider="Leaseweb · k3s", image="billing-py:v1", repo="billing-py", internet_exposed=True,
              exposure="LoadBalancer Service billing-py-gateway → gateway billing-py-gateway",
              gateway="billing-py-gateway")
m = Match(advisory_id=adv["id"], workload_id=wl.id, fixed_version="1.0.1", patch_available=True,
          component=Component(ecosystem="pypi", name="acme-authutils", version="1.0.0"))
hits = ["app.py:22:            key_id = self.headers.get(\"X-Key-Id\", \"default\")",
        "app.py:24:                key = acme_authutils.load_key(key_id)"]

print(f"provider={config.LLM_PROVIDER} model={config.model_name()}")
t0 = time.time()
result = llm.chat(triage.SYSTEM, triage._prompt(adv, wl, m, hits, None), triage.TriageResult)
print(f"triage ({time.time() - t0:.1f}s): {result.model_dump_json(indent=2)}")

eco = PypiEcosystem()
_, old_src = eco.artifacts("acme-authutils", "1.0.0")
_, new_src = eco.artifacts("acme-authutils", "1.0.1")
path = "acme_authutils/_metrics.py"
diff = vetter._diff(path, eco.sources(old_src).get(path), eco.sources(new_src)[path])
t0 = time.time()
review = llm.chat(vetter.REVIEW_SYSTEM.format(language="Python"),
                  f"Advisory {adv['id']}: {adv['summary']}\nLibrary: acme-authutils 1.0.0 -> 1.0.1\n"
                  f"File: {path} (new file)\n\n```diff\n{diff}\n```", ChunkReview)
print(f"review ({time.time() - t0:.1f}s): {review.model_dump_json(indent=2)}")
