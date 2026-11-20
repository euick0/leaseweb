"""Policy gate: plain Python over policy.yaml, with optional per-repository
overrides from the repository's .patchpilot.yaml (`policy:` key).

Decisions: auto | needs_approval | block | queue | ignore | escalate. The model's
recommendation is an input; the decision is made here, in code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import yaml

from . import config
from .schemas import TriageResult, VetResult, Workload

DEFAULTS = {
    "patch": {"clean": "auto", "suspicious": "needs_approval", "malicious": "block"},
    "mitigate": "needs_approval",
    "not_reachable": "ignore",
    # act now only on workloads the internet can reach; the rest is queued for
    # the next maintenance window. `always` acts everywhere.
    "act_now_when": "internet_exposed",
    "blocked_patch_fallback": "mitigate",
}


@dataclass
class Decision:
    action: str               # patch | mitigate | none
    decision: str             # auto | needs_approval | block | queue | ignore | escalate
    reason: str


def load(repo_policy: Optional[dict] = None) -> dict:
    policy = {**DEFAULTS, "patch": dict(DEFAULTS["patch"])}
    if config.POLICY_FILE.exists():
        file = yaml.safe_load(config.POLICY_FILE.read_text()) or {}
        policy.update({k: v for k, v in file.items() if k != "patch"})
        policy["patch"].update(file.get("patch") or {})
    if repo_policy:
        policy.update({k: v for k, v in repo_policy.items() if k != "patch"})
        policy["patch"].update(repo_policy.get("patch") or {})
    return policy


def decide(policy: dict, wl: Workload, triage: TriageResult, patch_available: bool,
           vet: Optional[VetResult], mitigation_ok: bool) -> Decision:
    if not triage.affected or triage.recommended_action == "ignore" or not triage.reachable:
        return Decision("none", policy["not_reachable"],
                        "not reachable in this workload" if triage.affected else "not affected")

    act_now = policy["act_now_when"] == "always" or wl.internet_exposed
    later = "" if act_now else " (queued: not internet-exposed, next maintenance window)"

    if patch_available and triage.recommended_action != "mitigate":
        if vet is None:
            return Decision("patch", "needs_approval", "fix not vetted")
        decision = policy["patch"].get(vet.verdict, "needs_approval")
        if decision == "block":
            if policy["blocked_patch_fallback"] == "mitigate" and mitigation_ok:
                return Decision("mitigate", policy["mitigate"],
                                f"fix blocked ({vet.verdict}); virtual patch on the gateway instead")
            return Decision("patch", "block", f"fix is {vet.verdict}; no safe mitigation available")
        if not act_now and decision == "auto":
            return Decision("patch", "queue", f"fix vetted {vet.verdict}{later}")
        return Decision("patch", decision, f"fix vetted {vet.verdict}")

    if mitigation_ok:
        decision = policy["mitigate"] if act_now else "queue"
        return Decision("mitigate", decision, ("no fix available" if not patch_available
                                               else "model recommends mitigation") + later)
    return Decision("none", "escalate", "no fix and no safe mitigation: needs a human")
