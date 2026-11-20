"""Policy gate: plain Python over policy.yaml, with optional per-repository
overrides from the repository's .patchpilot.yaml (`policy:` key).

Decisions: auto | needs_approval | block | queue | ignore | escalate. The model's
recommendation is an input; the decision is made here, in code.

The fleet file is validated in full and a bad one is an error. A repository can
only make the fleet policy stricter: an override that is looser, unknown, or
for a fleet-only key is dropped and reported, never applied.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import yaml

from . import config
from .schemas import TriageResult, VetResult, Workload

DEFAULTS = {
    "patch": {"clean": "auto", "unreviewed": "needs_approval", "suspicious": "needs_approval",
              "malicious": "block"},
    "mitigate": "needs_approval",
    # Internal workloads only: on an internet-exposed workload the model's "not
    # reachable" is never enough to ignore a CVE (see decide).
    "not_reachable": "ignore",
    # act now only on workloads the internet can reach; the rest is queued for
    # the next maintenance window. `always` acts everywhere.
    "act_now_when": "internet_exposed",
    "blocked_patch_fallback": "mitigate",
    # May prompts go to a model API outside our own infrastructure? (agent/llm.py)
    "allow_hosted_llm": False,
}

# What each key may be set to. Only a clean, fully reviewed fix can ever be automatic.
ALLOWED = {
    "mitigate": ("auto", "needs_approval", "block"),
    "not_reachable": ("ignore", "queue", "needs_approval"),
    "act_now_when": ("internet_exposed", "always"),
    "blocked_patch_fallback": ("mitigate", "none"),
    "allow_hosted_llm": (True, False),
}
ALLOWED_PATCH = {
    "clean": ("auto", "needs_approval", "block"),
    "unreviewed": ("needs_approval", "block"),
    "suspicious": ("needs_approval", "block"),
    "malicious": ("block",),
}
STRICTNESS = ["ignore", "auto", "queue", "needs_approval", "block"]     # loosest to strictest
REPO_KEYS = ("mitigate", "not_reachable")           # plus patch.*; everything else is fleet-only


class PolicyError(ValueError):
    pass


def _problems(doc: object) -> list[str]:
    """Why `doc` is not a valid (possibly partial) policy; empty when it is."""
    if not isinstance(doc, dict):
        return ["policy must be a mapping"]
    out = []
    for key, value in doc.items():
        if key == "patch":
            if not isinstance(value, dict):
                out.append("patch must be a mapping of verdict to decision")
                continue
            for verdict, decision in value.items():
                if verdict not in ALLOWED_PATCH:
                    out.append(f"patch.{verdict}: unknown verdict")
                elif decision not in ALLOWED_PATCH[verdict]:
                    out.append(f"patch.{verdict}: {decision!r} is not one of {', '.join(ALLOWED_PATCH[verdict])}")
        elif key not in ALLOWED:
            out.append(f"{key}: unknown key")
        elif value not in ALLOWED[key] or isinstance(value, bool) != isinstance(ALLOWED[key][0], bool):
            out.append(f"{key}: {value!r} is not one of {', '.join(str(v).lower() for v in ALLOWED[key])}")
    return out


def fleet() -> dict:
    """The fleet policy: defaults overlaid with policy.yaml. Raises PolicyError on a bad file."""
    policy = {**DEFAULTS, "patch": dict(DEFAULTS["patch"])}
    if config.POLICY_FILE.exists():
        try:
            file = yaml.safe_load(config.POLICY_FILE.read_text()) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"{config.POLICY_FILE.name}: {exc}") from exc
        problems = _problems(file)
        if problems:
            raise PolicyError(f"{config.POLICY_FILE.name}: " + "; ".join(problems))
        policy.update({k: v for k, v in file.items() if k != "patch"})
        policy["patch"].update(file.get("patch") or {})
    return policy


def load(repo_policy: Optional[dict] = None, notes: Optional[list[str]] = None) -> dict:
    """The fleet policy tightened by a repository's overrides. Overrides that are not
    applied are explained in `notes`."""
    policy = fleet()
    notes = notes if notes is not None else []
    if not repo_policy:
        return policy
    if not isinstance(repo_policy, dict):
        notes.append("repository policy ignored: it must be a mapping")
        return policy

    def tighten(label: str, current: str, wanted: object, allowed: tuple) -> str:
        if wanted not in allowed:
            notes.append(f"{label}: {wanted!r} ignored, not a valid value")
        elif STRICTNESS.index(wanted) < STRICTNESS.index(current):
            notes.append(f"{label}: {wanted!r} ignored, a repository cannot loosen the fleet's {current!r}")
        else:
            return wanted
        return current

    for key, value in repo_policy.items():
        if key == "patch" and isinstance(value, dict):
            for verdict, decision in value.items():
                if verdict in ALLOWED_PATCH:
                    policy["patch"][verdict] = tighten(f"patch.{verdict}", policy["patch"][verdict], decision,
                                                       ALLOWED_PATCH[verdict])
                else:
                    notes.append(f"patch.{verdict}: ignored, unknown verdict")
        elif key in REPO_KEYS:
            policy[key] = tighten(key, policy[key], value, ALLOWED[key])
        elif key in ALLOWED:
            notes.append(f"{key}: ignored, only the fleet policy can set it")
        else:
            notes.append(f"{key}: ignored, unknown key")
    return policy


@dataclass
class Decision:
    action: str               # patch | mitigate | none
    decision: str             # auto | needs_approval | block | queue | ignore | escalate
    reason: str


def claims_safe(triage: TriageResult) -> bool:
    """The model says there is nothing to do here. That is an opinion, not a fact."""
    return not triage.affected or triage.recommended_action == "ignore" or not triage.reachable


def unreachable_decision(policy: dict, wl: Workload) -> str:
    """What "the model says not reachable" is worth: the policy's choice, but on an
    internet-exposed workload never less than a place in the queue."""
    decision = policy["not_reachable"]
    return "queue" if decision == "ignore" and wl.internet_exposed else decision


def decide(policy: dict, wl: Workload, triage: TriageResult, patch_available: bool,
           vet: Optional[VetResult], mitigation_ok: bool) -> Decision:
    d = _decide(policy, wl, triage, patch_available, vet, mitigation_ok)
    if not claims_safe(triage):
        return d
    what = "not reachable in this workload" if triage.affected else "not affected"
    floor = unreachable_decision(policy, wl)
    if floor == "ignore":
        return Decision("none", "ignore", what)
    # the model's opinion lowers the urgency; it does not close the case
    if d.decision in ("auto", "queue") and STRICTNESS.index(d.decision) < STRICTNESS.index(floor):
        d.decision = floor
    why = "the workload is internet-exposed" if wl.internet_exposed else "the policy keeps these"
    d.reason = f"model says {what}, but {why}: a human confirms ({d.reason})"
    return d


def _decide(policy: dict, wl: Workload, triage: TriageResult, patch_available: bool,
            vet: Optional[VetResult], mitigation_ok: bool) -> Decision:
    act_now = policy["act_now_when"] == "always" or wl.internet_exposed
    later = "" if act_now else " (queued: not internet-exposed, next maintenance window)"

    if patch_available and triage.recommended_action != "mitigate":
        if vet is None:
            return Decision("patch", "needs_approval", "fix not vetted")
        decision = policy["patch"].get(vet.verdict, "needs_approval")
        if vet.verdict == "unreviewed":
            # an incomplete review never patches on its own, whatever the policy file says
            decision = "needs_approval" if decision in ("auto", "queue") else decision
            if decision == "needs_approval":
                return Decision("patch", decision, "fix not fully reviewed by the model: a human decides")
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
