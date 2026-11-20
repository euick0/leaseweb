"""Triage one matched workload with the model.

Input is evidence, not opinion: the advisory, where the package is used in the
workload's repository (grep hits), the gateway config, and the exposure facts
the target driver read from the platform. `patch_available`, `fixed_version`
and `internet_exposed` are facts and never come from the model.

If the model is down and nothing is cached, a conservative fallback assumes
the worst (affected and reachable) so nothing is silently ignored.
"""
from __future__ import annotations

from typing import Optional

from . import feed, llm
from .schemas import Match, TriageResult, Workload

SYSTEM = """You are a security engineer triaging one vulnerability advisory for ONE workload
in a company's fleet. Decide from the evidence given, not from general knowledge alone.

- affected: the vulnerable package version is present (it is, the SBOM matched; say false only
  if the evidence shows the vulnerable component is not loaded at all).
- reachable: untrusted input can reach the vulnerable functionality in THIS workload's code.
  Look at the grep hits: is the package called with request data?
- severity_for_this_workload: severity given reachability and the exposure facts.
- recommended_action: "patch" if a fixed version exists and the workload is affected and
  reachable; "mitigate" if no fix exists but a request filter on the gateway would stop the
  attack; "ignore" if not reachable; "investigate" if the evidence is insufficient.
- mitigation_pattern: a short literal substring present in every exploit request (for example
  "${" for expression injection or ".." for path traversal), or null.
- mitigation_fields: where the pattern arrives: "header:<Name>", "query" or "path".
- explanation: two or three sentences an operator can act on. Mention the exposure."""


def _prompt(adv: dict, wl: Workload, m: Match, grep_hits: list[str], gateway: Optional[str]) -> str:
    hits = "\n".join(grep_hits) or "(no hits)"
    return (f"Advisory {adv['id']} ({feed.title(adv)}): {adv.get('summary', '')}\n"
            f"{adv.get('details', '')[:1500]}\n\n"
            f"Workload: {wl.name} in environment {wl.target} ({wl.provider}"
            f"{', ' + wl.region if wl.region else ''})\n"
            f"Package: {m.component.coordinate} {m.component.version} ({m.component.ecosystem})\n"
            f"Fixed version available: {m.fixed_version or 'none'}\n"
            f"Internet exposed (fact from the platform): {wl.internet_exposed} - {wl.exposure}\n"
            f"Gateway in front: {wl.gateway or 'none'}\n\n"
            f"Where the repository uses the package (grep):\n{hits}\n\n"
            f"Gateway configuration:\n{(gateway or '(no gateway)')[:2500]}\n")


def fallback(adv: dict, m: Match) -> TriageResult:
    hint = feed.hints(adv).get("mitigation") or {}
    return TriageResult(
        affected=True, reachable=True, severity_for_this_workload="high",
        recommended_action="patch" if m.patch_available else ("mitigate" if hint else "investigate"),
        mitigation_pattern=hint.get("pattern"), mitigation_fields=hint.get("fields", []),
        explanation="Model unavailable and no cached answer: assuming the workload is affected and "
                    "reachable until a human or the model says otherwise.")


def triage(adv: dict, wl: Workload, m: Match, grep_hits: list[str],
           gateway: Optional[str]) -> tuple[TriageResult, str]:
    """Returns (result, source) where source is live, cache or fallback."""
    try:
        return llm.ask("triage", f"{adv['id']}-{wl.id}", SYSTEM, _prompt(adv, wl, m, grep_hits, gateway),
                       TriageResult)
    except llm.LLMUnavailable:
        return fallback(adv, m), "fallback"
