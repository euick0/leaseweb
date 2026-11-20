"""Vet an update before it is ever built.

Runs on the exact artifacts the build would use (artifacts/<ecosystem>/...).
Archives are read in memory; nothing from them is extracted to disk or
executed. The flow is shared; the ecosystem driver supplies how to unpack an
artifact and which APIs count as sensitive.

Deterministic checks decide where to look and can block on their own:
  hard  checksum mismatch; code in the shipped artifact that is not in its
        source (how the xz backdoor hid); new load-time code that reads the
        environment and talks to the network                  -> malicious
  soft  high-risk additions (exec, code loading, load-time code touching
        network/env/exec, long encoded blobs)  -> suspicious unless the model finds more
  info  sensitive APIs that are common in legitimate code -> shown, cleared by a clean review

The model then reviews the source diff file by file within a time budget,
flagged and new files first, and answers one question per file: is this
change consistent with a fix for the advisory, or does it add unrelated
behaviour? Its evidence lines are checked against the diff before use.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Callable, Optional

from . import config, feed, llm
from .drivers.base import Ecosystem
from .schemas import ChunkReview, FileReview, Flag, VetResult

LogFn = Callable[[str, str, Optional[str], object], None]

BASE64_LITERAL = re.compile(r"""["'][A-Za-z0-9+/]{40,}={0,2}["']""")

REVIEW_SYSTEM = """You are a software supply-chain security reviewer.
A new release of a {language} library is proposed as the fix for a security advisory.
You see the unified diff of ONE source file between the installed and the proposed version.
Answer one question: is this change consistent with fixing the advisory (or ordinary
maintenance such as refactoring or features), or does it add unrelated behaviour such as
sending data over the network, reading environment variables or secrets, executing
processes, loading code, or hiding data in encoded strings?

Rules:
- suspicious=true only for behaviour unrelated to the library's purpose and the fix.
- confidence=high only when the added lines clearly exfiltrate data or open remote access.
- evidence_lines: copy the exact added lines (without the leading '+') that support the finding.
- explanation: at most three sentences, written for an operator."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _added_lines(old: list[str], new: list[str]) -> list[str]:
    return [line[1:] for line in difflib.unified_diff(old, new, lineterm="", n=0)
            if line.startswith("+") and not line.startswith("+++")]


def _is_comment(line: str) -> bool:
    return line.strip().startswith(("//", "*", "/*", "#"))


# ------------------------------------------------------- deterministic part

def deterministic_checks(eco: Ecosystem, name: str, old_v: str, new_v: str) -> tuple[list[Flag], dict, dict]:
    """Returns (flags, old_sources, new_sources)."""
    flags: list[Flag] = []
    old_bin, old_src = eco.artifacts(name, old_v)
    new_bin, new_src = eco.artifacts(name, new_v)

    for p in (new_bin, new_src):
        if not p.exists():
            flags.append(Flag(check="artifact", severity="hard", file=p.name,
                              message=f"{p.name} is missing from the artifact store"))
    if flags:
        return flags, {}, {}

    # 1. checksums recorded when the artifact entered the store
    sums_path = config.ARTIFACTS / "checksums.json"
    sums = json.loads(sums_path.read_text()) if sums_path.exists() else {}
    for p in (new_bin, new_src):
        key = p.relative_to(config.ARTIFACTS).as_posix()      # checksums.json uses "/" on every OS
        want, got = sums.get(key), sha256(p)
        if want is None:
            flags.append(Flag(check="checksum", severity="hard", file=p.name,
                              message="no recorded checksum for this artifact"))
        elif want != got:
            flags.append(Flag(check="checksum", severity="hard", file=p.name,
                              message=f"SHA-256 {got[:16]}… does not match recorded {want[:16]}…"))

    old_sources = eco.sources(old_src) if old_src.exists() else {}
    new_sources = eco.sources(new_src)

    # 2. shipped code without matching source
    new_only = set(eco.shipped_without_source(new_bin, new_sources))
    old_only = set(eco.shipped_without_source(old_bin, old_sources)) if old_bin.exists() else set()
    for item in sorted(new_only - old_only):
        flags.append(Flag(check="shipped-without-source", severity="hard", file=item,
                          message="code in the shipped artifact that is not in its source release"))
    for item in sorted(new_only & old_only):
        flags.append(Flag(check="shipped-without-source", severity="info", file=item,
                          message="code without matching source, already present in the installed version"))

    # 3. newly introduced sensitive APIs and load-time code, per file
    for path, new_lines in sorted(new_sources.items()):
        old_lines = old_sources.get(path)
        added = _added_lines(old_lines or [], new_lines)
        if not added:
            continue
        code = [("" if _is_comment(l) else l) for l in added]
        hits: dict[str, list[str]] = {}
        kinds: set[str] = set()
        for s in eco.sensitive:
            already = old_lines is not None and any(re.search(s.regex, l) for l in old_lines)
            found = [l.strip() for l, c in zip(added, code) if c and re.search(s.regex, c)]
            if found and not already:
                hits[s.label] = found
                kinds.add(s.kind)
                flags.append(Flag(check="sensitive-api", severity=s.severity, file=path, lines=found[:5],
                                  message=f"newly introduces {s.label}"))
        blobs = [l.strip() for l, c in zip(added, code) if c and BASE64_LITERAL.search(c)]
        if blobs:
            flags.append(Flag(check="encoded-blob", severity="soft", file=path, lines=blobs[:3],
                              message="adds long base64-like string literals"))
        load_time = eco.load_time_lines(path, [c for c in code if c], new_lines)
        if not load_time:
            continue
        risky = kinds & {"env", "network", "exec", "load"}
        evidence = load_time[:4] + [l for s in eco.sensitive if s.label in hits for l in hits[s.label]][:4]
        if {"env", "network"} <= kinds:
            flags.append(Flag(check="exfiltration-pattern", severity="hard", file=path, lines=evidence,
                              message="new code that runs on load, reads the environment and opens a "
                                      "network connection"))
        elif risky:
            flags.append(Flag(check="load-time-code", severity="soft", file=path, lines=evidence,
                              message=f"new code that runs on load in a file that now uses "
                                      f"{', '.join(sorted(risky))}"))
        else:
            flags.append(Flag(check="load-time-code", severity="info", file=path, lines=load_time[:4],
                              message="adds code that runs on load"))

    # 4. new bundled or required dependencies
    if old_bin.exists():
        for dep in eco.new_dependencies(old_bin, new_bin):
            flags.append(Flag(check="new-dependency", severity="info", file=dep,
                              message="new dependency in the proposed version"))

    return flags, old_sources, new_sources


# ----------------------------------------------------------------- LLM part

def _diff(path: str, old: Optional[list[str]], new: list[str], limit: int = 9000) -> str:
    text = "\n".join(difflib.unified_diff(old or [], new, fromfile=f"a/{path}", tofile=f"b/{path}",
                                         lineterm="", n=3))
    if len(text) > limit:
        text = text[:limit] + "\n... [diff truncated]"
    return text


def _review_order(changed: list[str], flags: list[Flag], old_sources: dict,
                  focus: list[str]) -> list[str]:
    """Flagged files first, then files the advisory points at, then new files."""
    rank = {"hard": 0, "soft": 1, "info": 2}
    best: dict[str, int] = {}
    for f in flags:
        if f.file in changed:
            best[f.file] = min(best.get(f.file, 9), rank[f.severity])

    def key(path: str):
        focused = any(path.endswith(f) for f in focus)
        return (best.get(path, 3), 0 if focused else 1, 0 if path not in old_sources else 1, path)
    return sorted(changed, key=key)


def _verify_evidence(review: ChunkReview, added: list[str]) -> ChunkReview:
    """Keep only evidence lines that really are added lines of the diff."""
    stripped = {a.strip() for a in added}
    kept = [e for e in review.evidence_lines if e.strip().lstrip("+").strip() in stripped]
    if len(kept) != len(review.evidence_lines):
        review = review.model_copy(update={"evidence_lines": kept})
    return review


def vet(adv: dict, eco: Ecosystem, name: str, old_v: str, new_v: str, log: LogFn,
        review: bool = True) -> VetResult:
    t0 = time.time()
    flags, old_sources, new_sources = deterministic_checks(eco, name, old_v, new_v)
    counts = {s: sum(1 for f in flags if f.severity == s) for s in ("hard", "soft", "info")}
    log("fail" if counts["hard"] else "warn" if counts["soft"] else "ok",
        f"{name} {old_v} → {new_v}: {counts['hard']} hard, {counts['soft']} soft, {counts['info']} info flags",
        None, [f.model_dump() for f in flags if f.severity != "info"][:20])

    changed = [p for p, lines in new_sources.items() if old_sources.get(p) != lines]
    reviews: list[FileReview] = []
    artifact_broken = any(f.check in ("artifact", "checksum") for f in flags)

    uncached = 0
    if review and changed and not artifact_broken:
        order = _review_order(changed, flags, old_sources, feed.hints(adv).get("review_focus", []))
        deadline = t0 + config.VET_BUDGET_SECONDS
        system = REVIEW_SYSTEM.format(language=eco.language)
        for path in order:
            remaining = deadline - time.time()
            if remaining <= 2:
                break
            file_flags = [f for f in flags if f.file == path]
            diff = _diff(path, old_sources.get(path), new_sources[path])
            user = (f"Advisory {adv['id']}: {adv.get('summary', '')}\n"
                    f"{adv.get('details', '')[:1200]}\n\n"
                    f"Library: {name} {old_v} -> {new_v}\n"
                    f"File: {path} ({'new file' if path not in old_sources else 'modified'})\n"
                    f"Deterministic flags for this file: "
                    f"{'; '.join(f'{f.severity}: {f.message}' for f in file_flags) or 'none'}\n\n"
                    f"```diff\n{diff}\n```")
            try:
                answer, source = llm.ask("vet", f"{eco.name}-{name}-{old_v}-{new_v}-{path}", system, user,
                                         ChunkReview, timeout=max(remaining, 5))
            except llm.LLMUnavailable as exc:
                if config.LLM_MODE == "cache":
                    uncached += 1             # cache-only mode: review what was answered before
                    continue
                log("warn", f"Model review unavailable for {path}", str(exc), None)
                break
            answer = _verify_evidence(answer, _added_lines(old_sources.get(path) or [], new_sources[path]))
            reviews.append(FileReview(file=path, source=source, review=answer))
            log("ai" if not answer.suspicious else "warn",
                f"Reviewed {path.rsplit('/', 1)[-1]}: "
                f"{'SUSPICIOUS (' + answer.confidence + ')' if answer.suspicious else 'consistent with fix'}",
                answer.explanation, {"file": path, "source": source, **answer.model_dump()})

    if uncached:
        log("info", f"{uncached} changed file(s) have no cached review (LLM_MODE=cache)", None, None)

    # verdict
    reasons: list[str] = []
    for f in flags:
        if f.severity == "hard":
            reasons.append(f"{f.check}: {f.message} ({f.file})")
    for r in reviews:
        if r.review.suspicious and r.review.confidence == "high":
            reasons.append(f"model: {r.review.category} in {r.file} (high confidence)")
    if reasons:
        verdict = "malicious"
    else:
        for f in flags:
            if f.severity == "soft":
                reasons.append(f"{f.check}: {f.message} ({f.file})")
        for r in reviews:
            if r.review.suspicious:
                reasons.append(f"model: {r.review.category} in {r.file} ({r.review.confidence} confidence)")
        verdict = "suspicious" if reasons else "clean"
    if verdict == "clean":
        reviewed = {r.file for r in reviews}
        unreviewed = {f.file for f in flags if f.severity == "info" and f.check == "sensitive-api"} - reviewed
        reasons.append(f"no hard or soft flags; {len(reviews)} file(s) reviewed by the model"
                       + (f", {len(unreviewed)} info-flagged file(s) outside the review budget" if unreviewed else ""))

    new_bin, _ = eco.artifacts(name, new_v)
    return VetResult(ecosystem=eco.name, artifact=name, from_version=old_v, to_version=new_v, verdict=verdict,
                     reasons=reasons, flags=flags, reviews=reviews, files_changed=len(changed),
                     files_reviewed=len(reviews),
                     sha256=sha256(new_bin) if new_bin.exists() else None,
                     model=llm.describe() if reviews else None)
