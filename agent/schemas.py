"""The interfaces agreed in hour 0: triage JSON, vet JSON, and the shapes the
pipeline passes around. The LLM schemas are sent to Ollama as structured-output
formats, so every model answer is validated by Pydantic before it is used."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------- triage (LLM)

class TriageResult(BaseModel):
    affected: bool = Field(description="The vulnerable package and version are present in this workload")
    reachable: bool = Field(description="The workload's code actually passes untrusted input to the vulnerable functionality")
    severity_for_this_workload: Literal["critical", "high", "medium", "low", "none"]
    recommended_action: Literal["patch", "mitigate", "ignore", "investigate"]
    mitigation_pattern: Optional[str] = Field(
        default=None,
        description="Literal substring that, if blocked in the request, stops the exploit. Null if no mitigation is possible.")
    mitigation_fields: list[str] = Field(
        default_factory=list,
        description="Request fields the pattern must be blocked in: 'header:<Name>', 'query' or 'path'")
    explanation: str = Field(description="Two or three sentences for the operator explaining the decision")


# ---------------------------------------------------------- diff review (LLM)

class ChunkReview(BaseModel):
    suspicious: bool
    confidence: Literal["low", "medium", "high"]
    category: Literal["security_fix", "refactor", "feature", "unrelated_behaviour",
                      "data_exfiltration", "remote_access", "obfuscation", "other"]
    evidence_lines: list[str] = Field(default_factory=list,
                                      description="Exact added lines that support the finding, copied from the diff")
    explanation: str


# ------------------------------------------------------------------ vet (code)

Severity = Literal["info", "soft", "hard"]


class Flag(BaseModel):
    check: str
    severity: Severity
    file: Optional[str] = None
    lines: list[str] = Field(default_factory=list)
    message: str


class FileReview(BaseModel):
    file: str
    source: Literal["live", "cache", "seed"]
    part: Optional[str] = None          # "2/3" when the file's diff was reviewed in several parts
    review: ChunkReview


class VetResult(BaseModel):
    ecosystem: str
    artifact: str
    from_version: str
    to_version: str
    # unreviewed: nothing found, but the model did not answer for every file it had to review
    verdict: Literal["clean", "unreviewed", "suspicious", "malicious"]
    reasons: list[str]
    flags: list[Flag]
    reviews: list[FileReview]
    files_changed: int
    files_reviewed: int
    unreviewed: list[str] = Field(default_factory=list)   # files that had to be reviewed and were not
    sha256: Optional[str] = None
    model: Optional[str] = None
    cached: bool = False


# ------------------------------------------------------------ pipeline shapes

class Component(BaseModel):
    ecosystem: str                      # maven | pypi
    group: Optional[str] = None
    name: str
    version: str
    purl: Optional[str] = None
    path: Optional[str] = None

    @property
    def coordinate(self) -> str:
        return f"{self.group}:{self.name}" if self.group else self.name


class Workload(BaseModel):
    """One running service, as a target driver sees it. Everything here is a
    fact read from the platform, never model output."""
    id: str                             # <target>/<namespace>/<name>
    name: str
    target: str                         # environment name from fleet.yaml
    target_kind: str                    # kubernetes | compose
    provider: str                       # where it runs, e.g. "k3s on Leaseweb", "AWS (EKS)"
    region: Optional[str] = None
    image: str
    repo: Optional[str] = None          # source name from fleet.yaml
    internet_exposed: bool
    exposure: str                       # how it is (or is not) reachable, for the operator
    gateway: Optional[str] = None       # gateway workload in front of it, where virtual patches go
    health_path: str = "/health"


class Match(BaseModel):
    advisory_id: str
    workload_id: str
    component: Component
    fixed_version: Optional[str]
    patch_available: bool
