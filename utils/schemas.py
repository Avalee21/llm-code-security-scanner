from pydantic import BaseModel, Field
from typing import Optional, List


class RedTeamFinding(BaseModel):
    finding_id: str = Field(..., description="Unique ID, e.g. 'F-001'")
    cwe_id: str = Field(..., description="e.g. 'CWE-89'")
    cwe_name: str = Field(..., description="e.g. 'SQL Injection'")
    severity: str = Field(..., description="critical | high | medium | low")
    vulnerable_code: str = Field(..., description="The exact snippet flagged")
    exploit_argument: str = Field(..., description="Why this is exploitable")


class BlueTeamDefense(BaseModel):
    finding_id: str
    is_false_positive: bool
    counter_argument: str = Field(..., description="Why this may not be a real risk")


class JudgeVerdict(BaseModel):
    finding_id: str
    confirmed: bool
    reasoning: str
    patch: Optional[str] = Field(None, description="Patched code snippet if confirmed")


class DebateReport(BaseModel):
    findings: List[RedTeamFinding]
    defenses: List[BlueTeamDefense]
    verdicts: List[JudgeVerdict]
    verification_passed: Optional[bool] = None


# ── GitHub / diff-scan schemas ──────────────────────────────────


class FileDiff(BaseModel):
    """A single file's diff from a GitHub PR or commit."""
    filename: str = Field(..., description="Path of the changed file")
    status: str = Field(..., description="added | modified | removed | renamed")
    patch: str = Field("", description="Unified diff text")
    additions: int = Field(0)
    deletions: int = Field(0)
    added_lines: List[str] = Field(
        default_factory=list,
        description="Lines added/changed (content only, no +/- prefix)",
    )


class FileReport(BaseModel):
    """Debate report scoped to a single changed file."""
    filename: str
    language: Optional[str] = None
    report: DebateReport


class RepoScanReport(BaseModel):
    """Aggregate report for a GitHub PR or commit scan."""
    repo_url: str
    pr_number: Optional[int] = None
    commit_sha: Optional[str] = None
    file_reports: List[FileReport]
    total_findings: int = 0
    total_confirmed: int = 0
    total_dismissed: int = 0