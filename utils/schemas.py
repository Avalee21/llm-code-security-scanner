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