import json
import re
from langchain_core.prompts import ChatPromptTemplate
from utils.llm import get_llm, parse_llm_json
from utils.schemas import RedTeamFinding

SYSTEM_PROMPT = """You are a CWE (Common Weakness Enumeration) classification specialist.
Your sole task is to verify and correct the CWE classification of each security finding.

You are only responsible for correcting the CWE label — do NOT change severity, vulnerable_code, or exploit_argument.

Supported CWE taxonomy (the only valid CWEs for this project):
- CWE-22: Path Traversal
- CWE-78: OS Command Injection
- CWE-89: SQL Injection
- CWE-190: Integer Overflow or Wraparound
- CWE-476: NULL Pointer Dereference
- CWE-798: Use of Hard-coded Credentials

For each finding, examine the vulnerable_code and exploit_argument and determine whether the assigned CWE is correct.
If it is incorrect, assign the most appropriate CWE from the taxonomy above.
If the finding does not match any CWE in the taxonomy, keep the original CWE.

Classification guidance — use these code patterns to determine the correct CWE:
- CWE-22: User input concatenated into file paths (snprintf, strcat, fopen with user-controlled path components)
- CWE-78: User input reaching system(), popen(), exec*(), or subprocess with shell=True
- CWE-89: User input concatenated into SQL query strings (sprintf, strcat, +, f-string into SQL)
- CWE-190: Arithmetic on user-controlled integers without overflow/bounds check, especially before malloc/calloc allocation
- CWE-476: Pointer dereference after a code path where it could be NULL (failed malloc, unchecked function return)
- CWE-798: String literals used directly as passwords, API keys, cryptographic keys, or authentication secrets

Common misclassifications to watch for:
- CWE-120 (Buffer Overflow) vs CWE-190: If the root cause is an integer overflow that leads to a wrong buffer size, classify as CWE-190 (the overflow), not CWE-120 (the consequence).
- CWE-134 (Format String) vs CWE-78: If user input reaches printf-family functions, consider CWE-134; if it reaches system/exec, it is CWE-78.
- CWE-415 (Double Free) vs CWE-476: If the issue is dereferencing a NULL pointer, it is CWE-476; if it is freeing memory twice, keep the original CWE.
- CWE-122 (Heap Buffer Overflow) vs CWE-190: If the overflow originates from unchecked integer arithmetic used in allocation size, classify as CWE-190.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object must have exactly these fields:
- finding_id: string (matching the input finding_id exactly)
- cwe_id: string (e.g. "CWE-89" — corrected or unchanged)
- cwe_name: string (e.g. "SQL Injection" — matching the cwe_id)
"""

USER_PROMPT = """Review the following source code and the Red Team's findings.
Verify and correct the CWE classification for each finding.

Source code:
```
{code}
```

Red Team findings:
{findings_block}

Respond with a JSON array — one object per finding with finding_id, cwe_id, and cwe_name.
"""

DIFF_USER_PROMPT = """Review the following code diff and the Red Team's findings.
Verify and correct the CWE classification for each finding.

File: {filename}
```
{code}
```

Red Team findings:
{findings_block}

Respond with a JSON array — one object per finding with finding_id, cwe_id, and cwe_name.
"""


def _serialize_findings(findings: list[RedTeamFinding]) -> str:
    lines = []
    for i, f in enumerate(findings, start=1):
        lines.append(
            f"Finding {i}:\n"
            f"  finding_id: {f.finding_id}\n"
            f"  cwe_id: {f.cwe_id}\n"
            f"  cwe_name: {f.cwe_name}\n"
            f"  vulnerable_code: {f.vulnerable_code}\n"
            f"  exploit_argument: {f.exploit_argument}"
        )
    return "\n\n".join(lines)


def _parse_and_apply(raw: str, findings: list[RedTeamFinding]) -> list[RedTeamFinding]:
    data = parse_llm_json(raw)

    correction_map = {item["finding_id"]: item for item in data}
    result = []
    for finding in findings:
        correction = correction_map.get(finding.finding_id)
        if correction and (
            correction["cwe_id"] != finding.cwe_id
            or correction["cwe_name"] != finding.cwe_name
        ):
            result.append(finding.model_copy(update={
                "cwe_id": correction["cwe_id"],
                "cwe_name": correction["cwe_name"],
                "original_cwe_id": finding.cwe_id,
            }))
        else:
            result.append(finding)
    return result


def run_cwe_classifier(findings: list[RedTeamFinding], code: str) -> list[RedTeamFinding]:
    if not findings:
        return []

    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT),
    ])

    chain = prompt | llm
    response = chain.invoke({
        "code": code,
        "findings_block": _serialize_findings(findings),
    })

    return _parse_and_apply(response.content.strip(), findings)


def run_cwe_classifier_diff(
    findings: list[RedTeamFinding], code: str, filename: str
) -> list[RedTeamFinding]:
    if not findings:
        return []

    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", DIFF_USER_PROMPT),
    ])

    chain = prompt | llm
    response = chain.invoke({
        "code": code,
        "filename": filename,
        "findings_block": _serialize_findings(findings),
    })

    return _parse_and_apply(response.content.strip(), findings)
