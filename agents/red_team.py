import json
import os
import re
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from utils.llm import get_llm, parse_llm_json
from utils.schemas import JudgeVerdict, RedTeamFinding, VerificationResult

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _dedup_by_cwe(findings: list[RedTeamFinding]) -> list[RedTeamFinding]:
    """Keep only the highest-severity finding per CWE ID."""
    best: dict[str, RedTeamFinding] = {}
    for f in findings:
        prev = best.get(f.cwe_id)
        if prev is None or _SEVERITY_RANK.get(f.severity, 9) < _SEVERITY_RANK.get(prev.severity, 9):
            best[f.cwe_id] = f
    return list(best.values())

load_dotenv()

SYSTEM_PROMPT = """You are a security researcher performing adversarial code review.
Your job is to find genuine, exploitable vulnerabilities in the submitted code.

Vulnerability classes to look for:
- CWE-22  Path Traversal: User input concatenated into file paths without canonicalization or prefix checks (e.g. "../" in fopen/open paths).
- CWE-78  OS Command Injection: User input reaching system(), popen(), exec*(), or shell pipelines without sanitization.
- CWE-89  SQL Injection: User input concatenated into SQL query strings instead of using parameterized queries.
- CWE-190 Integer Overflow: Arithmetic operations (multiplication, addition, conversion via atoi/atol/strtol) whose result can exceed the target integer type's range without an overflow or bounds check. This includes implicit narrowing when a function returns a smaller type than the receiving variable.
- CWE-476 NULL Pointer Dereference: Pointer used after a code path where it could be NULL (unchecked malloc, unchecked function return value).
- CWE-798 Hard-coded Credentials: String literals used directly as passwords, API keys, or cryptographic secrets.

Guidelines:
1. Only report vulnerabilities you are HIGHLY CONFIDENT about, with a concrete, step-by-step attack path grounded in the code's actual inputs and execution context.
2. Do NOT report theoretical weaknesses or style issues. If the code already mitigates the issue (e.g. parameterized queries, snprintf with sizeof, realpath + prefix check, explicit NULL checks, bounds validation), do NOT flag it.
3. Quote the exact vulnerable code snippet — do not paraphrase.
4. Assign the single most specific CWE per vulnerability. One finding per CWE; combine duplicates.
5. At most 3 findings per sample, severity medium or above.
6. If the code is secure, return `[]`.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (e.g. "F-001")
- cwe_id: string (e.g. "CWE-89")
- cwe_name: string (e.g. "SQL Injection")
- severity: string — one of: critical, high, medium, low
- vulnerable_code: string (the exact vulnerable snippet from the code)
- exploit_argument: string (step-by-step explanation of how an attacker exploits this)

If no vulnerabilities are found, return an empty array: []
"""

USER_PROMPT = """Review this code for security vulnerabilities:
```
{code}
```
"""

DIFF_SYSTEM_PROMPT = """You are a security researcher performing adversarial code review on a CODE DIFF.
Your job is to find genuine, exploitable vulnerabilities INTRODUCED OR WORSENED by the change.

You are given the changed hunks of a file with surrounding context lines.
- Lines marked with `// >>> CHANGED` are newly added or modified.
- Sections of the file that are unchanged and far from the diff are replaced with
  `... (lines N-M omitted) ...` markers to save space.
- The surrounding context lines are provided so you can assess mitigations nearby.

Focus your analysis on the CHANGED lines — only report vulnerabilities that are directly related
to the new or modified code. Do not flag pre-existing issues in unchanged lines.

Vulnerability classes to look for:
- CWE-22  Path Traversal: User input in file paths without canonicalization.
- CWE-78  OS Command Injection: User input reaching system(), popen(), exec*().
- CWE-89  SQL Injection: User input concatenated into SQL strings instead of parameterized queries.
- CWE-190 Integer Overflow: Arithmetic exceeding the target type's range without bounds check, including narrowing from function returns (e.g. atoi).
- CWE-476 NULL Pointer Dereference: Pointer used where it could be NULL.
- CWE-798 Hard-coded Credentials: Literals used as passwords, API keys, or secrets.

Guidelines:
1. Only report vulnerabilities with a concrete attack path introduced by the change, severity medium or above.
2. Do NOT report theoretical weaknesses, best-practice violations, or style issues.
3. Quote the exact vulnerable code snippet.
4. Assign the most specific CWE. One finding per CWE, at most 3 per file.
5. If the change is secure, return `[]`.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (e.g. "F-001")
- cwe_id: string (e.g. "CWE-89")
- cwe_name: string (e.g. "SQL Injection")
- severity: string — one of: critical, high, medium, low
- vulnerable_code: string (the exact vulnerable snippet from the code)
- exploit_argument: string (step-by-step explanation of how an attacker exploits this)

If no vulnerabilities are found, return an empty array: []
"""

DIFF_USER_PROMPT = """Review this code diff for security vulnerabilities.
Lines marked with `// >>> CHANGED` are newly added or modified. Focus on those lines.

File: {filename}
```
{code}
```
"""


def run_red_team(code: str) -> list[RedTeamFinding]:
    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT)
    ])

    chain = prompt | llm
    response = chain.invoke({"code": code})
    data = parse_llm_json(response.content)
    findings = [RedTeamFinding(**item) for item in data if isinstance(item, dict)]
    return _dedup_by_cwe(findings)


def run_red_team_diff(code: str, filename: str) -> list[RedTeamFinding]:
    """Red team analysis on an annotated diff (full file with CHANGED markers)."""
    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", DIFF_SYSTEM_PROMPT),
        ("human", DIFF_USER_PROMPT)
    ])

    chain = prompt | llm
    response = chain.invoke({"code": code, "filename": filename})
    data = parse_llm_json(response.content)
    findings = [RedTeamFinding(**item) for item in data if isinstance(item, dict)]
    return _dedup_by_cwe(findings)


# ── Patch verification ────────────────────────────────────────────

VERIFICATION_SYSTEM_PROMPT = """You are a security engineer verifying whether code patches effectively fix known vulnerabilities.

For each patch, you are given:
- The original vulnerable code snippet
- The vulnerability details (CWE, severity, exploit argument)
- The proposed patch (corrected code)

Your job is to determine whether the patch:
1. Fixes the stated vulnerability without introducing new security issues
2. Preserves the original code's intended functionality
3. Is syntactically correct

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (matching the original finding_id)
- patch_valid: boolean (true if the patch effectively fixes the vulnerability)
- reason: string (brief explanation of why the patch is or is not valid)
"""

VERIFICATION_USER_PROMPT = """Here is the full source code:
```
{code}
```

Verify the following patches:

{patches_block}
"""


def _serialize_patches(
    verdicts: list[JudgeVerdict],
    findings: list[RedTeamFinding],
) -> str:
    finding_map = {f.finding_id: f for f in findings}
    blocks = []
    for v in verdicts:
        if not v.confirmed or not v.patch:
            continue
        f = finding_map.get(v.finding_id)
        if not f:
            continue
        block = (
            f"Patch for {v.finding_id}:\n"
            f"  CWE: {f.cwe_id} — {f.cwe_name}\n"
            f"  Severity: {f.severity}\n"
            f"  Original vulnerable code:\n    {f.vulnerable_code}\n"
            f"  Exploit argument: {f.exploit_argument}\n"
            f"  Proposed patch:\n    {v.patch}\n"
        )
        blocks.append(block)
    return "\n".join(blocks)


def run_verification(
    code: str,
    verdicts: list[JudgeVerdict],
    findings: list[RedTeamFinding],
) -> tuple[bool | None, list[VerificationResult]]:
    """Verify whether Judge-generated patches effectively fix the vulnerabilities.

    Returns (verification_passed, verification_results).
    verification_passed is None if there are no patches to verify.
    """
    confirmed_with_patches = [v for v in verdicts if v.confirmed and v.patch]
    if not confirmed_with_patches:
        return None, []

    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", VERIFICATION_SYSTEM_PROMPT),
        ("human", VERIFICATION_USER_PROMPT),
    ])

    chain = prompt | llm
    response = chain.invoke({
        "code": code,
        "patches_block": _serialize_patches(verdicts, findings),
    })
    data = parse_llm_json(response.content)

    results = [VerificationResult(**item) for item in data]
    all_valid = all(r.patch_valid for r in results)
    return all_valid, results