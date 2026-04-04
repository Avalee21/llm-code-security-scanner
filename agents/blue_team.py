import json
import os
import re
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from utils.llm import get_llm, parse_llm_json
from utils.schemas import BlueTeamDefense, RedTeamFinding

load_dotenv()

SYSTEM_PROMPT = """You are a defensive security engineer reviewing Red Team findings to filter false positives.

For each finding, examine the FULL source code and apply this checklist:
1. Input validation: Is the flagged input validated or sanitized elsewhere in the code?
2. Trusted context: Does this code only run in a controlled environment where the attack vector cannot reach? (Does not apply to undefined-behavior bugs like integer overflow, which are flaws regardless of input source.)
3. Severity inflation: Is the declared severity proportionate to the actual exploitability and impact?
4. Dead or unreachable code: Is the vulnerable path actually reachable given the function signatures and calling context?
5. CWE misclassification: Is the CWE label accurate, or is a benign pattern being misidentified?

Common false positive patterns — if ANY of these apply, you MUST mark the finding as a false positive:
- SQL: Code uses parameterized queries, prepared statements, or ORM-based queries (not string concatenation).
- Path Traversal (CWE-22): Code calls realpath() or equivalent AND validates that the resolved path starts with the intended prefix — a hardcoded prefix alone (e.g. snprintf with public_root + user_input) is NOT sufficient because "../" sequences are not stripped.
- OS Command Injection (CWE-78): Code uses subprocess with a list of arguments (no shell=True), or input is validated against a whitelist.
- Hardcoded Credentials (CWE-798): The "hardcoded" value is a configuration constant (file path, URL, table name, placeholder), NOT an actual secret, password, or API key.
- Integer Overflow (CWE-190): Code performs an explicit range or bounds check on the arithmetic result BEFORE use (e.g. if (x > MAX) return error). Assigning to a wider type (e.g. long long) does NOT count — the overflow happens inside the narrower operation or function return.
- NULL Pointer Deref (CWE-476): Code checks for NULL before dereferencing, or the pointer is guaranteed non-NULL by prior logic.
- Buffer Overflow: Code uses size-bounded functions like snprintf with sizeof, strlcpy, or similar safe APIs.

You MUST NOT simply agree with the Red Team. Write your counter_argument with full analytical reasoning first,
then set is_false_positive based on your analysis. If the code already contains a mitigation for the flagged vulnerability,
you MUST mark it as a false positive.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (matching the finding_id you were given, e.g. "F-001")
- is_false_positive: boolean (true if this finding does not represent a genuine, exploitable risk)
- counter_argument: string (your full analytical reasoning)

Return one object per finding. Preserve the original finding_id exactly.
"""

USER_PROMPT = """You are reviewing the following source code:
```
{code}
```

The Red Team submitted these findings. Evaluate each one critically against the code above:

{findings_block}

Respond with a JSON array — one defense object per finding.
"""

DIFF_SYSTEM_PROMPT = """You are a senior defensive security engineer conducting peer review of a Red Team's findings
on a CODE DIFF. The Red Team was asked to review only the CHANGED lines in a file.

You are given the changed hunks with surrounding context lines.
- Lines marked with `// >>> CHANGED` are newly added or modified.
- Sections replaced with `... (lines N-M omitted) ...` are unchanged and distant from the diff.

Your primary goal is to protect the codebase from unnecessary remediation work caused by false alarms.
Apply the same checklist as for full-file reviews, but also consider:
1. Did the vulnerability exist BEFORE the change? If so, it should not be attributed to this diff.
2. Does the surrounding (unchanged) context already mitigate the flagged issue?
3. Is the change actually introducing or worsening the vulnerability, or is it unrelated?

Apply the same common false positive patterns as usual (parameterized queries, realpath+validation, etc.).

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (matching the finding_id you were given)
- is_false_positive: boolean
- counter_argument: string (your full analytical reasoning)
"""

DIFF_USER_PROMPT = """You are reviewing the following code diff.
Lines marked with `// >>> CHANGED` are newly added or modified.

File: {filename}
```
{code}
```

The Red Team submitted these findings about the changed lines. Evaluate each one critically:

{findings_block}

Respond with a JSON array — one defense object per finding.
"""


def _serialize_findings(findings: list[RedTeamFinding]) -> str:
    lines = []
    for i, f in enumerate(findings, start=1):
        lines.append(
            f"Finding {i}:\n"
            f"  finding_id: {f.finding_id}\n"
            f"  cwe_id: {f.cwe_id}\n"
            f"  cwe_name: {f.cwe_name}\n"
            f"  severity: {f.severity}\n"
            f"  vulnerable_code: {f.vulnerable_code}\n"
            f"  exploit_argument: {f.exploit_argument}"
        )
    return "\n\n".join(lines)


def run_blue_team(findings: list[RedTeamFinding], code: str) -> list[BlueTeamDefense]:
    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT)
    ])

    chain = prompt | llm
    response = chain.invoke({
        "code": code,
        "findings_block": _serialize_findings(findings),
    })
    data = parse_llm_json(response.content)
    return [BlueTeamDefense(**item) for item in data]

def run_blue_team_diff(
    findings: list[RedTeamFinding], code: str, filename: str
) -> list[BlueTeamDefense]:
    """Blue team analysis on an annotated diff."""
    if not findings:
        return []

    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", DIFF_SYSTEM_PROMPT),
        ("human", DIFF_USER_PROMPT)
    ])

    chain = prompt | llm
    response = chain.invoke({
        "code": code,
        "filename": filename,
        "findings_block": _serialize_findings(findings),
    })
    data = parse_llm_json(response.content)
    return [BlueTeamDefense(**item) for item in data]


ROUND2_SYSTEM_PROMPT = """You are a principal security engineer conducting a final adversarial review.
A judge has already confirmed these findings after hearing initial arguments. Your job is to overturn wrongly confirmed findings.

IMPORTANT: You are not here to rubber-stamp the judge's decision. Be aggressive. Be specific. Cite the exact code.

For each finding, apply this escalated checklist in order:
1. ATTACK PATH FEASIBILITY: Trace the exact data flow from user input to the vulnerable line. Is there ANY implicit or explicit guard that blocks the attack before it reaches the vulnerable code? Even partial sanitization counts.
2. PRECONDITION ANALYSIS: What exact conditions must hold simultaneously for this exploit to work? List each precondition. If any precondition is unrealistic or already blocked, mark as false positive.
3. EXPLOIT ARGUMENT FLAWS: Is the Red Team's exploit argument technically accurate for this specific code? Wrong function semantics, incorrect assumptions about the language runtime, or misidentified variable scope all make the finding invalid.
4. MISSED MITIGATIONS: Re-read the full source code — not just the flagged snippet. Check: OS-level protections, compiler flags implied by usage patterns, API contract guarantees, calling context constraints.
5. CWE MISMATCH: If the confirmed CWE does not precisely match the actual code pattern, the finding is invalid regardless of whether some vulnerability exists.

Mandatory false positive triggers — if ANY apply, you MUST set is_false_positive=true:
- CWE-22: Code calls realpath() or equivalent AND checks that the resolved path starts with the allowed prefix — a hardcoded prefix combined with snprintf is NOT a mitigation because "../" sequences traverse out of it.
- CWE-78: Command is exec'd as a list (not shell string), or input is restricted to alphanumeric/whitelist characters.
- CWE-89: Query uses placeholders (%s, ?, :param) with separate parameter binding — NOT string concatenation.
- CWE-190: Result is explicitly range-checked before use (e.g. if (x > MAX) return error). Assigning to a wider type (e.g. long long) does NOT count — the overflow happens inside the narrower operation or function return.
- CWE-476: Pointer is checked != NULL before every dereference in the flagged code path.
- CWE-798: The "hardcoded" value is a file path, hostname, table name, or non-secret constant — NOT a password, API key, or private key.

You MUST provide a counter_argument that:
- Quotes the exact line(s) from the code that constitute the mitigation
- Explains step-by-step why the exploit cannot succeed given those lines
- Does NOT simply repeat the round 1 argument — add new evidence or a deeper analysis

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object must have exactly these fields:
- finding_id: string (matching the input finding_id exactly)
- is_false_positive: boolean
- counter_argument: string (your full escalated analytical reasoning with code citations)
"""

ROUND2_USER_PROMPT = """Source code under review:
```
{code}
```

These findings were confirmed by the judge in round 1. Each entry includes the round 1 defense argument that FAILED to convince the judge. Your task is to build a stronger case.

{findings_block}

Respond with a JSON array — one defense object per finding.
"""


def run_blue_team_round2(
    confirmed_findings: list[RedTeamFinding],
    code: str,
    round1_defenses: list[BlueTeamDefense],
) -> list[BlueTeamDefense]:
    """Second-round Blue Team challenge targeting only judge-confirmed findings."""
    if not confirmed_findings:
        return []

    defense_map = {d.finding_id: d.counter_argument for d in round1_defenses}

    lines = []
    for i, f in enumerate(confirmed_findings, start=1):
        r1 = defense_map.get(f.finding_id, "(no round 1 defense submitted)")
        lines.append(
            f"Finding {i}:\n"
            f"  finding_id: {f.finding_id}\n"
            f"  cwe_id: {f.cwe_id}\n"
            f"  cwe_name: {f.cwe_name}\n"
            f"  severity: {f.severity}\n"
            f"  vulnerable_code: {f.vulnerable_code}\n"
            f"  exploit_argument: {f.exploit_argument}\n"
            f"  ROUND 1 DEFENSE (failed): {r1}"
        )
    findings_block = "\n\n".join(lines)

    llm = get_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", ROUND2_SYSTEM_PROMPT),
        ("human", ROUND2_USER_PROMPT),
    ])
    chain = prompt | llm
    response = chain.invoke({"code": code, "findings_block": findings_block})
    data = parse_llm_json(response.content)
    return [BlueTeamDefense(**item) for item in data]