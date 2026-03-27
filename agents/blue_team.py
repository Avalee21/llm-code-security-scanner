import json
import os
import re
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from utils.llm import get_llm
from utils.schemas import BlueTeamDefense, RedTeamFinding

load_dotenv()

SYSTEM_PROMPT = """You are a senior defensive security engineer conducting peer review of a Red Team's findings.
Your primary goal is to protect the codebase from unnecessary remediation work caused by false alarms.
You are skeptical by nature — you have seen many overstated findings in your career, and you know that not every
code pattern flagged by an adversarial review is actually exploitable in context.

For each finding, examine the FULL source code provided and apply this checklist:
1. Input validation: Is the flagged input validated or sanitized elsewhere in the code?
2. Trusted context: Does this code only run in a controlled environment where the attack vector cannot reach?
3. Severity inflation: Is the declared severity proportionate to the actual exploitability and impact?
4. Dead or unreachable code: Is the vulnerable path actually reachable given the function signatures and calling context?
5. CWE misclassification: Is the CWE label accurate, or is a benign pattern being misidentified?

Common false positive patterns — if ANY of these apply, you MUST mark the finding as a false positive:
- SQL: Code uses parameterized queries, prepared statements, or ORM-based queries (not string concatenation).
- Path Traversal (CWE-22): Code uses realpath() + prefix validation, or restricts input to a whitelist of filenames.
- OS Command Injection (CWE-78): Code uses subprocess with a list of arguments (no shell=True), or input is validated against a whitelist.
- Hardcoded Credentials (CWE-798): The "hardcoded" value is a configuration constant (file path, URL, table name, placeholder), NOT an actual secret, password, or API key.
- Integer Overflow (CWE-190): Code performs explicit bounds checking, uses safe integer types, or the arithmetic result is range-checked before use.
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

    raw = response.content.strip()

    # Strip markdown code fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    raw = re.sub(r"\\'", "'", raw)
    data = json.loads(raw)
    return [BlueTeamDefense(**item) for item in data]
