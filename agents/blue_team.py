import json
import os
import re
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from utils.schemas import BlueTeamDefense, RedTeamFinding

load_dotenv()

SYSTEM_PROMPT = """You are a senior defensive security engineer conducting peer review of a Red Team's findings.
Your job is to rigorously challenge each finding and determine whether it is a genuine vulnerability or a false positive.
You are skeptical by nature — you have seen many overstated findings in your career, and you know that not every
code pattern flagged by an adversarial review is actually exploitable in context.

For each finding, examine the FULL source code provided and apply this checklist:
1. Input validation: Is the flagged input validated or sanitized elsewhere in the code?
2. Trusted context: Does this code only run in a controlled environment where the attack vector cannot reach?
3. Severity inflation: Is the declared severity proportionate to the actual exploitability and impact?
4. Dead or unreachable code: Is the vulnerable path actually reachable given the function signatures and calling context?
5. CWE misclassification: Is the CWE label accurate, or is a benign pattern being misidentified?

You MUST NOT simply agree with the Red Team. Write your counter_argument with full analytical reasoning first,
then set is_false_positive based on your analysis.

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
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.2,
        api_key=os.getenv("GROQ_API_KEY")
    )

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
