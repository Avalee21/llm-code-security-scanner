import json
import os
import re

from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate

from utils.llm import get_llm
from utils.schemas import BlueTeamDefense, JudgeVerdict, RedTeamFinding

load_dotenv()

SYSTEM_PROMPT = """You are an impartial security judge adjudicating a debate between a Red Team (attacker) and a Blue Team (defender).

For each disputed finding, you will see:
- The Red Team's vulnerability claim and exploit argument
- The Blue Team's counter-argument and false-positive assessment
- The full source code under review

Your job is to deliver a final, independent verdict on each finding by weighing both sides against the actual code.

Apply these criteria:
1. EXPLOITABILITY: Can the vulnerability actually be triggered given the code's structure, inputs, and execution context? The Red Team must demonstrate a concrete, step-by-step attack path — not a theoretical possibility.
2. EVIDENCE QUALITY: Which side provides more specific, code-grounded reasoning? Dismiss findings that rely on speculation, assumptions about external context, or generic vulnerability descriptions not tied to the actual code.
3. MITIGATIONS: Carefully check whether the code already contains effective defences (input validation, bounds checking, sanitisation, type constraints, safe APIs). If a mitigation is present and effective, dismiss the finding even if the Red Team ignores it.
4. CWE CORRECTNESS: Is the CWE classification accurate for the specific code pattern? A finding with the wrong CWE should be dismissed.
5. SEVERITY ACCURACY: Is the stated severity proportionate to real-world impact if exploited?

Rules:
- You must evaluate EVERY finding. Do not skip any.
- Base your verdict on the code, not on which side sounds more confident.
- The burden of proof is on the Red Team. If the exploit argument is vague, speculative, or does not match the actual code behaviour, dismiss the finding.
- When in doubt, favour dismissing over confirming. Only confirm findings with clear, code-backed evidence of exploitability.
- Set patch to null for all verdicts.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (matching the original finding_id exactly)
- confirmed: boolean (true if the vulnerability is genuine)
- reasoning: string (your independent analytical reasoning citing specific code evidence)
- patch: null
"""

USER_PROMPT = """Here is the source code under review:
```
{code}
```

Below are the disputed findings. For each one, the Red Team's claim is followed by the Blue Team's response.

{debate_block}

Deliver your verdict on each finding as a JSON array.
"""


def _serialize_debate(
    findings: list[RedTeamFinding],
    defenses: list[BlueTeamDefense],
) -> str:
    defense_map = {d.finding_id: d for d in defenses}
    blocks = []
    for i, f in enumerate(findings, start=1):
        d = defense_map.get(f.finding_id)
        block = (
            f"Dispute {i}:\n"
            f"  finding_id: {f.finding_id}\n"
            f"  cwe_id: {f.cwe_id}\n"
            f"  cwe_name: {f.cwe_name}\n"
            f"  severity: {f.severity}\n"
            f"  vulnerable_code: {f.vulnerable_code}\n"
            f"  RED TEAM exploit_argument: {f.exploit_argument}\n"
        )
        if d is not None:
            fp_label = "YES" if d.is_false_positive else "NO"
            block += (
                f"  BLUE TEAM is_false_positive: {fp_label}\n"
                f"  BLUE TEAM counter_argument: {d.counter_argument}"
            )
        else:
            block += "  BLUE TEAM: No defense submitted."
        blocks.append(block)
    return "\n\n".join(blocks)


def run_judge(
    findings: list[RedTeamFinding],
    defenses: list[BlueTeamDefense],
    code: str,
) -> list[JudgeVerdict]:
    """LLM-powered judge that weighs Red vs Blue arguments against the source code."""
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
        "debate_block": _serialize_debate(findings, defenses),
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
    verdict_map = {item["finding_id"]: item for item in data}

    # Guarantee one verdict per finding, in input order
    verdicts = []
    for f in findings:
        if f.finding_id in verdict_map:
            verdicts.append(JudgeVerdict(**verdict_map[f.finding_id]))
        else:
            verdicts.append(JudgeVerdict(
                finding_id=f.finding_id,
                confirmed=True,
                reasoning="Judge did not return a verdict for this finding; confirmed by default.",
                patch=None,
            ))
    return verdicts
