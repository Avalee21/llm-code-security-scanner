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
   Common mitigation mistakes — these do NOT count as mitigations:
   - CWE-22: Prepending a hardcoded prefix (e.g. snprintf(buf, ..., "%s/%s", root, user_input)) does NOT prevent path traversal — an attacker passes "../../etc/passwd" and traverses out of the prefix. Only realpath() + strncmp prefix check, chroot, or an explicit whitelist actually mitigates CWE-22.
   - CWE-78: shell=True with any string concatenation is always vulnerable regardless of other checks.
   - CWE-89: String concatenation into a query is always vulnerable regardless of other sanitization.

CWE exploit confirmation rules — if the code matches these patterns, CONFIRM the finding regardless of Blue Team arguments:
- CWE-22 CONFIRM if: user-controlled input is appended to a path (snprintf, strcat, string concat) without calling realpath() + validating the result stays within the intended directory. The attacker payload is "../../../etc/passwd".
- CWE-78 CONFIRM if: user input reaches system(), popen(), or subprocess with shell=True without strict whitelist validation.
- CWE-89 CONFIRM if: user input is concatenated directly into a SQL string (sprintf, +, f-string) rather than using parameterized queries.
- CWE-190 CONFIRM if: arithmetic on user-controlled integers is performed without bounds checking before use (e.g. malloc(user_size * element_size) without overflow check).
- CWE-476 CONFIRM if: a pointer that may be NULL is dereferenced without a NULL check immediately before.
- CWE-798 CONFIRM if: a hardcoded string literal is used directly as a password, API key, private key, or authentication secret.
4. CWE CORRECTNESS: Is the CWE classification accurate for the specific code pattern? A finding with the wrong CWE should be dismissed.
5. SEVERITY ACCURACY: Is the stated severity proportionate to real-world impact if exploited?

Rules:
- You must evaluate EVERY finding. Do not skip any.
- Base your verdict on the code, not on which side sounds more confident.
- The burden of proof is on the Red Team. If the exploit argument is vague, speculative, or does not match the actual code behaviour, dismiss the finding.
- When in doubt, favour dismissing over confirming. Only confirm findings with clear, code-backed evidence of exploitability.
- For CONFIRMED findings: generate a minimal code patch that fixes the vulnerability. Show only the corrected version of the vulnerable code snippet — not a diff. The patch must preserve the original code's intent while eliminating the security flaw.
  Patch quality rules (MUST follow):
  a. Only use standard library functions and APIs that actually exist (e.g. fopen modes are only: "r", "w", "a", "rb", "wb", "r+", "w+" — never invent modes like "re").
  b. The patch must be syntactically valid C/code for the language of the file.
  c. If the fix requires multiple lines, include all of them.
  d. Do not introduce new undefined variables or functions.
  e. If you are not confident in a correct, syntactically valid fix, set patch to null rather than generating a broken patch.
- For DISMISSED findings: set patch to null.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (matching the original finding_id exactly)
- confirmed: boolean (true if the vulnerability is genuine)
- reasoning: string (your independent analytical reasoning citing specific code evidence)
- patch: string (corrected code snippet) if confirmed, null if dismissed
"""

USER_PROMPT = """Here is the source code under review:
```
{code}
```

Below are the disputed findings. For each one, the Red Team's claim is followed by the Blue Team's response.

{debate_block}

Deliver your verdict on each finding as a JSON array.
"""

DIFF_SYSTEM_PROMPT = """You are an impartial security judge adjudicating a debate between a Red Team and Blue Team
about a CODE DIFF.

You are given the changed hunks with surrounding context lines.
- Lines marked with `// >>> CHANGED` are newly added or modified.
- Sections replaced with `... (lines N-M omitted) ...` are unchanged and distant from the diff.

Apply the same criteria as a full-file review, but also weigh:
1. Was the vulnerability INTRODUCED by the change, or did it pre-exist?
2. Does the surrounding context mitigate the issue?
3. Is the change actually security-relevant?

The burden of proof is on the Red Team. Only confirm findings with clear evidence that the
change introduces or worsens a genuine, exploitable vulnerability.
When in doubt, dismiss.

For CONFIRMED findings: generate a minimal code patch that fixes the vulnerability. Show only the corrected version of the vulnerable code snippet — not a diff. Only use real, valid API calls and syntax. If you cannot produce a correct patch with confidence, set patch to null.
For DISMISSED findings: set patch to null.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (matching the original finding_id exactly)
- confirmed: boolean
- reasoning: string (your independent analytical reasoning citing specific code evidence)
- patch: string (corrected code snippet) if confirmed, null if dismissed
"""

DIFF_USER_PROMPT = """Here is the annotated code diff under review.
Lines marked with `// >>> CHANGED` are newly added or modified.

File: {filename}
```
{code}
```

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
    raw = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
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


def run_judge_diff(
    findings: list[RedTeamFinding],
    defenses: list[BlueTeamDefense],
    code: str,
    filename: str,
) -> list[JudgeVerdict]:
    """Judge evaluation on an annotated diff."""
    if not findings:
        return []

    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", DIFF_SYSTEM_PROMPT),
        ("human", DIFF_USER_PROMPT),
    ])

    chain = prompt | llm
    response = chain.invoke({
        "code": code,
        "filename": filename,
        "debate_block": _serialize_debate(findings, defenses),
    })

    raw = response.content.strip()

    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    raw = re.sub(r"\\'" , "'", raw)
    data = json.loads(raw)
    verdict_map = {item["finding_id"]: item for item in data}

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


ROUND2_SYSTEM_PROMPT = """You are a chief security architect delivering a final ruling on contested vulnerability findings.
These findings survived the initial debate. You must now decide whether the Blue Team's escalated arguments are strong enough to overturn them.

Your standard for overturning a confirmed finding is HIGH but not impossible:
- The new defense must cite specific code lines that constitute an effective mitigation
- The new defense must demonstrate that the attack path is blocked, not merely theoretical
- Generic "this is safe in practice" arguments without code-level evidence do NOT overturn a confirmation

Apply this evaluation protocol for each finding:
1. Read the round 1 confirmation reasoning — understand exactly WHY it was confirmed.
2. Read the round 2 defense — identify the new evidence or argument not present in round 1.
3. Check the source code directly to verify whether the new defense argument is accurate.
4. Ask: Does the new defense identify a specific code-level guard that was overlooked in round 1?
   - YES + code confirms it → DISMISS (flip verdict)
   - NO or code does not support the claim → CONFIRM (keep verdict)

Flip to DISMISSED when:
- The defense identifies a concrete mitigation in the code (with line reference) that the round 1 analysis missed
- The exploit argument contains a factual error about how the code/language/API works
- The attack requires preconditions that are demonstrably impossible given the code context

Keep CONFIRMED when:
- The defense only repeats round 1 arguments without new evidence
- The defense argues "this is unlikely in practice" without showing a code-level guard
- The vulnerability is genuine and no effective mitigation exists in the code

For CONFIRMED findings: generate a syntactically valid patch.
Patch rules (strict):
a. Use only real, existing API functions with correct signatures
b. Valid C fopen modes: "r", "w", "a", "rb", "wb", "r+", "w+" only — never invent modes
c. If you cannot write a correct patch with confidence, set patch to null
d. Patch must compile without errors if extracted from context

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object must have exactly these fields:
- finding_id: string (matching the input finding_id exactly)
- confirmed: boolean
- reasoning: string (cite both the round 1 reasoning AND the new defense, explain your decision)
- patch: string or null
"""

ROUND2_USER_PROMPT = """Source code:
```
{code}
```

Round 2 review — each entry shows the original finding, the round 1 confirmation reasoning, and the new Blue Team defense:

{debate_block}

Deliver your final verdict as a JSON array.
"""


def run_judge_round2(
    confirmed_findings: list[RedTeamFinding],
    round1_verdicts: list[JudgeVerdict],
    round2_defenses: list[BlueTeamDefense],
    code: str,
) -> list[JudgeVerdict]:
    """Second-round Judge re-evaluation of confirmed findings with escalated Blue Team defenses."""
    if not confirmed_findings:
        return []

    r1_verdict_map = {v.finding_id: v for v in round1_verdicts}
    r2_defense_map = {d.finding_id: d for d in round2_defenses}

    blocks = []
    for i, f in enumerate(confirmed_findings, start=1):
        r1v = r1_verdict_map.get(f.finding_id)
        r2d = r2_defense_map.get(f.finding_id)
        block = (
            f"Finding {i}:\n"
            f"  finding_id: {f.finding_id}\n"
            f"  cwe_id: {f.cwe_id}\n"
            f"  cwe_name: {f.cwe_name}\n"
            f"  severity: {f.severity}\n"
            f"  vulnerable_code: {f.vulnerable_code}\n"
            f"  exploit_argument: {f.exploit_argument}\n"
            f"  ROUND 1 CONFIRMATION REASONING: {r1v.reasoning if r1v else '(not available)'}\n"
            f"  ROUND 2 BLUE TEAM DEFENSE: {r2d.counter_argument if r2d else '(no new defense)'}"
        )
        blocks.append(block)
    debate_block = "\n\n".join(blocks)

    llm = get_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", ROUND2_SYSTEM_PROMPT),
        ("human", ROUND2_USER_PROMPT),
    ])
    chain = prompt | llm
    response = chain.invoke({"code": code, "debate_block": debate_block})

    raw = response.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    raw = re.sub(r"\\'", "'", raw)
    raw = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
    data = json.loads(raw)
    verdict_map = {item["finding_id"]: item for item in data}

    verdicts = []
    for f in confirmed_findings:
        if f.finding_id in verdict_map:
            verdicts.append(JudgeVerdict(**verdict_map[f.finding_id]))
        else:
            r1v = r1_verdict_map.get(f.finding_id)
            verdicts.append(JudgeVerdict(
                finding_id=f.finding_id,
                confirmed=True,
                reasoning=r1v.reasoning if r1v else "Confirmed by default (no round 2 verdict).",
                patch=r1v.patch if r1v else None,
            ))
    return verdicts
