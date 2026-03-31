import json
import os
import re
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from utils.llm import get_llm
from utils.schemas import RedTeamFinding

load_dotenv()

SYSTEM_PROMPT = """You are a security researcher performing adversarial code review.
Your job is to find genuine, exploitable vulnerabilities in the submitted code.

Guidelines:
1. ONLY report vulnerabilities with a concrete, demonstrable attack path. You must be able to explain step-by-step how an attacker would trigger the flaw given the code's actual inputs and execution context.
2. DO NOT report theoretical weaknesses, best-practice violations, or style issues. If the code already contains an effective mitigation (input validation, bounds checking, sanitisation), do not flag the mitigated issue.
3. QUOTE the exact vulnerable code snippet — do not paraphrase or approximate.
4. Assign the most specific CWE that matches the root cause. Do not use a generic CWE when a precise one exists.
5. Limit your findings to at most 3 per code sample. Prioritize by severity and exploitability.
6. If the code is secure or you cannot construct a concrete exploit, return an empty array.

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

Guidelines:
1. ONLY report vulnerabilities with a concrete, demonstrable attack path introduced by the change.
2. DO NOT report theoretical weaknesses, best-practice violations, or style issues.
3. QUOTE the exact vulnerable code snippet — do not paraphrase or approximate.
4. Assign the most specific CWE that matches the root cause.
5. Limit your findings to at most 3 per file. Prioritize by severity and exploitability.
6. If the change is secure or you cannot construct a concrete exploit, return an empty array.

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
    
    raw = response.content.strip()
    
    # Strip markdown code fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    raw = re.sub(r"\\'", "'", raw)
    data = json.loads(raw)
    return [RedTeamFinding(**item) for item in data]

def run_red_team_diff(code: str, filename: str) -> list[RedTeamFinding]:
    """Red team analysis on an annotated diff (full file with CHANGED markers)."""
    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", DIFF_SYSTEM_PROMPT),
        ("human", DIFF_USER_PROMPT)
    ])

    chain = prompt | llm
    response = chain.invoke({"code": code, "filename": filename})

    raw = response.content.strip()

    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    raw = re.sub(r"\\'" , "'", raw)
    data = json.loads(raw)
    return [RedTeamFinding(**item) for item in data]