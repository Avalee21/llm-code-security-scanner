import json
import os
import re
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from utils.llm import get_llm
from utils.schemas import RedTeamFinding

load_dotenv()

SYSTEM_PROMPT = """You are a security researcher performing adversarial code review.
Your job is to find vulnerabilities in the submitted code and argue why each is exploitable.
Be specific and aggressive — assume the worst about how the code could be attacked.

You must respond with ONLY a valid JSON array. No explanation, no markdown, no backticks.
Each object in the array must have exactly these fields:
- finding_id: string (e.g. "F-001")
- cwe_id: string (e.g. "CWE-89")
- cwe_name: string (e.g. "SQL Injection")
- severity: string — one of: critical, high, medium, low
- vulnerable_code: string (the exact vulnerable snippet)
- exploit_argument: string (why this is exploitable)

If no vulnerabilities are found, return an empty array: []
"""

USER_PROMPT = """Review this code for security vulnerabilities:
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