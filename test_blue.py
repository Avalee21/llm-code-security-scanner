from agents.red_team import run_red_team
from agents.blue_team import run_blue_team

vulnerable_code = """
import os

def read_file(filename):
    path = "/var/data/" + filename
    with open(path, 'r') as f:
        return f.read()
"""

findings = run_red_team(vulnerable_code)
print(f"Red Team produced {len(findings)} finding(s).")
for f in findings:
    print(f"  {f.finding_id} [{f.severity}] {f.cwe_id} — {f.cwe_name}")

defenses = run_blue_team(findings, code=vulnerable_code)
print(f"\nBlue Team produced {len(defenses)} defense(s).")
for d in defenses:
    verdict = "FALSE POSITIVE" if d.is_false_positive else "CONFIRMED"
    print(f"  {d.finding_id} -> {verdict}")
    print(f"  Argument: {d.counter_argument}")
    print("  ---")
