"""Select a golden evaluation set from the CASTLE-C250 dataset.

Picks 5 programs per CWE (3 vulnerable + 2 non-vulnerable) from 6 target CWEs,
producing 30 test cases total. Output is saved to data/golden_set.json.
"""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
CASTLE_JSON = os.path.join(PROJECT_ROOT, "data", "castle-raw", "datasets", "CASTLE-C250.json")
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "data", "golden_set.json")

# 6 CWEs most relevant to OWASP Top 10 and common vulnerability patterns
TARGET_CWES = {
    22: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    78: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    89: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    190: "Integer Overflow or Wraparound",
    476: "NULL Pointer Dereference",
    798: "Use of Hard-coded Credentials",
}

VULNERABLE_PER_CWE = 3
NON_VULNERABLE_PER_CWE = 2


def main():
    with open(CASTLE_JSON) as f:
        data = json.load(f)

    cwe_names = {}
    for cwe_id_str, info in data["cwes"].items():
        cwe_names[int(cwe_id_str)] = info["name"]

    golden_set = []

    for cwe_id in sorted(TARGET_CWES.keys()):
        tests = [t for t in data["tests"] if t["cwe"] == cwe_id]
        vulnerable = [t for t in tests if t["vulnerable"]]
        non_vulnerable = [t for t in tests if not t["vulnerable"]]

        selected_vuln = vulnerable[:VULNERABLE_PER_CWE]
        selected_safe = non_vulnerable[:NON_VULNERABLE_PER_CWE]

        for t in selected_vuln + selected_safe:
            golden_set.append({
                "id": f"CASTLE-CWE-{cwe_id}-{t['number']}",
                "name": t["name"],
                "code": t["code"],
                "cwe_id": f"CWE-{cwe_id}",
                "cwe_name": cwe_names.get(cwe_id, TARGET_CWES[cwe_id]),
                "has_vulnerability": t["vulnerable"],
                "source": "CASTLE",
            })

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(golden_set, f, indent=2)

    # Print summary
    print(f"Golden set: {len(golden_set)} test cases")
    vuln_count = sum(1 for t in golden_set if t["has_vulnerability"])
    safe_count = len(golden_set) - vuln_count
    print(f"  Vulnerable: {vuln_count}")
    print(f"  Non-vulnerable: {safe_count}")
    print(f"\nCWE breakdown:")
    for cwe_id in sorted(TARGET_CWES.keys()):
        cwe_tests = [t for t in golden_set if t["cwe_id"] == f"CWE-{cwe_id}"]
        v = sum(1 for t in cwe_tests if t["has_vulnerability"])
        s = len(cwe_tests) - v
        print(f"  CWE-{cwe_id}: {v} vulnerable, {s} non-vulnerable")
    print(f"\nSaved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
