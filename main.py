import argparse
import json
import sys

from agents.red_team import run_red_team
from agents.blue_team import run_blue_team
from orchestrator.graph import run_pipeline

GOLDEN_SET_PATH = "data/golden_set.json"


def _load_golden_sample(selector: str) -> tuple[str, str]:
    """Load a sample from the golden set by index (e.g. '0') or ID (e.g. 'CASTLE-CWE-22-1').
    Returns (label, code)."""
    with open(GOLDEN_SET_PATH, "r", encoding="utf-8") as f:
        samples = json.load(f)

    # Try numeric index first
    if selector.isdigit():
        idx = int(selector)
        if idx < 0 or idx >= len(samples):
            print(f"Error: index {idx} out of range (0–{len(samples) - 1})", file=sys.stderr)
            sys.exit(1)
        sample = samples[idx]
    else:
        # Match by ID
        sample = next((s for s in samples if s["id"] == selector), None)
        if sample is None:
            ids = [s["id"] for s in samples]
            print(f"Error: no sample with id '{selector}'", file=sys.stderr)
            print(f"Available IDs: {', '.join(ids)}", file=sys.stderr)
            sys.exit(1)

    vuln_tag = "VULNERABLE" if sample["has_vulnerability"] else "SAFE"
    label = f"{sample['id']} ({sample['cwe_id']} — {sample['cwe_name']}, {vuln_tag})"
    return label, sample["code"]


def main():
    parser = argparse.ArgumentParser(
        description="LLM Code Security Scanner — adversarial debate pipeline"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to a source file to scan")
    group.add_argument(
        "--golden", metavar="INDEX_OR_ID",
        help="Scan a sample from the golden set by index (0-29) or ID (e.g. CASTLE-CWE-22-1)",
    )
    group.add_argument(
        "--list-golden", action="store_true",
        help="List all available golden set samples and exit",
    )
    parser.add_argument(
        "--no-mlflow", action="store_true",
        help="Disable MLflow experiment tracking for this run",
    )
    parser.add_argument(
        "--red-only", action="store_true",
        help="Run only the Red Team agent (no Blue Team, Judge, or MLflow)",
    )
    parser.add_argument(
        "--blue-only", action="store_true",
        help="Run Red + Blue Team agents only (no Judge or MLflow)",
    )
    args = parser.parse_args()

    if args.list_golden:
        with open(GOLDEN_SET_PATH, "r", encoding="utf-8") as f:
            samples = json.load(f)
        for i, s in enumerate(samples):
            vuln = "VULNERABLE" if s["has_vulnerability"] else "SAFE"
            print(f"  [{i:2d}] {s['id']:<25s} {s['cwe_id']} {s['cwe_name']:<30s} {vuln}")
        return

    if args.golden is not None:
        label, code = _load_golden_sample(args.golden)
        sample_id = args.golden
        print(f"Scanning golden sample: {label}\n")
    else:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                code = f.read()
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        sample_id = None
        print(f"Scanning {args.file} …\n")

    # ── Red-only mode ────────────────────────────────────────
    if args.red_only:
        findings = run_red_team(code)
        print(f"Red Team found {len(findings)} finding(s).\n")
        for f in findings:
            print(f"  {f.finding_id} [{f.severity}] {f.cwe_id} — {f.cwe_name}")
            print(f"    Code : {f.vulnerable_code}")
            print(f"    Argue: {f.exploit_argument}")
            print()
        return

    # ── Blue-only mode (Red + Blue, no Judge) ────────────────
    if args.blue_only:
        findings = run_red_team(code)
        print(f"Red Team found {len(findings)} finding(s).")
        for f in findings:
            print(f"  {f.finding_id} [{f.severity}] {f.cwe_id} — {f.cwe_name}")
        print()

        defenses = run_blue_team(findings, code=code)
        print(f"Blue Team produced {len(defenses)} defense(s).\n")
        for d in defenses:
            verdict = "FALSE POSITIVE" if d.is_false_positive else "CONFIRMED"
            print(f"  {d.finding_id} -> {verdict}")
            print(f"    Argument: {d.counter_argument}")
            print()
        return

    # ── Full pipeline ────────────────────────────────────────
    track = not args.no_mlflow
    report = run_pipeline(code, track=track, sample_id=sample_id)

    # ── Summary ──────────────────────────────────────────────
    confirmed = [v for v in report.verdicts if v.confirmed]
    dismissed = [v for v in report.verdicts if not v.confirmed]

    print(f"Red Team findings : {len(report.findings)}")
    print(f"Confirmed         : {len(confirmed)}")
    print(f"Dismissed (FP)    : {len(dismissed)}")
    print()

    for v in report.verdicts:
        tag = "CONFIRMED" if v.confirmed else "DISMISSED"
        finding = next(
            (f for f in report.findings if f.finding_id == v.finding_id), None
        )
        if finding:
            print(f"[{tag}] {v.finding_id}  {finding.cwe_id} — {finding.cwe_name}")
            print(f"  Severity : {finding.severity}")
            print(f"  Reasoning: {v.reasoning}")
            print()

    # ── Full JSON output ─────────────────────────────────────
    print("--- Full debate report (JSON) ---")
    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()