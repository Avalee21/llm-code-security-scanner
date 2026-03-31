import argparse
import json
import sys

from agents.red_team import run_red_team
from agents.blue_team import run_blue_team
from orchestrator.graph import run_pipeline, run_repo_scan
from utils.github import (
    parse_github_url,
    fetch_diffs_for_target,
    fetch_file_content,
    extract_diff_context,
)

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
    group.add_argument(
        "--pr", metavar="URL",
        help="Scan a GitHub pull request diff (e.g. https://github.com/owner/repo/pull/123)",
    )
    group.add_argument(
        "--commit", metavar="URL",
        help="Scan a GitHub commit diff (e.g. https://github.com/owner/repo/commit/abc123)",
    )
    parser.add_argument(
        "--github-token",
        help="GitHub personal access token (or set GITHUB_TOKEN env var)",
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

    # ── GitHub PR / commit diff mode ─────────────────────────
    if args.pr or args.commit:
        url = args.pr or args.commit
        token = args.github_token
        track = not args.no_mlflow

        target = parse_github_url(url)
        print(f"Fetching diff from {target.owner}/{target.repo} …")
        diffs = fetch_diffs_for_target(target, token)

        if not diffs:
            print("No scannable code files found in this diff.")
            return

        print(f"Found {len(diffs)} code file(s) with changes:\n")
        for d in diffs:
            print(f"  {d.filename} ({d.additions}+ / {d.deletions}-)")
        print()

        # Fetch full file content and annotate with diff markers
        # Determine the ref to fetch from
        if target.kind == "pr":
            # For PRs, use the PR head — fetch via the merge ref
            ref = f"pull/{target.pr_number}/head"
        elif target.kind == "commit":
            ref = target.commit_sha
        else:
            ref = target.head_ref

        annotated_codes: dict[str, str] = {}
        for d in diffs:
            try:
                full_code = fetch_file_content(
                    target.owner, target.repo, d.filename, ref, token
                )
                annotated_codes[d.filename] = extract_diff_context(
                    full_code, d.patch
                )
            except Exception as exc:
                print(f"  Warning: could not fetch {d.filename}: {exc}")
                # Will fall back to raw patch in run_repo_scan

        print("Running adversarial diff scan …\n")
        repo_report = run_repo_scan(
            diffs,
            annotated_codes,
            repo_url=url,
            pr_number=target.pr_number,
            commit_sha=target.commit_sha,
            track=track,
        )

        # ── Summary ──────────────────────────────────────────
        print(f"\n{'=' * 60}")
        print(f"Repo Scan Summary")
        print(f"{'=' * 60}")
        print(f"Files scanned     : {len(repo_report.file_reports)}")
        print(f"Total findings    : {repo_report.total_findings}")
        print(f"Confirmed         : {repo_report.total_confirmed}")
        print(f"Dismissed (FP)    : {repo_report.total_dismissed}")
        print()

        for fr in repo_report.file_reports:
            confirmed = [v for v in fr.report.verdicts if v.confirmed]
            if not fr.report.findings:
                print(f"  {fr.filename}: no findings")
                continue
            print(f"  {fr.filename}: {len(fr.report.findings)} finding(s), "
                  f"{len(confirmed)} confirmed")
            for v in fr.report.verdicts:
                tag = "CONFIRMED" if v.confirmed else "DISMISSED"
                finding = next(
                    (f for f in fr.report.findings if f.finding_id == v.finding_id),
                    None,
                )
                if finding:
                    print(f"    [{tag}] {v.finding_id}  {finding.cwe_id} — {finding.cwe_name}")
                    print(f"      Reasoning: {v.reasoning}")
            print()

        print("--- Full repo scan report (JSON) ---")
        print(repo_report.model_dump_json(indent=2))
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