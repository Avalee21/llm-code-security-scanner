import hashlib
import os
from typing import TypedDict, Optional

import mlflow
from langgraph.graph import StateGraph, END

from agents.red_team import run_red_team, run_red_team_diff, run_verification
from agents.blue_team import run_blue_team, run_blue_team_diff, run_blue_team_round2
from agents.judge_patcher import run_judge, run_judge_diff, run_judge_round2
from agents.cwe_classifier import run_cwe_classifier, run_cwe_classifier_diff
from utils.metrics import final_verdicts
from utils.schemas import (
    BlueTeamDefense,
    DebateReport,
    FileReport,
    FileDiff,
    JudgeVerdict,
    RedTeamFinding,
    RepoScanReport,
)


class PipelineState(TypedDict, total=False):
    code: str
    findings: list[RedTeamFinding]
    defenses: list[BlueTeamDefense]
    verdicts: list[JudgeVerdict]
    report: DebateReport
    confirmed_findings: list[RedTeamFinding]
    defenses_r2: list[BlueTeamDefense]
    verdicts_r2: list[JudgeVerdict]


# ── Node functions ──────────────────────────────────────────────


def red_team_node(state: PipelineState) -> dict:
    findings = run_red_team(state["code"])
    return {"findings": findings}


def cwe_classifier_node(state: PipelineState) -> dict:
    findings = run_cwe_classifier(state["findings"], state["code"])
    report = state["report"].model_copy(update={"findings": findings})
    return {"findings": findings, "report": report}


def blue_team_node(state: PipelineState) -> dict:
    defenses = run_blue_team(state["findings"], state["code"])
    return {"defenses": defenses}


def judge_node(state: PipelineState) -> dict:
    verdicts = run_judge(state["findings"], state["defenses"], state["code"])
    report = DebateReport(
        findings=state["findings"],
        defenses=state["defenses"],
        verdicts=verdicts,
    )
    return {"verdicts": verdicts, "report": report}


def blue_team_r2_node(state: PipelineState) -> dict:
    confirmed = [f for f in state["findings"]
                 if any(v.confirmed and v.finding_id == f.finding_id for v in state["verdicts"])]
    if not confirmed:
        return {}
    defenses_r2 = run_blue_team_round2(confirmed, state["code"], state["defenses"])
    return {"confirmed_findings": confirmed, "defenses_r2": defenses_r2}


def judge_r2_node(state: PipelineState) -> dict:
    verdicts_r2 = run_judge_round2(
        state["confirmed_findings"], state["verdicts"], state["defenses_r2"], state["code"]
    )
    report = state["report"].model_copy(update={
        "round2_defenses": state["defenses_r2"],
        "round2_verdicts": verdicts_r2,
    })
    return {"verdicts_r2": verdicts_r2, "report": report}


def verification_node(state: PipelineState) -> dict:
    """Verify Judge-generated patches by re-checking with the Red Team."""
    report = state["report"]
    passed, results = run_verification(
        state["code"], final_verdicts(report), report.findings,
    )
    updated = report.model_copy(update={
        "verification_passed": passed,
        "verification_results": results if results else None,
    })
    return {"report": updated}


# ── Graph construction ──────────────────────────────────────────


def _should_run_round2(state: PipelineState) -> str:
    return "blue_team_r2" if any(v.confirmed for v in state["verdicts"]) else "cwe_classifier"


def build_graph() -> StateGraph:
    graph = StateGraph(PipelineState)

    graph.add_node("red_team", red_team_node)
    graph.add_node("blue_team", blue_team_node)
    graph.add_node("judge", judge_node)
    graph.add_node("blue_team_r2", blue_team_r2_node)
    graph.add_node("judge_r2", judge_r2_node)
    graph.add_node("cwe_classifier", cwe_classifier_node)
    graph.add_node("verification", verification_node)

    graph.set_entry_point("red_team")
    graph.add_edge("red_team", "blue_team")
    graph.add_edge("blue_team", "judge")
    graph.add_conditional_edges("judge", _should_run_round2, {
        "blue_team_r2": "blue_team_r2",
        "cwe_classifier": "cwe_classifier",
    })
    graph.add_edge("blue_team_r2", "judge_r2")
    graph.add_edge("judge_r2", "cwe_classifier")
    graph.add_edge("cwe_classifier", "verification")
    graph.add_edge("verification", END)

    return graph.compile()


# ── MLflow logging ──────────────────────────────────────────────


def _log_to_mlflow(report: DebateReport, code: str, sample_id: str | None = None):
    """Log pipeline metrics and artifacts to MLflow."""
    confirmed = [v for v in report.verdicts if v.confirmed]
    dismissed = [v for v in report.verdicts if not v.confirmed]

    mlflow.log_params({
        "code_sha256": hashlib.sha256(code.encode()).hexdigest()[:16],
        "sample_id": sample_id or "custom",
    })
    mlflow.log_metrics({
        "findings_count": len(report.findings),
        "confirmed_count": len(confirmed),
        "false_positive_count": len(dismissed),
    })
    mlflow.log_text(report.model_dump_json(indent=2), "debate_report.json")


# ── Public entry point ──────────────────────────────────────────


def run_pipeline(
    code: str,
    *,
    track: bool = True,
    sample_id: str | None = None,
) -> DebateReport:
    """Run the full Red → Blue → Judge pipeline and return the debate report."""
    app = build_graph()
    result = app.invoke({"code": code})
    report = result["report"]

    if track:
        mlflow.set_experiment("code-security-scanner")
        with mlflow.start_run():
            _log_to_mlflow(report, code, sample_id)

    return report


# ── Diff-aware pipeline ─────────────────────────────────────────


def run_diff_pipeline(
    annotated_code: str,
    filename: str,
) -> DebateReport:
    """Run the Red → Blue → Judge → Verification pipeline on one annotated diff file."""
    findings = run_red_team_diff(annotated_code, filename)
    defenses = run_blue_team_diff(findings, annotated_code, filename)
    verdicts = run_judge_diff(findings, defenses, annotated_code, filename)
    report = DebateReport(
        findings=findings,
        defenses=defenses,
        verdicts=verdicts,
    )
    confirmed = [f for f in findings
                 if any(v.confirmed and v.finding_id == f.finding_id for v in verdicts)]
    if confirmed:
        defenses_r2 = run_blue_team_round2(confirmed, annotated_code, defenses)
        verdicts_r2 = run_judge_round2(confirmed, verdicts, defenses_r2, annotated_code)
        report.round2_defenses = defenses_r2
        report.round2_verdicts = verdicts_r2
    # CWE classifier runs after debate to avoid influencing verdicts
    findings = run_cwe_classifier_diff(findings, annotated_code, filename)
    report.findings = findings
    passed, results = run_verification(annotated_code, final_verdicts(report), findings)
    report.verification_passed = passed
    report.verification_results = results if results else None
    return report


def run_repo_scan(
    diffs: list[FileDiff],
    annotated_codes: dict[str, str],
    *,
    repo_url: str,
    pr_number: int | None = None,
    commit_sha: str | None = None,
    track: bool = True,
) -> RepoScanReport:
    """Scan all changed files through the diff-aware pipeline.

    Parameters
    ----------
    diffs : list[FileDiff]
        Parsed diffs for each changed file.
    annotated_codes : dict[str, str]
        Mapping of filename → annotated full file content (with CHANGED markers).
        If a filename is missing, falls back to scanning the raw patch only.
    """
    file_reports: list[FileReport] = []
    total_findings = 0
    total_confirmed = 0
    total_dismissed = 0

    for diff in diffs:
        code = annotated_codes.get(diff.filename)
        if code is None:
            # Fallback: use the patch itself as the code
            code = diff.patch

        ext = os.path.splitext(diff.filename)[1].lstrip(".")
        print(f"  Scanning {diff.filename} ({diff.additions}+ / {diff.deletions}-) …")

        report = run_diff_pipeline(code, diff.filename)

        merged = final_verdicts(report)
        confirmed = sum(1 for v in merged if v.confirmed)
        dismissed = len(merged) - confirmed
        total_findings += len(report.findings)
        total_confirmed += confirmed
        total_dismissed += dismissed

        file_reports.append(FileReport(
            filename=diff.filename,
            language=ext or None,
            report=report,
        ))

    repo_report = RepoScanReport(
        repo_url=repo_url,
        pr_number=pr_number,
        commit_sha=commit_sha,
        file_reports=file_reports,
        total_findings=total_findings,
        total_confirmed=total_confirmed,
        total_dismissed=total_dismissed,
    )

    if track:
        mlflow.set_experiment("code-security-scanner")
        with mlflow.start_run():
            mlflow.log_params({
                "repo_url": repo_url[:250],
                "pr_number": str(pr_number or ""),
                "commit_sha": str(commit_sha or "")[:16],
                "files_scanned": len(file_reports),
            })
            mlflow.log_metrics({
                "total_findings": total_findings,
                "total_confirmed": total_confirmed,
                "total_dismissed": total_dismissed,
            })
            mlflow.log_text(
                repo_report.model_dump_json(indent=2), "repo_scan_report.json"
            )

    return repo_report