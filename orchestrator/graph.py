import hashlib
import os
from typing import TypedDict, Optional

import mlflow
from langgraph.graph import StateGraph, END

from agents.red_team import run_red_team, run_red_team_diff
from agents.blue_team import run_blue_team, run_blue_team_diff
from agents.judge_patcher import run_judge, run_judge_diff
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


# ── Node functions ──────────────────────────────────────────────


def red_team_node(state: PipelineState) -> dict:
    findings = run_red_team(state["code"])
    return {"findings": findings}


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


# ── Graph construction ──────────────────────────────────────────


def build_graph() -> StateGraph:
    graph = StateGraph(PipelineState)

    graph.add_node("red_team", red_team_node)
    graph.add_node("blue_team", blue_team_node)
    graph.add_node("judge", judge_node)

    graph.set_entry_point("red_team")
    graph.add_edge("red_team", "blue_team")
    graph.add_edge("blue_team", "judge")
    graph.add_edge("judge", END)

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
    """Run the Red → Blue → Judge pipeline on one annotated diff file."""
    findings = run_red_team_diff(annotated_code, filename)
    defenses = run_blue_team_diff(findings, annotated_code, filename)
    verdicts = run_judge_diff(findings, defenses, annotated_code, filename)
    return DebateReport(
        findings=findings,
        defenses=defenses,
        verdicts=verdicts,
    )


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

        confirmed = sum(1 for v in report.verdicts if v.confirmed)
        dismissed = len(report.verdicts) - confirmed
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