import hashlib
from typing import TypedDict, Optional

import mlflow
from langgraph.graph import StateGraph, END

from agents.red_team import run_red_team
from agents.blue_team import run_blue_team
from agents.judge_patcher import run_judge
from utils.schemas import (
    BlueTeamDefense,
    DebateReport,
    JudgeVerdict,
    RedTeamFinding,
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