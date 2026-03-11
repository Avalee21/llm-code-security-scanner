from typing import TypedDict, Optional

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
    verdicts = run_judge(state["findings"], state["defenses"])
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


# ── Public entry point ──────────────────────────────────────────


def run_pipeline(code: str) -> DebateReport:
    """Run the full Red → Blue → Judge pipeline and return the debate report."""
    app = build_graph()
    result = app.invoke({"code": code})
    return result["report"]