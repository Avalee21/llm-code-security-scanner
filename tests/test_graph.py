from unittest.mock import patch, MagicMock

from orchestrator.graph import build_graph, run_pipeline, _log_to_mlflow
from utils.schemas import (
    BlueTeamDefense,
    DebateReport,
    JudgeVerdict,
    RedTeamFinding,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(fid: str = "F-001") -> RedTeamFinding:
    return RedTeamFinding(
        finding_id=fid,
        cwe_id="CWE-22",
        cwe_name="Path Traversal",
        severity="high",
        vulnerable_code="open(user_input)",
        exploit_argument="user_input is unsanitized",
    )


def _defense(fid: str = "F-001", fp: bool = False) -> BlueTeamDefense:
    return BlueTeamDefense(
        finding_id=fid,
        is_false_positive=fp,
        counter_argument="Stub counter argument",
    )


SAMPLE_CODE = "int main() { return 0; }"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@patch("orchestrator.graph.run_judge")
@patch("orchestrator.graph.run_blue_team")
@patch("orchestrator.graph.run_red_team")
def test_pipeline_returns_debate_report(mock_red, mock_blue, mock_judge):
    mock_red.return_value = [_finding()]
    mock_blue.return_value = [_defense()]
    mock_judge.return_value = [
        JudgeVerdict(finding_id="F-001", confirmed=True, reasoning="confirmed", patch=None)
    ]

    report = run_pipeline(SAMPLE_CODE, track=False)

    assert isinstance(report, DebateReport)
    assert len(report.findings) == 1
    assert len(report.defenses) == 1
    assert len(report.verdicts) == 1


@patch("orchestrator.graph.run_judge")
@patch("orchestrator.graph.run_blue_team")
@patch("orchestrator.graph.run_red_team")
def test_pipeline_calls_agents_in_order(mock_red, mock_blue, mock_judge):
    mock_red.return_value = [_finding()]
    mock_blue.return_value = [_defense()]
    mock_judge.return_value = [
        JudgeVerdict(finding_id="F-001", confirmed=True, reasoning="ok", patch=None)
    ]

    run_pipeline(SAMPLE_CODE, track=False)

    mock_red.assert_called_once_with(SAMPLE_CODE)
    mock_blue.assert_called_once()
    mock_judge.assert_called_once()


@patch("orchestrator.graph.run_judge")
@patch("orchestrator.graph.run_blue_team")
@patch("orchestrator.graph.run_red_team")
def test_pipeline_no_findings(mock_red, mock_blue, mock_judge):
    mock_red.return_value = []
    mock_blue.return_value = []
    mock_judge.return_value = []

    report = run_pipeline(SAMPLE_CODE, track=False)

    assert report.findings == []
    assert report.defenses == []
    assert report.verdicts == []


@patch("orchestrator.graph.run_judge")
@patch("orchestrator.graph.run_blue_team")
@patch("orchestrator.graph.run_red_team")
def test_pipeline_multiple_findings(mock_red, mock_blue, mock_judge):
    findings = [_finding("F-001"), _finding("F-002")]
    defenses = [_defense("F-001", fp=True), _defense("F-002", fp=False)]
    verdicts = [
        JudgeVerdict(finding_id="F-001", confirmed=False, reasoning="FP", patch=None),
        JudgeVerdict(finding_id="F-002", confirmed=True, reasoning="real", patch=None),
    ]
    mock_red.return_value = findings
    mock_blue.return_value = defenses
    mock_judge.return_value = verdicts

    report = run_pipeline(SAMPLE_CODE, track=False)

    assert len(report.findings) == 2
    assert len(report.verdicts) == 2
    confirmed = [v for v in report.verdicts if v.confirmed]
    assert len(confirmed) == 1


@patch("orchestrator.graph.mlflow")
@patch("orchestrator.graph.run_judge")
@patch("orchestrator.graph.run_blue_team")
@patch("orchestrator.graph.run_red_team")
def test_pipeline_mlflow_tracking_enabled(mock_red, mock_blue, mock_judge, mock_mlflow):
    mock_red.return_value = [_finding()]
    mock_blue.return_value = [_defense()]
    mock_judge.return_value = [
        JudgeVerdict(finding_id="F-001", confirmed=True, reasoning="ok", patch=None)
    ]

    run_pipeline(SAMPLE_CODE, track=True, sample_id="test-sample")

    mock_mlflow.set_experiment.assert_called_once_with("code-security-scanner")
    mock_mlflow.start_run.assert_called_once()


@patch("orchestrator.graph.mlflow")
@patch("orchestrator.graph.run_judge")
@patch("orchestrator.graph.run_blue_team")
@patch("orchestrator.graph.run_red_team")
def test_pipeline_mlflow_tracking_disabled(mock_red, mock_blue, mock_judge, mock_mlflow):
    mock_red.return_value = [_finding()]
    mock_blue.return_value = [_defense()]
    mock_judge.return_value = [
        JudgeVerdict(finding_id="F-001", confirmed=True, reasoning="ok", patch=None)
    ]

    run_pipeline(SAMPLE_CODE, track=False)

    mock_mlflow.set_experiment.assert_not_called()
    mock_mlflow.start_run.assert_not_called()


@patch("orchestrator.graph.mlflow")
def test_log_to_mlflow_metrics(mock_mlflow):
    report = DebateReport(
        findings=[_finding("F-001"), _finding("F-002")],
        defenses=[_defense("F-001", fp=True), _defense("F-002")],
        verdicts=[
            JudgeVerdict(finding_id="F-001", confirmed=False, reasoning="FP", patch=None),
            JudgeVerdict(finding_id="F-002", confirmed=True, reasoning="ok", patch=None),
        ],
    )

    _log_to_mlflow(report, SAMPLE_CODE, sample_id="golden-0")

    mock_mlflow.log_params.assert_called_once()
    params = mock_mlflow.log_params.call_args[0][0]
    assert params["sample_id"] == "golden-0"

    mock_mlflow.log_metrics.assert_called_once()
    metrics = mock_mlflow.log_metrics.call_args[0][0]
    assert metrics["findings_count"] == 2
    assert metrics["confirmed_count"] == 1
    assert metrics["false_positive_count"] == 1

    mock_mlflow.log_text.assert_called_once()
