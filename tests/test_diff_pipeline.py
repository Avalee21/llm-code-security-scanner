"""Tests for the diff-aware pipeline and repo scan orchestration."""

from unittest.mock import patch, MagicMock

from orchestrator.graph import run_diff_pipeline, run_repo_scan
from utils.schemas import (
    BlueTeamDefense,
    DebateReport,
    FileDiff,
    FileReport,
    JudgeVerdict,
    RedTeamFinding,
    RepoScanReport,
)


def _finding(fid="F-001"):
    return RedTeamFinding(
        finding_id=fid,
        cwe_id="CWE-120",
        cwe_name="Buffer Copy without Checking Size of Input",
        severity="high",
        vulnerable_code="strcpy(buf, argv[1]);",
        exploit_argument="Attacker provides long argv[1] to overflow buf.",
    )


def _defense(fid="F-001"):
    return BlueTeamDefense(
        finding_id=fid,
        is_false_positive=False,
        counter_argument="No bounds checking on buf.",
    )


def _verdict(fid="F-001", confirmed=True):
    return JudgeVerdict(
        finding_id=fid,
        confirmed=confirmed,
        reasoning="strcpy with unchecked input is exploitable.",
        patch=None,
    )


# ── Schema tests ────────────────────────────────────────────────


class TestDiffSchemas:
    def test_file_diff_creation(self):
        fd = FileDiff(
            filename="main.c",
            status="modified",
            patch="+line",
            additions=1,
            deletions=0,
            added_lines=["line"],
        )
        assert fd.filename == "main.c"
        assert fd.additions == 1

    def test_file_report_creation(self):
        report = DebateReport(
            findings=[_finding()],
            defenses=[_defense()],
            verdicts=[_verdict()],
        )
        fr = FileReport(filename="main.c", language="c", report=report)
        assert fr.filename == "main.c"
        assert len(fr.report.findings) == 1

    def test_repo_scan_report_creation(self):
        report = DebateReport(
            findings=[_finding()],
            defenses=[_defense()],
            verdicts=[_verdict()],
        )
        rsr = RepoScanReport(
            repo_url="https://github.com/owner/repo/pull/1",
            pr_number=1,
            file_reports=[
                FileReport(filename="main.c", report=report),
            ],
            total_findings=1,
            total_confirmed=1,
            total_dismissed=0,
        )
        assert rsr.pr_number == 1
        assert rsr.total_confirmed == 1

    def test_repo_scan_report_json_roundtrip(self):
        report = DebateReport(
            findings=[_finding()],
            defenses=[_defense()],
            verdicts=[_verdict()],
        )
        rsr = RepoScanReport(
            repo_url="https://github.com/owner/repo/pull/1",
            file_reports=[
                FileReport(filename="main.c", report=report),
            ],
            total_findings=1,
            total_confirmed=1,
        )
        json_str = rsr.model_dump_json()
        rsr2 = RepoScanReport.model_validate_json(json_str)
        assert rsr2.total_findings == 1
        assert rsr2.file_reports[0].filename == "main.c"


# ── Diff pipeline tests ────────────────────────────────────────


class TestRunDiffPipeline:
    @patch("orchestrator.graph.run_judge_diff")
    @patch("orchestrator.graph.run_blue_team_diff")
    @patch("orchestrator.graph.run_red_team_diff")
    def test_returns_debate_report(self, mock_red, mock_blue, mock_judge):
        mock_red.return_value = [_finding()]
        mock_blue.return_value = [_defense()]
        mock_judge.return_value = [_verdict()]

        report = run_diff_pipeline("code", "main.c")

        assert isinstance(report, DebateReport)
        assert len(report.findings) == 1
        assert len(report.verdicts) == 1

    @patch("orchestrator.graph.run_judge_diff")
    @patch("orchestrator.graph.run_blue_team_diff")
    @patch("orchestrator.graph.run_red_team_diff")
    def test_passes_filename_to_agents(self, mock_red, mock_blue, mock_judge):
        mock_red.return_value = []
        mock_blue.return_value = []
        mock_judge.return_value = []

        run_diff_pipeline("code", "src/app.py")

        mock_red.assert_called_once_with("code", "src/app.py")
        mock_blue.assert_called_once_with([], "code", "src/app.py")
        mock_judge.assert_called_once_with([], [], "code", "src/app.py")

    @patch("orchestrator.graph.run_judge_diff")
    @patch("orchestrator.graph.run_blue_team_diff")
    @patch("orchestrator.graph.run_red_team_diff")
    def test_no_findings(self, mock_red, mock_blue, mock_judge):
        mock_red.return_value = []
        mock_blue.return_value = []
        mock_judge.return_value = []

        report = run_diff_pipeline("safe code", "safe.c")

        assert len(report.findings) == 0
        assert len(report.verdicts) == 0


# ── Repo scan tests ────────────────────────────────────────────


class TestRunRepoScan:
    @patch("orchestrator.graph.run_diff_pipeline")
    @patch("orchestrator.graph.mlflow")
    def test_scans_all_files(self, mock_mlflow, mock_pipeline):
        mock_pipeline.return_value = DebateReport(
            findings=[_finding()],
            defenses=[_defense()],
            verdicts=[_verdict()],
        )

        diffs = [
            FileDiff(filename="a.c", status="modified", patch="+x",
                     additions=1, deletions=0, added_lines=["x"]),
            FileDiff(filename="b.py", status="added", patch="+y",
                     additions=1, deletions=0, added_lines=["y"]),
        ]
        annotated = {"a.c": "annotated_a", "b.py": "annotated_b"}

        result = run_repo_scan(
            diffs, annotated,
            repo_url="https://github.com/o/r/pull/1",
            pr_number=1,
            track=False,
        )

        assert isinstance(result, RepoScanReport)
        assert len(result.file_reports) == 2
        assert result.total_findings == 2
        assert result.total_confirmed == 2

    @patch("orchestrator.graph.run_diff_pipeline")
    @patch("orchestrator.graph.mlflow")
    def test_falls_back_to_patch_when_no_annotated(self, mock_mlflow, mock_pipeline):
        mock_pipeline.return_value = DebateReport(
            findings=[], defenses=[], verdicts=[],
        )

        diffs = [
            FileDiff(filename="x.c", status="modified", patch="+hello",
                     additions=1, deletions=0, added_lines=["hello"]),
        ]
        # No annotated code provided for x.c
        annotated = {}

        run_repo_scan(
            diffs, annotated,
            repo_url="https://github.com/o/r/pull/1",
            track=False,
        )

        # Pipeline should have been called with the raw patch as fallback
        mock_pipeline.assert_called_once_with("+hello", "x.c")

    @patch("orchestrator.graph.run_diff_pipeline")
    @patch("orchestrator.graph.mlflow")
    def test_empty_diffs_returns_empty_report(self, mock_mlflow, mock_pipeline):
        result = run_repo_scan(
            [], {},
            repo_url="https://github.com/o/r/pull/1",
            track=False,
        )

        assert len(result.file_reports) == 0
        assert result.total_findings == 0
        mock_pipeline.assert_not_called()
