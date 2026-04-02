import json
from unittest.mock import MagicMock, patch

from agents.cwe_classifier import run_cwe_classifier, run_cwe_classifier_diff
from utils.schemas import RedTeamFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(finding_id: str, cwe_id: str = "CWE-22", cwe_name: str = "Path Traversal") -> RedTeamFinding:
    return RedTeamFinding(
        finding_id=finding_id,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        severity="high",
        vulnerable_code="open(user_input)",
        exploit_argument="user_input is unsanitized",
    )


def _mock_response(payload: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.content = json.dumps(payload)
    return mock


def _run_with_mock(findings, code, payload):
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = _mock_response(payload)

    with patch("agents.cwe_classifier.get_llm"), \
         patch("agents.cwe_classifier.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        return run_cwe_classifier(findings, code)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_classifier_corrects_wrong_cwe():
    """Classifier changes CWE-22 to CWE-89 when the finding is SQL Injection."""
    findings = [_finding("F-001", "CWE-22", "Path Traversal")]
    payload = [{"finding_id": "F-001", "cwe_id": "CWE-89", "cwe_name": "SQL Injection"}]

    result = _run_with_mock(findings, "SELECT * FROM t WHERE id=" + "x", payload)

    assert len(result) == 1
    assert result[0].cwe_id == "CWE-89"
    assert result[0].cwe_name == "SQL Injection"


def test_classifier_keeps_correct_cwe():
    """Classifier leaves CWE unchanged when already correct."""
    findings = [_finding("F-001", "CWE-89", "SQL Injection")]
    payload = [{"finding_id": "F-001", "cwe_id": "CWE-89", "cwe_name": "SQL Injection"}]

    result = _run_with_mock(findings, "some code", payload)

    assert result[0].cwe_id == "CWE-89"
    assert result[0].original_cwe_id is None  # no correction made


def test_empty_findings_returns_empty():
    """Empty input returns empty list without calling the LLM."""
    with patch("agents.cwe_classifier.get_llm") as mock_get_llm:
        result = run_cwe_classifier([], "some code")
        mock_get_llm.assert_not_called()
    assert result == []


def test_original_cwe_id_preserved_on_correction():
    """original_cwe_id is set to the Red Team's original CWE when corrected."""
    findings = [_finding("F-001", "CWE-22", "Path Traversal")]
    payload = [{"finding_id": "F-001", "cwe_id": "CWE-78", "cwe_name": "OS Command Injection"}]

    result = _run_with_mock(findings, "some code", payload)

    assert result[0].original_cwe_id == "CWE-22"


def test_markdown_fence_stripping():
    """Classifier handles JSON wrapped in markdown code fences."""
    findings = [_finding("F-001", "CWE-22", "Path Traversal")]
    payload = [{"finding_id": "F-001", "cwe_id": "CWE-89", "cwe_name": "SQL Injection"}]

    mock_chain = MagicMock()
    fenced = "```json\n" + json.dumps(payload) + "\n```"
    mock_chain.invoke.return_value = MagicMock(content=fenced)

    with patch("agents.cwe_classifier.get_llm"), \
         patch("agents.cwe_classifier.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        result = run_cwe_classifier(findings, "code")

    assert result[0].cwe_id == "CWE-89"


def test_multiple_findings_only_wrong_corrected():
    """Only misclassified findings are updated; correct ones are left alone."""
    findings = [
        _finding("F-001", "CWE-22", "Path Traversal"),   # wrong
        _finding("F-002", "CWE-89", "SQL Injection"),     # correct
    ]
    payload = [
        {"finding_id": "F-001", "cwe_id": "CWE-78", "cwe_name": "OS Command Injection"},
        {"finding_id": "F-002", "cwe_id": "CWE-89", "cwe_name": "SQL Injection"},
    ]

    result = _run_with_mock(findings, "some code", payload)

    assert result[0].cwe_id == "CWE-78"
    assert result[0].original_cwe_id == "CWE-22"
    assert result[1].cwe_id == "CWE-89"
    assert result[1].original_cwe_id is None


def test_diff_variant_empty_findings():
    """run_cwe_classifier_diff returns empty list for empty findings."""
    with patch("agents.cwe_classifier.get_llm") as mock_get_llm:
        result = run_cwe_classifier_diff([], "diff code", "file.c")
        mock_get_llm.assert_not_called()
    assert result == []
