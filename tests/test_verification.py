import json
from unittest.mock import MagicMock, patch

from agents.red_team import run_verification
from utils.schemas import (
    JudgeVerdict,
    RedTeamFinding,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(finding_id: str = "F-001") -> RedTeamFinding:
    return RedTeamFinding(
        finding_id=finding_id,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        severity="high",
        vulnerable_code="cursor.execute('SELECT * FROM users WHERE id=' + uid)",
        exploit_argument="uid is unsanitized",
    )


def _verdict(finding_id: str = "F-001", confirmed: bool = True, patch_code: str | None = None) -> JudgeVerdict:
    return JudgeVerdict(
        finding_id=finding_id,
        confirmed=confirmed,
        reasoning="Test reasoning",
        patch=patch_code,
    )


def _mock_response(payload: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.content = json.dumps(payload)
    return mock


def _run_verification_with_mock(code, verdicts, findings, payload):
    """Run run_verification with a mocked LLM."""
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = _mock_response(payload)

    with patch("agents.red_team.get_llm"), \
         patch("agents.red_team.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        return run_verification(code, verdicts, findings)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_verification_all_patches_valid():
    """All patches verified as valid → verification_passed = True."""
    verdicts = [_verdict("F-001", confirmed=True, patch_code="safe_code()")]
    findings = [_finding("F-001")]
    payload = [{"finding_id": "F-001", "patch_valid": True, "reason": "Patch uses parameterized query"}]

    passed, results = _run_verification_with_mock("def foo(): pass", verdicts, findings, payload)

    assert passed is True
    assert len(results) == 1
    assert isinstance(results[0], VerificationResult)
    assert results[0].patch_valid is True


def test_verification_some_patches_invalid():
    """One invalid patch → verification_passed = False."""
    verdicts = [
        _verdict("F-001", confirmed=True, patch_code="safe_code()"),
        _verdict("F-002", confirmed=True, patch_code="still_bad()"),
    ]
    findings = [_finding("F-001"), _finding("F-002")]
    payload = [
        {"finding_id": "F-001", "patch_valid": True, "reason": "Fix is correct"},
        {"finding_id": "F-002", "patch_valid": False, "reason": "Still vulnerable to injection"},
    ]

    passed, results = _run_verification_with_mock("def foo(): pass", verdicts, findings, payload)

    assert passed is False
    assert len(results) == 2
    assert results[0].patch_valid is True
    assert results[1].patch_valid is False


def test_verification_no_patches_returns_none():
    """No confirmed verdicts with patches → skip verification."""
    verdicts = [_verdict("F-001", confirmed=False, patch_code=None)]
    findings = [_finding("F-001")]

    passed, results = run_verification("def foo(): pass", verdicts, findings)

    assert passed is None
    assert results == []


def test_verification_confirmed_but_no_patch_skipped():
    """Confirmed verdict without a patch → skip verification."""
    verdicts = [_verdict("F-001", confirmed=True, patch_code=None)]
    findings = [_finding("F-001")]

    passed, results = run_verification("def foo(): pass", verdicts, findings)

    assert passed is None
    assert results == []


def test_verification_mixed_verdicts_only_checks_patched():
    """Only confirmed verdicts with patches are verified."""
    verdicts = [
        _verdict("F-001", confirmed=True, patch_code="fixed()"),
        _verdict("F-002", confirmed=False, patch_code=None),  # dismissed, skipped
        _verdict("F-003", confirmed=True, patch_code=None),   # no patch, skipped
    ]
    findings = [_finding("F-001"), _finding("F-002"), _finding("F-003")]
    payload = [{"finding_id": "F-001", "patch_valid": True, "reason": "Patch is effective"}]

    passed, results = _run_verification_with_mock("def foo(): pass", verdicts, findings, payload)

    assert passed is True
    assert len(results) == 1
    assert results[0].finding_id == "F-001"


def test_verification_markdown_fence_stripped():
    """LLM response wrapped in markdown fences is handled correctly."""
    verdicts = [_verdict("F-001", confirmed=True, patch_code="safe()")]
    findings = [_finding("F-001")]
    raw_payload = [{"finding_id": "F-001", "patch_valid": True, "reason": "OK"}]
    fenced = "```json\n" + json.dumps(raw_payload) + "\n```"

    mock_response = MagicMock()
    mock_response.content = fenced
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = mock_response

    with patch("agents.red_team.get_llm"), \
         patch("agents.red_team.ChatPromptTemplate") as mock_prompt_cls:
        mock_prompt_cls.from_messages.return_value.__or__ = lambda self, other: mock_chain
        passed, results = run_verification("def foo(): pass", verdicts, findings)

    assert passed is True
    assert len(results) == 1
