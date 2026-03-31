"""GitHub integration — fetch PR / commit diffs via the REST API."""

import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests

from utils.schemas import FileDiff

# ── URL parsing ─────────────────────────────────────────────────

# Supported URL formats:
#   https://github.com/owner/repo/pull/123
#   https://github.com/owner/repo/commit/abc123
#   https://github.com/owner/repo/compare/base...head

_PR_RE = re.compile(
    r"github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)"
)
_COMMIT_RE = re.compile(
    r"github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-f]{7,40})"
)
_COMPARE_RE = re.compile(
    r"github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/compare/(?P<base>[^.]+)\.\.\.(?P<head>[^/?#]+)"
)


@dataclass
class GitHubTarget:
    owner: str
    repo: str
    kind: str  # "pr" | "commit" | "compare"
    pr_number: Optional[int] = None
    commit_sha: Optional[str] = None
    base_ref: Optional[str] = None
    head_ref: Optional[str] = None


def parse_github_url(url: str) -> GitHubTarget:
    """Parse a GitHub PR, commit, or compare URL into a structured target."""
    m = _PR_RE.search(url)
    if m:
        return GitHubTarget(
            owner=m.group("owner"),
            repo=m.group("repo"),
            kind="pr",
            pr_number=int(m.group("number")),
        )

    m = _COMMIT_RE.search(url)
    if m:
        return GitHubTarget(
            owner=m.group("owner"),
            repo=m.group("repo"),
            kind="commit",
            commit_sha=m.group("sha"),
        )

    m = _COMPARE_RE.search(url)
    if m:
        return GitHubTarget(
            owner=m.group("owner"),
            repo=m.group("repo"),
            kind="compare",
            base_ref=m.group("base"),
            head_ref=m.group("head"),
        )

    raise ValueError(
        f"Unsupported GitHub URL format: {url}\n"
        "Expected: .../pull/<N>, .../commit/<SHA>, or .../compare/<base>...<head>"
    )


# ── API helpers ─────────────────────────────────────────────────

API_BASE = "https://api.github.com"

# Extensions we consider scannable source code
_CODE_EXTENSIONS = frozenset({
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".py", ".pyw",
    ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".java", ".kt", ".kts",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".scala",
    ".sh", ".bash",
    ".sql",
    ".sol",  # Solidity
})

MAX_CHANGED_LINES = 500  # Skip files with too many changes (LLM context limit)


def _headers(token: Optional[str] = None) -> dict[str, str]:
    token = token or os.getenv("GITHUB_TOKEN")
    h: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get_json(url: str, token: Optional[str] = None) -> dict | list:
    resp = requests.get(url, headers=_headers(token), timeout=30)
    resp.raise_for_status()
    return resp.json()


# ── Diff parsing ────────────────────────────────────────────────


def _parse_added_lines(patch: str) -> list[str]:
    """Extract content of added/changed lines from a unified diff patch."""
    lines = []
    for raw_line in patch.splitlines():
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            lines.append(raw_line[1:])  # strip leading '+'
    return lines


def _is_code_file(filename: str) -> bool:
    """Return True if the file extension looks like scannable source code."""
    _, ext = os.path.splitext(filename)
    return ext.lower() in _CODE_EXTENSIONS


# ── Public API ──────────────────────────────────────────────────


def fetch_pr_diffs(
    owner: str,
    repo: str,
    pr_number: int,
    token: Optional[str] = None,
) -> list[FileDiff]:
    """Fetch per-file diffs for a GitHub pull request."""
    url = f"{API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/files"
    # Paginate (GitHub returns max 30 files per page by default, 100 max)
    all_files: list[dict] = []
    page = 1
    while True:
        data = _get_json(f"{url}?per_page=100&page={page}", token)
        if not data:
            break
        all_files.extend(data)
        if len(data) < 100:
            break
        page += 1

    return _files_to_diffs(all_files)


def fetch_commit_diffs(
    owner: str,
    repo: str,
    commit_sha: str,
    token: Optional[str] = None,
) -> list[FileDiff]:
    """Fetch per-file diffs for a single commit."""
    url = f"{API_BASE}/repos/{owner}/{repo}/commits/{commit_sha}"
    data = _get_json(url, token)
    return _files_to_diffs(data.get("files", []))


def fetch_compare_diffs(
    owner: str,
    repo: str,
    base: str,
    head: str,
    token: Optional[str] = None,
) -> list[FileDiff]:
    """Fetch per-file diffs for a compare range."""
    url = f"{API_BASE}/repos/{owner}/{repo}/compare/{base}...{head}"
    data = _get_json(url, token)
    return _files_to_diffs(data.get("files", []))


def fetch_file_content(
    owner: str,
    repo: str,
    path: str,
    ref: str,
    token: Optional[str] = None,
) -> str:
    """Fetch raw file content at a specific ref (branch/tag/SHA)."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    resp = requests.get(url, headers=_headers(token), timeout=30)
    resp.raise_for_status()
    return resp.text


def fetch_diffs_for_target(
    target: GitHubTarget,
    token: Optional[str] = None,
) -> list[FileDiff]:
    """Dispatch to the right fetch function based on the parsed target."""
    if target.kind == "pr":
        return fetch_pr_diffs(target.owner, target.repo, target.pr_number, token)
    elif target.kind == "commit":
        return fetch_commit_diffs(target.owner, target.repo, target.commit_sha, token)
    elif target.kind == "compare":
        return fetch_compare_diffs(
            target.owner, target.repo, target.base_ref, target.head_ref, token
        )
    raise ValueError(f"Unknown target kind: {target.kind}")


# ── Internal helpers ────────────────────────────────────────────


def _files_to_diffs(files: list[dict]) -> list[FileDiff]:
    """Convert GitHub API file objects to FileDiff models, filtering non-code files."""
    diffs: list[FileDiff] = []
    for f in files:
        filename = f.get("filename", "")
        status = f.get("status", "modified")
        patch = f.get("patch", "")

        # Skip non-code files
        if not _is_code_file(filename):
            continue
        # Skip removed files (nothing to scan)
        if status == "removed":
            continue
        # Skip files with too many changes
        additions = f.get("additions", 0)
        deletions = f.get("deletions", 0)
        if additions + deletions > MAX_CHANGED_LINES:
            continue

        diffs.append(FileDiff(
            filename=filename,
            status=status,
            patch=patch,
            additions=additions,
            deletions=deletions,
            added_lines=_parse_added_lines(patch),
        ))
    return diffs


def _parse_hunk_line_numbers(patch: str) -> set[int]:
    """Parse a unified diff patch and return the set of added line numbers in the new file."""
    added_line_nums: set[int] = set()
    current_line = 0
    for raw_line in patch.splitlines():
        hunk_match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_line)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added_line_nums.add(current_line)
            current_line += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            pass
        else:
            current_line += 1
    return added_line_nums


def annotate_code_with_diff(full_code: str, patch: str) -> str:
    """Annotate full file content with markers showing which lines were changed.

    Returns the full file with >>> CHANGED markers on modified/added lines,
    giving agents full context while highlighting the diff.
    """
    if not patch:
        return full_code

    added_line_nums = _parse_hunk_line_numbers(patch)

    lines = full_code.splitlines()
    annotated = []
    for i, line in enumerate(lines, start=1):
        if i in added_line_nums:
            annotated.append(f"{line}  // >>> CHANGED")
        else:
            annotated.append(line)
    return "\n".join(annotated)


# Default number of context lines above/below each changed hunk
CONTEXT_LINES = 15

# If the full file is shorter than this, send the whole annotated file instead
SMALL_FILE_THRESHOLD = 150


def extract_diff_context(
    full_code: str,
    patch: str,
    *,
    context_lines: int = CONTEXT_LINES,
) -> str:
    """Extract only the changed hunks with surrounding context from a file.

    Instead of sending the entire file (which can be thousands of lines),
    this returns a compact view: each changed region plus *context_lines*
    lines above and below, separated by ``... (lines N-M omitted) ...``
    markers.  Changed lines are tagged with ``// >>> CHANGED``.

    If the file is small (≤ SMALL_FILE_THRESHOLD lines), falls back to
    the full annotated file since the savings would be negligible.
    """
    if not patch or not full_code:
        return full_code or ""

    lines = full_code.splitlines()

    # For small files, send the whole thing annotated
    if len(lines) <= SMALL_FILE_THRESHOLD:
        return annotate_code_with_diff(full_code, patch)

    added_line_nums = _parse_hunk_line_numbers(patch)
    if not added_line_nums:
        return full_code

    # Build a set of line numbers to include (changed lines + context)
    include: set[int] = set()
    for ln in added_line_nums:
        for ctx in range(ln - context_lines, ln + context_lines + 1):
            if 1 <= ctx <= len(lines):
                include.add(ctx)

    # Render the compact view with omission markers
    result: list[str] = []
    prev_included = 0  # last line number we emitted

    for i in sorted(include):
        # If there's a gap, insert an omission marker
        if i > prev_included + 1 and prev_included > 0:
            omitted_start = prev_included + 1
            omitted_end = i - 1
            result.append(
                f"... (lines {omitted_start}-{omitted_end} omitted) ..."
            )

        line = lines[i - 1]  # 0-indexed list, 1-indexed line numbers
        if i in added_line_nums:
            result.append(f"{line}  // >>> CHANGED")
        else:
            result.append(line)
        prev_included = i

    # Trailing omission marker if we didn't include the end of the file
    if prev_included < len(lines):
        result.append(
            f"... (lines {prev_included + 1}-{len(lines)} omitted) ..."
        )

    # Leading omission marker if we didn't start from line 1
    first_included = min(include)
    if first_included > 1:
        result.insert(0, f"... (lines 1-{first_included - 1} omitted) ...")

    return "\n".join(result)
