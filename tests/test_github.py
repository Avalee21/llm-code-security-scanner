"""Tests for utils/github.py — URL parsing, diff parsing, code annotation."""

import pytest
from utils.github import (
    parse_github_url,
    GitHubTarget,
    _parse_added_lines,
    _parse_hunk_line_numbers,
    _is_code_file,
    annotate_code_with_diff,
    extract_diff_context,
    SMALL_FILE_THRESHOLD,
    _files_to_diffs,
)


# ── URL parsing ─────────────────────────────────────────────────


class TestParseGitHubUrl:
    def test_pr_url(self):
        t = parse_github_url("https://github.com/octocat/hello-world/pull/42")
        assert t.kind == "pr"
        assert t.owner == "octocat"
        assert t.repo == "hello-world"
        assert t.pr_number == 42

    def test_commit_url(self):
        t = parse_github_url(
            "https://github.com/octocat/hello-world/commit/abc1234def5678"
        )
        assert t.kind == "commit"
        assert t.owner == "octocat"
        assert t.repo == "hello-world"
        assert t.commit_sha == "abc1234def5678"

    def test_compare_url(self):
        t = parse_github_url(
            "https://github.com/octocat/hello-world/compare/main...feature-branch"
        )
        assert t.kind == "compare"
        assert t.owner == "octocat"
        assert t.repo == "hello-world"
        assert t.base_ref == "main"
        assert t.head_ref == "feature-branch"

    def test_pr_url_with_trailing_path(self):
        t = parse_github_url(
            "https://github.com/owner/repo/pull/99/files"
        )
        assert t.kind == "pr"
        assert t.pr_number == 99

    def test_commit_url_short_sha(self):
        t = parse_github_url(
            "https://github.com/owner/repo/commit/abc1234"
        )
        assert t.kind == "commit"
        assert t.commit_sha == "abc1234"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="Unsupported GitHub URL"):
            parse_github_url("https://github.com/owner/repo")

    def test_non_github_url_raises(self):
        with pytest.raises(ValueError, match="Unsupported GitHub URL"):
            parse_github_url("https://gitlab.com/owner/repo/pull/1")


# ── Diff parsing ────────────────────────────────────────────────


SAMPLE_PATCH = """\
@@ -10,6 +10,8 @@ int main() {
     int x = 0;
     int y = 1;
+    char *buf = malloc(100);
+    strcpy(buf, argv[1]);
     printf("hello");
     return 0;
 }"""


class TestParseAddedLines:
    def test_extracts_added_lines(self):
        lines = _parse_added_lines(SAMPLE_PATCH)
        assert len(lines) == 2
        assert "char *buf = malloc(100);" in lines[0]
        assert "strcpy(buf, argv[1]);" in lines[1]

    def test_empty_patch(self):
        assert _parse_added_lines("") == []

    def test_ignores_removed_lines(self):
        patch = "@@ -1,3 +1,2 @@\n-old line\n context\n+new line"
        lines = _parse_added_lines(patch)
        assert len(lines) == 1
        assert lines[0] == "new line"

    def test_ignores_header_plus(self):
        patch = "--- a/file.c\n+++ b/file.c\n@@ -1,2 +1,3 @@\n line\n+added"
        lines = _parse_added_lines(patch)
        assert len(lines) == 1
        assert lines[0] == "added"


# ── Code file detection ─────────────────────────────────────────


class TestIsCodeFile:
    @pytest.mark.parametrize("name", [
        "main.c", "app.py", "index.js", "Server.java", "lib.rs",
        "handler.go", "util.cpp", "query.sql", "contract.sol",
    ])
    def test_code_files_accepted(self, name):
        assert _is_code_file(name) is True

    @pytest.mark.parametrize("name", [
        "README.md", "data.json", "config.yml", "image.png",
        "Makefile", "LICENSE", ".gitignore",
    ])
    def test_non_code_files_rejected(self, name):
        assert _is_code_file(name) is False


# ── Code annotation ─────────────────────────────────────────────


class TestAnnotateCodeWithDiff:
    def test_marks_added_lines(self):
        full_code = (
            "int main() {\n"
            "    int x = 0;\n"
            "    int y = 1;\n"
            "    char *buf = malloc(100);\n"
            "    strcpy(buf, argv[1]);\n"
            "    printf(\"hello\");\n"
            "    return 0;\n"
            "}"
        )
        patch = (
            "@@ -1,6 +1,8 @@\n"
            " int main() {\n"
            "     int x = 0;\n"
            "     int y = 1;\n"
            "+    char *buf = malloc(100);\n"
            "+    strcpy(buf, argv[1]);\n"
            "     printf(\"hello\");\n"
            "     return 0;\n"
            " }"
        )
        result = annotate_code_with_diff(full_code, patch)
        lines = result.splitlines()
        assert "// >>> CHANGED" in lines[3]  # char *buf line
        assert "// >>> CHANGED" in lines[4]  # strcpy line
        assert "// >>> CHANGED" not in lines[0]  # int main line
        assert "// >>> CHANGED" not in lines[5]  # printf line

    def test_empty_patch_returns_original(self):
        code = "int main() { return 0; }"
        assert annotate_code_with_diff(code, "") == code

    def test_no_patch_returns_original(self):
        code = "print('hello')"
        assert annotate_code_with_diff(code, "") == code


# ── _files_to_diffs filtering ───────────────────────────────────


class TestFilesToDiffs:
    def test_filters_non_code_files(self):
        files = [
            {"filename": "main.py", "status": "modified", "patch": "+x=1",
             "additions": 1, "deletions": 0},
            {"filename": "README.md", "status": "modified", "patch": "+hello",
             "additions": 1, "deletions": 0},
        ]
        diffs = _files_to_diffs(files)
        assert len(diffs) == 1
        assert diffs[0].filename == "main.py"

    def test_filters_removed_files(self):
        files = [
            {"filename": "old.py", "status": "removed", "patch": "-x=1",
             "additions": 0, "deletions": 1},
        ]
        assert _files_to_diffs(files) == []

    def test_filters_large_diffs(self):
        files = [
            {"filename": "huge.py", "status": "modified", "patch": "+x",
             "additions": 300, "deletions": 300},  # 600 > MAX_CHANGED_LINES
        ]
        assert _files_to_diffs(files) == []

    def test_keeps_added_files(self):
        files = [
            {"filename": "new.py", "status": "added", "patch": "+x=1",
             "additions": 1, "deletions": 0},
        ]
        diffs = _files_to_diffs(files)
        assert len(diffs) == 1
        assert diffs[0].status == "added"


# ── Compact diff context extraction ─────────────────────────────


class TestExtractDiffContext:
    """Tests for extract_diff_context — the compact, token-efficient mode."""

    def _make_large_file(self, num_lines: int = 300) -> str:
        """Generate a large file where each line is 'line_<N>'."""
        return "\n".join(f"line_{i}" for i in range(1, num_lines + 1))

    def test_small_file_returns_full_annotated(self):
        """Files ≤ SMALL_FILE_THRESHOLD should fall through to full annotation."""
        code = "\n".join(f"line_{i}" for i in range(1, SMALL_FILE_THRESHOLD + 1))
        patch = "@@ -5,0 +5,1 @@\n+new_line"
        result = extract_diff_context(code, patch)
        # Should contain ALL lines, not omission markers
        assert "omitted" not in result
        assert "// >>> CHANGED" in result

    def test_large_file_omits_distant_lines(self):
        """For large files, lines far from the diff should be omitted."""
        code = self._make_large_file(300)
        # Change at line 150 — lines 1-134 and 166-300 should be omitted
        patch = "@@ -149,3 +149,4 @@\n context\n+new_code_here\n context"
        result = extract_diff_context(code, patch)
        assert "omitted" in result
        assert "// >>> CHANGED" in result
        # The changed line content should be present
        assert "new_code_here" not in result  # new_code_here is in the patch, not the file
        # But surrounding file lines should be present
        assert "line_150" in result

    def test_changed_lines_marked(self):
        """Changed lines should have the >>> CHANGED annotation."""
        code = self._make_large_file(200)
        patch = "@@ -100,2 +100,3 @@\n context\n+inserted_line\n context"
        result = extract_diff_context(code, patch)
        changed_lines = [l for l in result.splitlines() if ">>> CHANGED" in l]
        assert len(changed_lines) >= 1

    def test_context_lines_included(self):
        """Lines within the context window around the change should be present."""
        code = self._make_large_file(300)
        # Change at line 150
        patch = "@@ -150,1 +150,2 @@\n context\n+added_stuff"
        result = extract_diff_context(code, patch, context_lines=10)
        # Lines 140-160 should be present (150 ± 10)
        for i in range(141, 161):
            assert f"line_{i}" in result
        # Line 100 should NOT be present (too far)
        assert "line_100" not in result

    def test_empty_patch_returns_original(self):
        code = "int main() { return 0; }"
        assert extract_diff_context(code, "") == code

    def test_empty_code_returns_empty(self):
        assert extract_diff_context("", "+added") == ""

    def test_multiple_hunks_both_included(self):
        """Changes in different parts of the file should both appear."""
        code = self._make_large_file(300)
        patch = (
            "@@ -50,2 +50,3 @@\n context\n+change_at_50\n context\n"
            "@@ -250,2 +251,3 @@\n context\n+change_at_250\n context"
        )
        result = extract_diff_context(code, patch, context_lines=5)
        # Both regions should be present
        assert "line_50" in result
        assert "line_250" in result
        # Middle should be omitted
        assert "line_150" not in result

    def test_custom_context_lines(self):
        """context_lines parameter should control the window size."""
        code = self._make_large_file(300)
        patch = "@@ -150,1 +150,2 @@\n context\n+added"
        # With 3 context lines, only lines 147-153 should be included
        result = extract_diff_context(code, patch, context_lines=3)
        assert "line_148" in result
        assert "line_152" in result
        assert "line_140" not in result
