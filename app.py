"""Streamlit dashboard for the LLM Code Security Scanner."""

import json
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from orchestrator.graph import run_pipeline, run_repo_scan
from utils.github import (
    parse_github_url,
    fetch_diffs_for_target,
    fetch_file_content,
    extract_diff_context,
)
from utils.schemas import DebateReport, RepoScanReport

GOLDEN_SET_PATH = "data/golden_set.json"

# ── Page config ──────────────────────────────────────────────────

st.set_page_config(
    page_title="LLM Code Security Scanner",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ LLM Code Security Scanner")
st.caption("Adversarial multi-agent vulnerability detection — Red Team → Blue Team → Judge")

# ── Sidebar ──────────────────────────────────────────────────────

with st.sidebar:
    st.header("⚙️ Settings")
    track_mlflow = st.checkbox("Log to MLflow", value=False)
    st.divider()
    st.markdown(
        "**How it works**\n\n"
        "1. **Red Team** scans for vulnerabilities\n"
        "2. **Blue Team** challenges false positives\n"
        "3. **Judge** delivers final verdicts\n\n"
        "Only findings that survive the adversarial debate are confirmed."
    )

# ── Helper: render a single DebateReport ─────────────────────────


def _severity_color(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
    }.get(severity.lower(), "⚪")


def render_report(report: DebateReport, code: str | None = None):
    """Render a DebateReport with findings, debate, and verdicts."""
    if not report.findings:
        st.success("✅ No vulnerabilities found.")
        return

    confirmed = [v for v in report.verdicts if v.confirmed]
    dismissed = [v for v in report.verdicts if not v.confirmed]

    # ── Summary metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Findings", len(report.findings))
    col2.metric("Confirmed", len(confirmed))
    col3.metric("Dismissed (FP)", len(dismissed))

    st.divider()

    # ── Per-finding detail
    defense_map = {d.finding_id: d for d in report.defenses}
    verdict_map = {v.finding_id: v for v in report.verdicts}

    for finding in report.findings:
        verdict = verdict_map.get(finding.finding_id)
        defense = defense_map.get(finding.finding_id)
        is_confirmed = verdict.confirmed if verdict else True

        badge = "🚨 CONFIRMED" if is_confirmed else "✅ DISMISSED"
        sev = _severity_color(finding.severity)

        with st.expander(
            f"{badge}  {sev} {finding.finding_id} — {finding.cwe_id} {finding.cwe_name}  [{finding.severity}]",
            expanded=is_confirmed,
        ):
            # ── Vulnerable code
            st.markdown("**Vulnerable Code**")
            st.code(finding.vulnerable_code, language="c")

            # ── Debate tabs
            tab_red, tab_blue, tab_judge = st.tabs([
                "🔴 Red Team (Attack)",
                "🔵 Blue Team (Defense)",
                "⚖️ Judge (Verdict)",
            ])

            with tab_red:
                st.markdown(finding.exploit_argument)

            with tab_blue:
                if defense:
                    fp_label = "**Yes — False Positive**" if defense.is_false_positive else "**No — Real Vulnerability**"
                    st.markdown(f"Is False Positive: {fp_label}")
                    st.markdown(defense.counter_argument)
                else:
                    st.caption("No defense submitted.")

            with tab_judge:
                if verdict:
                    status = "**CONFIRMED** ✅" if verdict.confirmed else "**DISMISSED** ❌"
                    st.markdown(f"Verdict: {status}")
                    st.markdown(verdict.reasoning)

                    # Patch display (future-ready)
                    if verdict.patch:
                        st.markdown("**Suggested Fix**")
                        st.code(verdict.patch, language="c")
                    elif verdict.confirmed:
                        st.caption("No suggested fix available yet.")
                else:
                    st.caption("No verdict returned.")

    # ── Verification status
    if report.verification_passed is not None:
        st.divider()
        if report.verification_passed:
            st.success("🛡️ Verification: PASSED — all patches confirmed effective")
        else:
            st.warning("⚠️ Verification: FAILED — some patches may be ineffective")

        if report.verification_results:
            for vr in report.verification_results:
                icon = "✅" if vr.patch_valid else "❌"
                st.markdown(f"  {icon} **{vr.finding_id}**: {vr.reason}")

    # ── Raw JSON (collapsible)
    with st.expander("📄 Full JSON Report"):
        st.json(json.loads(report.model_dump_json()))


# ── Tabs ─────────────────────────────────────────────────────────

tab_code, tab_github, tab_golden = st.tabs([
    "📝 Paste Code",
    "🔗 GitHub PR / Commit",
    "📦 Golden Set Sample",
])

# ═══════════════════════════════════════════════════════════════════
# Tab 1: Paste Code
# ═══════════════════════════════════════════════════════════════════

with tab_code:
    st.subheader("Scan source code")
    code_input = st.text_area(
        "Paste your code below:",
        height=300,
        placeholder="Paste C, Python, JavaScript, or any source code here…",
    )

    if st.button("🔍 Scan Code", key="scan_code", disabled=not code_input.strip()):
        with st.spinner("Running adversarial debate pipeline…"):
            try:
                report = run_pipeline(
                    code_input, track=track_mlflow, sample_id=None
                )
                st.session_state["code_report"] = report
                st.session_state["code_input"] = code_input
            except Exception as e:
                st.error(f"Pipeline error: {e}")

    if "code_report" in st.session_state:
        render_report(
            st.session_state["code_report"],
            st.session_state.get("code_input"),
        )

# ═══════════════════════════════════════════════════════════════════
# Tab 2: GitHub PR / Commit
# ═══════════════════════════════════════════════════════════════════

with tab_github:
    st.subheader("Scan a GitHub pull request or commit")

    col_url, col_token = st.columns([3, 1])
    with col_url:
        github_url = st.text_input(
            "GitHub URL",
            placeholder="https://github.com/owner/repo/pull/123",
        )
    with col_token:
        github_token = st.text_input(
            "Token (optional)",
            type="password",
            placeholder="ghp_…",
            help="For private repos or higher rate limits. Can also set GITHUB_TOKEN env var.",
        )

    if st.button("🔍 Scan Diff", key="scan_diff", disabled=not github_url.strip()):
        try:
            target = parse_github_url(github_url)
        except ValueError as e:
            st.error(str(e))
            st.stop()

        token = github_token or None

        with st.spinner(f"Fetching diff from {target.owner}/{target.repo}…"):
            try:
                diffs = fetch_diffs_for_target(target, token)
            except Exception as e:
                st.error(f"GitHub API error: {e}")
                st.stop()

        if not diffs:
            st.warning("No scannable code files found in this diff.")
            st.stop()

        # Show changed files
        st.info(f"Found **{len(diffs)}** code file(s) with changes")
        for d in diffs:
            st.caption(f"  `{d.filename}` ({d.additions}+ / {d.deletions}-)")

        # Fetch and annotate
        if target.kind == "pr":
            ref = f"pull/{target.pr_number}/head"
        elif target.kind == "commit":
            ref = target.commit_sha
        else:
            ref = target.head_ref

        annotated_codes: dict[str, str] = {}
        for d in diffs:
            try:
                full_code = fetch_file_content(
                    target.owner, target.repo, d.filename, ref, token
                )
                annotated_codes[d.filename] = extract_diff_context(
                    full_code, d.patch
                )
            except Exception:
                pass  # Falls back to raw patch

        with st.spinner("Running adversarial diff scan…"):
            try:
                repo_report = run_repo_scan(
                    diffs,
                    annotated_codes,
                    repo_url=github_url,
                    pr_number=target.pr_number,
                    commit_sha=target.commit_sha,
                    track=track_mlflow,
                )
                st.session_state["repo_report"] = repo_report
            except Exception as e:
                st.error(f"Pipeline error: {e}")

    if "repo_report" in st.session_state:
        repo_report: RepoScanReport = st.session_state["repo_report"]

        # ── Aggregate summary
        st.divider()
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Files Scanned", len(repo_report.file_reports))
        col2.metric("Total Findings", repo_report.total_findings)
        col3.metric("Confirmed", repo_report.total_confirmed)
        col4.metric("Dismissed (FP)", repo_report.total_dismissed)

        # ── Per-file results
        for fr in repo_report.file_reports:
            st.divider()
            confirmed_count = sum(
                1 for v in fr.report.verdicts if v.confirmed
            )
            lang_label = fr.language or "unknown"
            st.subheader(f"📄 {fr.filename}  ({lang_label})")
            st.caption(
                f"{len(fr.report.findings)} finding(s), "
                f"{confirmed_count} confirmed"
            )
            render_report(fr.report)

        # ── Full JSON
        with st.expander("📄 Full Repo Scan Report (JSON)"):
            st.json(json.loads(repo_report.model_dump_json()))

# ═══════════════════════════════════════════════════════════════════
# Tab 3: Golden Set
# ═══════════════════════════════════════════════════════════════════

with tab_golden:
    st.subheader("Scan a golden set sample")
    st.caption(
        "30 curated C code samples (6 CWEs × 5 each) from the CASTLE dataset. "
        "Each sample has a known ground-truth label."
    )

    try:
        with open(GOLDEN_SET_PATH, "r", encoding="utf-8") as f:
            samples = json.load(f)
    except FileNotFoundError:
        st.error(f"Golden set not found: {GOLDEN_SET_PATH}")
        st.stop()

    # Build selection options
    options = []
    for i, s in enumerate(samples):
        vuln = "🔴 VULNERABLE" if s["has_vulnerability"] else "🟢 SAFE"
        options.append(f"[{i}] {s['id']} — {s['cwe_id']} {s['cwe_name']} ({vuln})")

    selected = st.selectbox("Select a sample:", options)
    idx = int(selected.split("]")[0].strip("["))
    sample = samples[idx]

    # Show sample metadata
    col1, col2, col3 = st.columns(3)
    col1.markdown(f"**CWE:** {sample['cwe_id']}")
    col2.markdown(f"**Name:** {sample['name']}")
    vuln_label = "🔴 Vulnerable" if sample["has_vulnerability"] else "🟢 Safe"
    col3.markdown(f"**Ground Truth:** {vuln_label}")

    with st.expander("View source code", expanded=False):
        st.code(sample["code"], language="c")

    if st.button("🔍 Scan Sample", key="scan_golden"):
        with st.spinner("Running adversarial debate pipeline…"):
            try:
                report = run_pipeline(
                    sample["code"],
                    track=track_mlflow,
                    sample_id=sample["id"],
                )
                st.session_state["golden_report"] = report
                st.session_state["golden_sample"] = sample
            except Exception as e:
                st.error(f"Pipeline error: {e}")

    if "golden_report" in st.session_state:
        report = st.session_state["golden_report"]
        sample_data = st.session_state["golden_sample"]

        # ── Ground truth comparison
        confirmed = any(v.confirmed for v in report.verdicts)
        has_vuln = sample_data["has_vulnerability"]

        if confirmed and has_vuln:
            st.success("✅ **True Positive** — correctly identified the vulnerability")
        elif not confirmed and not has_vuln:
            st.success("✅ **True Negative** — correctly cleared safe code")
        elif confirmed and not has_vuln:
            st.error("❌ **False Positive** — flagged safe code as vulnerable")
        else:
            st.warning("⚠️ **False Negative** — missed a known vulnerability")

        render_report(report, sample_data["code"])
