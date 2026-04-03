"""Streamlit dashboard for the LLM Code Security Scanner."""

import json
from datetime import datetime, timezone

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

import mlflow
from mlflow.tracking import MlflowClient

from orchestrator.graph import run_pipeline, run_repo_scan
from scripts.eval_baseline import run_baseline_single, SYSTEM_PROMPT as BASELINE_PROMPT
from utils.github import (
    parse_github_url,
    fetch_diffs_for_target,
    fetch_file_content,
    extract_diff_context,
)
from utils.llm import get_llm_info
from utils.metrics import (
    SampleResult,
    classify_sample,
    compute_metrics,
    final_verdicts,
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

    verdicts = final_verdicts(report)
    confirmed = [v for v in verdicts if v.confirmed]
    dismissed = [v for v in verdicts if not v.confirmed]

    # ── Summary metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Findings", len(report.findings))
    col2.metric("Confirmed", len(confirmed))
    col3.metric("Dismissed (FP)", len(dismissed))

    st.divider()

    # ── Per-finding detail
    defense_map = {d.finding_id: d for d in report.defenses}
    defense_r2_map = {d.finding_id: d for d in report.round2_defenses} if report.round2_defenses else {}
    verdict_map = {v.finding_id: v for v in verdicts}
    verdict_r1_map = {v.finding_id: v for v in report.verdicts}

    for finding in report.findings:
        verdict = verdict_map.get(finding.finding_id)
        verdict_r1 = verdict_r1_map.get(finding.finding_id)
        defense = defense_map.get(finding.finding_id)
        defense_r2 = defense_r2_map.get(finding.finding_id)
        is_confirmed = verdict.confirmed if verdict else True
        had_round2 = defense_r2 is not None

        badge = "🚨 CONFIRMED" if is_confirmed else "✅ DISMISSED"
        sev = _severity_color(finding.severity)

        with st.expander(
            f"{badge}  {sev} {finding.finding_id} — {finding.cwe_id} {finding.cwe_name}  [{finding.severity}]",
            expanded=is_confirmed,
        ):
            # ── Vulnerable code
            st.markdown("**Vulnerable Code**")
            st.code(finding.vulnerable_code, language="c")

            # ── Debate tabs (show R2 tabs when round 2 happened for this finding)
            if had_round2:
                tab_red, tab_blue, tab_judge_r1, tab_blue_r2, tab_judge = st.tabs([
                    "🔴 Red Team",
                    "🔵 Blue Team R1",
                    "⚖️ Judge R1",
                    "🔵 Blue Team R2",
                    "⚖️ Final Verdict",
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

                with tab_judge_r1:
                    if verdict_r1:
                        status = "**CONFIRMED** ✅" if verdict_r1.confirmed else "**DISMISSED** ❌"
                        st.markdown(f"Round 1 Verdict: {status}")
                        st.markdown(verdict_r1.reasoning)
                    else:
                        st.caption("No round 1 verdict.")

                with tab_blue_r2:
                    fp_label = "**Yes — False Positive**" if defense_r2.is_false_positive else "**No — Real Vulnerability**"
                    st.markdown(f"Is False Positive: {fp_label}")
                    st.markdown(defense_r2.counter_argument)

                with tab_judge:
                    if verdict:
                        status = "**CONFIRMED** ✅" if verdict.confirmed else "**DISMISSED** ❌"
                        st.markdown(f"Final Verdict: {status}")
                        st.markdown(verdict.reasoning)

                        # Patch display
                        if verdict.patch:
                            st.markdown("**Suggested Fix**")
                            st.code(verdict.patch, language="c")
                        elif verdict.confirmed:
                            st.caption("No suggested fix available yet.")
                    else:
                        st.caption("No verdict returned.")
            else:
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

                        # Patch display
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

tab_code, tab_github, tab_golden, tab_eval = st.tabs([
    "📝 Paste Code",
    "🔗 GitHub PR / Commit",
    "📦 Golden Set Sample",
    "📊 Evaluation",
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
                1 for v in final_verdicts(fr.report) if v.confirmed
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
        has_vuln = sample_data["has_vulnerability"]
        expected_cwe = sample_data.get("cwe_id")
        _flagged, base_class, _cwe_flagged, cwe_class = classify_sample(
            report, has_vuln, expected_cwe,
        )

        # Classification (CWE-strict: requires correct CWE for TP)
        cls_msgs = {
            "TP": ("success", f"✅ **True Positive** — correctly identified {expected_cwe}"),
            "TN": ("success", "✅ **True Negative** — correctly cleared safe code"),
            "FP": ("error", "❌ **False Positive** — flagged safe code as vulnerable"),
            "FN": ("warning", f"⚠️ **False Negative** — missed {expected_cwe} vulnerability"),
        }
        level, msg = cls_msgs[cwe_class]
        getattr(st, level)(msg)

        # Extra context when base detection found something but wrong CWE
        if _flagged and not _cwe_flagged and has_vuln:
            st.caption(f"Note: a vulnerability was detected but with the wrong CWE (expected {expected_cwe})")

        render_report(report, sample_data["code"])

# ═══════════════════════════════════════════════════════════════════
# Tab 4: Evaluation
# ═══════════════════════════════════════════════════════════════════


def _render_eval_config(params: dict[str, str]):
    """Render run configuration banner."""
    cols = st.columns(4)
    cols[0].markdown(f"**Backend:** {params.get('llm_backend', '—')}")
    cols[1].markdown(f"**Model:** {params.get('llm_model', '—')}")
    cols[2].markdown(f"**Samples:** {params.get('completed', params.get('eval_set_size', '—'))}")
    cols[3].markdown(f"**Method:** {params.get('method', '—')}")


def _render_eval_metrics(metrics: dict[str, float], per_cwe: dict | None = None, sample_results: list | None = None):
    """Render evaluation metrics (CWE-strict: correct CWE required for TP)."""

    def _pct(val) -> str:
        v = float(val or 0) * 100
        if v == 0:
            return "0 %"
        if v == 100:
            return "100 %"
        return f"{v:.1f} %"

    # ── Accuracy ─────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TP", int(metrics.get("cwe_tp", metrics.get("tp", 0))))
    c2.metric("FP", int(metrics.get("cwe_fp", metrics.get("fp", 0))))
    c3.metric("TN", int(metrics.get("cwe_tn", metrics.get("tn", 0))))
    c4.metric("FN", int(metrics.get("cwe_fn", metrics.get("fn", 0))))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Precision", _pct(metrics.get("cwe_precision", metrics.get("precision", 0))))
    c2.metric("Recall", _pct(metrics.get("cwe_recall", metrics.get("recall", 0))))
    c3.metric("F1", _pct(metrics.get("cwe_f1", metrics.get("f1", 0))))
    c4.metric("FPR", _pct(metrics.get("cwe_false_positive_rate", metrics.get("false_positive_rate", 0))))

    # ── Details (collapsed) ──────────────────────────────────
    with st.expander("📊 Per-CWE & Per-Sample Details"):
        if per_cwe:
            rows = []
            for cwe_id in sorted(per_cwe):
                c = per_cwe[cwe_id]
                rows.append({
                    "CWE": cwe_id,
                    "TP": c.get("cwe_tp", c.get("tp", 0)),
                    "FP": c.get("cwe_fp", c.get("fp", 0)),
                    "TN": c.get("cwe_tn", c.get("tn", 0)),
                    "FN": c.get("cwe_fn", c.get("fn", 0)),
                    "F1": _pct(c.get("cwe_f1", c.get("f1", 0))),
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)

        if sample_results:
            for sr in sample_results:
                cls = sr.get("cwe_classification", sr.get("classification", ""))
                icon = {"TP": "✅", "TN": "✅", "FP": "❌", "FN": "⚠️"}.get(cls, "❓")
                label = (
                    f"{icon} **{sr['sample_id']}** ({sr['cwe_id']}) — {cls}"
                    f"  |  {sr.get('findings_count', '?')} findings, {sr.get('confirmed_count', '?')} confirmed"
                )
                st.markdown(label)


with tab_eval:
    st.subheader("Evaluation Dashboard")
    st.caption("Run the full pipeline on golden set samples and view aggregate metrics.")

    eval_section = st.radio(
        "Mode",
        ["🚀 Eval All (run now)", "� Compare Runs (MLflow)"],
        horizontal=True,
    )

    # ── Section 1: Eval All ─────────────────────────────────────
    if eval_section == "🚀 Eval All (run now)":
        col_method, col_limit, col_info = st.columns([1, 1, 2])
        with col_method:
            eval_method = st.selectbox("Method", ["Debate Pipeline", "Baseline (single-pass)"])
        with col_limit:
            sample_limit = st.selectbox("Samples", [5, 10, 30], index=1)
        with col_info:
            llm_info = get_llm_info()
            st.markdown(
                f"**Backend:** {llm_info['llm_backend']}  •  "
                f"**Model:** {llm_info['llm_model']}"
            )

        is_baseline = eval_method == "Baseline (single-pass)"
        method_label = "baseline-single-pass" if is_baseline else "debate-pipeline"

        if st.button("🚀 Run Evaluation", key="run_eval"):
            try:
                with open(GOLDEN_SET_PATH, "r", encoding="utf-8") as f:
                    eval_samples = json.load(f)
            except FileNotFoundError:
                st.error(f"Golden set not found: {GOLDEN_SET_PATH}")
                st.stop()

            eval_samples = eval_samples[:sample_limit]
            results: list[SampleResult] = []
            errors: list[str] = []

            progress = st.progress(0, text="Starting evaluation…")
            status_area = st.empty()

            for i, s in enumerate(eval_samples):
                progress.progress(
                    (i) / len(eval_samples),
                    text=f"Scanning {s['id']} ({i + 1}/{len(eval_samples)})…",
                )
                try:
                    if is_baseline:
                        report = run_baseline_single(s["code"])
                    else:
                        report = run_pipeline(s["code"], track=False)
                    flagged, classification, cwe_flagged, _ = classify_sample(
                        report, s["has_vulnerability"], s["cwe_id"],
                    )
                    results.append(SampleResult(
                        sample_id=s["id"],
                        cwe_id=s["cwe_id"],
                        has_vulnerability=s["has_vulnerability"],
                        flagged=flagged,
                        report=report,
                        cwe_flagged=cwe_flagged,
                    ))
                    icon = {"TP": "✅", "TN": "✅", "FP": "❌", "FN": "⚠️"}.get(classification, "❓")
                    status_area.caption(f"{icon} {s['id']}: {classification}")
                except Exception as e:
                    errors.append(f"{s['id']}: {e}")
                    status_area.caption(f"❌ {s['id']}: ERROR — {e}")

            progress.progress(1.0, text="Evaluation complete!")

            if not results:
                st.error("No successful runs — cannot compute metrics.")
                st.stop()

            eval_metrics = compute_metrics(results)
            st.session_state["eval_metrics"] = eval_metrics
            st.session_state["eval_errors"] = errors
            st.session_state["eval_llm_info"] = llm_info
            st.session_state["eval_method"] = method_label

            # ── Log aggregate results to MLflow ──────────────
            try:
                import hashlib
                from agents.red_team import SYSTEM_PROMPT as RED_PROMPT
                from agents.blue_team import SYSTEM_PROMPT as BLUE_PROMPT
                from agents.judge_patcher import SYSTEM_PROMPT as JUDGE_PROMPT

                mlflow.set_experiment("code-security-scanner")
                with mlflow.start_run(run_name="golden-set-eval"):
                    mlflow.log_params({
                        "eval_set": "golden_set",
                        "eval_set_size": sample_limit,
                        "completed": len(results),
                        "errors": len(errors),
                        "method": method_label,
                        "llm_backend": llm_info["llm_backend"],
                        "llm_model": llm_info["llm_model"],
                        "prompt_red_sha": hashlib.sha256(RED_PROMPT.encode()).hexdigest()[:12],
                        "prompt_blue_sha": hashlib.sha256(BLUE_PROMPT.encode()).hexdigest()[:12],
                        "prompt_judge_sha": hashlib.sha256(JUDGE_PROMPT.encode()).hexdigest()[:12],
                    })
                    mlflow.log_metrics({
                        "precision": eval_metrics.precision,
                        "recall": eval_metrics.recall,
                        "f1": eval_metrics.f1,
                        "false_positive_rate": eval_metrics.false_positive_rate,
                        "tp": eval_metrics.tp, "fp": eval_metrics.fp,
                        "tn": eval_metrics.tn, "fn": eval_metrics.fn,
                        "cwe_precision": eval_metrics.cwe_precision,
                        "cwe_recall": eval_metrics.cwe_recall,
                        "cwe_f1": eval_metrics.cwe_f1,
                        "cwe_false_positive_rate": eval_metrics.cwe_false_positive_rate,
                        "cwe_tp": eval_metrics.cwe_tp, "cwe_fp": eval_metrics.cwe_fp,
                        "cwe_tn": eval_metrics.cwe_tn, "cwe_fn": eval_metrics.cwe_fn,
                        "total_findings": eval_metrics.total_findings,
                        "total_confirmed": eval_metrics.total_confirmed,
                        "cwe_matched_confirmed": eval_metrics.cwe_matched_confirmed,
                        "finding_precision": eval_metrics.finding_precision,
                    })
                    mlflow.log_text(
                        json.dumps(eval_metrics.sample_results, indent=2),
                        "per_sample_results.json",
                    )
                    mlflow.log_text(
                        json.dumps(eval_metrics.per_cwe, indent=2),
                        "per_cwe_results.json",
                    )
                    if errors:
                        mlflow.log_text("\n".join(errors), "errors.txt")
                st.success("✅ Results logged to MLflow")
            except Exception as e:
                st.warning(f"Failed to log to MLflow: {e}")

        if "eval_metrics" in st.session_state:
            eval_metrics = st.session_state["eval_metrics"]
            errors = st.session_state.get("eval_errors", [])
            llm_info = st.session_state.get("eval_llm_info", {})
            method_label = st.session_state.get("eval_method", "debate-pipeline")

            if errors:
                st.warning(f"{len(errors)} sample(s) failed: {', '.join(errors)}")

            st.divider()
            _render_eval_config({
                "llm_backend": llm_info.get("llm_backend", "—"),
                "llm_model": llm_info.get("llm_model", "—"),
                "completed": str(len(eval_metrics.sample_results)),
                "method": method_label,
            })
            st.divider()
            _render_eval_metrics(
                {
                    "cwe_tp": eval_metrics.cwe_tp, "cwe_fp": eval_metrics.cwe_fp,
                    "cwe_tn": eval_metrics.cwe_tn, "cwe_fn": eval_metrics.cwe_fn,
                    "cwe_precision": eval_metrics.cwe_precision,
                    "cwe_recall": eval_metrics.cwe_recall,
                    "cwe_f1": eval_metrics.cwe_f1,
                    "cwe_false_positive_rate": eval_metrics.cwe_false_positive_rate,
                    "total_findings": eval_metrics.total_findings,
                    "total_confirmed": eval_metrics.total_confirmed,
                    "cwe_matched_confirmed": eval_metrics.cwe_matched_confirmed,
                    "finding_precision": eval_metrics.finding_precision,
                },
                per_cwe=eval_metrics.per_cwe,
                sample_results=eval_metrics.sample_results,
            )

    # ── Section 2: Compare MLflow Runs ───────────────────────────
    else:
        # Load all eval runs once
        if "mlflow_runs" not in st.session_state:
            st.session_state["mlflow_runs"] = []
        if st.button("🔄 Load MLflow Runs", key="load_mlflow_runs"):
            try:
                client = MlflowClient()
                exp = client.get_experiment_by_name("code-security-scanner")
                if exp is None:
                    st.error("No MLflow experiment found. Run an evaluation first.")
                    st.stop()
                all_runs = client.search_runs(
                    experiment_ids=[exp.experiment_id],
                    filter_string="params.eval_set = 'golden_set'",
                    order_by=["start_time DESC"],
                    max_results=50,
                )
                if not all_runs:
                    st.error("No evaluation runs found.")
                else:
                    st.session_state["mlflow_runs"] = all_runs
            except Exception as e:
                st.error(f"Failed to load MLflow runs: {e}")

        all_runs = st.session_state.get("mlflow_runs", [])
        if all_runs:
            # Build labels for dropdown
            def _run_label(run) -> str:
                p = run.data.params
                t = datetime.fromtimestamp(
                    run.info.start_time / 1000, tz=timezone.utc
                ).strftime("%m/%d %H:%M")
                method = p.get("method", "?")
                model = p.get("llm_model", "?")
                n = p.get("completed", p.get("eval_set_size", "?"))
                return f"{method} | {model} | {n} samples | {t}"

            labels = [_run_label(r) for r in all_runs]

            col_left, col_right = st.columns(2)
            with col_left:
                idx_a = st.selectbox("Left run", range(len(labels)),
                                     format_func=lambda i: labels[i], key="cmp_left")
            with col_right:
                default_b = min(1, len(labels) - 1)
                idx_b = st.selectbox("Right run", range(len(labels)),
                                     format_func=lambda i: labels[i], index=default_b, key="cmp_right")

            def _render_selected_run(run, col_key: str):
                import os
                client = MlflowClient()
                params = run.data.params
                metrics = run.data.metrics
                t = datetime.fromtimestamp(
                    run.info.start_time / 1000, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
                st.caption(f"{t}  |  `{run.info.run_id[:12]}…`")
                _render_eval_config(params)
                st.divider()
                # Load artifacts
                per_cwe, sample_results = None, None
                try:
                    artifacts_dir = client.download_artifacts(run.info.run_id, "")
                    cwe_path = os.path.join(artifacts_dir, "per_cwe_results.json")
                    sample_path = os.path.join(artifacts_dir, "per_sample_results.json")
                    if os.path.exists(cwe_path):
                        with open(cwe_path, "r") as f:
                            per_cwe = json.load(f)
                    if os.path.exists(sample_path):
                        with open(sample_path, "r") as f:
                            sample_results = json.load(f)
                except Exception:
                    pass
                _render_eval_metrics(metrics, per_cwe=per_cwe, sample_results=sample_results)

            col_a, col_b = st.columns(2)
            with col_a:
                _render_selected_run(all_runs[idx_a], "left")
            with col_b:
                _render_selected_run(all_runs[idx_b], "right")
