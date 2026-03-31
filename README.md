# LLM Code Security Scanner

A multi-agent system that performs automated code security review using an adversarial debate pattern. It can scan individual source files **or GitHub pull requests / commits**, focusing only on changed lines to catch vulnerabilities introduced by new code.

Three LLM-powered agents collaborate to identify vulnerabilities:

- **Red Team** — scans code for potential security vulnerabilities, requiring concrete exploit paths
- **Blue Team** — critically evaluates Red Team findings and filters out false positives
- **Judge** — delivers a reasoned final verdict on each finding by weighing both sides against the source code

The pipeline is orchestrated with [LangGraph](https://github.com/langchain-ai/langgraph) and experiment tracking is handled by [MLflow](https://mlflow.org/).

## Setup

### 1. Clone and install dependencies

```bash
git clone git@github.com:Avalee21/llm-code-security-scanner.git
cd llm-code-security-scanner
pip install -r requirements.txt
```

### 2. Configure environment variables

Copy the example env file and fill in your API key:

```bash
cp .env.example .env
```

Edit `.env` and set:

| Variable              | Description                                    |
| --------------------- | ---------------------------------------------- |
| `GROQ_API_KEY`        | Your [Groq](https://console.groq.com/) API key |
| `LLM_BACKEND`         | `groq` (default) or `modal`                    |
| `MODAL_ENDPOINT_URL`  | Modal vLLM endpoint (only if `LLM_BACKEND=modal`) |
| `MLFLOW_TRACKING_URI` | MLflow store path (default `./mlruns`)         |
| `GITHUB_TOKEN`        | GitHub token (optional — for private repos / higher rate limits) |

## Usage

### Scan a source file

```bash
python main.py --file path/to/code.c
```

### Scan a GitHub pull request or commit

Point the scanner at any GitHub PR or commit URL — it fetches the diff, extracts only the changed code with surrounding context, and runs the adversarial debate on each modified file:

```bash
# Scan a pull request
python main.py --pr https://github.com/Avalee21/vulnerable-code-demo/pull/1

# Scan a specific commit
python main.py --commit https://github.com/Avalee21/vulnerable-code-demo/commit/875bcbbf97463462cf8feb3fef1b8ee34785c7e1
```

For private repositories, provide a GitHub token:

```bash
python main.py --pr https://github.com/owner/private-repo/pull/42 --github-token ghp_xxx
# Or set GITHUB_TOKEN in your .env
```

The scanner automatically:
- Filters to source code files only (skips `.md`, `.json`, images, etc.)
- Extracts changed hunks with ~15 lines of surrounding context (not the full file) to save tokens
- Skips files with >500 changed lines
- Runs the full Red → Blue → Judge debate per file

### Scan a golden set sample

List all available samples:

```bash
python main.py --list-golden
```

Scan by index or ID:

```bash
python main.py --golden 0
python main.py --golden CASTLE-CWE-22-1
```

### Demo individual agents

Run only the Red Team (attack) stage:

```bash
python main.py --golden 0 --red-only
```

Run Red + Blue Team (attack and defense) without the Judge:

```bash
python main.py --file code.c --blue-only
```

These modes skip the Judge, MLflow logging, and evaluation — useful for demos and debugging.

### Disable MLflow tracking

Append `--no-mlflow` to any scan command:

```bash
python main.py --file code.c --no-mlflow
```

## Web Dashboard

Launch the interactive Streamlit dashboard:

```bash
streamlit run app.py
```

Open http://localhost:8502 in your browser. The dashboard provides three modes:

- **Paste Code** — paste any source code and scan it
- **GitHub PR / Commit** — enter a GitHub URL to scan only the changed lines
- **Golden Set** — pick a sample from the curated test set and compare results against ground truth

Each scan shows the full adversarial debate: Red Team findings, Blue Team defenses, and Judge verdicts with expandable reasoning.

## Batch Evaluation

Run the full debate pipeline on golden set samples and log aggregate metrics to MLflow:

```bash
python -m scripts.eval_golden_set                # all 30 samples
python -m scripts.eval_golden_set --limit 10      # first 10 samples
```

Run the single-pass baseline (one LLM call per sample, no debate) for comparison:

```bash
python -m scripts.eval_baseline --limit 10
```

Both scripts print a per-sample table, overall precision/recall/F1, CWE-matched metrics, and a per-CWE breakdown, then log everything to MLflow.

### Evaluation Metrics

The evaluation tracks two levels of accuracy:

- **Binary detection** — did the system correctly flag vulnerable code and clear safe code? (precision, recall, F1, FPR)
- **CWE-matched detection** — did the system identify the *correct vulnerability type*? Only counts as TP when a confirmed finding carries the matching CWE. (cwe\_precision, cwe\_recall, cwe\_f1, cwe\_fpr)
- **Finding precision** — of all confirmed findings, what fraction match the ground-truth CWE? Measures Red Team noise.

This prints a per-sample table, overall precision/recall/F1, and a per-CWE breakdown, then logs everything to an MLflow run named `golden-set-eval`.

## Viewing Results in MLflow

Start the MLflow UI:

```bash
mlflow ui
```

Open http://127.0.0.1:5000 in your browser. Results are under the **code-security-scanner** experiment. Each run contains:

- **Params** — model name, backend, prompt version hashes, method (`debate-pipeline` or `baseline-single-pass`)
- **Metrics** — precision, recall, F1, false positive rate, TP/FP/TN/FN counts (both binary and CWE-matched)
- **Artifacts** — `per_sample_results.json`, `per_cwe_results.json`

## Running Tests

```bash
pytest
```

Tests mock all LLM calls so no API key is needed.

## Project Structure

```
app.py                     Streamlit web dashboard
main.py                    CLI entry point
orchestrator/graph.py      LangGraph pipeline wiring + MLflow logging
agents/
  red_team.py              Red Team agent (LLM-powered)
  blue_team.py             Blue Team agent (LLM-powered)
  judge_patcher.py         Judge agent (LLM-powered)
utils/
  llm.py                   Shared LLM factory (Groq / Modal backends)
  schemas.py               Pydantic models (findings, defenses, verdicts, diff reports)
  metrics.py               Evaluation metrics (binary + CWE-matched)
  github.py                GitHub API integration (PR/commit diff fetching)
scripts/
  eval_golden_set.py       Debate pipeline evaluation
  eval_baseline.py         Single-pass baseline evaluation
  select_golden_set.py     Script used to curate golden set from CASTLE-C250
  modal_server.py          vLLM server deployment on Modal
data/
  golden_set.json          30 curated C samples (6 CWEs × 5 each)
tests/                     Unit tests (pytest)
```
