# LLM Code Security Scanner

A multi-agent system that performs automated C code security review using an adversarial debate pattern. Three LLM-powered agents collaborate to identify vulnerabilities:

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

## Usage

### Scan a source file

```bash
python main.py --file path/to/code.c
```

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
main.py                    CLI entry point
orchestrator/graph.py      LangGraph pipeline wiring + MLflow logging
agents/
  red_team.py              Red Team agent (LLM-powered)
  blue_team.py             Blue Team agent (LLM-powered)
  judge_patcher.py         Judge agent (LLM-powered)
utils/
  llm.py                   Shared LLM factory (Groq / Modal backends)
  schemas.py               Pydantic models (findings, defenses, verdicts)
  metrics.py               Evaluation metrics (binary + CWE-matched)
scripts/
  eval_golden_set.py       Debate pipeline evaluation
  eval_baseline.py         Single-pass baseline evaluation
  select_golden_set.py     Script used to curate golden set from CASTLE-C250
  modal_server.py          vLLM server deployment on Modal
data/
  golden_set.json          30 curated C samples (6 CWEs × 5 each)
tests/                     Unit tests (pytest)
```
