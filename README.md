# LLM Code Security Scanner

A multi-agent system that performs automated C code security review using an adversarial debate pattern. Three LLM-powered agents collaborate to identify vulnerabilities:

- **Red Team** — aggressively scans code for potential security vulnerabilities
- **Blue Team** — critically evaluates Red Team findings and filters out false positives
- **Judge** — makes the final call on each finding based on both arguments

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

Run the full pipeline on all 30 golden set samples and log aggregate metrics to MLflow:

```bash
python -m scripts.eval_golden_set
```

This prints a per-sample table, overall precision/recall/F1, and a per-CWE breakdown, then logs everything to an MLflow run named `golden-set-eval`.

## Viewing Results in MLflow

Start the MLflow UI:

```bash
mlflow ui
```

Open http://127.0.0.1:5000 in your browser. Results are under the **code-security-scanner** experiment. The `golden-set-eval` run contains:

- **Metrics** — precision, recall, F1, false positive rate, TP/FP/TN/FN counts
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
  red_team.py              Red Team agent (Groq LLM)
  blue_team.py             Blue Team agent (Groq LLM)
  judge_patcher.py         Judge agent (rule-based stub)
utils/
  schemas.py               Pydantic models (findings, defenses, verdicts)
  metrics.py               Evaluation metrics (precision, recall, F1)
scripts/
  eval_golden_set.py       Batch golden set evaluation
  select_golden_set.py     Script used to curate golden set from CASTLE-C250
data/
  golden_set.json          30 curated C samples (6 CWEs × 5 each)
tests/                     Unit tests (pytest)
```
