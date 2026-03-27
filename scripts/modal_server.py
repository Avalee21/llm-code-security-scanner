"""Serve a model with vLLM on Modal.

Usage:
    modal serve scripts/modal_server.py    # dev mode
    modal deploy scripts/modal_server.py   # persistent
"""

import modal

MODEL_NAME = "Qwen/Qwen2.5-Coder-32B-Instruct-AWQ"

def download_model():
    from huggingface_hub import snapshot_download
    snapshot_download(MODEL_NAME)

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("vllm>=0.4.0", "torch", "huggingface_hub", "autoawq")
    .run_function(download_model)
)

app = modal.App("security-scanner-vllm")


@app.function(
    image=image,
    gpu="A100-40GB",
    timeout=3600,
    scaledown_window=300,
)
@modal.web_server(port=8000, startup_timeout=600)
def serve():
    import subprocess
    subprocess.Popen([
        "python", "-m", "vllm.entrypoints.openai.api_server",
        "--model", MODEL_NAME,
        "--host", "0.0.0.0",
        "--port", "8000",
        "--quantization", "awq",
        "--max-model-len", "8192",
    ])