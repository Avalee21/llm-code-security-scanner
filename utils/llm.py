"""Shared LLM factory — returns a Groq, Modal, or Azure OpenAI client
depending on environment variables.

Set LLM_BACKEND=modal  (and MODAL_ENDPOINT_URL) to use your Modal vLLM server.
Set LLM_BACKEND=foundry (and FOUNDRY_ENDPOINT_URL / FOUNDRY_API_KEY)
    to use Microsoft Foundry (serverless Llama deployment).
Defaults to Groq when LLM_BACKEND is unset or set to "groq".
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_core.language_models import BaseChatModel

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# LLM_MODEL_GROQ = "meta-llama/llama-4-scout-17b-16e-instruct"
LLM_MODEL_GROQ = "llama-3.3-70b-versatile"
LLM_MODEL_MODAL = "Qwen/Qwen2.5-Coder-32B-Instruct-AWQ"
LLM_MODEL_FOUNDRY = "Llama-3.3-70B-Instruct"


def get_llm_info() -> dict[str, str]:
    """Return the active backend and model name (for MLflow logging)."""
    backend = os.getenv("LLM_BACKEND", "groq").lower()
    model_map = {"modal": LLM_MODEL_MODAL, "foundry": LLM_MODEL_FOUNDRY}
    model = model_map.get(backend, LLM_MODEL_GROQ)
    return {"llm_backend": backend, "llm_model": model}


def get_llm(temperature: float = 0.0) -> BaseChatModel:
    backend = os.getenv("LLM_BACKEND", "groq").lower()

    if backend == "modal":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            base_url=os.getenv("MODAL_ENDPOINT_URL"),
            api_key="not-needed",
            model=LLM_MODEL_MODAL,
            temperature=temperature,
        )

    if backend == "foundry":
        from langchain_openai import ChatOpenAI
        endpoint = os.getenv("FOUNDRY_ENDPOINT_URL", "").rstrip("/")
        if not endpoint.endswith("/v1"):
            endpoint += "/v1"
        return ChatOpenAI(
            base_url=endpoint,
            api_key=os.getenv("FOUNDRY_API_KEY"),
            model=LLM_MODEL_FOUNDRY,
            temperature=temperature,
        )

    from langchain_groq import ChatGroq
    return ChatGroq(
        model=LLM_MODEL_GROQ,
        temperature=temperature,
        api_key=os.getenv("GROQ_API_KEY"),
    )
