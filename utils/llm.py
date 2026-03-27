"""Shared LLM factory — returns either a Groq or OpenAI-compatible client
depending on environment variables.

Set LLM_BACKEND=modal (and MODAL_ENDPOINT_URL) to use your Modal vLLM server.
Defaults to Groq when LLM_BACKEND is unset or set to "groq".
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_core.language_models import BaseChatModel

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

LLM_MODEL_GROQ = "llama-3.3-70b-versatile"
LLM_MODEL_MODAL = "Qwen/Qwen2.5-Coder-32B-Instruct-AWQ"


def get_llm(temperature: float = 0.2) -> BaseChatModel:
    backend = os.getenv("LLM_BACKEND", "groq").lower()

    if backend == "modal":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            base_url=os.getenv("MODAL_ENDPOINT_URL"),
            api_key="not-needed",
            model=LLM_MODEL_MODAL,
            temperature=temperature,
        )

    from langchain_groq import ChatGroq
    return ChatGroq(
        model=LLM_MODEL_GROQ,
        temperature=temperature,
        api_key=os.getenv("GROQ_API_KEY"),
    )
