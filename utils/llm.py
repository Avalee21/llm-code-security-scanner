"""Shared LLM factory — returns a Groq, Modal, or Azure OpenAI client
depending on environment variables.

Set LLM_BACKEND=modal  (and MODAL_ENDPOINT_URL) to use your Modal vLLM server.
Set LLM_BACKEND=foundry (and FOUNDRY_ENDPOINT_URL / FOUNDRY_API_KEY)
    to use Microsoft Foundry (serverless Llama deployment).
Defaults to Groq when LLM_BACKEND is unset or set to "groq".
"""

import json
import os
import re
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


def parse_llm_json(raw: str | None) -> list | dict:
    """Parse LLM output as JSON with cleanup and fallback extraction."""
    if not raw:
        return []
    text = raw.strip()
    if not text:
        return []

    # Strip markdown code fences
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) >= 3 else parts[-1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
        if not text:
            return []

    # Fix common LLM JSON issues
    text = re.sub(r"\\'", "'", text)
    text = re.sub(r',\s*([}\]])', r'\1', text)

    def _fix_backslashes(s: str) -> str:
        """Double-escape any backslash not part of a valid JSON escape sequence."""
        return re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', s)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Retry with backslash fixing
    try:
        return json.loads(_fix_backslashes(text))
    except json.JSONDecodeError:
        pass

    # Fallback: extract the first JSON array or object via bracket matching
    for start_char, end_char in [('[', ']'), ('{', '}')]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == '\\':
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == start_char:
                depth += 1
            elif c == end_char:
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    candidate = re.sub(r',\s*([}\]])', r'\1', candidate)
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        pass
                    try:
                        return json.loads(_fix_backslashes(candidate))
                    except json.JSONDecodeError:
                        break

    # Nothing parseable found — return empty list rather than crashing the pipeline
    return []
