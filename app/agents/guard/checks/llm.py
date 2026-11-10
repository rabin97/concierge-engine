"""LLM calls for the guard (classifier and judge) through any OpenAI-compatible endpoint,
such as Amazon Bedrock's (model ``openai.gpt-oss-120b``).

The app calls the guard with ``asyncio.run`` once per request, so each call gets a new event
loop. An ``AsyncOpenAI`` client can't be shared across loops, so this uses the sync client in
a worker thread instead.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Awaitable, Callable

Complete = Callable[[str], Awaitable[str]]


def make_openai_complete(client, model: str, max_output_tokens: int = 1024) -> Complete:
    """Adapter for a sync ``openai.OpenAI`` client, using the Responses API.

    ``max_output_tokens`` is generous because reasoning models (gpt-oss) spend part of it
    thinking before they write the JSON answer."""

    def _call(prompt: str) -> str:
        resp = client.responses.create(model=model, input=[{"role": "user", "content": prompt}],
                                       max_output_tokens=max_output_tokens)
        return resp.output_text or ""

    async def complete(prompt: str) -> str:
        return await asyncio.to_thread(_call, prompt)

    return complete


def extract_json(reply: str) -> dict:
    """The last JSON object in a reply (models sometimes add prose or code fences)."""
    for m in reversed(list(re.finditer(r"\{[^{}]*\}", reply, re.S))):
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
    raise ValueError("reply has no JSON object")
