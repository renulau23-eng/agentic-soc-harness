"""Provider for any server exposing the OpenAI ``/v1/chat/completions`` contract:
NVIDIA NIM, vLLM, TGI, llama.cpp server, build.nvidia.com, or the CoE's own
sovereign inference service. This is the only network-facing provider; the
Nemotron and Sovereign providers specialise it.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from ash.config import ModelProfile
from ash.core.errors import ProviderError
from ash.core.types import Message, ModelResponse, ToolCall, ToolSpec, Usage
from ash.observability import get_logger, metrics

log = get_logger(__name__)

_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL)
# Some Nemotron/Qwen builds emit tool calls as text when the server lacks a parser.
_TEXT_TOOLCALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self, profile: ModelProfile, *, transport: httpx.BaseTransport | None = None):
        if not profile.base_url:
            raise ProviderError(f"model profile '{profile.name}' needs base_url")
        self.profile = profile
        self.model = profile.model
        headers = {"Content-Type": "application/json"}
        if profile.api_key:
            headers["Authorization"] = f"Bearer {profile.api_key}"
        self._client = httpx.Client(
            base_url=profile.base_url.rstrip("/"),
            headers=headers,
            timeout=profile.timeout_s,
            transport=transport,
        )
        self.max_retries = int(profile.extra.get("max_retries", 3))

    # ------------------------------------------------------------------ #
    def build_payload(self, messages: list[Message], tools: list[ToolSpec] | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [m.to_openai() for m in self.prepare_messages(messages)],
            "temperature": self.profile.temperature,
            "max_tokens": self.profile.max_tokens,
        }
        if tools:
            payload["tools"] = [t.to_openai() for t in tools]
            payload["tool_choice"] = "auto"
        payload.update(self.profile.extra.get("request_overrides", {}))
        return payload

    def prepare_messages(self, messages: list[Message]) -> list[Message]:
        """Hook for subclasses (e.g. Nemotron reasoning toggle)."""
        return messages

    def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ModelResponse:
        payload = self.build_payload(messages, tools)
        started = time.perf_counter()
        data = self._post_with_retry("/chat/completions", payload)
        latency = (time.perf_counter() - started) * 1000
        resp = self.parse_response(data)
        resp.latency_ms = latency
        resp.provider = self.name
        resp.model = data.get("model", self.model)
        metrics.inc("ash_model_calls_total", provider=self.name, model=self.model)
        metrics.inc("ash_model_tokens_total", resp.usage.total_tokens, provider=self.name, model=self.model)
        metrics.observe("ash_model_latency_ms", latency, provider=self.name, model=self.model)
        log.debug(
            "model call",
            provider=self.name,
            model=self.model,
            latency_ms=round(latency, 1),
            tool_calls=len(resp.tool_calls),
            tokens=resp.usage.total_tokens,
        )
        return resp

    def _post_with_retry(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        last: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                r = self._client.post(path, json=payload)
                if r.status_code >= 500 or r.status_code == 429:
                    raise ProviderError(f"{r.status_code}: {r.text[:200]}")
                if r.status_code >= 400:
                    raise ProviderError(f"{r.status_code}: {r.text[:500]}")
                return r.json()
            except (httpx.TransportError, ProviderError) as exc:  # retry only transient classes
                last = exc
                if isinstance(exc, ProviderError) and not str(exc).startswith(("5", "429")):
                    raise
                metrics.inc("ash_model_errors_total", provider=self.name, model=self.model)
                if attempt < self.max_retries:
                    time.sleep(min(2 ** (attempt - 1) * 0.5, 8.0))
        raise ProviderError(f"model call failed after {self.max_retries} attempts: {last}")

    # ------------------------------------------------------------------ #
    def parse_response(self, data: dict[str, Any]) -> ModelResponse:
        try:
            choice = data["choices"][0]
            msg = choice.get("message", {})
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"malformed completion: {data}") from exc

        content: str | None = msg.get("content")
        reasoning: str | None = msg.get("reasoning_content") or msg.get("reasoning")
        if content:
            m = _THINK_RE.search(content)
            if m:
                reasoning = (reasoning or "") + m.group(1).strip()
                content = _THINK_RE.sub("", content).strip()

        tool_calls: list[ToolCall] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            tool_calls.append(
                ToolCall(
                    id=tc.get("id") or ToolCall().id,
                    name=fn.get("name", ""),
                    arguments=_parse_args(fn.get("arguments")),
                )
            )
        if not tool_calls and content:
            for raw in _TEXT_TOOLCALL_RE.findall(content):
                try:
                    obj = json.loads(raw)
                    tool_calls.append(ToolCall(name=obj["name"], arguments=obj.get("arguments", {})))
                except (json.JSONDecodeError, KeyError):
                    continue
            if tool_calls:
                content = _TEXT_TOOLCALL_RE.sub("", content).strip() or None

        usage = data.get("usage") or {}
        return ModelResponse(
            content=content,
            tool_calls=tool_calls,
            reasoning=reasoning,
            usage=Usage(
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
            ),
            finish_reason=choice.get("finish_reason"),
        )

    def healthcheck(self) -> bool:
        try:
            r = self._client.get("/models", timeout=5.0)
            return r.status_code < 500
        except httpx.HTTPError:
            return False


def _parse_args(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except json.JSONDecodeError:
        return {"_raw": raw}
