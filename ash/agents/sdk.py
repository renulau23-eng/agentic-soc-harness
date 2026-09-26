"""SDK for building protocol-compatible external agents."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException

from ash.agents.external import CallbackResult, ExecutionRequest, ExecutionResult

Handler = Callable[[ExecutionRequest], ExecutionResult | dict[str, Any]]


class ExternalAgentApplication:
    def __init__(self, name: str, version: str, bearer_token: str = "") -> None:
        self.name = name
        self.version = version
        self.bearer_token = bearer_token
        self.handlers: dict[str, Handler] = {}
        self.app = FastAPI(title=name, version=version)
        self.app.add_api_route("/health", self.health, methods=["GET"])
        self.app.add_api_route("/execute", self.execute, methods=["POST"], response_model=ExecutionResult)
        self.app.add_api_route("/mcp", self.mcp, methods=["POST"])

    def capability(self, name: str):
        def decorator(fn: Handler) -> Handler:
            self.handlers[name] = fn
            return fn

        return decorator

    def health(self) -> dict[str, Any]:
        return {"status": "healthy", "name": self.name, "version": self.version, "capabilities": sorted(self.handlers)}

    def execute(self, request: ExecutionRequest, authorization: str | None = Header(default=None)) -> ExecutionResult:
        if self.bearer_token and authorization != f"Bearer {self.bearer_token}":
            raise HTTPException(status_code=401, detail="invalid control-plane credential")
        handler = self.handlers.get(request.capability)
        if not handler:
            raise HTTPException(status_code=422, detail=f"unsupported capability {request.capability}")
        result = handler(request)
        return (
            result
            if isinstance(result, ExecutionResult)
            else ExecutionResult(invocation_id=request.invocation_id, **result)
        )

    def mcp(self, body: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
        params = body.get("params", {})
        if body.get("method") != "tools/call" or params.get("name") != "execute_security_agent":
            return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "method not found"}}
        result = self.execute(ExecutionRequest.model_validate(params.get("arguments", {})), authorization)
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": {"structuredContent": result.model_dump(mode="json")}}


class ControlPlaneClient:
    def __init__(self, base_url: str, agent_api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"x-agent-key": agent_api_key}

    def submit(self, invocation_id: str, result: CallbackResult) -> dict[str, Any]:
        response = httpx.post(
            f"{self.base_url}/external-agent-invocations/{invocation_id}/callback",
            headers=self.headers,
            json=result.model_dump(mode="json"),
            timeout=15,
        )
        response.raise_for_status()
        return response.json()
