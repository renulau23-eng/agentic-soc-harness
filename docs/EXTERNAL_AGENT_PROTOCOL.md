# ASH External Agent Protocol 1.0

An external agent registers once and receives a one-time API key used only for callbacks and self-service operations. Operators own enablement, routes, scopes, transport authentication, timeouts, concurrency, and circuit-breaker policy.

## Execute contract

The harness sends `POST <agent.endpoint>` for HTTP agents, `tools/call` with tool name `execute_security_agent` for MCP agents, or unary gRPC method `/ash.agent.v1.AgentService/Execute`.

```json
{
  "protocol_version": "1.0",
  "invocation_id": "inv_...",
  "capability": "triage",
  "event": {"severity": "high"},
  "context": {},
  "callback_url": "https://ash/api/v1/external-agent-invocations/inv_.../callback",
  "deadline": "2026-09-27T12:00:00Z",
  "trace_context": {}
}
```

The immediate response uses the same invocation ID and status `accepted`, `completed`, or `failed`. An accepted job later posts a `CallbackResult` to `callback_url` using `X-Agent-Key`. Major protocol versions must match; additive fields are allowed within a major version.

## Security

- Agent callback keys are random, stored only as SHA-256 hashes, shown once, and independently rotatable.
- Outbound auth supports bearer secrets, OAuth 2.0 client credentials, workload identity, and mTLS.
- Production secret references must use `env://NAME` or `file:///run/secrets/...`.
- Data-fabric access scopes belong to each registration and are not inferred from capability names.
- All management and dispatch routes require ASH RBAC permissions; callbacks require the invocation-owning agent credential.

## Delivery semantics

Redis Streams provide at-least-once delivery. Invocation idempotency keys prevent duplicate work records. Workers retry with exponential backoff, then move exhausted jobs to `ash:external-agent-jobs:dead-letter`. The SQL invocation row is the durable workflow-resume record and operational source of truth.
