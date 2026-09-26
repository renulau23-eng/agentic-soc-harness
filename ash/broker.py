"""Redis Streams transport for horizontally scaled external-agent workers."""

from __future__ import annotations

import json


class InlineBroker:
    distributed = False

    def publish(self, invocation_id: str) -> str:
        return invocation_id


class RedisBroker:
    distributed = True

    def __init__(self, url: str, stream: str = "ash:external-agent-jobs") -> None:
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError("install agentic-soc-harness[distributed] to use Redis") from exc
        self.client = redis.Redis.from_url(url, decode_responses=True)
        self.stream = stream

    def publish(self, invocation_id: str) -> str:
        return str(self.client.xadd(self.stream, {"invocation_id": invocation_id}))

    def ensure_group(self, group: str) -> None:
        try:
            self.client.xgroup_create(self.stream, group, id="0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def consume(self, group: str, consumer: str, block_ms: int = 5000):
        self.ensure_group(group)
        for _, messages in self.client.xreadgroup(group, consumer, {self.stream: ">"}, count=1, block=block_ms):
            yield from messages

    def acknowledge(self, group: str, message_id: str) -> None:
        self.client.xack(self.stream, group, message_id)

    def retry(self, invocation_id: str, attempt: int, error: str) -> None:
        self.client.xadd(
            self.stream,
            {"invocation_id": invocation_id, "attempt": attempt, "previous_error": error[:2000]},
        )

    def dead_letter(self, invocation_id: str, error: str) -> None:
        self.client.xadd(
            f"{self.stream}:dead-letter",
            {"invocation_id": invocation_id, "error": error[:4000], "payload": json.dumps({})},
        )


def create_broker(url: str | None) -> InlineBroker | RedisBroker:
    return RedisBroker(url) if url else InlineBroker()
