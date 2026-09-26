"""Distributed worker entry point: ``ash worker``."""

from __future__ import annotations

import socket
import time

from ash.broker import RedisBroker, create_broker
from ash.runtime import Harness


def run() -> None:
    harness = Harness.build()
    broker = create_broker(harness.settings.broker_url)
    if not isinstance(broker, RedisBroker):
        raise RuntimeError("ASH_BROKER_URL must point to Redis for distributed workers")
    group = harness.settings.worker_group
    consumer = socket.gethostname()
    for message_id, fields in broker.consume(group, consumer):
        invocation_id = fields["invocation_id"]
        try:
            harness.external_agents.execute(invocation_id)
            broker.acknowledge(group, message_id)
        except Exception as exc:
            invocation = harness.external_agents.get_invocation(invocation_id)
            if invocation.attempts < harness.settings.external_agent_max_attempts:
                delay = harness.settings.external_agent_retry_base_seconds * (2 ** max(invocation.attempts - 1, 0))
                time.sleep(delay)
                broker.retry(invocation_id, invocation.attempts, str(exc))
            else:
                broker.dead_letter(invocation_id, str(exc))
            broker.acknowledge(group, message_id)


if __name__ == "__main__":
    run()
