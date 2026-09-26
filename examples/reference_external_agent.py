"""Run with: uvicorn examples.reference_external_agent:app --port 8100"""

import os

from ash.agents.external import ExecutionRequest, ExecutionResult
from ash.agents.sdk import ExternalAgentApplication

agent = ExternalAgentApplication("reference-triage-agent", "1.0.0", os.getenv("AGENT_BEARER_TOKEN", ""))


@agent.capability("triage")
def triage(request: ExecutionRequest) -> ExecutionResult:
    severity = str(request.event.get("severity", "medium"))
    return ExecutionResult(
        invocation_id=request.invocation_id,
        output={"disposition": "suspicious" if severity in {"high", "critical"} else "review"},
        decisions=[{"type": "triage", "severity": severity, "confidence": 0.91,
                    "summary": "Reference remote agent completed protocol 1.0 triage."}],
        metrics={"confidence": 0.91},
    )


app = agent.app
