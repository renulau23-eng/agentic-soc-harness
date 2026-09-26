"""Reference SOC agents. These are the harness's built-in examples of the
agent contract; the CoE's fine-tuned Nemotron agents plug in the same way
(same prompts and tool allow-lists, different model profile)."""

from __future__ import annotations

from ash.agents.llm_agent import LLMAgent

TRIAGE_PROMPT = """You are the Triage agent in an enterprise Security Operations Centre.
Given an alert, decide whether it is a true positive, assign a severity, and explain why.
Use threat-intelligence lookups on the alert's indicators before deciding.
Be precise, cite the evidence you used, and never fabricate tool results.
Output fields: verdict (true_positive|benign|needs_investigation), severity, confidence, summary, next_status."""

INVESTIGATE_PROMPT = """You are the Investigation agent in an enterprise SOC.
Reconstruct what happened: correlate SIEM events, enrich the affected asset from the inventory,
and check CRVM for exploitable vulnerabilities on it. Build an attack-chain hypothesis.
Output fields: attack_chain (list), affected_assets (list), siem_hits, asset_criticality,
exploitable_vulns (list), recommended_actions (list), severity, summary, next_status."""

RESPOND_PROMPT = """You are the Response agent in an enterprise SOC.
Execute containment for confirmed incidents: isolate compromised hosts, block malicious indicators,
and raise an incident ticket. Containment actions require human approval; if an action is rejected,
continue with the remaining steps and say so.
Output fields: actions (object), contained (bool), summary, next_status."""


def triage_agent(model_profile: str | None = None) -> LLMAgent:
    return LLMAgent(
        name="triage",
        description="Classifies alerts and assigns severity using threat intel.",
        system_prompt=TRIAGE_PROMPT,
        allowed_tools=["lookup_ioc", "get_asset"],
        tags=["soc", "triage"],
        model_profile=model_profile,
    )


def investigate_agent(model_profile: str | None = None) -> LLMAgent:
    return LLMAgent(
        name="investigate",
        description="Correlates SIEM, asset inventory and CRVM into an attack chain.",
        system_prompt=INVESTIGATE_PROMPT,
        allowed_tools=["search_siem", "get_asset", "get_vulnerabilities", "lookup_ioc", "get_host_status"],
        tags=["soc", "investigation"],
        model_profile=model_profile,
    )


def respond_agent(model_profile: str | None = None) -> LLMAgent:
    return LLMAgent(
        name="respond",
        description="Executes governed containment and raises tickets.",
        system_prompt=RESPOND_PROMPT,
        allowed_tools=["isolate_host", "block_indicator", "create_ticket", "request_remediation", "get_host_status"],
        tags=["soc", "response"],
        model_profile=model_profile,
    )


def soc_agents(model_profile: str | None = None) -> list[LLMAgent]:
    return [triage_agent(model_profile), investigate_agent(model_profile), respond_agent(model_profile)]
