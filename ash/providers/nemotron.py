"""NVIDIA Nemotron family provider.

Works with any Nemotron model served through NVIDIA NIM, vLLM or
build.nvidia.com (all OpenAI-compatible). Adds the Nemotron-specific
conventions on top of the generic provider:

* Reasoning ("thinking") is toggled with ``/think`` or ``/no_think`` in the
  system prompt (Nemotron 3 Nano/Super and Nemotron Nano 2 convention). The
  provider injects it from ``ModelProfile.reasoning``.
* ``<think>…</think>`` blocks and ``reasoning_content`` are lifted into
  ``ModelResponse.reasoning`` so agents receive clean content.
* Text-encoded ``<tool_call>`` blocks are parsed when the server has no
  native tool parser enabled.

Tested targets (all same contract): nvidia/nemotron-3-nano-30b-a3b,
nvidia/nemotron-3-super-120b-a12b, nvidia/nemotron-nano-9b-v2,
llama-3.3-nemotron-super-49b, and CoE LoRA-adapted Nemotron 30B SOC builds.
"""

from __future__ import annotations

from ash.core.types import Message, Role
from ash.providers.openai_compat import OpenAICompatibleProvider


class NemotronProvider(OpenAICompatibleProvider):
    name = "nemotron"

    THINK_ON = "/think"
    THINK_OFF = "/no_think"

    def prepare_messages(self, messages: list[Message]) -> list[Message]:
        toggle = self.THINK_ON if self.profile.reasoning else self.THINK_OFF
        if self.profile.extra.get("reasoning_toggle") == "none":
            return messages
        out = list(messages)
        if out and out[0].role == Role.SYSTEM:
            sys_msg = out[0]
            content = sys_msg.content or ""
            if not content.lstrip().startswith(("/think", "/no_think")):
                out[0] = sys_msg.model_copy(update={"content": f"{toggle}\n{content}".strip()})
        else:
            out.insert(0, Message(role=Role.SYSTEM, content=toggle))
        return out


class SovereignProvider(OpenAICompatibleProvider):
    """Reserved slot for the CoE's own models (Sovereign 7B, Nemotron-30B SOC
    LoRA builds served in-house). Identical wire contract today; keep this
    class so sovereign-specific prompt formats, adapters or tokenizer quirks
    can be added later without touching agents."""

    name = "sovereign"

    def prepare_messages(self, messages: list[Message]) -> list[Message]:
        # Sovereign SOC adapters are trained with a fixed system preamble; allow
        # operators to pin it via profile.extra["system_preamble"].
        preamble = self.profile.extra.get("system_preamble")
        if not preamble:
            return messages
        out = list(messages)
        if out and out[0].role == Role.SYSTEM:
            out[0] = out[0].model_copy(update={"content": f"{preamble}\n\n{out[0].content or ''}".strip()})
        else:
            out.insert(0, Message(role=Role.SYSTEM, content=preamble))
        return out
