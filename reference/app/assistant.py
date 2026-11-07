"""Stand-in for the LLM call.

Kept as a stub so the security pieces can be tested without an API key. A real
version would send SYSTEM_PROMPT plus the caller's message (as user content,
never pasted into the system prompt) and parse any tool calls it returns.
"""

import os
import secrets
from dataclasses import dataclass, field

# Random per process. If this string ever shows up in a reply, the prompt is leaking.
CANARY = os.environ.get("PROMPT_CANARY") or "cnry-" + secrets.token_hex(6)

SYSTEM_PROMPT = f"""You answer questions about business hours and services.
You cannot change accounts or take payments. If unsure, hand off to a human.
[{CANARY}]"""


@dataclass
class ModelOutput:
    reply: str
    tool_calls: list[dict] = field(default_factory=list)


def respond(caller_text: str) -> ModelOutput:
    if "hours" in caller_text.lower():
        return ModelOutput(
            "We're open 9 to 5, Monday to Friday.", [{"tool": "lookup_hours", "args": {}}]
        )
    return ModelOutput("Thanks for your message. Someone will get back to you shortly.")


def leaks_prompt(reply: str) -> bool:
    return CANARY in reply
