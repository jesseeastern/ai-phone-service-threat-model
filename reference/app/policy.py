"""The check that sits between the model and anything it wants to do.

The model only proposes actions. Code here decides if they run.
"""

from dataclasses import dataclass

from .logs import hash_number
from .store import Store

ALLOWED_TOOLS = {"send_sms", "lookup_hours", "handoff_to_human"}


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


@dataclass
class Policy:
    outbound_allowlist: set[str]
    tool_limit: int = 10  # per caller
    tool_window_seconds: int = 600
    daily_budget_cents: int = 500

    async def check(
        self, store: Store, caller: str, tool: str, args: dict, est_cost_cents: int = 0
    ) -> Decision:
        if tool not in ALLOWED_TOOLS:
            return Decision(False, "unknown_tool")

        if tool == "send_sms":
            to = args.get("to", "")
            # replying to the person who texted us is fine, anything else has to be allowlisted
            if to != caller and to not in self.outbound_allowlist:
                return Decision(False, "not_allowlisted")

        key = "tool:" + hash_number(caller)
        if not await store.hit(key, self.tool_limit, self.tool_window_seconds):
            return Decision(False, "rate_limit")

        if not await store.reserve_spend(est_cost_cents, self.daily_budget_cents):
            return Decision(False, "budget")

        return Decision(True)
