"""The check that sits between the model and anything it wants to do.

The model only proposes actions. Code here decides if they run.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

ALLOWED_TOOLS = {"send_sms", "lookup_hours", "handoff_to_human"}


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


@dataclass
class RateLimiter:
    max_events: int
    window_seconds: int
    _hits: dict[str, deque] = field(default_factory=lambda: defaultdict(deque))

    def hit(self, key: str, now: float | None = None) -> bool:
        """Record a hit. Returns False if this key is over the limit."""
        now = time.monotonic() if now is None else now
        q = self._hits[key]
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        if len(q) >= self.max_events:
            return False
        q.append(now)
        return True


@dataclass
class Policy:
    outbound_allowlist: set[str]
    limiter: RateLimiter
    daily_budget_cents: int = 500
    spent_today_cents: int = 0

    def check(self, caller: str, tool: str, args: dict, est_cost_cents: int = 0) -> Decision:
        if tool not in ALLOWED_TOOLS:
            return Decision(False, "unknown_tool")

        if tool == "send_sms":
            to = args.get("to", "")
            # replying to the person who texted us is fine, anything else has to be allowlisted
            if to != caller and to not in self.outbound_allowlist:
                return Decision(False, "not_allowlisted")

        if self.spent_today_cents + est_cost_cents > self.daily_budget_cents:
            return Decision(False, "budget")

        if not self.limiter.hit(caller):
            return Decision(False, "rate_limit")

        self.spent_today_cents += est_cost_cents
        return Decision(True)
