"""Where rate limits, spend and history live.

MemoryStore keeps everything in the process. It's fine for tests and the demo,
but it resets on restart and every instance has its own counts.

PostgresStore keeps it in the database, so limits survive restarts and are
shared across instances. The counters are single atomic statements, so two
requests at the same moment can't both squeeze in under the limit.

Keys passed in are already hashed. Raw phone numbers never reach the store.
"""

import datetime
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Protocol

_now = time.monotonic  # swapped for a fake clock in the demo


class Store(Protocol):
    async def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Count one hit for key. False if it's over the limit for this window."""

    async def reserve_spend(self, cents: int, budget_cents: int) -> bool:
        """Add cents to today's spend. False (and nothing added) if it would go over budget."""

    async def record_message(
        self,
        caller_hash: str,
        caller_masked: str,
        channel: str,
        direction: str,
        body: str | None,
        injection_flag: bool = False,
    ) -> None: ...

    async def record_decision(
        self, caller_hash: str, tool: str, allowed: bool, reason: str, cost_cents: int = 0
    ) -> None: ...


@dataclass
class MemoryStore:
    _hits: dict[str, deque] = field(default_factory=lambda: defaultdict(deque))
    _spend: dict[datetime.date, int] = field(default_factory=lambda: defaultdict(int))
    messages: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)

    async def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        # sliding window
        now = _now()
        q = self._hits[key]
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    async def reserve_spend(self, cents: int, budget_cents: int) -> bool:
        today = datetime.date.today()
        if self._spend[today] + cents > budget_cents:
            return False
        self._spend[today] += cents
        return True

    async def record_message(
        self, caller_hash, caller_masked, channel, direction, body, injection_flag=False
    ):
        self.messages.append(
            {
                "caller_hash": caller_hash,
                "channel": channel,
                "direction": direction,
                "body": body,
                "injection_flag": injection_flag,
            }
        )

    async def record_decision(self, caller_hash, tool, allowed, reason, cost_cents=0):
        self.decisions.append(
            {"caller_hash": caller_hash, "tool": tool, "allowed": allowed, "reason": reason}
        )


# Fixed window: the hit lands in a bucket keyed by the start of the current
# window. Simpler than a sliding window in SQL, at the cost of allowing up to
# 2x the limit right around a window boundary.
_HIT_SQL = """
INSERT INTO rate_limits (key, window_start, hits)
VALUES (%(key)s, to_timestamp(floor(extract(epoch FROM now()) / %(window)s) * %(window)s), 1)
ON CONFLICT (key, window_start) DO UPDATE SET hits = rate_limits.hits + 1
RETURNING hits
"""

# Only adds the spend if the new total stays under budget. No row back = over budget.
_SPEND_SQL = """
INSERT INTO daily_spend (day, cents)
SELECT current_date, %(cents)s WHERE %(cents)s <= %(budget)s
ON CONFLICT (day) DO UPDATE SET cents = daily_spend.cents + EXCLUDED.cents
WHERE daily_spend.cents + EXCLUDED.cents <= %(budget)s
RETURNING cents
"""

# Reuse the caller's session if they've been active in the last 30 minutes.
_SESSION_SQL = """
WITH recent AS (
    SELECT id FROM sessions
    WHERE caller_hash = %(hash)s AND channel = %(channel)s
      AND started_at > now() - interval '30 minutes'
    ORDER BY started_at DESC LIMIT 1
), created AS (
    INSERT INTO sessions (caller_hash, caller_masked, channel)
    SELECT %(hash)s, %(masked)s, %(channel)s
    WHERE NOT EXISTS (SELECT 1 FROM recent)
    RETURNING id
)
SELECT id FROM recent UNION ALL SELECT id FROM created
"""


class PostgresStore:
    def __init__(self, pool):
        self.pool = pool  # psycopg_pool.AsyncConnectionPool

    async def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        async with self.pool.connection() as conn:
            cur = await conn.execute(_HIT_SQL, {"key": key, "window": window_seconds})
            (hits,) = await cur.fetchone()
        return hits <= limit

    async def reserve_spend(self, cents: int, budget_cents: int) -> bool:
        async with self.pool.connection() as conn:
            cur = await conn.execute(_SPEND_SQL, {"cents": cents, "budget": budget_cents})
            return await cur.fetchone() is not None

    async def _session_id(self, conn, caller_hash, caller_masked, channel) -> int:
        cur = await conn.execute(
            _SESSION_SQL, {"hash": caller_hash, "masked": caller_masked, "channel": channel}
        )
        (session_id,) = await cur.fetchone()
        return session_id

    async def record_message(
        self, caller_hash, caller_masked, channel, direction, body, injection_flag=False
    ):
        async with self.pool.connection() as conn:
            sid = await self._session_id(conn, caller_hash, caller_masked, channel)
            await conn.execute(
                "INSERT INTO messages (session_id, direction, body, injection_flag)"
                " VALUES (%s, %s, %s, %s)",
                (sid, direction, body, injection_flag),
            )

    async def record_decision(self, caller_hash, tool, allowed, reason, cost_cents=0):
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO tool_decisions (caller_hash, tool, allowed, reason, cost_cents)"
                " VALUES (%s, %s, %s, %s, %s)",
                (caller_hash, tool, allowed, reason or None, cost_cents),
            )
