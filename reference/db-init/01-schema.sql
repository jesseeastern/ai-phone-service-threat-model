-- Sessions and messages for the assistant. Numbers are stored hashed, with a
-- masked copy for support. Message bodies get deleted after the retention window.

CREATE TABLE IF NOT EXISTS sessions (
    id            BIGSERIAL PRIMARY KEY,
    caller_hash   TEXT NOT NULL,
    caller_masked TEXT NOT NULL,
    channel       TEXT NOT NULL CHECK (channel IN ('voice', 'sms', 'mms')),
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS sessions_caller_idx ON sessions (caller_hash, started_at DESC);

CREATE TABLE IF NOT EXISTS messages (
    id          BIGSERIAL PRIMARY KEY,
    session_id  BIGINT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    direction   TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    body        TEXT,
    media_sha256 TEXT,
    injection_flag BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tool_decisions (
    id          BIGSERIAL PRIMARY KEY,
    caller_hash TEXT NOT NULL,
    tool        TEXT NOT NULL,
    allowed     BOOLEAN NOT NULL,
    reason      TEXT,
    cost_cents  INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rate limit counters, one row per key per window. Keys are hashed numbers.
CREATE TABLE IF NOT EXISTS rate_limits (
    key          TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    hits         INTEGER NOT NULL,
    PRIMARY KEY (key, window_start)
);

CREATE TABLE IF NOT EXISTS daily_spend (
    day   DATE PRIMARY KEY,
    cents INTEGER NOT NULL CHECK (cents >= 0)
);

-- Retention: run daily (cron or pg_cron). Keeps metadata, drops content after 30 days.
-- UPDATE messages SET body = NULL WHERE created_at < now() - interval '30 days';
-- DELETE FROM rate_limits WHERE window_start < now() - interval '1 day';

-- The app connects as this role, which can't drop tables or touch other schemas.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'assistant_app') THEN
        -- password gets set by db-init/02-app-role.sh from APP_DB_PASSWORD
        CREATE ROLE assistant_app LOGIN;
    END IF;
END
$$;
GRANT SELECT, INSERT, UPDATE ON sessions, messages, tool_decisions, rate_limits, daily_spend
    TO assistant_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO assistant_app;
