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
    session_id  BIGINT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    allowed     BOOLEAN NOT NULL,
    reason      TEXT,
    cost_cents  INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Retention: run daily (cron or pg_cron). Keeps metadata, drops content after 30 days.
-- UPDATE messages SET body = NULL WHERE created_at < now() - interval '30 days';

-- The app connects as this role, which can't drop tables or touch other schemas.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'assistant_app') THEN
        CREATE ROLE assistant_app LOGIN PASSWORD NULL;
    END IF;
END
$$;
GRANT SELECT, INSERT, UPDATE ON sessions, messages, tool_decisions TO assistant_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO assistant_app;
