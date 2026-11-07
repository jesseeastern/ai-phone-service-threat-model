# Reference webhook

A small FastAPI app that shows the mitigations from the threat model in actual code. It's not a full assistant. The LLM call is a stub (`app/assistant.py`) so everything can be tested without an API key.

What it does:

- Rejects any webhook without a valid provider signature (`app/signature.py`)
- Flags obvious injection attempts in caller text (`app/injection.py`). This is just for alerting.
- Rate limits inbound messages per caller, so flooding the number doesn't mean a paid reply to every text
- Runs every action the model proposes through a policy check: tool allowlist, outbound number allowlist, per-caller rate limit, daily spend cap (`app/policy.py`)
- Keeps rate limits, spend and message history in Postgres when `DATABASE_URL` is set, otherwise in memory (`app/store.py`)
- Puts a canary string in the system prompt and blocks any reply that contains it
- Checks MMS media URLs are on the provider's host before fetching, sniffs the real file type and caps the size (`app/media.py`)
- Logs one JSON line per event with masked and hashed phone numbers, in the format the rules in `detections/` expect (`app/logs.py`)

## Running it

```bash
cd reference
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

With Docker:

```bash
cp .env.example .env    # fill it in
docker compose up --build
```

The database tests need a real Postgres and wipe its tables, so use a throwaway one:

```bash
docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres pytest
```

## Why Postgres

The first version kept rate limits and the spend counter in memory. That meant a restart or redeploy reset them to zero, and two copies of the app would each have their own counts, which doubles the real limit. Someone pumping SMS just has to wait for a deploy.

Now the counters are single SQL statements (`INSERT ... ON CONFLICT ... RETURNING`), so they're shared across instances and can't race. The tests fire 50 requests at once against a limit of 10 and check exactly 10 get through, and restart the store halfway through to check the count carries over.

The app connects as `assistant_app`, a role that can insert and update but can't delete or drop anything. If someone did get SQL injection in, they couldn't wipe the history. Phone numbers are stored hashed with a masked copy for support, same as the logs.

The in-memory limiter is a sliding window. The Postgres one is a fixed window because it's one simple statement, which means someone could get up to twice the limit right at a window boundary. For a limit of 10 per 10 minutes I'm fine with that.

The app listens on `127.0.0.1:8000`. To point a real Twilio number at it you need a public HTTPS URL (a tunnel or a reverse proxy), and `PUBLIC_BASE_URL` has to match it exactly or every signature check fails.

## Not done yet

- Retention isn't automated. The cleanup queries are at the bottom of `db-init/01-schema.sql` and need a daily cron or pg_cron.
- No voice path. Voice comes in as a transcript from the provider, so it would go through the same checks as SMS.
- MMS files are checked but not re-encoded or scanned. See `docs/mms-handling.md`.
