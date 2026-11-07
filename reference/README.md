# Reference webhook

A small FastAPI app that shows the mitigations from the threat model in actual code. It's not a full assistant. The LLM call is a stub (`app/assistant.py`) so everything can be tested without an API key.

What it does:

- Rejects any webhook without a valid provider signature (`app/signature.py`)
- Flags obvious injection attempts in caller text (`app/injection.py`). This is just for alerting.
- Runs every action the model proposes through a policy check: tool allowlist, outbound number allowlist, per-caller rate limit, daily spend cap (`app/policy.py`)
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

The app listens on `127.0.0.1:8000`. To point a real Twilio number at it you need a public HTTPS URL (a tunnel or a reverse proxy), and `PUBLIC_BASE_URL` has to match it exactly or every signature check fails.

## Not done yet

- The app doesn't write to Postgres yet. `schema.sql` is the table layout I'd use, and the rate limiter and spend counter are in memory, so they reset on restart and won't work across more than one instance. Redis or the database would fix that.
- No voice path. Voice comes in as a transcript from the provider, so it would go through the same checks as SMS.
- MMS files are checked but not re-encoded or scanned. See `docs/mms-handling.md`.
