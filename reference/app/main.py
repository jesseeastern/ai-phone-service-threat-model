import logging
import os
from contextlib import asynccontextmanager
from html import escape
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response

from . import assistant, signature
from .country import country_of
from .injection import looks_like_injection
from .logs import hash_number, log_event, mask_number
from .media import MediaRejected, check_url
from .policy import Policy
from .store import MemoryStore, PostgresStore, Store

AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
# Set this if the app sits behind a proxy, since the signature is over the public URL.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "")
OUTBOUND_ALLOWLIST = {
    n.strip() for n in os.environ.get("OUTBOUND_ALLOWLIST", "").split(",") if n.strip()
}
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Separate limit on inbound messages per caller. Without it, someone can text
# the number over and over and get a paid reply to every message.
INBOUND_LIMIT = 10
INBOUND_WINDOW_SECONDS = 600
REPLY_COST_CENTS = 1

policy = Policy(outbound_allowlist=OUTBOUND_ALLOWLIST)
store: Store = MemoryStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global store
    if not DATABASE_URL:
        logging.getLogger(__name__).warning(
            "DATABASE_URL not set, using in-memory store (limits reset on restart)"
        )
        yield
        return

    from psycopg_pool import AsyncConnectionPool

    async with AsyncConnectionPool(DATABASE_URL, min_size=1, max_size=10, open=False) as pool:
        await pool.open(wait=True, timeout=10)
        store = PostgresStore(pool)
        yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

FALLBACK = "Sorry, I can't help with that one. Someone will follow up."


def twiml(message: str) -> Response:
    body = f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{escape(message)}</Message></Response>'
    return Response(content=body, media_type="application/xml")


def twiml_empty() -> Response:
    body = '<?xml version="1.0" encoding="UTF-8"?><Response></Response>'
    return Response(content=body, media_type="application/xml")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/sms")
async def sms(request: Request):
    form = await request.form()
    params = {k: str(v) for k, v in form.items()}
    url = (PUBLIC_BASE_URL.rstrip("/") + request.url.path) if PUBLIC_BASE_URL else str(request.url)
    src_ip = request.client.host if request.client else None

    if not signature.is_valid(AUTH_TOKEN, url, params, request.headers.get("X-Twilio-Signature")):
        log_event("webhook.rejected", reason="bad_signature", path=request.url.path, src_ip=src_ip)
        return Response(status_code=403)

    caller = params.get("From", "")
    caller_hash = hash_number(caller)
    body = params.get("Body", "")
    num_media = int(params.get("NumMedia", "0") or 0)
    channel = "mms" if num_media else "sms"

    for i in range(num_media):
        media_url = params.get(f"MediaUrl{i}", "")
        try:
            check_url(media_url)
        except MediaRejected as e:
            log_event(
                "mms.rejected", caller, reason=e.reason, media_host=urlparse(media_url).hostname
            )
            return twiml(FALLBACK)

    if not await store.hit("in:" + caller_hash, INBOUND_LIMIT, INBOUND_WINDOW_SECONDS):
        log_event("inbound.throttled", caller, channel=channel, reason="rate_limit")
        return twiml_empty()

    flagged = looks_like_injection(body)
    log_event(
        f"{channel}.inbound", caller, channel=channel, injection_flag=flagged, length=len(body)
    )
    await store.record_message(caller_hash, mask_number(caller), channel, "in", body, flagged)

    out = assistant.respond(body)

    for call in out.tool_calls:
        tool, args = call["tool"], call.get("args", {})
        decision = await policy.check(store, caller, tool, args)
        await store.record_decision(caller_hash, tool, decision.allowed, decision.reason)
        if not decision.allowed:
            log_event(
                "tool.blocked",
                caller,
                tool=tool,
                to_country=country_of(args.get("to", caller)),
                decision="blocked",
                reason=decision.reason,
            )
            return twiml(FALLBACK)
        log_event("tool.allowed", caller, tool=tool, decision="allowed")

    if assistant.leaks_prompt(out.reply):
        log_event("llm.canary_leak", caller, channel=channel)
        return twiml(FALLBACK)

    if not await store.reserve_spend(REPLY_COST_CENTS, policy.daily_budget_cents):
        log_event("sms.blocked", caller, channel=channel, reason="budget")
        return twiml_empty()

    log_event(
        "sms.outbound",
        caller,
        channel=channel,
        to_country=country_of(caller),
        cost_cents=REPLY_COST_CENTS,
    )
    await store.record_message(caller_hash, mask_number(caller), channel, "out", out.reply)
    return twiml(out.reply)
