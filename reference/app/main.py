import os
from html import escape
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response

from . import assistant, signature
from .injection import looks_like_injection
from .logs import log_event
from .media import MediaRejected, check_url
from .policy import Policy, RateLimiter

AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
# Set this if the app sits behind a proxy, since the signature is over the public URL.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "")
OUTBOUND_ALLOWLIST = {
    n.strip() for n in os.environ.get("OUTBOUND_ALLOWLIST", "").split(",") if n.strip()
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
policy = Policy(
    outbound_allowlist=OUTBOUND_ALLOWLIST, limiter=RateLimiter(max_events=10, window_seconds=600)
)

FALLBACK = "Sorry, I can't help with that one. Someone will follow up."


def twiml(message: str) -> Response:
    body = f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{escape(message)}</Message></Response>'
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

    flagged = looks_like_injection(body)
    log_event(
        f"{channel}.inbound", caller, channel=channel, injection_flag=flagged, length=len(body)
    )

    out = assistant.respond(body)

    for call in out.tool_calls:
        decision = policy.check(caller, call["tool"], call.get("args", {}))
        if not decision.allowed:
            log_event(
                "tool.blocked",
                caller,
                tool=call["tool"],
                decision="blocked",
                reason=decision.reason,
            )
            return twiml(FALLBACK)
        log_event("tool.allowed", caller, tool=call["tool"], decision="allowed")

    if assistant.leaks_prompt(out.reply):
        log_event("llm.canary_leak", caller, channel=channel)
        return twiml(FALLBACK)

    log_event("sms.outbound", caller, channel=channel, cost_cents=1)
    return twiml(out.reply)
