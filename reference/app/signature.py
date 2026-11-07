"""Webhook signature check.

Uses Twilio's scheme since it's the most common: HMAC-SHA1 over the full URL
plus every POST param (sorted by name, key and value appended with no
separator), base64 encoded, sent in X-Twilio-Signature. Other providers do
something similar, so swap this out if you use one of them.
"""

import base64
import hashlib
import hmac


def compute_signature(auth_token: str, url: str, params: dict[str, str]) -> str:
    payload = url + "".join(k + params[k] for k in sorted(params))
    digest = hmac.new(auth_token.encode(), payload.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def is_valid(auth_token: str, url: str, params: dict[str, str], signature: str | None) -> bool:
    if not signature or not auth_token:
        return False
    expected = compute_signature(auth_token, url, params)
    # constant time compare so the check can't be timed
    return hmac.compare_digest(expected, signature)
