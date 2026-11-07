"""Inbound MMS media checks. See docs/mms-handling.md."""

from urllib.parse import urlparse

import httpx

MAX_BYTES = 2 * 1024 * 1024

# Twilio media lives under api.twilio.com. Change for your provider.
ALLOWED_MEDIA_HOSTS = {"api.twilio.com"}

_MAGIC = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n\x1a\n": "image/png",
}


class MediaRejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def check_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise MediaRejected("not_https")
    if parsed.hostname not in ALLOWED_MEDIA_HOSTS:
        raise MediaRejected("bad_media_host")


def sniff_type(head: bytes) -> str | None:
    for magic, mime in _MAGIC.items():
        if head.startswith(magic):
            return mime
    return None


def fetch(url: str, client: httpx.Client) -> tuple[bytes, str]:
    """Download with a hard size cap. Returns (bytes, detected type)."""
    check_url(url)
    buf = bytearray()
    with client.stream("GET", url, follow_redirects=False) as r:
        r.raise_for_status()
        for chunk in r.iter_bytes():
            buf.extend(chunk)
            if len(buf) > MAX_BYTES:
                raise MediaRejected("too_large")
    mime = sniff_type(bytes(buf[:16]))
    if mime is None:
        raise MediaRejected("bad_type")
    return bytes(buf), mime
