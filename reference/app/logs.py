"""One JSON line per event. Field names match detections/ and docs/architecture.md."""

import hashlib
import json
import logging
import os
import sys
import time

_logger = logging.getLogger("phone_assistant")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)

# Salt the hash so a leaked log can't be reversed with a table of every phone number.
_HASH_SALT = os.environ.get("LOG_HASH_SALT", "dev-only-change-me")

# indirection so tests and the demo can use a fake clock
_now = time.time


def mask_number(number: str) -> str:
    """+15065551234 -> +1506***1234"""
    if len(number) < 9:
        return "***"
    return number[:5] + "***" + number[-4:]


def hash_number(number: str) -> str:
    return hashlib.sha256((_HASH_SALT + number).encode()).hexdigest()[:16]


def log_event(event: str, number: str | None = None, **fields) -> dict:
    record = {"ts": round(_now(), 3), "event": event}
    if number:
        record["from_hash"] = hash_number(number)
        record["from_masked"] = mask_number(number)
    record.update(fields)
    _logger.info(json.dumps(record))
    return record
