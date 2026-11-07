"""Cheap pattern check for obvious prompt injection.

This is NOT the defence. Anyone can rephrase around a regex. The defence is the
policy check in policy.py, which doesn't care what the model was told. This just
raises a flag in the logs so someone can look at the session.
"""

import re

_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts?|rules)",
    r"disregard (your|the|all) (instructions|rules|guidelines)",
    r"(reveal|print|show|repeat) (me )?(your|the) (system )?(prompt|instructions)",
    r"you are now (in )?(developer|dan|admin|god) mode",
    r"^\s*(system|assistant)\s*:",
    r"<\s*/?\s*(system|instructions?)\s*>",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _PATTERNS]


def looks_like_injection(text: str) -> bool:
    return any(p.search(text) for p in _COMPILED)
