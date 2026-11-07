"""Rough country lookup from an E.164 number, just enough for fraud alerts.

Not a full numbering plan. Use a library like phonenumbers for anything real.
+1 covers the US, Canada and the Caribbean, so it's reported as NANP.
"""

# longest prefix wins
_PREFIXES = {
    "+1": "NANP",
    "+44": "GB",
    "+33": "FR",
    "+53": "CU",
    "+371": "LV",
    "+960": "MV",
    "+252": "SO",
    "+239": "ST",
    "+670": "TL",
    "+688": "TV",
    "+882": "INTL",
    "+883": "INTL",
}


def country_of(number: str) -> str:
    for length in (4, 3, 2):
        code = _PREFIXES.get(number[:length])
        if code:
            return code
    return "UNKNOWN"
