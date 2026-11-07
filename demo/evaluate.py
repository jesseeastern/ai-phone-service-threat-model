"""Run the Sigma rules in detections/ over a JSONL log file and print alerts.

This is a small local matcher, not a SIEM. It handles the parts of Sigma these
rules use: field equals value, lists, booleans, wildcards, and/or/not, and
event_count correlations. In production you'd convert the rules with sigma-cli
and run them in Splunk, Elastic, Sentinel, etc.

    python demo/evaluate.py demo/sample_events.jsonl
"""

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import SigmaBool, SigmaNull, SigmaNumber, SigmaString, SpecialChars

RULES_DIR = Path(__file__).resolve().parent.parent / "detections"
LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class Alert:
    ts: float
    level: str
    title: str
    detail: str


def _string_regex(value: SigmaString) -> re.Pattern:
    parts = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(part))
    # Sigma string matching is case-insensitive
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


def _field_matches(event: dict, field: str, value) -> bool:
    actual = event.get(field)
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(value, SigmaBool):
        return actual is value.boolean
    if isinstance(value, SigmaNumber):
        return actual == value.number
    if isinstance(value, SigmaString):
        return bool(_string_regex(value).match(str(actual)))
    raise NotImplementedError(f"value type {type(value).__name__} not supported")


def _eval(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _field_matches(event, node.field, node.value)
    raise NotImplementedError(f"condition {type(node).__name__} not supported")


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    return any(_eval(c.parse(), event) for c in rule.detection.parsed_condition)


def load_rules(path: Path = RULES_DIR):
    collection = SigmaCollection.load_ruleset([str(path)])
    collection.resolve_rule_references()
    rules = [r for r in collection if isinstance(r, SigmaRule)]
    correlations = [r for r in collection if isinstance(r, SigmaCorrelationRule)]
    return rules, correlations


def evaluate(events: list[dict], rules, correlations, min_level: str = "low") -> list[Alert]:
    alerts: list[Alert] = []
    matched: dict[str, list[dict]] = defaultdict(list)  # rule name -> events

    for event in events:
        for rule in rules:
            if not rule_matches(rule, event):
                continue
            if rule.name:
                matched[rule.name].append(event)
            level = rule.level.name.lower() if rule.level else "informational"
            if LEVELS.index(level) >= LEVELS.index(min_level):
                detail = ", ".join(f"{f}={event.get(f)}" for f in (rule.fields or []))
                alerts.append(Alert(event.get("ts", 0), level, rule.title, detail))

    for corr in correlations:
        if corr.type.name != "EVENT_COUNT":
            raise NotImplementedError(f"correlation type {corr.type} not supported")
        if corr.condition.op not in (
            SigmaCorrelationConditionOperator.GTE,
            SigmaCorrelationConditionOperator.GT,
        ):
            raise NotImplementedError("only gte/gt correlation conditions are supported")
        threshold = corr.condition.count + (
            1 if corr.condition.op == SigmaCorrelationConditionOperator.GT else 0
        )
        source = [e for ref in corr.rules for e in matched.get(ref.rule.name, [])]
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for e in source:
            groups[tuple(e.get(g) for g in corr.group_by)].append(e)

        for key, group in groups.items():
            window: deque = deque()
            for e in sorted(group, key=lambda x: x.get("ts", 0)):
                window.append(e["ts"])
                while e["ts"] - window[0] > corr.timespan.seconds:
                    window.popleft()
                if len(window) >= threshold:
                    detail = ", ".join(f"{g}={v}" for g, v in zip(corr.group_by, key, strict=True))
                    detail += f", count={len(window)} in {corr.timespan.spec}"
                    alerts.append(Alert(e["ts"], corr.level.name.lower(), corr.title, detail))
                    window.clear()  # one alert per burst

    return sorted(alerts, key=lambda a: a.ts)


def read_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile", type=Path)
    ap.add_argument("--min-level", default="low", choices=LEVELS)
    args = ap.parse_args(argv)

    rules, correlations = load_rules()
    events = read_jsonl(args.logfile)
    alerts = evaluate(events, rules, correlations, args.min_level)

    print(f"{len(events)} events, {len(rules)} rules, {len(correlations)} correlations\n")
    for a in alerts:
        print(f"[{a.level.upper():8}] {a.title}")
        if a.detail:
            print(f"           {a.detail}")
    print(f"\n{len(alerts)} alerts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
