import json
from pathlib import Path

import evaluate
import simulate

HERE = Path(__file__).parent


def titles(alerts):
    return {a.title for a in alerts}


def test_every_attack_is_caught():
    rules, correlations = evaluate.load_rules()
    alerts = evaluate.evaluate(simulate.run(), rules, correlations, min_level="medium")
    assert titles(alerts) == {
        "Burst Of Forged Webhook Requests From One IP",
        "Known Prompt Injection Pattern In Caller Input",
        "Assistant Tried To Message A Number Outside The Allowlist",
        "System Prompt Canary Token In Assistant Output",
        "MMS Media URL Not On Provider Host",
        "Caller Hit The Inbound Rate Limit",
        "Outbound Message To A High Risk Destination Country",
    }


def test_normal_traffic_is_quiet():
    rules, correlations = evaluate.load_rules()
    alerts = evaluate.evaluate(simulate.run(include_attacks=False), rules, correlations)
    assert alerts == []


def test_single_bad_request_does_not_trip_burst_rule():
    rules, correlations = evaluate.load_rules()
    bursts = [
        a
        for a in evaluate.evaluate(simulate.run(), rules, correlations)
        if a.title.startswith("Burst")
    ]
    assert len(bursts) == 1
    assert "198.51.100.23" in bursts[0].detail


def test_rate_limit_stops_sms_pumping():
    # 15 messages from one number: 10 get replies, 5 get throttled, and the
    # outbound volume never reaches the pumping threshold
    events = simulate.run()
    flood = [e for e in events if e.get("from_masked") == "+1506***1304"]
    assert sum(e["event"] == "sms.outbound" for e in flood) == 10
    assert sum(e["event"] == "inbound.throttled" for e in flood) == 5


def test_sample_file_is_up_to_date():
    committed = [
        json.loads(line) for line in (HERE / "sample_events.jsonl").read_text().splitlines()
    ]
    assert committed == simulate.run(), "re-run: python demo/simulate.py > demo/sample_events.jsonl"


def test_no_raw_numbers_in_logs():
    raw = json.dumps(simulate.run())
    for number in ("5065551201", "5065551304", "5355512345"):
        assert number not in raw
