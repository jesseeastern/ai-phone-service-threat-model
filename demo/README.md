# Detection demo

Does the detection stuff actually work? This folder answers that by running fake traffic through the reference app and checking which Sigma rules fire.

`simulate.py` replays about an hour of traffic. Most of it is normal people asking about hours. Mixed in:

| Time | What happens | What should catch it |
|------|--------------|----------------------|
| 09:15 | 12 forged webhook requests from one IP, plus one stray from another IP | Burst rule fires once, for the first IP only |
| 09:27 | Prompt injection that the model falls for. It tries to text an international number | Injection flag, then the policy check blocks the text |
| 09:46 | The model repeats its system prompt | Canary token catches it before the reply goes out |
| 09:50 | MMS with a media URL pointing at the cloud metadata address | Media host check |
| 09:55 | One number sends 15 messages in 3 minutes | Inbound rate limit kicks in after 10 |
| 10:03 | A text from a Cuban number | High risk destination rule on the reply |

`evaluate.py` loads the rules from `detections/` with pySigma and runs them over the log file. It only supports the Sigma features these rules use. For anything real you'd convert the rules with sigma-cli and run them in a SIEM.

## Running it

```bash
pip install -r reference/requirements-dev.txt pysigma
python demo/simulate.py > demo/sample_events.jsonl
python demo/evaluate.py demo/sample_events.jsonl --min-level medium
```

The output from the last run is in [`alerts.txt`](alerts.txt), and the raw logs are in [`sample_events.jsonl`](sample_events.jsonl).

## What the tests check

- Every attack above sets off the rule it should
- Normal traffic on its own sets off nothing
- One bad request doesn't trip the burst rule
- The rate limit keeps the flooding number under the SMS pumping threshold, so that rule stays quiet. It's a backup for when the limiter isn't working.
- No raw phone numbers end up in the logs
- `sample_events.jsonl` matches what the simulator produces now

## Things I noticed building this

The first version of the app only rate limited tool calls, not inbound messages. A number that just kept texting "hello?" got a paid reply every time, and the pumping rule was the only thing that would have noticed. Adding the inbound limit fixed that. That's the kind of gap you only find by actually running the traffic.
