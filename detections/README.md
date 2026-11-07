# Detections

Sigma rules for the risks in the main README. They run against the JSON logs described in [docs/architecture.md](../docs/architecture.md#what-id-log), and the reference app in [`reference/`](../reference) writes logs in that format.

`logsource` is `product: phone_assistant`, `service: app`. That's a custom log source, so you need a small pipeline or field mapping for whatever SIEM you're converting to.

| Rule | Level | Risk |
|------|-------|------|
| `webhook_bad_signature.yml` | low | 6 |
| `webhook_bad_signature_burst.yml` (correlation) | high | 6 |
| `outbound_not_allowlisted.yml` | high | 1, 5 |
| `premium_destination.yml` | medium | 5 |
| `sms_outbound.yml` (base rule) | informational | |
| `sms_pumping_volume.yml` (correlation) | high | 5, 8 |
| `prompt_injection_attempt.yml` | medium | 1, 2 |
| `system_prompt_canary_leak.yml` | critical | 3 |
| `mms_media_ssrf.yml` | high | 2 |

## Checking and converting

```bash
pip install sigma-cli
sigma check detections/

# example: convert to Splunk SPL
sigma plugin install splunk
sigma convert -t splunk --without-pipeline detections/
```

## Notes

- The country list in `premium_destination.yml` is a starting point, not a definitive list. Your telephony provider usually publishes which destinations get hit by fraud most. Tune it to where the business actually has customers.
- The thresholds (10 in 5 minutes, 20 in 10 minutes) are guesses for a small deployment. Look at a few weeks of normal traffic and set them above that.
- Spend alerts are better done with the provider's own usage triggers plus a budget alert in the cloud account than with a Sigma rule.
