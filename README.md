# AI Phone Service Threat Model

A quick threat model for an AI phone service I'm building. It takes voice calls, and I'm adding MMS support. This is a design review, not a pentest report. There's no client data or real numbers in here.

## How it works

A caller talks or texts. Speech gets turned into text, an LLM decides what to say, it may trigger some backend actions, and the reply goes back out by voice or message. Every one of those hand-offs is a place something can go wrong.

## Risks

| # | Risk | Rating | What I'd do about it |
|---|------|--------|----------------------|
| 1 | Prompt injection through what the caller says or types | High | Keep system instructions apart from caller input. Limit what the model can do. Check every tool call outside the model before it runs. |
| 2 | Injection hidden in MMS images or attachments | High | Treat all media as untrusted. Never let text pulled from an image trigger an action. |
| 3 | Data leakage: the model exposing its prompt, config, or another caller's info | High | One session per caller, no shared memory between callers, no secrets in prompts. |
| 4 | Someone impersonating a customer to the assistant | Medium | Confirm identity another way before any account action. No sensitive actions on voice alone. |
| 5 | Tool misuse: toll fraud, spam texts, expensive loops | Medium | Rate limits, spend caps, allowlist for outbound numbers, alerts on spikes. |
| 6 | Fake webhook requests pretending to be the telephony provider | Medium | Verify request signatures and use HTTPS only. |
| 7 | Call and message logs holding sensitive info | Medium | Store the minimum, encrypt it, set retention limits, mask phone numbers in logs. |
| 8 | Call flooding that causes outages or a huge bill | Low to Medium | Concurrency caps, rate limiting, budget alerts. |
| 9 | The assistant giving a wrong answer with confidence | Medium | Keep its scope narrow, hand off to a human when unsure, review transcripts. |

## Tests I plan to run

- A set of prompt injection and jailbreak strings against both the call and text paths
- Cross-session leak checks using two test numbers
- Forged webhook requests
- An MMS with injected instructions hidden in an image

## Notes

Ratings are my own call on likelihood and impact, not a formal scoring system. The risk categories follow the OWASP Top 10 for LLM Applications. I'll update this as I run the tests. Feedback is welcome.
