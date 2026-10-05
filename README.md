# Threat Model: LLM Phone and SMS Assistants

A quick, general threat model for AI assistants that take voice calls and text or MMS messages. It's a design level look at common risks, not a pentest report and not a review of any specific product.

## How these systems work

A caller talks or texts. Speech gets turned into text, an LLM decides what to say, it may trigger backend actions, and the reply goes back out by voice or message. Every one of those hand-offs is a place something can go wrong.

## Common risks

| # | Risk | Typical rating | Common mitigations |
|---|------|----------------|--------------------|
| 1 | Prompt injection through what the caller says or types | High | Keep system instructions apart from caller input. Limit what the model can do. Check every tool call outside the model before it runs. |
| 2 | Injection hidden in MMS images or attachments | High | Treat all media as untrusted. Never let text pulled from an image trigger an action. |
| 3 | Data leakage: the model exposing its prompt, config, or another caller's info | High | One session per caller, no shared memory between callers, no secrets in prompts. |
| 4 | Someone impersonating a customer to the assistant | Medium | Confirm identity another way before any account action. No sensitive actions on voice alone. |
| 5 | Tool misuse: toll fraud, spam texts, expensive loops | Medium | Rate limits, spend caps, allowlist for outbound numbers, alerts on spikes. |
| 6 | Fake webhook requests pretending to be the telephony provider | Medium | Verify request signatures and use HTTPS only. |
| 7 | Call and message logs holding sensitive info | Medium | Store the minimum, encrypt it, set retention limits, mask phone numbers in logs. |
| 8 | Call flooding that causes outages or a huge bill | Low to Medium | Concurrency caps, rate limiting, budget alerts. |
| 9 | The assistant giving a wrong answer with confidence | Medium | Keep its scope narrow, hand off to a human when unsure, review transcripts. |

## Tests worth running

- A set of prompt injection and jailbreak strings against both the call and text paths
- Cross-session leak checks using two test numbers
- Forged webhook requests
- An MMS with injected instructions hidden in an image

## Notes

Ratings are a general judgment of likelihood and impact for a typical deployment, not a formal scoring system. The categories follow the OWASP Top 10 for LLM Applications. Feedback is welcome.
