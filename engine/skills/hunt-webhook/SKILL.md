---
name: hunt-webhook
description: "Hunt webhook & callback-URL vulnerabilities — SSRF via user-controlled callback/notification URLs (reaching cloud metadata / internal services), missing or bypassable signature verification on inbound webhooks, event replay (no idempotency -> double-processed state changes), cross-tenant webhook-subscription IDOR, SSRF allow-list bypass on callback hosts, and outbound data leakage to attacker URLs. Use on any /webhooks, /hooks, /integrations, /callback, or 'notification URL' feature."
sources: 0xray-authored
---

# HUNT-WEBHOOK — Webhook & Callback-URL Abuse

Webhooks hand an attacker-influenceable URL to the server and have it make an **authenticated
outbound request** to that URL — frequently from inside the trust boundary. That is a first-class
SSRF primitive, bundled with a cluster of auth/idempotency bugs on the inbound receiver side.

## What actually pays (and what does not)

- **SSRF to a sensitive internal target** with the **response body** (or an OOB callback carrying
  internal data) proving the request landed. A webhook that only resolves DNS, or returns a generic
  error, is *not yet* a finding — apply the OOB-or-it-didn't-happen gate from `hunt-ssrf`.
- **Signature verification missing or bypassable** AND a forged event drives a **persisted** state
  change (e.g. a forged `payment.succeeded` marks an order paid).
- **Replay without idempotency** where re-sending a captured signed event re-applies a state change
  (double credit, double fulfilment).
- **Cross-tenant subscription (IDOR)** where you register your URL to receive **another tenant's**
  events — prove it by capturing a victim tenant's payload.

What does **not** pay: a webhook posting to *your own* configured URL with *your own* data (that is
the feature); a 200 on a callback with no internal reach or state effect; "I could point it at
localhost" with no evidence the request was actually made.

## Where to look
- Settings -> Integrations / Developer / Webhooks; `/webhooks`, `/hooks`, `/api/*/webhooks`,
  `/integrations`, `/callbacks`, `/notifications`, `/subscribe`.
- Any field named `url`, `callback_url`, `notification_url`, `endpoint`, `target_url`,
  `webhook_url`, `return_url`.
- Inbound webhook *receivers* (them -> you): Stripe/GitHub/Shopify-style endpoints that verify
  `Stripe-Signature`, `X-Hub-Signature-256`, `X-Signature`.

## 1) SSRF via the callback URL
Point the webhook at your OOB listener first to confirm the server fetches it — note the **source IP**,
the User-Agent, and whether it **follows redirects**. Then pivot inward:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/     # AWS IMDSv1
http://metadata.google.internal/computeMetadata/v1/                   # GCP (needs Metadata-Flavor: Google)
http://127.0.0.1:<port>/   http://[::1]/   http://localhost/
```

Confirm with the response body surfaced in the delivery log, or an OOB hit carrying internal data.
Bypass allow-lists with the `hunt-ssrf` table: decimal/octal/IPv6 encodings, `@`-confusion,
DNS rebinding, an open redirect on an allowed host, or `http://allowed.com.attacker.com`.

## 2) Signature verification (inbound receivers)
- Strip the signature header entirely — is the event still accepted?
- Send an empty / garbage signature — accepted?
- If the signing secret is **publishable or leaked** (JS bundle, APK, docs sample, repo), forge a
  valid signature.
- Try algorithm downgrade on the receiver (HMAC-SHA256 -> none / plaintext compare).

Prove impact: a forged inbound event must drive a **persisted** state change, not just a 200.

## 3) Replay / idempotency
Capture one legitimately-signed delivery and re-POST it N times. If the handler has no idempotency
key / event-id dedup, each replay re-applies the effect. Show the **state after** replay (balance,
order count, credits) — not just N×200. See `hunt-race-condition` for the single-packet variant.

## 4) Cross-tenant subscription (IDOR)
Subscribe your URL to an event type scoped to another tenant/object id. If you start receiving their
payloads, that is cross-tenant data exfiltration — prove it with a captured payload belonging to
victim B. See `hunt-idor`.

## PoC minimums
| Sub-class | Minimum proof |
|---|---|
| Webhook SSRF | internal response body, or OOB callback carrying internal data |
| Signature bypass | forged event accepted **and** state change persisted |
| Replay | duplicate processing visible in state after N replays |
| Cross-tenant | another tenant's event payload received at your URL |

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class ssrf --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).

Cross-references: `hunt-ssrf`, `hunt-idor`, `hunt-api-misconfig`, `hunt-race-condition`,
`security-arsenal`, `triage-validation`.
