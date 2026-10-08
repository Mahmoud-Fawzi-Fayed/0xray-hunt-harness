---
name: hunt-webhook
description: "Hunt webhook & callback-URL vulnerabilities — SSRF via user-controlled callback/notification URLs (reaching cloud metadata / internal services), missing or bypassable signature verification on inbound webhooks, event replay (no idempotency -> double-processed state changes), cross-tenant webhook-subscription IDOR, SSRF allow-list bypass on callback hosts, and outbound data leakage to attacker URLs. Use on any /webhooks, /hooks, /integrations, /callback, or 'notification URL' feature."
sources: 0xray-authored
---

# HUNT-WEBHOOK — Webhook & callback-URL abuse

Two different bugs share the word "webhook". Classify first:

- **Outbound (you choose their URL).** The server sends an event to a URL you control. Bug classes: SSRF, data leak to an attacker host, allow-list bypass, secret-in-query leakage.
- **Inbound (they POST to the app).** A provider-style receiver accepts events. Bug classes: missing/forgeable signature, replay, event-type confusion, cross-tenant routing.

A webhook that delivers **your** event to **your** URL is the feature. It becomes a finding only with internal reach, another tenant's data, or a forged/replayed event that changes state.

## Decision tree

1. Find every field: `url`, `callback_url`, `notification_url`, `endpoint`, `target_url`, `webhook_url`, `hook_url`, `return_url`, plus Integration / Developer settings and `/webhooks`, `/hooks`, `/integrations`, `/callbacks`, `/subscriptions`.
2. **Outbound?** Register your OOB host (unique path per sink). Wait for the delivery — many products queue it. Record source IP, User-Agent, redirects followed, and which headers the product lets you set.
3. If the HTTP callback arrived, try one internal target (metadata or `127.0.0.1` on a known port). Prefer a product "custom headers" feature to send `Metadata-Flavor: Google`, `Metadata: true`, or `X-aws-ec2-metadata-token`.
4. **Inbound?** Capture one real delivery. Replay it unchanged. Then mutate the body with the signature stripped, blank, and mismatched. Watch **state**, not the HTTP status.
5. **IDOR?** Point your URL at an event subscription whose id, org, or project belongs to account B. Proof is B's payload at your listener.

## 1) Outbound SSRF and leaks

Confirm the fetch first (`https://<sink>-<rand>.<oob>/`). DNS-only means the resolver ran; an HTTP hit from their IP means the dispatcher fetched. Then one internal URL, not a port sweep (`hunt-ssrf` bypass table: decimal/octal/IPv6, `@` confusion, DNS rebinding, 30x from an allowlisted host, `http://allowed.attacker.com`).

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/api/token          (IMDSv2 PUT + header; only if the client can set method/headers)
http://169.254.170.2/                            (ECS/EKS task role; append the relative URI the environment would use)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/opc/v2/instance/          (Oracle; needs Authorization: Bearer Oracle — same header gate)
http://100.100.100.200/latest/meta-data/         (Alibaba)
http://127.0.0.1:80/
```

The synchronous "save / test / ping" request and the queued worker are different clients. Probe each once. A hit on only one of them is still the finding.

Header gate (this is the usual metadata miss): GCP returns 403 without `Metadata-Flavor: Google`; Azure returns 400 without `Metadata: true`; IMDSv2 returns 401 without the token header; Oracle returns 401 without `Authorization: Bearer Oracle`. Those error bodies **are** proof you reached link-local. Credential theft needs the header. Paths that add it:

- The webhook form has custom headers → set the one header, resend once.
- The URL is passed to a raw client → CRLF in the URL (`%0d%0aMetadata-Flavor:%20Google`) if the client does not strip CR/LF. Prove with the metadata body or a Collaborator request that shows the injected header, not with a theory.
- The dispatcher follows redirects → 302 from your host does **not** add third-party headers. Use CRLF or a custom-header field instead.

Also try non-HTTP schemes once (`file:///etc/passwd`, `gopher://127.0.0.1:6379/`, `dict://127.0.0.1:6379/`) when the value is not forced to `https`. A scheme error that echoes `file` is not a read.

**Data leak without SSRF:** the delivery body contains another user's events, or the signing secret is appended to the query string and shows up in your access log. Quote the field. Your own test event is not a leak.

**Allow-list:** validation that fetches you and then follows your 302, or that checks the host string but not the DNS answer (rebinding). One successful internal response or one OOB hit from the internal hop is enough.

## 2) Inbound signature

Test in this order. Stop at the first one that changes persisted state.

| Test | Passes if |
|---|---|
| Header omitted | Event applied (order paid, user created, flag flipped) |
| Empty / `sha256=` / wrong hex of the right length | Same |
| Old algorithm still accepted (`X-Hub-Signature` sha1 when sha256 exists, `v0` vs `v1`) | Forged body accepted |
| Secret is in the JS bundle, docs, mobile app, or a sample repo | You compute the real HMAC and the forged event sticks |
| Timestamp window (Stripe-style `t=`, Svix `webhook-timestamp`) | A captured signature still works after the documented tolerance, or `t` is not checked |
| Valid signature headers copied onto a **different** body | State changes — the signature is not bound to this body |
| Content-Type the verifier skips (`text/plain`, empty, `application/json; charset=utf-16`) while the handler still applies the JSON | Forged body persisted |
| Duplicate JSON keys in **one** body (`{"type":"payment.failed","type":"payment.succeeded"}`) under a valid HMAC of the raw bytes | Verifier and handler parse different winners (first vs last key) — the handler's object changes state |
| HMAC is over `json.dumps(parsed)` / a canonical form, not the wire bytes | A body that canonicalizes to the signed form but parses to a different event persists |

Compute HMAC only for a secret you already have. Do not brute-force the signing key.

Provider header names vary (`Stripe-Signature`, `X-Hub-Signature-256`, `X-Shopify-Hmac-Sha256`, `X-Signature`, `svix-signature`). The test is the same: does the handler bind the signature to **this** body and **this** tenant?

HMAC-then-parse split: many verifiers hash the raw bytes, then a second parser applies the event. Duplicate keys, Unicode normalization, or `json.dumps` re-serialization make those two views diverge. Keep the captured signature, change only the JSON shape, re-read the object. Proof is the **handler's** state, not a 200 from the verifier.

**Event-type confusion:** keep a valid signature if you must, but also try an unsigned body that flips `type` (`payment.failed` → `payment.succeeded`, `test` → `live`). Impact is the object that changed, shown by reading it back.

## 3) Replay

Re-POST one captured delivery N times (N≈10, not thousands). If there is no event-id / idempotency dedup, each replay re-applies the effect. Proof is the **after** state: balance, credit count, order status, seat count. N× HTTP 200 with unchanged state is not a bug. See `hunt-race-condition` for the concurrent variant (same event in one packet).

## 4) Cross-tenant subscription

`POST /webhooks` or `PUT /webhooks/{id}` with B's org/project/account id and your URL. Also try `GET /webhooks/{id}` for B's secret or historical deliveries. Proof: one payload that contains B's identifier or data you did not create. Your own subscription echoing your own action is the feature (`hunt-idor`).

## Validation

| Sub-class | Proof | Not proof |
|---|---|---|
| SSRF | Internal body (metadata, `localhost` banner) **or** OOB HTTP hit that could only come from an internal hop | Error string that echoes your URL; DNS-only on a public host; "I set the URL to localhost" |
| Signature bypass | Forged or stripped-signature event **and** a persisted state change you can re-read | HTTP 200 with no object change |
| Parse split | Valid HMAC of the raw bytes; handler applies a duplicate-key / re-serialized view that changes state | Two parsers agree; only whitespace differed |
| Replay | Same event id applied twice; show the counter/balance before and after | Repeated 200s |
| Cross-tenant | B's event body at your listener, or B's webhook secret via IDOR | A list of your own endpoints |
| Secret in URL | The secret appears in the request your server received | A secret shown once in the owner's settings UI |

Unique marker per sink (`/<rand>`). Body-diff the business object. Blind deliveries: wait for the queue; do not retract on a 30s poll.

## Chains

- Webhook SSRF → cloud role creds → `cloud-iam-deep` (read-only `sts get-caller-identity` / one scoped read).
- Forged `payment.succeeded` → order marked paid → `hunt-business-logic`.
- Replay of a credit/refund → double balance → `hunt-race-condition`.
- Cross-tenant stream → PII or internal URLs → further IDOR.
- Custom-header SSRF → IMDSv2/GCP/Azure header requirement bypassed.

## Rails

- In-scope only. One test subscription, one internal URL, one forged event. Do not mass-create hooks or dump another tenant's backlog.
- No signing-secret brute-force. No traffic flood against the receiver.
- Draft only — do not submit.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class ssrf --url "<endpoint>" --title "<title>"
```

Use class `idor` or `business-logic` when that is the actual bug. `NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the endpoint, event type, or bypass is a concrete differentiator.

Cross-refs: `hunt-ssrf`, `hunt-idor`, `hunt-race-condition`, `hunt-business-logic`, `triage-validation`.
