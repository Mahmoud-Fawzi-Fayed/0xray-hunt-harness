---
name: hunt-business-logic
description: Hunting skill for business logic vulnerabilities. Built from public bug bounty reports. Covers price and quantity tampering, coupon and credit abuse, step-skip and state-machine bugs, webhook trust, quota bypass, and cross-user workflow IDOR. Use when hunting business logic on any target — financial impact must be demonstrated, not assumed.
sources: hackerone_public, github
report_count: 12
---

# HUNT-BUSINESS-LOGIC

The server trusts the client, or trusts a step the client can skip, about money, identity, or entitlement. Prove the **stored** outcome (order total, balance, role, flag), not a UI glitch.

## Decision tree

| Flow you have | First abuse | Proof |
|---|---|---|
| Checkout / cart / invoice | Client `price`, `qty`, `currency`, `product_id` | Order object total ≠ catalog price. One order |
| Coupon / gift card / credit | Replay, stack, negative, or parallel redeem | Balance or redemption count changed twice (`hunt-race-condition`) |
| Subscription / trial | `trial_end`, `plan`, `price_id`, re-subscribe | Account flag shows the unpaid plan |
| Verify email / phone / KYC | Call the post-verify endpoint with an unverified session; replay A's token on B | Feature flag flips without owning the mailbox/phone |
| Quota (invites, seats, free tier) | Two creates that the limit should block, or a race of ~10 | Count of resources > cap |
| Webhook / return URL from a PSP | Unsigned `status=paid` (`hunt-webhook`) | Order moves to paid without a real charge |
| Transfer / refund | `beneficiary_id` = B, or refund after you keep the item | B's balance or the ledger entry |
| Multi-step wizard | Jump to the last step's API | State machine accepts `complete` from `new` |
| Store receipt / license / IAP | Replay A's valid receipt or license on account B once | B's entitlement flips. Do not forge or crack the store signature |
| Refund | `amount` above the capture, or a different currency / unit (cents vs dollars) | The ledger entry is the larger refund. One refund |
| Approval / workflow | `approver_id` or `reviewer_id` set to yourself on your own request | Stored state becomes approved |

If the endpoint never changes server state, it is not this class.

## Price, quantity, currency

Send the tamper on the **server** request that creates the charge or the order, not only the browser total.

```json
{"items":[{"id":"SKU","qty":1,"price":0.01},{"id":"SKU2","qty":-1,"price":100}]}
{"qty":0.0001,"price":1,"currency":"JPY"}
{"qty":1e-10,"amount":"0.00","product_id":"EXPENSIVE"}
```

```http
amount=0.01&currency=USD&order_id=ORDER&product_id=SKU
```

What to vary, one at a time: `price` / `amount` / `unit_amount`, `qty` (0, negative, fraction, huge), `currency` (zero-decimal vs two-decimal), `product_id` swapped after the price was quoted, `tax` / `shipping` negative, coupon stacked with a sale price. Integer overflow on a cents field (`qty` × `price` wraps) shows up as a tiny or negative server total. Dual values: `amount=100&amount=1` (parser last/first), locale `"1,00"` vs `"1.00"`, and a top-level `amount` that disagrees with the line-item array. PSP vs app: if the client also sends a PaymentIntent / `client_secret`, the **order object** must match the PSP amount — a $1 intent attached to a $100 SKU is the finding.

Re-read `GET /orders/{id}` (or the PSP line item). The finding is the amount the **server** will capture. Do not mass-order. If a real card would be charged or goods shipped, stop at the order-create response that already shows the wrong total unless the program told you to finish payment.

Mass-assignment cousin: body includes `price`, `plan_id`, `discount`, `role` because the update DTO and the database model are the same object (`hunt-api-misconfig`).

## Step skip and state

- Map the wizard's API calls. Replay the last one with a fresh session that never called the earlier steps.
- Flip `status`, `verified`, `paid`, `role`, `step` in the JSON. Re-read.
- Email/phone: the UI gates the button; `POST /api/enable` with the unverified session often does not. Token reuse: A's verify token bound to B's account.
- Callback number: submit a number you do not control and see whether trust is granted **before** OTP. Do not send OTPs to strangers. Do not guess OTP codes.
- Internal/staff storefronts linked from JS, `robots.txt`, or old bundles: one unauthenticated load of the order API. Obscurity is not the bug — the missing authz on the order is.

## Quotas and rate limits

A limit that is real fails closed without spoofed headers. Send ~10 identical authorized actions (invite, promo claim, free-tier create). If all succeed where the cap is 1, you have a logic bug. If they fail until you rotate `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` / `True-Client-IP`, the app is taking the client IP from a header — show one blocked request and one allowed request.

Do not turn this into password, OTP, or API-key guessing. Do not send hundreds of emails.

Parallel duplicate of a **one-time** claim is `hunt-race-condition` (last-byte sync). Sequential replay that keeps working is missing idempotency — still this skill.

## Webhooks and client-trusted payment

```bash
curl -s -X POST "https://$TARGET/payment/callback" -H 'Content-Type: application/json' \
  -d '{"status":"success","amount":"0.01","order_id":"ORDER","transaction_id":"marker-'"$RAND"'"}'
```

Impact is the order moving to paid (re-read it). A `200` that does not change the order is not a bypass. Unsigned webhooks, empty signatures, and replays are `hunt-webhook`. Test the signature; do not brute-force it.

## Validation

1. **State before and after**, with ids. "The UI showed $0" is not enough if the server invoice says full price.
2. **Attacker position:** fresh account or no account. A bug that needs the admin panel you already have is self-inflicted.
3. **One reproduction** a reviewer can repeat. Flaky only under a race → measure it with the race skill (n≥10, success more than once) instead of a single lucky click.
4. **Loss is concrete:** wrong amount on a real order object, unpaid entitlement flag, another user's verification, quota exceeded. "The flow looks odd" is not a report.

## Chains

| Logic bug | Chain | Impact |
|---|---|---|
| Client price accepted | — | Pay catalog value for a token amount |
| Coupon / credit check-then-act | `hunt-race-condition` single-packet | N redemptions of a one-use code |
| `beneficiary_id` / `account_id` from the client | `hunt-idor` | Move value from B |
| `verified` / `role` writable | `hunt-api-misconfig` | Skip KYC or become a privileged plan |
| Email-change without re-auth | `hunt-ato` | Reset lands in the attacker's mailbox |
| Receipt replay / self-approval | second test account | Unpaid entitlement, or an approval you granted yourself |
| Unsigned PSP callback | `hunt-webhook` | Free goods |
| Staff route from a bundle | `changed-js-deepdive` | Unauthenticated order API |

## Rails

- In-scope only. One order, one coupon race, one forged callback. No bulk fraud, no shipping a cart full of goods, no carding.
- No OTP/password keyspace exhaustion. No email-bomb "rate-limit proof".
- Draft only — do not submit. Claim the dollar or state effect you actually caused, nothing larger.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class business-logic --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the parameter or the fix bypass is a concrete differentiator.

Cross-refs: `hunt-race-condition`, `hunt-idor`, `hunt-webhook`, `hunt-api-misconfig`, `hunt-ato`, `triage-validation`.
