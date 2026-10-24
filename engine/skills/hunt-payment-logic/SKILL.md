---
name: hunt-payment-logic
description: "Hunt payment and billing logic flaws — price tampering, negative amounts, currency confusion, coupon stacking, race conditions on charges, refund abuse, free trial bypass, subscription downgrades keeping paid features. Use when a target has payments, billing, subscriptions, coupons, credits, or e-commerce checkout."
---

## Decision tree

| You see | Do once | Proves |
|---|---|---|
| Price/amount in client-side request body | Change `amount` to `0`, `-1`, or `0.01` | Charge succeeds at manipulated price |
| Currency parameter (`currency`, `cur`) | Pay in weakest currency, check credit in strongest | Credit mismatch: paid $0.01 VND, credited $0.01 USD |
| Coupon/promo code field | Apply same code twice, apply two codes, apply after checkout | Discount stacks or applies when it shouldn't |
| Quantity field | Set `quantity: -1` or `quantity: 999999` with unit price | Negative total or overflow |
| Refund endpoint | Refund more than original amount, refund twice | Balance exceeds original payment |
| Free trial signup | Re-register with same payment method, different email | Unlimited free trials |
| Subscription tier change | Downgrade plan, check if premium features persist | Access to paid features on free plan |

## Price/amount tampering

Intercept the payment request. Fields to modify:
```json
{"amount": 0, "price": 1, "total": 0.01, "unit_price": -100,
 "quantity": -1, "discount": 99999, "tax": -50}
```

Test both the checkout/charge endpoint AND the cart/order creation endpoint — some validate at charge but not at cart.

Integer overflow: `amount: 2147483647` (int32 max) or `amount: 99999999999` may wrap to negative.

## Currency confusion

```bash
# Pay in cheap currency
curl -X POST "$TARGET/api/checkout" -d '{"amount":100,"currency":"VND"}' -H "Authorization: Bearer $A"
# Check balance — was it credited as 100 USD?
curl "$TARGET/api/balance" -H "Authorization: Bearer $A"
```

Also test: changing currency between cart creation and payment completion. The conversion may not re-validate.

## Coupon / promo abuse

```bash
# Apply same coupon twice
curl -X POST "$TARGET/api/cart/coupon" -d '{"code":"SAVE50"}' -H "Authorization: Bearer $A"
curl -X POST "$TARGET/api/cart/coupon" -d '{"code":"SAVE50"}' -H "Authorization: Bearer $A"

# Stack different coupons
curl -X POST "$TARGET/api/cart/coupon" -d '{"code":"SAVE50"}' -H "Authorization: Bearer $A"
curl -X POST "$TARGET/api/cart/coupon" -d '{"code":"WELCOME20"}' -H "Authorization: Bearer $A"

# Apply coupon after payment is initiated
# (start checkout, then apply coupon, then complete payment)
```

## Race condition (TOCTOU)

Send the same payment completion request concurrently:
```bash
# Use GNU parallel or curl in background
for i in $(seq 1 5); do
  curl -X POST "$TARGET/api/payment/complete" \
    -d '{"payment_id":"PAY_123","token":"tok_abc"}' \
    -H "Authorization: Bearer $A" &
done
wait
# Check: was the credit applied multiple times?
curl "$TARGET/api/balance" -H "Authorization: Bearer $A"
```

## Refund abuse

```bash
# Modify refund amount to exceed original
curl -X POST "$TARGET/api/refund" -d '{"order_id":"ORD_123","amount":999}' -H "Authorization: Bearer $A"

# Double refund
curl -X POST "$TARGET/api/refund" -d '{"order_id":"ORD_123"}' -H "Authorization: Bearer $A"
curl -X POST "$TARGET/api/refund" -d '{"order_id":"ORD_123"}' -H "Authorization: Bearer $A"
```

## Subscription downgrade

1. Subscribe to premium plan
2. Use premium feature, note the API endpoint
3. Downgrade to free plan
4. Call the premium API endpoint again — does it still work?

Also: cancel subscription, check if access persists past billing cycle end date.

## Validation

- **Re-read after every write.** `GET /balance`, `GET /order`, `GET /subscription` to confirm the state actually changed.
- Price tamper: the order completed AND the charged amount matches your tampered value (check payment provider if possible).
- Race: balance or credit increased by more than one payment's worth.
- Coupon: total reflects double discount, not just a 200 OK on the second apply.
- Refund: balance exceeds what was originally paid.

A 200 OK on a modified request is NOT proof. The actual financial state must reflect the manipulation.

## Chains

- Price tamper to $0 → free access to paid features → `hunt-business-logic`
- Race condition on credits → infinite balance → `hunt-idor` if credits transfer to other users
- Subscription bypass → access premium API → `hunt-api-misconfig` (hidden premium endpoints)

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class payment-logic --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop. Draft only — do not submit.

Cross-refs: `hunt-business-logic`, `hunt-race`, `hunt-idor`, `hunt-api-misconfig`.
