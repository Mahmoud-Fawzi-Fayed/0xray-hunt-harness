---
name: hunt-hypothesis
description: "Invent the next test from the live response, not from a vulnerability catalog. Developer-psychology hypothesis ranking, lateral chaining, response-anomaly pattern recognition. Use on every deep hunt when the URL is unknown, when the last look returned nothing, or when the worklist is empty but a session is live."
---

# hunt-hypothesis — Invent Tests from Live Bytes

Do not start from a class list (SQLi, XSS, IDOR, …). Those lists make the model replay the same probes and close the URL. Start from the bytes on the wire for THIS request, then invent a test that would be false if the developer had been careful.

## Core loop — SEE → INVENT → TEST → CHAIN

### 1. SEE — Read the response like a developer wrote it

Send the request as the logged-in test user. Read status, headers, and body.
- **Every input:** params, headers, cookies, JSON body fields, file uploads, content-type variants
- **Every object ID:** user_id, org_id, invoice_id — note the format (sequential? UUID v4? v1/v7 time-ordered? base64?)
- **Every trust boundary:** who the caller is, which object is named, which other host the server might talk to
- **Every assumption:** what the developer assumed the client would never send

### 2. INVENT — Developer psychology hypotheses

The developer made assumptions. Name them:

| Developer assumption | Hypothesis | Test |
|---|---|---|
| "The client always sends the user's own ID" | What if I send another user's ID? | Swap `user_id` in the request, compare response bodies |
| "Auth is checked on this endpoint" | What if I strip the session cookie? | Send without auth — 200 with data = auth bypass |
| "This field is read-only" | What if I add `role`, `is_admin`, `verified` to the JSON body? | POST/PUT with extra fields — mass assignment |
| "The ID is unguessable" | What if it's sequential or time-ordered? | Check: is `id+1` or `id-1` valid? Is UUID v1/v7? |
| "This internal endpoint isn't reachable" | What if the path exists but isn't linked in the UI? | Try `/admin/*`, `/internal/*`, `/debug/*`, `/api/v1/*` vs `/api/v2/*` |
| "Rate limiting protects this" | What if the limit is per-IP only? | Change `X-Forwarded-For` — does the limit reset? |
| "Content-type is always JSON" | What if I send XML? | Switch to `application/xml` — XXE if parsed |
| "This redirect only goes to our domain" | What if I use `//evil.com` or `\/evil.com`? | Open redirect → OAuth token theft chain |
| "GraphQL queries are read-only" | What if mutations are exposed? | Introspection or guess mutation names from query names |

### 3. TEST — One variable at a time

- Use unique markers (8+ random chars) so you can grep the response for YOUR input
- Compare bodies, not status codes — a 200 with different data is the signal
- Time-based: n>=10 timings against a fast baseline, not just one slow request
- OOB: for blind vulns, use collaborator/interactsh — DNS is not enough, need HTTP callback with data

### 4. CHAIN — Lateral movement from primitives to impact

Single primitives often don't pay. Chains do:

| Primitive found | Chain to | Impact |
|---|---|---|
| Open redirect | → OAuth `redirect_uri` bypass → token theft | ATO (Critical) |
| XSS (reflected) | → steal admin session → CSRF password change | ATO (Critical) |
| IDOR (read) | → read email/phone → password reset → ATO | ATO (High→Critical) |
| SSRF (blind) | → hit cloud metadata → AWS keys → RCE | RCE (Critical) |
| Info leak (source maps) | → find hardcoded API keys → access internal APIs | Data breach (High) |
| CORS misconfiguration | → credentialed cross-origin read → steal PII | Data theft (High) |
| Race condition (coupon) | → apply coupon N times → financial impact | Business logic (Medium→High) |

## Response anomalies that signal bugs

- **Different error messages** for existing vs non-existing resources → enumeration oracle
- **Timing differences** (200ms vs 20ms) → blind injection or side-channel
- **Inconsistent field names** between endpoints (camelCase vs snake_case) → different backend, different auth
- **Missing fields** in one role vs another → the field exists but is filtered client-side
- **Version header drift** across subdomains → older version = older bugs
- **Stack trace in error** → framework + version → known CVEs
- **JWT with `alg: HS256`** and a public key available → key confusion
- **Set-Cookie without HttpOnly/Secure** → XSS → session theft feasible

## When the worklist is empty

1. Run `browser.py capture` on the seed URLs — SPA XHR/fetch calls are the REAL surface
2. Grep JS bundles for `/api/`, `fetch(`, `axios.`, `graphql`, endpoint patterns
3. Check for undocumented API versions (`/v1/` → try `/v2/`, `/v3/`, `/internal/`)
4. Look at mobile API endpoints (different auth, often less restricted)
5. Check WebSocket connections — different protocol, often different auth model
6. Run `learn.py auto` on the stack if no skill matches what you're seeing

## Where ideas come from

The live response, linked JS, OpenAPI/GraphQL the session can see, and the hunt memory block (previous look, missed signals, open hypotheses). Public writeups for THIS stack only after you have named the stack from the response.

A hunt-* skill is a reference AFTER you have a hypothesis that matches it. It is not the menu.

## Not a finding

Reflection of your marker, an error page, a missing header, a 401 on a logged-out call, a marketing HTML page, identical A/B bodies, a scanner-class issue with no attacker-attainable harm.

## Anti-patterns

- Walking a vulnerability catalog instead of reasoning from the response
- Testing SQLi on a static CDN or a GraphQL endpoint that doesn't touch SQL
- Repeating the same test that failed last time with a slightly different payload
- Claiming severity without demonstrated impact (e.g. "could lead to RCE" without RCE)
- Ignoring auth context — testing unauthenticated when the bug requires auth

## Return

The JSON the harness asked for. Put unused ideas in `hypotheses`. Put things you saw and did not prove in `signals_missed`. Those feed the next round. Do not empty them to look finished.
