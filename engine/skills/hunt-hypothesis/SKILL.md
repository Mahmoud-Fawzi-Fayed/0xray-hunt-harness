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

Name one assumption actually supported by the baseline. Vary only the dimension that assumption concerns:
- **Actors and ownership:** would the same operation be safe for another role, tenant, owner, or accessor?
- **Inputs and parsers:** which accepted value, encoding, content type, or parser assumption could change behavior?
- **State and sequence:** what precondition, transition, replay, or second-order effect should be impossible?
- **External effects:** which callback, integration, or downstream trust relationship is visible in the response?
- **Protocol behavior:** what does this protocol's actual negotiation or framing assume?

Record the baseline observation IDs. Only after the hypothesis is concrete, call `skill_map.for_hypothesis(...)` with those IDs; without them the harness returns methodology only. Test one dimension at a time and leave every other dimension unresolved.

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

1. Re-check discovery source status; failed or unattempted sources are unknown, not empty surface
2. Run authenticated browser capture when the observed application uses a SPA or client-side calls
3. Mine observed responses, schemas, and bundles for relationships to operations not yet profiled
4. Expand only from live links, `Allow` evidence, documented operations, and supplied artifacts—not guessed path lists
5. Record inaccessible protocols or roles as blocked and continue with validated surface
6. Run `learn.py auto` only after live behavior reveals a concrete knowledge gap

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
