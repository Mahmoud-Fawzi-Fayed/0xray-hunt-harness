# hunt-methodology — Analysis-Driven Endpoint Pentest

Reference methodology for deep endpoint hunting. Read this when you need structured guidance — it is not mandatory for every endpoint.

## Step 1 — SEE
Fetch the endpoint (and linked JS/source maps) as the authenticated session. Write what the product is doing:
- Every input field, parameter, header the endpoint accepts
- Every object id, user id, role identifier in the response
- Every other host, API, or service the response references
- The trust boundary: what separates user A's data from user B's

## Step 2 — INVENT
From those bytes, name ONE trust boundary and ONE test that would be false if the developer had been careful.
- Do NOT start from SQLi/XSS/IDOR because those words exist in a list
- Start from what the RESPONSE told you — what assumption did the developer make?
- If HUNT MEMORY shows a previous look, do something different this time

## Step 3 — RUN
Execute that test with curl/netget. Then a SECOND different test if the first is negative.
- Authed fetch: `python3 engine/engine/netget.py GET "<url>" --as A`
- Cross-account: `python3 engine/engine/netget.py GET "<url>" --as B`
- IDOR sweep: `python3 engine/engine/authz.py diff --slug <program> --url "<url>"`
- Unknown stack: `python3 engine/engine/learn.py auto --kind tech --name "<thing>" --context "<why>"`

## Step 4 — PROVE
Claim a vulnerability ONLY with demonstrated, exploitable impact:
- Not mere reflection, an error message, or a permissive header
- IDOR/BOLA: A-vs-B body-diff showing B received A's unique marker
- Use in-scope, read-only actions only
- HOLD_RTFS and HOLD_INFORMATIVE findings are not real bounty findings

## Anti-patterns to avoid
- Walking a vulnerability catalog instead of reasoning from the response
- Testing SQLi/XSS because they're "common" when the endpoint is a static CDN
- Claiming severity without demonstrated impact
- Ignoring the AUTHZ GATE when two accounts are available
