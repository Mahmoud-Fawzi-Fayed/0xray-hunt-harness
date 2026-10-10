---
name: hunt-hypothesis
description: Invent the next test from the live response, not from a vulnerability catalog. Use on every deep hunt when the URL is unknown, when the last look returned nothing, or when the worklist is empty but a session is live.
---

# Hunt from what the app just did

Do not start from a class list (SQLi, XSS, IDOR, …). Those lists make the model replay the same probes and close the URL. Start from the bytes on the wire for THIS request, then invent a test that would be false if the developer had been careful.

## Every look

1. Send the request as the logged-in test user. Read status, headers, and body. JSON, HTML, and JS are all source.
2. Write one sentence: what this endpoint is for, in the product's words.
3. List every trust boundary you can see: who the caller is, which object is named, which other host or account the server might talk to, which field the client is not supposed to set.
4. Invent ONE test that crosses a boundary. The test is a hypothesis: "if I do X, the server should refuse, and if it does not, here is the impact."
5. Run that test. Compare bodies, not status codes. Unique marker, 8+ random characters, not `test` or `admin`.
6. If it fails, invent a different test from a different field or a different role. Do not repeat the last look.

## Where ideas come from

The live response, linked JS, OpenAPI/GraphQL the session can see, and the hunt memory block (previous look, missed signals, open hypotheses). Public writeups for THIS stack only after you have named the stack from the response. `learn.py auto` if no skill matches what you saw.

A hunt-* skill is a reference AFTER you have a hypothesis that matches it. It is not the menu.

## Not a finding

Reflection of your marker, an error page, a missing header, a 401 on a logged-out call, a marketing HTML page, identical A/B bodies, a scanner-class issue with no attacker-attainable harm.

## Return

The JSON the harness asked for. Put unused ideas in `hypotheses`. Put things you saw and did not prove in `signals_missed`. Those feed the next round. Do not empty them to look finished.
