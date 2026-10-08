---
name: hunt-http-smuggling
description: "Hunt HTTP request smuggling (CL.TE, TE.CL, H2.CL, H2.TE, CL.0, client-side desync). Cause: front-end proxy and back-end server disagree on where one request ends and the next begins (Content-Length vs Transfer-Encoding header parsing inconsistency). CL.TE: front-end uses CL, back uses TE. TE.CL: opposite. H2.CL / H2.TE: HTTP/2 downgrade into an HTTP/1.1 back-end. Detection tools: Burp HTTP Request Smuggler extension, smuggler.py, h2csmuggler. Confirm with a unique path on a second request you send (not a victim) plus n>=3 timing against a fast baseline. Validate: cache poisoning only on a cache-buster you own, auth bypass only if the smuggled internal path returns data, credential mixing only between two sessions you control. Use when hunting CDN+origin stacks, load balancer / WAF bypass, or any front-end that downgrades HTTP/2."
---

# HUNT-HTTP-SMUGGLING — Request smuggling

A front-end and a back-end disagree on where the request ends, so bytes you send are parsed as the **next** request. A timeout on a POST whose body you yourself never finished is not smuggling. The effect has to land on a **second** request on that connection (or a second client, for cache/capture).

Strict proxies answer the classic dual `Content-Length` + `Transfer-Encoding` probe with `400`. That retires **that variant only**. Keep going: obfuscated TE, duplicate CL, H2 downgrade, CL.0, client-side desync.

## Rails
- In-scope only. Prove with **your** two requests (or two clients you control).
- No poisoning of a shared cache entry, no capture of a real user's cookies, no request loops.
- Use a unique path (`/smug-<uniq>`) so the desync is obvious and harmless.
- One confirmed variant, then stop. Stop at draft. Never auto-submit.
- A front-end `400` is a negative result for that probe, not a finding.

## Decision tree

1. **See the hop.** `Via`, `Server`, `CF-Ray`, `X-Served-By`, `X-Cache`, ALB/Akamai/Fastly/Cloudflare headers. HTTP/2 to you and HTTP/1.1 to the origin is the common 2024–2026 shape (H2.CL / H2.TE). Classic CL.TE still shows up on older HAProxy, F5, Citrix ADC, Squid, ATS, and custom proxies — do not decide from the `Server` banner alone.
2. **Baseline.** A normal `POST` with a correct `Content-Length` and no `Transfer-Encoding` returns fast. A correct chunked body `0\r\n\r\n` returns fast. Note the time.
3. **CL.TE timing.** Front-end honors `Content-Length`, back-end honors `Transfer-Encoding`. `Content-Length: 4` and body bytes `1\r\nA\r\nX` — the front-end forwards only `1\r\nA`. The back-end reads a chunk of size 1 (`A`) and waits for the next chunk. Timeout **only** on this shape, not on the baseline. Repeat ≥3, interleaved with the baseline. Then confirm with step 6.
4. **TE.CL timing.** Opposite parser. Front-end consumes the chunked framing and treats the message as finished; back-end still waits for `Content-Length` bytes that never arrive (or eats the next request). Same rule: delay must be absent on the baseline. ≥3 interleaved pairs.
5. **If both classic probes return 400,** obfuscate **one** header and retry once each, then move to H2 and CL.0. Do not send the whole matrix at high rate.
   - `Transfer-Encoding: chunked` plus a second `Transfer-Encoding: x`
   - `Transfer-Encoding: chunked` (trailing space), `Transfer-Encoding:\tchunked`, `Transfer-Encoding : chunked`
   - Duplicate `Content-Length` (`0` and the real length) — which side keeps which value is the bug
   - `Content-Length: +4` / `Content-Length: 4 ` 
6. **Confirm with a prefix, not with a hang.** Smuggle a tiny follow-up that names a unique path, then send an ordinary request on the **same** connection:
   ```
   GET /smug-UNIQ HTTP/1.1
   Host: TARGET
   X: x
   ```
   The next response is a 404 (or a reflection) for `/smug-UNIQ`, not for the path you asked. That body-diff is the proof. CL must count the exact bytes the CL-parser will accept, including CRLFs. If the prefix is off by two bytes, fix the count; do not call it confirmed.
7. **H2.CL / H2.TE.** You speak HTTP/2; the origin speaks HTTP/1.1. A `content-length` the front-end ignores (it trusts the frame) but the origin honors, or a `transfer-encoding` that appears only after downgrade, produces the same prefix effect. Need a client that can send raw H2 frames (Burp HTTP Request Smuggler, `h2csmuggler`). curl's HTTP/1.1 probe does not test this path. Confirmation is still the unique path on the **next** request.
8. **CL.0 / early response.** The back-end answers without reading the body (`Content-Length` ignored, or a request line it treats as body-less). Leftover bytes prefix the next request on a keep-alive connection. Same unique-path confirmation. This is also the shape behind browser-powered (client-side) desync when a browser will actually send the request — prove it with a browser you control, one navigation, not a campaign.
9. **Hop-by-hop.** `Connection: Content-Length` (or `Transfer-Encoding`) asks a proxy to strip that header before the next hop. If an edge strips it and the next proxy still split on it, you get a desync. One probe. Akamai-style edge cache poisoning from this primitive is `hunt-cache-poison` and must be proven on a cache-buster you own.

## What to do with a confirmed prefix
Use it once, against yourself:
- Unique path in the smuggled request line → second response is for that path (parser bug proven).
- Smuggle a request to a path the **front-end** forbids and the origin allows (`/admin`, an internal rewrite). Impact is whatever that response contains.
- Two of your own sessions: smuggle `GET /account` with no cookie, then send session B on the same connection. If the body is session B's account, you have shown connection poisoning. Do not aim this at another person.
- Cache: only if `hunt-cache-poison` validation passes on a `?cb=<uniq>` key. Do not poison `/` or a shared static asset.

## Validation
- **Confirmed:** on a reused connection, request 2's response is determined by the prefix in request 1 (unique path visible), and a control connection without the desync headers returns request 2's real path.
- **Timing alone:** ≥3 delays on the probe and ≥3 fast baselines. Say "timeout desync" and still try the unique-path confirm. If the path confirm fails, do not claim cache poison or ATO.
- **Not a finding:** your POST hung because the client never sent the body; a 400; HTTP/2 settings the tool could not negotiate; a delay that also appears on the baseline.

## Chains
- **`hunt-cache-poison`** — prefix stored under a key you then fetch without the smuggle headers. One cache-buster. Stop.
- **`hunt-auth-bypass`** — smuggled path reaches an origin route the edge ACL drops. Quote the internal body.
- **`hunt-xss`** — reflected payload is in the **second** response, which you triggered. Self-reflection in the smuggled request is not stored XSS.
- **`hunt-idor`** — only with two sessions you control, as above.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
