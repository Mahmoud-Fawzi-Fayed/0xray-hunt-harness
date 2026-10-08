---
name: hunt-cache-poison
description: Hunting skill for cache poison vulnerabilities. Built from 10 public bug bounty reports including X-Forwarded-Host poisoning, X-HTTP-Method-Override / GCS cache, reflected→stored XSS via cache, classic Omer-Gil Web Cache Deception, Cloudflare Cache Deception Armor bypass, session-token cache deception, Akamai hop-by-hop smuggling → server-side edge poisoning, Kettle/Doyhenard path-normalization WCD against Cloudflare/Fastly/GCP, and cache-key injection (keyed-fragment collision). Use when hunting cache poisoning, Web Cache Deception, CDN-fronted apps.
sources: github, hackerone_public, portswigger_research, omergil_research, youstin_research
report_count: 10
---

# HUNT-CACHE-POISON — Cache poisoning and cache deception

**Poisoning:** you change a response that other clients later receive for a key you do not fully control.
**Deception:** a victim's authenticated response is stored under a URL an attacker can fetch.

Both require a **second client** that did not send your poison header and did not use the victim session. Your own browser showing your own header is not a cache bug. Historical notes (Shopify X-Forwarded-Host H1 #977851, HackerOne X-Forwarded-Port H1 #409370, GitLab method-override H1 #1160407, PayPal WCD, Cloudflare `.avif` armor bypass H1 #1391635, Akamai hop-by-hop, Kettle 2024 path-normalization research) describe shapes — reproduce the behavior, do not cite a program you did not test.

## Rails
- In-scope only. Every probe uses a throwaway key `?cb=<uniq>` or a path you created. Do not poison `/`, shared JS/CSS, or another tenant's host.
- No error-page DoS, no re-poison loop, no TTL hammering.
- Web cache deception: **your** two accounts. Do not send a logged-in victim a link.
- One poisoned key, one clean fetch, stop. Stop at draft. Never auto-submit.
- "DoS via cached 4xx" is out of scope for this harness even if a program once paid it.

## Decision tree

1. **Is anything cached?** Two identical GETs. `Age` increases, or `X-Cache` / `CF-Cache-Status` / `X-Cache-Status` goes MISS then HIT. `Cache-Control: private` / `no-store` and always-MISS means there is no shared cache — stop unless a named rule (extension, `s-maxage`) says otherwise.
2. **What is the key?** Diff `Vary`, and change one thing at a time: query param, header, method, cookie, path encoding. If the second request is a MISS, that input is keyed. Keyed reflection is not poisoning.
3. **Unkeyed reflection (poison).** Add `X-Forwarded-Host: p-<uniq>.example` on `?cb=<uniq>`. If the marker appears in HTML, `Location`, `Link`, CSP, or a script URL, fetch the **same** URL with no poison header from another IP or a clean client. Marker still present + HIT + `Age` > 0 → proven. Then stop. Do not repeat on a real path.
4. **Unkeyed query.** Some caches include only a param allow-list. `?cb=<uniq>&utm_content=p-<uniq>` then fetch `?cb=<uniq>&utm_content=p-<uniq>` vs the canonical URL the victim would request. You must show the victim URL, not a URL nobody visits. Fat GET (body on GET) only if the cache key ignores the body and the origin uses it — second client, same URL, no body. **Parameter cloaking** (still on `?cb=<uniq>`): if a param is unkeyed (`utm_*`, `fbclid`, `_`), the cache and the origin may split on different characters. One request each: `?cb=<uniq>&utm_content=x;param=p-<uniq>` and `?cb=<uniq>&utm_content=x?param=p-<uniq>`, where `param` is reflected and **is** keyed when sent as its own parameter. Second client fetches the URL a real user requests. Marker + HIT + `Age` > 0 proves it. **Private is not private** when `CDN-Cache-Control: public` or `s-maxage` disagrees with `Cache-Control: private` / `no-store` — the second client is the proof. A reflected `Access-Control-Allow-Origin` stored without `Vary: Origin` is this bug when a second client that sent no `Origin` still receives your origin (`hunt-cors` owns the policy itself).
5. **Method override.** `X-HTTP-Method-Override: HEAD` or a raw HEAD stored under the GET key (GitLab/GCS class). Prove on `?cb=<uniq>`: the clean GET body becomes empty or HEAD-like. Do not do this to a production asset.
6. **Deception (WCD).** While logged in as account A, request a dynamic page with a static-looking suffix the cache stores and the origin still routes:
   ```
   /account/settings.css
   /account/settings.jpg
   /account/settings.avif
   /account/settings.webp
   /account/settings.ico
   /account/settings.mjs
   /account/settings%3F.css
   /account/settings%23.css
   /account/settings;.css
   /account/settings%00.css
   /account/settings%0a.css
   /account/settings.aaaa
   /static/..%2faccount
   ```
   Origin returns A's HTML (email, CSRF, marker you put in A's profile). Cache stores it because of the extension or a normalization difference (Kettle/Doyhenard: encoded dot, delimiter, `%2f` vs `/`; origin delimiter not used by the CDN — `;` Spring, `.ext` Rails, `%00` OpenLiteSpeed, `%0a` Nginx rewrite). Account B, or curl with no cookie, gets A's marker. One path. Stop.
7. **Cache-key injection** (keyed fragments concatenated with no separator — Nginx `$uri$http_accept` class, YesWeHack 2026). Split a unique marker across two adjacent key parts so two different requests hash to the same key:

   ```
   GET /anyendpoint                 (store a unique body under ?cb=<uniq>)
   GET /anyend    +  Accept: point  (or Host / a keyed cookie — one adjacent fragment)
   ```

   Detected: both requests return the same cached body. Proven: a second client requests the **normal victim URL** and receives that body (HIT + `Age` > 0 + marker). Collision only on a throwaway path is not impact. Do not turn a key collision into CPDoS.
8. **Smuggle into the cache** only after `hunt-http-smuggling` is confirmed. Store under `?cb=<uniq>` only.

Headers worth one request each: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded: host=p-<uniq>.example`. A WAF block on one name is not a reason to skip the rest.

## Validation
- **Poison:** client 2 did not send the header and received the marker; response shows HIT and a positive `Age`; `Vary` does not list that header. Say the TTL (`Cache-Control` / `Age`) you observed.
- **Key injection:** two different requests collide; the second client fetched the **normal** victim URL and got the marker. Collision on a throwaway path nobody visits is not impact.
- **Deception:** the cached body contains A's unique profile marker and B's request had no session.
- **Not a finding:** reflection only on the request that carries the header; `Age: 0` forever; `Vary` includes the header; HTML cached only in **your** browser; a path suffix the origin answers with 404 and the cache stores the 404 (no private data).
- **Severity:** poisoned script/HTML on a shared key that a second client executed or would execute (High) — you still must not leave it on a production URL. Deception that returns another user's email or session token (High/Critical) proven with your two accounts. A poison key nobody else requests is Low; say that and do not inflate it.

## Chains
- Poisoned `src` / unescaped host in HTML → `hunt-xss`. One cache-buster, one browser.
- Deception body contains a CSRF token or email → `hunt-idor` / `hunt-ato` wording for **that** data. Do not replay a real user's session.
- Smuggling prefix → this skill's second-client test. Hop-by-hop `Connection: Content-Length` is the Akamai-class shape; same proof rule.
- `X-Forwarded-Host` in a password-reset mail is `hunt-host-header`, not a cache bug, unless the **cached** page is what you showed.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
