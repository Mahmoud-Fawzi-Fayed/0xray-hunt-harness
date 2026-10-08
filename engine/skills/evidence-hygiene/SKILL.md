---
name: evidence-hygiene
description: "Evidence-capture and PoC-redaction discipline for bug-bounty submissions: cookie redaction protocol (which fields to mask, Preview annotation / Burp panel hiding / DevTools workflow), PII black-bar discipline (what to mask in other-user data — names, emails, phones, faces — vs what is safe to leave — usernames, trace IDs, request bodies), HAR file sanitization (jq filters for Cookie/Set-Cookie/Authorization/API-key headers, query-string tokens, and the raw URL), Copy-as-cURL scrubbing, Burp Repeater/Intruder screenshot hygiene (hide request body, show only Results table for rate-limit attacks), Chrome DevTools Console PoC patterns (credentials include so cookies are not echoed, labeled console.log), screenshot capture order, filename conventions, post-submission rotation hygiene. Use BEFORE any PoC screenshot, BEFORE attaching a HAR, or whenever preparing evidence with session cookies or other-user PII. Pairs with bugcrowd-reporting and report-writing."
---

# EVIDENCE HYGIENE — Capture, Proof, Redaction

Use **before** any screenshot, HAR, or attachment. Evidence convinces a triager; live cookies, real-user PII, and unmarked “200 OK” dumps do not.

STOP at draft. Attach to the **draft** only. Never auto-submit.

## What each finding must show (proof type)

Match the class to **one** of these. If you cannot, you are not ready (`triage-validation` Q6).

| Proof | How to capture | Hygiene |
|---|---|---|
| **Unique marker** | Plant `Bounty-YYYYMMDD-<rand>` in the field you read/write; screenshot it in **attacker** response | Marker must not collide with CSS/IDs; never reuse `XSS-test` |
| **Body-diff** | Same request: baseline vs exploit; show **bytes that differ** (identity, PII key, new email) | Redact PII values; leave keys + your test uid |
| **n≥10 timing** | Table of interleaved samples + **median**; not one curl | No victim lockout; your account only |
| **OOB** | Collaborator/OAST screenshot with **unique** subdomain/path tied to this PoC | Redact other interactions; show timestamp + marker |

Status code alone is never enough. Reflection of your URL in an error is not impact.

## Sensitive vs leave-visible

| Category | Examples | Treatment |
|---|---|---|
| Your secrets | Session, refresh, API keys, `Authorization`, CSRF bound to you | Always redact |
| Other-user PII | Names, emails, phones, addresses, faces, gov IDs | Black-bar; keep JSON **keys** |
| Triager glue | `x-request-id`, trace ids, your test uid/email, GraphQL op name, URL/method | Leave visible |
| Test passwords | Throwaway on a test user | OK if **rotated after** submit |

## Cookie redaction
Mask: session names (`sid`, `authn`, `JSESSIONID`, `__Host-*`, `__Secure-*`), Bearer/JWT, `Set-Cookie` values, `Cookie` header.

Safe: `__cf_bm`, `_ga`, `Server`, `X-Frame-Options`, trace ids, test uid.

**Prefer not capturing:** DevTools `fetch(..., {credentials:'include'})` so cookies never appear in the Console screenshot. Burp: drag divider to hide request; Intruder: Results table only (`#`, payload, status, length) — **small burst** evidence, not a million rows. **Copy as cURL / Copy as fetch** includes `Cookie` and `Authorization` — scrub before it enters a report, ticket, or chat. The address bar and `Location` (`code`, `access_token`, `id_token`, reset tokens) are secrets even when the header pane looks clean.

**Image:** black rectangle over values. Then `strings -a shot.png | grep -niE 'eyJ|Bearer |cookie:'` — plaintext leaks show up; a black bar over compressed pixels will not, so still cover the glyphs.

**HAR:**
```bash
sanitize_har() {
  jq '
    def secret_header:
      (.name|ascii_downcase)|IN(
        "cookie","authorization","proxy-authorization",
        "x-csrf-token","x-xsrf-token","x-api-key","x-auth-token","x-access-token",
        "cf-access-jwt-assertion","x-amz-security-token"
      );
    def secret_query:
      (.name|ascii_downcase)|IN(
        "access_token","id_token","refresh_token","code","token",
        "reset_token","session","password","otp","id_token_hint"
      );
    def scrub_text:
      if . == null then . else
        gsub("(?i)(?<k>password|passwd|otp|refresh_token|access_token|id_token|reset_token)=[^&\"\\s]+"; "\(.k)=<REDACTED>")
        | gsub("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*"; "<JWT_REDACTED>")
      end;
    .log.entries |= map(
      (.request.headers |= map(if secret_header then .value="<REDACTED>" else . end)) |
      (.response.headers |= map(if ((.name|ascii_downcase)=="set-cookie") or secret_header then .value="<REDACTED>" else . end)) |
      (.request.cookies |= map(.value="<REDACTED>")) |
      (.response.cookies |= map(.value="<REDACTED>")) |
      (.request.queryString |= map(if secret_query then .value="<REDACTED>" else . end)) |
      (.request.url |= gsub("(?i)(?<k>access_token|id_token|id_token_hint|refresh_token|reset_token|session|password|otp|code|token)=[^&#]+"; "\(.k)=<REDACTED>")) |
      (if .request.postData then
          .request.postData.text |= scrub_text
          | if .request.postData.params then
              .request.postData.params |= map(
                if (.name|ascii_downcase)|test("password|otp|token|secret|authorization")
                then .value="<REDACTED>" else . end)
            else . end
        else . end) |
      (if .response.content then .response.content.text |= scrub_text else . end) |
      (if ._webSocketMessages then ._webSocketMessages |= map(.data |= scrub_text) else . end)
    )
  ' "$1" > "${1%.har}.sanitized.har"
}
```
`request.url` is a separate field from `queryString` — scrub both. Keep `postData` structure (that is the PoC) but run `scrub_text` on values, on `response.content.text`, and on Chrome `_webSocketMessages`. Application panel shots (Local/Session Storage, IndexedDB): leave **keys**, mask **values**. Verify:

```bash
grep -niE 'eyJ[A-Za-z0-9_-]{8,}|Bearer |authn=|access_token=[^<& ]|id_token=[^<& ]' file.sanitized.har && echo LEAK
```

## PII in IDOR/ATO bodies
Leave: `"email": "<REDACTED>@example.com"`, attacker uid, victim **uid**, endpoint. Mask local-part, phone, name, photo. In the write-up: say PII is masked; unredacted available **on the platform thread**.

## Console PoC
```js
fetch('/api/endpoint', {
  method: 'POST',
  headers: {'content-type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({ /* payload */ })
}).then(r => r.json()).then(j => console.log('MARKER Bounty-…', JSON.stringify(j)))
```
`allow pasting` before the first shot. Clear console between steps (Cmd+K / Ctrl+L). Long bodies: log keys + the **one** critical field, not the whole dump.

## Screenshot order (state-change)
1. Pre-state (marker / `verify` true)
2. The buggy request (impact)
3. Negative post (`old` fails)
4. Positive post (`new` works)
5. OOB/inbox if the chain needs it

Files: `{finding}-step{n}-{what}.png`. One sitting, don’t reload if it mints a new cookie.

## Rate-limit / timing evidence
Show ~20–50 attempts: status, time, length. Known-good seed at the end. **Do not** attach a 10^6 Intruder run — that violates the no-exhaust rail and is noisy. Medians for timing, not a single slow request.

## Post-draft / post-submit
Rotate test session and password so any missed cookie in a PNG is dead. Keep unredacted HAR **local**; triager asks → platform private attach, not email. No public write-up until the program allows. Sweep Downloads for stale HARs.

## Pairing
Should I report? `triage-validation` + `triage-rtfs`. Body template: `report-writing`. This skill is **only** capture/redact/proof-shape.

Cross-refs: `triage-validation`, `triage-rtfs`, `report-writing`, `bugcrowd-reporting`.
