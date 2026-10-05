---
name: hunt-jwt
description: "Hunt JSON Web Token flaws — alg:none / alg-casing, RS256->HS256 key confusion (sign with the RSA public key as the HMAC secret), kid header injection (path traversal / SQLi), jku/x5u/jwk header pointing at an attacker JWKS, claim tampering (sub/role/tenant/aud), missing expiry or no server-side revocation (replay after logout), and access/refresh/audience token confusion. Use whenever a request carries an eyJ... token in a header, cookie, or body. Respects the no-bruteforce rule: test only known-default / leaked secrets, never keyspace exhaustion."
sources: 0xray-authored
---

# HUNT-JWT — JSON Web Token Attacks

## Decode first
Every `eyJ...` is base64url `header.payload.signature` — decode it with no network call. Read the
**header** (`alg`, `kid`, `jku`/`x5u`/`jwk`) and the **claims** (`sub`, `role`, `scope`,
`tenant`/`org`, `aud`, `iss`, `exp`, `iat`). Every attack below follows from what the header asks the
server to trust.

## What actually pays
A **forged or manipulated token the server accepts**, yielding a **privileged or cross-account
action**. A merely-decoded token, a "weak-looking" secret you never actually forged with, or an
expired token that is correctly rejected are **not** findings.

## Attack matrix
1. **alg:none** — set header `{"alg":"none"}` (also try `None`, `NONE`, `nOnE`) and drop the
   signature. If accepted, you can sign arbitrary claims.
2. **RS256 -> HS256 key confusion** — the server verifies RS256 with a public key. Re-sign the token
   with **HS256 using the PEM public-key bytes as the HMAC secret**. If the library trusts the `alg`
   from the header, it verifies your HMAC against the public key it already holds. Grab the key from
   `/jwks.json`, `/.well-known/jwks.json`, an embedded cert, or the TLS chain.
3. **Weak HMAC secret** — try only **known defaults / leaked** values (`secret`, `changeme`, the
   framework default, a secret leaked in a JS bundle / APK / repo). **Do NOT run keyspace brute
   force** — that violates the no-bruteforce rule; a targeted known-secret check is fine.
4. **kid injection** — `kid` selects the verification key. Try path traversal
   (`"kid":"../../../dev/null"` -> empty key -> sign with `""`), a predictable file path, or **SQLi in
   `kid`** (`"kid":"x' UNION SELECT 'attacker-known-key'-- -"`) to force verification against a value
   you control.
5. **jku / x5u / jwk header injection** — point `jku`/`x5u` at an attacker-hosted JWKS, or embed a
   `jwk` inline, so the server fetches/uses **your** public key to verify **your** token. This is also
   an SSRF primitive — pair with `hunt-ssrf`.
6. **Claim tampering** — once you can sign, flip `role` / `is_admin` / `scope` / `tenant` / `sub` for
   privilege escalation or cross-account access.
7. **Audience / issuer confusion** — a token minted for service/audience A accepted by service B
   (`aud`/`iss` not validated). Common across SSO / multi-service estates — see `hunt-auth-bypass`.
8. **Expiry & revocation** — `exp` not enforced (replay an old token); token still valid after
   logout / password change (no server-side revocation) — see `hunt-session`.
9. **Access / refresh confusion** — a refresh token accepted where an access token is expected, or
   vice versa.

## Tooling
Decode/edit by hand or with a JWT tool; Burp's **JWT Editor** handles signing and the key-confusion
attack. Use `openssl` to fetch/convert the public key. Always confirm the forged token against a
real protected endpoint.

## PoC minimum
Forged/manipulated token **accepted by the server** AND a **cross-account or privileged action
performed** (read/write another user's data, reach an admin-only route). Capture the request carrying
the forged token plus the response proving the action.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class auth-bypass --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).

Cross-references: `hunt-auth-bypass`, `hunt-ato`, `hunt-session`, `hunt-api-misconfig`, `hunt-ssrf`
(for `jku`/`x5u`), `security-arsenal`, `triage-validation`.
