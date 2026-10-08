---
name: hunt-session
description: "Hunt Session Management vulnerabilities — session fixation (no regeneration on login), insufficient invalidation on logout / password-change / email-change, predictable or low-entropy session IDs, JWT-as-session with no exp/revocation, refresh-token rotation/reuse-detection gaps, OAuth/SSO session linkage, device-bound-session (DBSC) downgrade, and cookie attribute issues (Secure/HttpOnly/SameSite/__Host-). Validate with TWO real sessions (attacker A + victim B), body-diff every 200, and OOB confirmation for theft chains. Medium to Critical (fixation→admin hijack, no-invalidation→persistent ATO)."
sources: hackerone_public, portswigger_research, owasp_wstg
report_count: 18
---

# HUNT-SESSION — Session Management

## Rails
- In-scope only. Two sessions on **your** accounts (A and B). Never steal a third-party cookie.
- Read-only until login/logout/password-change on accounts you own.
- **No keyspace guessing of session IDs.** Entropy = decode + sample of **issued-to-you** cookies, not brute-forcing others’ sids.
- STOP at draft. Missing `HttpOnly` without an XSS sink is Low/Info.

## Decision tree
1. Capture full `Set-Cookie` set (names, flags, `Domain`, prefixes) on anonymous + login + logout.
2. **Fixation** (Phase 1) → **logout invalidation** (2) → **password/email/MFA change** (3) → flags (4) → entropy (5) → JWT-session (6) → refresh rotation (7) → SSO/DBSC (8) → cookie toss/partition (9).
3. Every “still authenticated” claim = **body-diff of unique identity marker**, garbage-cookie negative control, cache-buster, second IP if possible.

## Surface
```
Set-Cookie: session / sid / JSESSIONID / connect.sid / PHPSESSID / ASP.NET_SessionId / laravel_session
/login /logout /auth/refresh /oauth/token /account/change-password /settings/email
?sid= ?session= in URL   Sec-Session-Registration (DBSC)   __Host-  __Secure-  Partitioned
```

Grounding (technique, not fake IDs): OWASP WSTG-SESS-01/02/03; ACROS fixation; Auth0/IETF OAuth BCP refresh rotation; Argo CD CVE-2024-22424 (SameSite=Lax + sibling subdomain); W3C DBSC; RFC 6265bis prefixes. JWT forge → `hunt-jwt`. CSRF → `hunt-csrf`.

```bash
get_cookie () {
  local jar="$1" re="${2:-session|sid|sess|JSESSIONID|connect\\.sid|PHPSESSID|laravel_session|AspNetCore}"
  awk -v re="$re" '
    /^#HttpOnly_/ { sub(/^#HttpOnly_/,""); }
    /^#/ { next }
    NF>=7 && $6 ~ re { print $6"="$7 }
  ' "$jar" | tail -1
}
```

### Phase 1 — Fixation
```bash
curl -s -L -c "$JAR_A" "https://$TARGET/login" -o /dev/null
PRE=$(get_cookie "$JAR_A")
# authenticate reusing jar; also try forcing Cookie: session=AAAAdeadbeefAAAA
curl -s -L -c "$JAR_A" -b "$JAR_A" -X POST "https://$TARGET/login" \
  -d "username=A@ex.com&password=Pass1" -o /dev/null
POST=$(get_cookie "$JAR_A")
AUTH=$(curl -s -b "$JAR_A" "https://$TARGET/api/me")
```
**Hit:** `$POST == $PRE` **and** `$AUTH` contains A’s marker. Forced ID accepted + authenticated = Critical (attacker-chosen sid). **FP:** cookie value rotates but a second cookie stays stable — diff the **full** cookie set; prove old value is dead (Phase 2).

Login CSRF (related): A plants sid via `Domain=.target.com` or form GET to `/login`; B authenticates into A’s sid (`hunt-csrf`).

### Phase 2 — Logout
Replay **old** cookie string after logout (not the jar). Body-diff vs pre-logout `/api/me`. Garbage cookie must not match. Retest after delay + other IP (lazy expiry / IP bind).

### Phase 3 — Password / email / “logout all”
Two jars, same user: A stolen, B acts. B changes password/email/MFA or “revoke all”. Replay A. Sibling-session survival = persistent ATO multiplier (`hunt-ato`). If change-password has no current-password/MFA, escalate (`hunt-mfa-bypass`).

### Phase 4 — Cookie flags
```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
| Flag | Finding only when |
|---|---|
| No HttpOnly | + real XSS/DOM sink (`hunt-xss`) |
| No Secure | + HTTP/HSTS gap (`hunt-tls-network`) |
| SameSite missing/`None` | CSRF or CSWSH (`hunt-csrf`, `hunt-websocket`) |
| SameSite=Lax only | Sibling-subdomain top-level nav (CVE-2024-22424 class) |
| No `__Host-`/`__Secure-` | Precondition for fixation / cookie toss |
| `Domain=.target.com` | Any sibling (or takeover) can set/overwrite (`hunt-subdomain`) |
| No `Partitioned` / CHIPS | Third-party embed still gets the cookie — CSRF/embed chains |

### Phase 5 — Entropy (issued to you)
Sample **tens** of login cookies (not 10). Duplicates = catastrophic. Decode base64/hex for `userId`/timestamp. Sequential delta. **Do not** iterate guessed sids against `/api/me`. NIST SP 800-63B ≥64 bits is the bar.

### Phase 6 — JWT-as-session
Decode `exp`/`jti`. Logout then replay **same** JWT — body-diff `/api/me`. Forge attacks live in `hunt-jwt` (no cracking).

### Phase 7 — Refresh rotation / reuse
Mint RT1 → rotate to RT2 → replay RT1. BCP: replay of RT1 must kill the **family** (RT2 dead). No rotation or no family-kill = persistent stealable credential. Confirm with your tokens only.

### Phase 8 — SSO / DBSC
Logout at IdP only; app session still authed = SLO gap. If `Sec-Session-*` present, strip device-bound proof and replay plain cookie — if accepted, DBSC is advisory.

### Phase 9 — Cookie toss / jar overflow
Over-write session from a **weaker** origin (HTTP sibling, taken-over host) via `Set-Cookie; Domain=.target.com`. Cookie bomb (jar overflow) dropping `__Host-` cookies is a rare auxiliary — prove fixation/ATO, not just 400s.

## Validation
- Two **real** sessions, never placeholders.
- Body-diff identity marker; garbage negative control; cache-buster.
- Theft chains: OOB receipt of cookie/token (Collaborator), unique marker.
- Flag gaps are **policy** until chained.

**Severity:** fixation → admin/SSO = **Critical**. Survive password/email change or RT reuse = **High–Critical**. Predictable sid structure (no guessing performed) = **High**. Logout-only persist = **Medium–High**. Flags standalone = **Low/Info**.

## Chains
| Finding | Compose | Impact |
|---|---|---|
| Fixation | Admin login | Admin ATO |
| No invalidate on reset | XSS/CSWSH theft | Persistent ATO |
| `Domain=.` cookie | Subdomain takeover | Fixation ATO |
| SameSite=Lax | Sibling CSRF | State change |
| JWT no `jti` | `hunt-jwt` forge | Permanent access |

Cross-refs: `hunt-ato`, `hunt-jwt`, `hunt-oauth`, `hunt-csrf`, `hunt-xss`, `hunt-websocket`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
