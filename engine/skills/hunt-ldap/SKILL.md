---
name: hunt-ldap
description: "Hunt LDAP Injection and XPath Injection — authentication bypass, blind char-by-char attribute exfiltration, AD user/group enumeration, XML-store XPath bypass. Covers the LDAP special-character set (* ( ) \\ NUL /), search-filter-context vs DN-injection, parenthesis-balancing, AND/OR filter logic, and {SSHA}/{CRYPT} userPassword exfil on non-AD directories. Use when target uses LDAP/AD authentication, corporate SSO with a directory backend, an address-book/people-search API, or XML-based data stores queried with XPath."
sources: hackerone_public, owasp, portswigger
report_count: 0
---

# HUNT-LDAP — LDAP injection and XPath injection

String-built LDAP filters (RFC 4515) and string-built XPath queries. Public write-ups rarely include a live bounty id — ground the report in the filter you proved, not a borrowed H1 number. OWASP WSTG-INPV-06 and the PortSwigger LDAP labs match this oracle.

## Rails
- In-scope only. Use an account you control for any login test.
- No password spraying, credential stuffing, or hash cracking. If you recover a `{SSHA}` / `{CRYPT}` value, stop at the hash. Do not run hashcat or john.
- No full directory dump. One true/false pair, one record, or a 3-character prefix is the proof.
- Stop at draft. Never auto-submit.
- Active Directory `unicodePwd` is write-only. Never report "AD password hashes" from LDAP.

## AD vs other directories

| | OpenLDAP, 389-DS, ApacheDS | Active Directory |
|---|---|---|
| Password attr | `userPassword` may be readable (`{SSHA}`, `{CRYPT}`). `+` requests operational attributes when you control the attribute list | `unicodePwd` is never returned. `ms-Mcs-AdmPwd` and `msLAPS-Password` are local-admin passwords when the directory actually returns them |
| What a read proves | that attribute's value | `sAMAccountName`, `userPrincipalName`, `mail`, `memberOf`, `description` / `info`, or a LAPS value in the body |
| Auth bypass | same filter tricks | same filter tricks, if the app builds the filter by concat |

`description` sometimes holds a password an admin typed there. That is a finding only when the value is in the response. Do not guess that it does.

## Decision tree

1. **Confirm the backend.** Errors: `InvalidSearchFilterException`, `Bad search filter`, `LDAP: error code`, `javax.naming`, `com.sun.jndi.ldap`, `ldap_search`, `System.DirectoryServices`. Surfaces: corporate login, people search, address book, "find a colleague", `/api/directory`, SSO that still binds to LDAP.
2. **Baseline** a normal username and a wrong password. Save status, length, and a body marker (`Invalid credentials` vs a session cookie).
3. **Unbalanced vs balanced.** Username `test)` vs `test()`. A syntax error on the unbalanced input and a normal failure on the balanced one means the value is inside a filter. If **this** field looks identical for both, still try `*` / `\` here, then move to the next LDAP-shaped input (people search, address book, `/api/directory`, group picker, password field). Do not retire the class off one login box.
4. **Which context.**
   - Filter `(attr=VALUE)` → `* ( ) \ NUL & | !`.
   - DN `uid=VALUE,ou=people,dc=corp` → `, = + " \ < > ;`. A `*` is not a wildcard in a DN. Payloads do not transfer.
5. **Auth bypass** only if the always-true filter returns a session that loads a post-login page, and the false filter does not.
6. **Blind read** only if you need a secret attribute to explain impact. Recover a short prefix (the `{SSHA}` tag, or three characters). Stop.
7. **XPath** when the store is XML (`//user[name='INPUT']`). No SQL comments — balance quotes yourself.

## Payloads

Assume a common shape `(&(uid=USER)(userPassword=PASS))`. Count parentheses on the **finished** filter. An extra `)` is a syntax error, not a bypass.

```
*
admin*
admin)(&)
*)(uid=*))(|(uid=*
*)(objectClass=*
admin)(!(userPassword=ZZZ))
```
NUL (`%00`) truncates on some C libraries; try once.

If the parameter selects **attributes** rather than the filter, ask for `*` and `+`, then `userPassword` or `ms-Mcs-AdmPwd` / `msLAPS-Password`. A `*` in the filter widens matches; it does not add operational attributes. Quote the value. Do not dump the directory.

**DN injection** (commas matter): `admin,ou=other,dc=corp` and see if the bind DN changes in an error string.

**XPath**
```
' or '1'='1
' or ''='
admin' or '1'='1' or 'a'='b
')] | //user[1]/password | //user[('
```
Blind XPath, one character: a predicate `substring(//user[1]/mail,1,1)='a'` whose true and false responses you already distinguished.

**Search oracle (enumeration):** one unlikely prefix `zzqx*` (expect empty) vs one common prefix `a*` (expect hits). If the counts differ, fetch **one** object and stop. Do not loop `a`–`z`.

**Referral / OOB (rare):** if the server chases a referral you inject, `ldap://UNIQUE.collab/a` is the proof. One attempt.

## Bypasses
| Control | Attempt |
|---|---|
| Escapes `*` but not `(` | parenthesis payload |
| Strips `(` once | `))(|(uid=*` |
| URL-decodes late | `%28` `%29` `%2a` `%00` `%5c` |
| Blocks `*` in the login field | inject the password field, or a search box instead |
| WAF on `)(` | encode, or move the payload to JSON `{"username":"..."}` |

## Validation
- **Bypass:** session cookie (or equivalent) plus a successful authenticated request. The same request with one parenthesis removed, or with `uid=zzqx_no_such`, must fail. If true and false both log in, the endpoint is broken open — report that, not LDAP injection.
- **Attribute read:** the value appears in the body, or a 3-character blind prefix reproduces on three repeats while the false control stays false.
- **Enumeration:** show the empty control and one real record (name, mail, or `memberOf`). Do not attach a user list.
- **XPath:** a real account context, quotes balanced, not a 500.
- **Not a finding:** a 500 that appears for every special character including ones you balanced; a size change caused only by the payload being reflected.

**Severity:** authenticated as a privileged directory entry (Critical); a secret you actually read from `userPassword` or `description` (High); one-record or `memberOf` disclosure (Medium); a boolean oracle with no sensitive attribute (Medium, and say you stopped). Do not raise it by describing a spray you did not do and must not do.

## Chains
- Bypass → one action as that user (`hunt-idor` on a single object).
- `memberOf` / admin name in the response → note it. Do not spray the name.
- Non-AD hash in the body → quote the scheme tag. Cracking is out of scope for this harness.
- Referral callback → `hunt-ssrf` wording, only for the host you hit.
- XPath `doc()` / `unparsed-text()` that returns a file → `hunt-xxe` / `hunt-lfi` validation (file bytes).

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
