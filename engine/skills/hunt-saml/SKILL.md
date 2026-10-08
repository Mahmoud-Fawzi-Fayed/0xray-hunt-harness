---
name: hunt-saml
description: "Hunt SAML / SSO attacks. Patterns: XML Signature Wrapping (XSW) — modify Assertion while keeping Signature valid by relocating signed element, comment injection in NameID (admin@target.com<!--evil-->@attacker.com → some parsers see admin@target.com), signature stripping (remove Signature element entirely, server should reject but doesn't), key confusion (signed by attacker's IdP, accepted by SP), audience-restriction not validated, replay attack (same Assertion accepted twice within validity window), encrypted-assertion branch skip, parser-differential (two XML parsers). Tools: SAML Raider Burp extension, samlmagic, manual XML manipulation. Detection: any /saml endpoint, /Shibboleth.sso, /sso/saml/, Microsoft ADFS endpoints. Validate: account takeover via altered NameID, admin role injection via altered AttributeStatement. Use when hunting SSO flows, when SAML AssertionConsumerService is reachable, when chaining IdP-trust to SP-impersonation."
---

# HUNT-SAML — SAML / SSO

## Rails
- In-scope only. Use **your** IdP test user / captured assertion from **your** login. Do not impersonate a real third-party victim.
- Read-only until you have a captured `SAMLResponse`; then mutate **copies** against ACS. One successful ATO on a test user is enough.
- No brute-force of NameIDs / passwords. One targeted NameID swap (test-user → second test-user or documented admin mailbox you own) proves impersonation.
- STOP at draft. Claim only a session issued for an identity you were not entitled to.

## Decision tree (any SP)
1. **Find ACS / SSO:** `/saml`, `/saml/acs`, `/SAML2/POST`, `/Shibboleth.sso`, `/adfs/ls`, `/auth/saml/callback`, `?SAMLResponse=`, `RelayState`. Libraries: `ruby-saml`, `pysaml2`, `OneLogin`, `simplesamlphp`, `samlify`, `xml-crypto`, ADFS, Okta/Azure as IdP.
2. Capture a **valid** `SAMLResponse` (POST binding = raw base64; Redirect = deflate then base64 — not gzip).
3. Walk attacks in yield order: **sig strip → comment/NameID → XSW / parser-diff → encrypted-assertion branch → aud/dest/recipient → replay → XXE → RelayState**.
4. Success = SP issues a session as **another identity** (NameID or privileged AttributeStatement). XML that parses but does not change the auth decision is not Critical.

## Attack surface
```
/saml /saml/acs /sso/saml /auth/saml/callback /Shibboleth.sso
/adfs/ls /SAML2/POST /login/callback ?SAMLResponse= RelayState
metadata.xml  SPSSODescriptor  AssertionConsumerService
```

```bash
echo "$SAML_B64" | base64 -d | xmllint --format - > saml.xml   # POST binding
# Redirect binding:
python3 -c "import sys,base64,zlib; print(zlib.decompress(base64.b64decode(sys.argv[1]),-15).decode())" "$SAML_B64"
```

## Attack matrix

| # | Class | What to do | Confirm |
|---|---|---|---|
| 1 | **Signature stripping** | Delete `<ds:Signature>` (and encrypted-sig variants). Change `<NameID>` to a second test identity. Re-encode, POST to ACS. | Session as the swapped identity. `wantAssertionsSigned=false` / verify skipped. |
| 2 | **Comment injection** | `<NameID>admin@sp.example.com<!---->.attacker.com</NameID>` (you register/control the full string as IdP NameID). Canonicalization **without-comments** signs `admin@sp.example.com.attacker.com`; some text extractors read only `admin@sp.example.com`. ruby-saml CVE-2017-11428 / CVE-2024-45409 family. | Login as the **prefix** identity, not the IdP account. |
| 3 | **XSW (signature wrapping)** | Keep signed assertion intact; insert a **sibling/parent** unsigned assertion the SP consumes first. Signature still covers original `#ID`. | Business logic uses unsigned NameID/attrs; verifier sees signed node. |
| 4 | **Parser differential** | Two parsers (e.g. REXML vs Nokogiri — GitHub Enterprise CVE-2025-25291/25292): inject sibling `<Assertion>` so verifier and consumer resolve **different nodes** for the same XPath. | Signature valid + consumed NameID is attacker-controlled. |
| 5 | **Encrypted-assertion branch** | If `EncryptedAssertion` is enabled, forge on the code path that decrypts **then** fails to re-verify (GitHub GHES CVE-2024-4985 class). | Unsigned/forged assertion accepted only when encryption flag on. |
| 6 | **Audience / Destination / Recipient / InResponseTo** | Replay assertion issued for SP-A against SP-B; drop `<AudienceRestriction>`; change `Recipient` ACS URL; replay `InResponseTo` against a fresh login. | Cross-IdP / cross-SP session (Slack confused-deputy class). |
| 7 | **Replay / NotOnOrAfter** | Submit the same `SAMLResponse` twice; submit after `NotOnOrAfter`; skew `NotBefore`. | Second ACS POST still issues a session. |
| 8 | **IdP / key confusion** | Assertion signed by **your** IdP (or self-signed) presented to SP that does not pin IdP cert / `Issuer`. | SP trusts attacker IdP. |
| 9 | **AttributeStatement priv-esc** | Leave NameID as your user; inject `isAdmin` / `groups=Admins` / `role=site_admin` **inside** the signed vs unsigned node (pairs with XSW). | Privileged app role, not just display name. |
| 10 | **XXE in SAML XML** | DOCTYPE + external entity in `SAMLResponse` (`hunt-xxe`). Many SPs disable DTD — still probe once. | File/SSRF data in error, log, or NameID render — unique OOB marker. |
| 11 | **RelayState** | Treat as open redirect / login CSRF (`hunt-open-redirect`, `hunt-csrf`). | Redirect or bound state not validated. |

### Signature strip
```
1. Decode → saml.xml
2. Delete every <Signature>…</Signature>
3. Set NameID to TEST_B identity you own (or a role-bearing attribute)
4. POST binding: base64 -w0 saml.xml  (no compression)
   Redirect: raw DEFLATE then base64, then URL-encode
5. POST to ACS with original RelayState
```

### XSW shape (XSW1-style sibling)
```xml
<samlp:Response>
  <saml:Assertion ID="evil">
    <saml:Subject><saml:NameID>admin@sp.example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <saml:Subject><saml:NameID>you@sp.example.com</saml:NameID></saml:Subject>
    <ds:Signature>… Reference URI="#legit" …</ds:Signature>
  </saml:Assertion>
</samlp:Response>
```
SAML Raider (Burp) enumerates XSW1–XSW8; try each once. Do not stop at the first XML error — parsers fail closed differently per variant.

### Comment / C14N mismatch
```xml
<NameID>victim@company.com<!---->.evil.com</NameID>
```
Works only when **signer's C14N** and **app text extraction** disagree on comments. Also try XML namespace prefix tricks and control chars in email (`\r` / trailing NUL) for domain-enforcement bypass (H1-class SAML signup).

## Binding notes
| Binding | Encode | Pitfall |
|---|---|---|
| POST | raw base64 of XML | Do **not** deflate |
| Redirect | raw DEFLATE (zlib -15) + base64 + URL-encode | gzip ≠ DEFLATE; zlib header will fail |

## Validation
- **Session as another identity:** `/me` / app UI shows TEST_B (or admin) unique marker, not your original NameID. Body-diff vs your baseline session.
- **Negative control:** unmodified assertion still logs in as you; garbage XML is rejected.
- **Privilege:** changing `locale` / displayName is **not** ATO. Need NameID, `AuthnContext`, or role-bearing attributes to change the authz decision.
- **OOB:** XXE/`jku`-like metadata fetch → unique Collaborator. Sig-strip ATO is in-band (issued cookie).
- Reproduce twice from a fresh browser (capture → mutate → ACS).

**Severity:** XSW / sig-strip / parser-diff → any-user or admin ATO = **Critical**. Comment injection to a specific mailbox = **High–Critical**. Audience fail enabling cross-SP replay = **High**. XXE file read = **High** (or SSRF). RelayState-only redirect = hand to `hunt-open-redirect` (Low unless token leak).

## Chains
| Primitive | Compose into | Impact |
|---|---|---|
| XSW / sig-strip NameID | SP issues session then OAuth token | Admin API (`hunt-oauth`, `hunt-ato`) |
| Audience not checked | Assertion from IdP-A accepted at SP-B | Cross-tenant / partner-portal (`hunt-auth-bypass`) |
| Encrypted-assertion branch | `site_admin` provision | GHES-class full admin |
| XXE in ACS | File read of IdP cert / secrets | Forge forever (`hunt-xxe`) |
| RelayState open redirect | Token in URL after SSO | ATO (`hunt-open-redirect`) |

Cross-refs: `hunt-ato`, `hunt-auth-bypass`, `hunt-oauth`, `hunt-xxe`, `security-arsenal`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
