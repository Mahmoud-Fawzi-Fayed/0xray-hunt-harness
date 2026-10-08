---
name: hunt-idor
description: Hunting skill for idor vulnerabilities. Built from 26 public bug bounty reports. Use when hunting idor on any target.
sources: github, hackerone_public
report_count: 26
---

# HUNT-IDOR — Object / Function-Level Authorization

## Rails
- In-scope only. Two **your** accounts (A owner, B attacker); optional third tenant C for cross-org.
- Read-only by default. Mutations (PUT/PATCH/DELETE) only against objects **you created**. Prove write-IDOR **once** on a disposable object; do not mass-delete.
- Sequential IDs: probe **A’s id ± a few** and IDs **leaked in-app**. No exhaustive user-table dump, no credential stuffing.
- STOP at draft. 200 with empty/redacted body is not a finding.

## What pays
B reads or mutates **A’s** object (or tenant C’s) with no grant. Highest: billing, messages, API keys, membership/role, export/download, admin actions.

## Decision tree (any API)
1. **Map object references** while logged in as A: path IDs, query, JSON body, headers (`X-Org-Id`, `X-User-Id`), GraphQL `id`/`gid://`, WS payloads, exports, signed URLs.
2. **Classify the ID:** sequential int → ±1/±10 on **your** objects. UUID v4 → harvest from other responses (do not brute). UUID v1 and UUID v7 (time-ordered, RFC 9562) → reconstruct only inside a timestamp you already saw on your own objects. Hashids/sqids/base64 → decode. ULID → prefix time.
3. Replay **A’s IDs as B** (swap cookie/Bearer only). All verbs: GET POST PUT PATCH DELETE. Also: no auth, expired token, another tenant.
4. If 403: run **bypass table**. If 200: **body-diff** vs B’s own object — must contain A’s unique marker (email, invoice line, filename).
5. Ask: which **state-change** takes the same ID? Read-IDOR + write on email/role/refund/membership = ATO/financial (`hunt-ato`).

Do not stop at the first 403. Version, verb, encoding, and nested body each get a probe.

## Surface signals
```
/users/{id} /orders/{id} /invoices/{id} /messages/{id} /files/{uuid}
/orgs/{orgId}/members  /tenants/{tid}  /reports/{id}/download
?user_id= account_id= customer_id= documentId= resource_id=
GraphQL: node(id:) billingDocument(id:) user(id:)
Headers: X-Org-Id X-Account-Id X-Tenant-Id X-User-Id
```
JS: `fetch(\`/api/users/${id}\`)`, `invoiceId`, Redux `organizationId`. Mobile APIs often skip the check the web app has.

## Methodology
```bash
# A: capture object + unique marker
curl -s -H "Cookie: $A" https://$TARGET/api/invoices/$INV_A | tee a.json
# B: replay same URL
curl -s -H "Cookie: $B" https://$TARGET/api/invoices/$INV_A | tee b.json
diff -u a.json b.json
# Finding iff b.json contains A's marker and B has no legitimate grant
```

**GraphQL:** introspection if enabled; every query/mutation with `id` / `input.id`. Alias batching:
```graphql
{ a:user(id:"A"){email} b:user(id:"B"){email} }
query { node(id:"gid://app/Invoice/A"){ ... on Invoice { pdfUrl total } } }
```

**Function-level (BFLA):** sibling routes under `/admin/*` — if 9 have middleware and 1 does not, that 1 is the bug. Replay admin export/delete/impersonate from B’s **low-priv** session **and** with no session.

## Payloads / bypasses

| Defense / shape | Probe |
|---|---|
| Sequential ID | A’s id ±1, ±10 (objects you can see leaked in lists). Stop after proof. |
| UUID leaked elsewhere | Notifications, exports, webhooks, GraphQL lists, `Location`, email links |
| Encoded | `echo dXNlcl8xMjM= \| base64 -d`; Hashids; hex(int) |
| Alternate identifier | Path UUID is checked, body/query `email`/`username`/`slug`/`external_id`/`customer_number` is not. Replay A’s *other* key as B. |
| Wrap / sentinel | `id=-1`, `0`, `null`, `""`, `2147483647`, `2147483648` (32-bit wrap). One each. |
| Array / CSV | `?id=B,A`  `id[]=B&id[]=A`  `{"id":["B","A"]}` |
| Relay / global ID | `printf 'Invoice:%s' "$ID_A" \| base64` → `node(id:"base64")`. Shopify `gid://app/Invoice/A` already in GraphQL block. |
| 403 on `/v2/` | Repeat on `/v1/`, `/internal/`, `/mobile/`, trailing slash, `.json`, `;.css` |
| GET protected | POST/PUT/PATCH/DELETE/OPTIONS; `_method=DELETE`; `X-HTTP-Method-Override` |
| `user_id` in WHERE | Body `{"id":A}`, nested `{"data":{"id":A}}`, array `{"id":[B,A]}` / `{"id":{"$in":[A]}}` (`hunt-nosqli`) |
| HPP | `?id=B&id=A`  `?user_id=B&userId=A`. JSON duplicate keys `{"id":B,"id":A}` (first-key vs last-key parsers) |
| Other representation of the same id | `/resource/A.pdf`, `/resource/A.json`, `Accept: application/xml`, the mobile or GraphQL field for the REST id. One format often skips the check |
| JSON Patch / merge-patch | `Content-Type: application/json-patch+json` with `{"op":"replace","path":"/ownerId","value":A}` on **your** URL; `application/merge-patch+json` body `{"id":A}` |
| Name variants | `user_id` `userId` `uid` `account` `customer_id` `ownerId` `subject` |
| JSON merge / mass assignment | Add `"role":"admin"`, `"org_id":A_ORG` on a membership POST (`hunt-api-misconfig`) |
| Tenant in JWT only | Send `X-Org-Id: A_ORG` or body `tenantId` that disagrees with token |
| Signed URL | Swap resource id inside path, keep signature; or reuse A’s URL as B |
| Second-order | A’s id in a job/export B can trigger; webhook B can register |
| Batch | `{"ids":[A,B]}`  GraphQL aliases  `/bulkGet` |
| UUID v1 | Extract time+MAC; generate neighbors for **your** window only |
| Soft-delete | Access after “remove member”; token still valid (`hunt-session`) |

```bash
for m in GET POST PUT PATCH DELETE; do
  curl -s -o /tmp/idor -w "$m %{http_code} %{size_download}\n" -X "$m" \
    -H "Cookie: $B" https://$TARGET/api/users/$A_ID/profile
done
```

## Common root causes
- ORM `findById(req.params.id)` with no `userId`/`orgId` scope
- Authn middleware, no object-level authz
- Client-supplied `org_id` trusted
- GraphQL auto-resolvers; nested relations not re-checked
- Verb/version inconsistency
- Related object leaks a private FK

## Validation
- **B cannot legitimately access A’s object** (different user, preferably different tenant).
- Response contains **A’s unique marker** (body-diff vs B baseline and vs 401 garbage cookie). 200 + `[]` / redacted fields / `"access denied"` in body = **not** IDOR.
- Write-IDOR: mutate a **disposable** A object, confirm via A’s session (second channel). Revert if cheap.
- Blind: unique marker in export/email/OOB webhook, not status-only.
- Reproduce from two fresh accounts in <10 minutes.

**Severity:** cross-tenant PII/financial read = **High**. Write (email, role, refund, delete) = **High–Critical**. Same-org teammate read of intended-shared data = often N/A. Unauthenticated + IDOR = **Critical** (`hunt-auth-bypass`).

## Chains
| Primitive | Compose | Impact |
|---|---|---|
| `PATCH /users/{id}` email | Password reset | Zero-click ATO (`hunt-ato`) |
| File download IDOR | `Content-Disposition` filename XSS | Session theft (`hunt-xss`) |
| GraphQL `node(id:)` | Nested orders/PII | Mass tenant dump — prove **one** extra tenant, stop |
| `POST /teams/{id}/members` | Mass-assign `role=OWNER` | Cross-tenant admin |
| Read orders + refund IDOR | Financial | Money move — one test refund, stop |
| Soft-delete + live token | Persistent access | Post-removal ATO (`hunt-session`) |

Cross-refs: `hunt-auth-bypass`, `hunt-ato`, `hunt-graphql`, `hunt-api-misconfig`, `hunt-session`, `security-arsenal`, `triage-validation`, `triage-rtfs` (UUID-as-capability).

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
