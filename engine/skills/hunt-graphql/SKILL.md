---
name: hunt-graphql
description: Hunting skill for graphql vulnerabilities. Built from public reports across IDOR via node() / GID / Federation _entities, mutation IDOR, cross-tenant IDOR, SSRF via argument, small-batch authz and query-cost bugs (do not DoS the origin), SQLi via argument, broken object-level authz, auth-bypass via unscoped mutations, and PII from missing field-level authz. Use when hunting graphql on any target.
sources: hackerone_public, github, gitlab_security
report_count: 12
---

## Crown Jewel Targets

GraphQL vulnerabilities are high-value because the attack surface is both broad and deep — a single endpoint can expose entire data models, privilege escalation paths, and cross-API state confusion. Highest payouts occur in:

- **Platform APIs** (GitHub, Shopify, Stripe-tier targets) where GraphQL mutations interact with REST APIs managing the same resources
- **Race conditions between GraphQL mutations and REST endpoints** where state synchronization is non-atomic — these hit medium-to-high severity reliably
- **Authorization persistence bugs** where team/org/repo membership state is controlled by one API but readable/writable by another
- **B2B SaaS platforms** where one tenant affecting another via schema traversal = critical
- **Internal admin GraphQL endpoints** accidentally exposed to lower-privilege users

That desync is one pattern. Most targets have a single GraphQL API and no second writer — hunt object authz, field authz, unauthenticated mutations, and URL arguments first.

## Branch first

| You have | Do once | Proven when |
|---|---|---|
| Schema or `Did you mean` | List mutations and URL-shaped arguments | Not a finding |
| `node(id:)`, a Relay GID, or `_entities` | One object you do not own | That object's private field |
| A field on your type that exists on others | Ask for email, a token, or a recovery field on user B | B's value, not an error |
| A mutation with no auth check | Call it once, unauthenticated, on an object you may create | A state change you can show |
| An argument that is a URL, host, or webhook | One collaborator URL (`hunt-ssrf`) | Server-side DNS/HTTP hit. A response body only if the resolver returns it |
| `@defer` / `@stream` on a field you should not see | One deferred field | The incremental chunk contains it and the first payload did not |
| The same object writable from REST and GraphQL | Steps 4–7 below | The two APIs disagree after one revoke or grant |

Read-only GraphQL POST (queries/introspection) is allowed in non-intrusive mode. Mutations still require explicit authorization; POST is not treated as proof of a write by itself. Use bounded queries only and never test depth, aliases, or batches for service exhaustion.

Skip steps 4–7 when nothing else writes the object.

---

## Attack Surface Signals

**URL Patterns:**
```
/graphql
/api/graphql
/v1/graphql
/query
/gql
/graph
/api/v2/graphql
/internal/graphql
```

**Response Headers:**
```
Content-Type: application/json  (with query body)
X-Request-Id + no REST-style path params = likely GraphQL
```

**JavaScript Source Patterns:**
```js
// grep for these in JS bundles
"query {"
"mutation {"
"__typename"
"apollo"
"ApolloClient"
"graphql-tag"
"gql`"
"operationName"
"GRAPHQL_URI"
```

**Tech Stack Signals:**
- Apollo Server/Client in JS bundles
- Relay in React apps
- `graphene` or `strawberry` (Python), `graphql-ruby`, `gqlgen` (Go), `Lighthouse` (Laravel)
- POST requests with `{"query": "..."}` body shape in Burp history
- `__schema` or `__type` in any response = confirmed GraphQL

**Recon Sources:**
- `github.com` search: `"graphql" site:target.com`
- Wayback Machine for `/graphql` paths
- JS bundle scanning with `LinkFinder` or `getallurls`

---

## Step-by-Step Hunting Methodology

1. **Discover the endpoint** — spider JS bundles, check `/graphql`, `/api/graphql`, review Burp passive scan hits for `application/json` POST with query fields

2. **Test introspection** — send the full introspection query. Even if blocked, try field-level enumeration:
   ```graphql
   { __typename }
   ```
   If that returns, introspection may be partially blocked but the schema is discoverable

3. **Map the full schema** — use `InQL` (Burp extension) or `graphql-voyager` to visualize relationships. Specifically look for:
   - Mutations that modify ownership, permissions, or membership
   - Mutations that mirror REST API functionality

4. **Identify REST/GraphQL overlap** — only if both APIs write the same object. Document each shared resource. These dual-write surfaces are the desync targets. Otherwise stay on the branch table.

5. **Test authorization boundaries per mutation** — replay mutations as lower-privilege users. Does the server enforce the same authz as the equivalent REST call?

6. **Hunt cross-API state desync** — find sequences where:
   - REST action should revoke access
   - GraphQL mutation re-grants or preserves it
   - Test the ordering: REST first → GraphQL → check state; then GraphQL first → REST → check state

7. **Test for persistent privilege after role/membership changes** — remove a user via REST, then call the corresponding GraphQL mutation for that resource. Query current state via both APIs and compare.

8. **Probe for IDOR in node IDs** — GraphQL global IDs often encode object type + ID. Swap IDs across object boundaries and across account contexts.

9. **Check a small batch** — a JSON array of 2–5 operations, or aliases of one mutation. Look for authz, cost, or a one-time action applied per element. Do not grow the batch until the process OOMs. One batch that returns another user's row or double-applies a mutation is the proof. Alias concurrency depends on the server (see below); if aliases run serially, use parallel HTTP (`hunt-race-condition`).

10. **Document the exact reproduction chain** — for RC bugs, time-based steps must be reproducible deterministically.

---

## Payload & Detection Patterns

**Introspection (mutations + args — a type list without args is not a map):**
```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name kind ofType { name } } }
        type { name kind ofType { name } }
      }
    }
  }
}
```
A stacktrace in `extensions.exception` is `hunt-source-leak`, not an authz finding.

**Minimal introspection probes (try when full `__schema` is blocked):**
```graphql
{ __typename }
{ __type(name:"Query") { fields { name } } }
{ __type(name:"User") { name fields { name } } }
```

**Apollo Federation `_entities` (cross-service IDOR) and leftover `_service`:**
```graphql
{ _entities(representations: [{__typename:"User", id:"ID_B"}]) { ... on User { email } } }
{ _service { sdl } }
```
A `__typename` you learned from errors plus B's id, returning B's fields, is broken object authz. One object, then stop. `_service { sdl }` is schema recon (often live when `__schema` is blocked), not impact.

**Argument injection (one marker, then the other skill's proof):**
```graphql
query($id: String) { user(id: $id) { email } }
```
`variables: {"id":"1' AND 1=2--"}` vs `{"id":"1' AND 1=1--"}` — body-diff, then `hunt-sqli`. JSON `{"id":{"$gt":""}}` — `hunt-nosqli`. Do not claim injection from an error string alone.

**GET / CSRF / APQ:** `GET /graphql?query={__typename}` with the session cookie and no CSRF token is cookie-authenticated CSRF if a mutation is also accepted via GET (`hunt-csrf`). Persisted queries (`extensions.persistedQuery`) that fall back to a raw `query` when the hash misses are ad-hoc GraphQL again. `application/graphql` and `multipart/form-data` (file-upload spec) are the same endpoint — test the upload part for stored XSS and the URL part for SSRF.

**`@defer` (incremental delivery).** Ask for a field your role cannot see, deferred:

```graphql
query { user(id: "ID_B") { name ... @defer { email } } }
```

If `email` is absent from the first JSON and present in a later `multipart/mixed` chunk, the check ran only on the initial payload. One field, then stop.

**curl introspection test:**
```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

**Field suggestion probe (bypass blind introspection blocks):**
```graphql
{ unknownField }
```
If response returns `"Did you mean: [realFieldName]?"` — schema is enumerable despite introspection being disabled.

**Small batch (authz / one-time action, not a load test):**
```json
[
  {"query": "{ user(id: \"ID_A\") { email } }"},
  {"query": "{ user(id: \"ID_B\") { email } }"}
]
```
Stop when one element returns B's data or applies a mutation twice. WebSocket subscriptions (`graphql-ws` `connection_init`) often skip the HTTP auth middleware — send one `subscription` without the token and compare to the HTTP result.

**Dual-API desync (any product that writes the same object over REST and GraphQL):**
```bash
# 1. As admin, revoke A via the REST (or UI) path that should remove access.
# 2. As A, immediately call the GraphQL mutation that grants that same relation.
# 3. Re-read the object on BOTH APIs. The bug is REST showing "removed" while
#    GraphQL (or a direct resource GET) still allows A's action.
# Swap the order (GraphQL revoke, REST grant) if the first order is clean.
```

**Grep for GraphQL in JS bundles:**
```bash
grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js
grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js
```

**InQL / clairvoyance for blind schema enumeration:**
```bash
# /tmp/fields-from-js.txt is names already extracted from the bundle — not a password list.
python3 clairvoyance.py -u "https://$TARGET/graphql" \
  -H "Authorization: Bearer $TOKEN" \
  -w /tmp/fields-from-js.txt -o schema.json
```

---

## Common Root Causes

1. **Dual-write without atomic locking** — developers implement the same resource modification in both REST and GraphQL independently. Neither system is aware the other exists for that resource. State updates aren't serialized or compared.

2. **Inconsistent authorization middleware** — REST endpoints go through one auth layer (e.g., middleware chain), GraphQL resolvers go through a different resolver-level check. The same action, different enforcement.

3. **GraphQL as "new REST" migration** — teams add GraphQL mutations that mirror REST functionality without auditing the permission model. The GraphQL version is less mature and skips checks the REST version accumulated over time.

4. **Introspection left on in production** — default framework settings (Apollo, Graphene) enable introspection in all environments. Developers forget to disable it, treating it as "just documentation."

5. **Node ID trust without re-authorization** — GraphQL global IDs (`base64("ObjectType:123")`) are decoded and trusted without verifying the requesting user has access to that specific object.

6. **Mutation side effects not mirrored** — when a REST action triggers cascading effects (e.g., team removal cascades to permission revocation), the GraphQL equivalent mutation doesn't trigger the same cascades.

---

## Bypass Techniques

**Defense: Introspection disabled**
- Bypass via field suggestion errors — send invalid field names and parse "did you mean X?" responses
- Map names from JS query strings and from `Did you mean` errors. A short wordlist of fields you already saw is schema recon, not credential brute-force. Stop once the operations you need are known.
- Check JS bundles for hardcoded operations (`changed-js-deepdive`)

**Defense: Depth / cost limiting**
- One query slightly past the documented depth or cost, to see if the limiter is off or if a negative `first:` subtracts cost (historical pattern). Do not send a recursive fragment bomb or hold the connection open. If the server rejects the deep query, the control works — move on.

**Defense: Rate limiting per IP**
- A batch of 2–5 identical mutations, to see if a one-time action applies more than once (`hunt-race-condition`). Not a way to guess tokens, OTPs, or passwords.

**Defense: Auth checks on mutations**
- Test with tokens at different privilege tiers (viewer, member, admin)
- Test unauthenticated — some mutations don't check session at all
- Test with tokens from *different organizations* — multi-tenant IDOR

**Defense: WAF blocking `__schema`**
- Alias the introspection field:
```graphql
{ s: __schema { t: types { n: name } } }
```
- Use HTTP parameter pollution or alternate content-type headers

**Defense: Operation whitelisting (persisted queries)**
- Check if the server falls back to ad-hoc queries when the `extensions.persistedQuery` hash mismatches
- Look for a non-whitelisted endpoint (dev, staging, internal proxy)

### Alias batching: when it wins races vs when it doesn't

A common claim is "alias batching defeats per-user rate limits and double-spend protections." Whether this actually wins depends on the **resolver execution model**:

| Resolver type | Behavior on aliased mutations | What to do |
|---|---|---|
| Multi-threaded / `DataLoader`-batched async | Aliases in one request can run concurrently | Two aliases of a one-time action you own. A second success is the bug. Stop |
| Single-threaded / one DB connection per request | Aliases run in order; the second fails closed | Not a race. Parallel HTTP, one duplicate, then stop (`hunt-race-condition`) |
| Distributed gateway (Apollo Federation) | Subgraphs may run side by side | Same bar: one extra success, then stop |

Do not grow the batch to drain a balance, coupon, or inventory. Two successes on an object you own is the proof.

---

## Gate 0 Validation

1. **What can the attacker DO right now?**
   Must be a concrete action: access data they shouldn't see, retain privileges after revocation, modify another user's resources. "The schema is visible" alone is not enough — what does the schema unlock?

2. **What does the victim LOSE?**
   Must be a real asset: data confidentiality, access control integrity, org security guarantees. For the RC pattern: an org admin loses the guarantee that removing a team revokes all access. That's a security contract violation.

3. **Can it be reproduced in 10 minutes from scratch?**
   For RC/desync bugs: write the exact curl sequence. Run it twice. If the privilege persists deterministically (not timing-dependent flakiness), it's reportable. If it requires millisecond timing luck, document the window and test on low-load times.

---

## Real Impact Examples

**Scenario A — Covert Persistent Admin After Team Removal (GitHub-pattern)**
An attacker who legitimately had admin access to a repository via team membership gets removed by the org admin through the REST API. The attacker, before removal completes, calls the `updateTeamsRepository` GraphQL mutation to re-associate their team with admin permissions. The REST removal and GraphQL re-grant create a desync where the UI shows the team as removed, but the GraphQL state preserves admin-level access. The attacker retains covert write access to the repository indefinitely — pushing code, reading secrets in CI/CD — without appearing in the team's member list. This persists through org audits.

**Scenario B — Covert Access via Repo Transfer Race (GitHub-pattern)**
An attacker with admin access initiates a repository transfer to another organization via the REST API. During or after the transfer, they invoke `updateTeamsRepository` on the now-transferred repo's ID. Because the GraphQL mutation doesn't validate current org ownership state consistently with the REST transfer event, the original attacker's team retains admin access on a repo now owned by a different organization. The receiving org has no visibility into this team association. The attacker can exfiltrate intellectual property from an org they have no legitimate relationship with.

**Scenario C — Introspection as Reconnaissance Prerequisite (Shopify-pattern)**
On a platform where introspection is intentionally enabled (per-program rules), a hunter maps the full schema and discovers undocumented mutations for `fulfillmentOrderMove` and `inventoryAdjust` that are not surfaced in public docs. These mutations accept merchant IDs as arguments with no scoping validation visible in the schema. This recon directly enables targeted IDOR testing against merchant-to-merchant data isolation — the introspection itself is zero-severity, but it is the entry point to critical findings.

---

## Disclosed Report Citations (Backfill +9 — 2019-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill beyond the original 3 internal references. Each is a distinct GraphQL subclass with a working PoC documented in the cited writeup.

4. **HackerOne — Confidential user-data exposure via GraphQL `User` type** ([H1 #489146](https://hackerone.com/reports/489146))
    - Subclass: broken field-level authorization (PII exposure)
    - Payload: direct `user(id:...)` query returning `email`, `backup_codes_hash`, `facebook_user_id`, `account_recovery_phone_number_verified_at`, `totp_enabled`
    - Root cause: backend migration introduced a GraphQL `User` type with no field-level authz; any authenticated user could enumerate PII of all users
    - Year: 2019 — **$20,000**, 1,028 upvotes

5. **HackerOne — `DestroyLlmConversation` mutation IDOR (Copilot pre-release)** ([H1 #2218334](https://hackerone.com/reports/2218334))
    - Subclass: mutation IDOR on AI/LLM feature
    - Payload: `mutation { destroyLlmConversation(input:{id:"<victim_conv_id>"}) { … } }`
    - Root cause: new LLM-conversation mutation shipped without authorization decorator; any user could destroy any conversation
    - Year: 2023 — caught pre-launch, no bounty (202 upvotes)

6. **Shopify — `BillingDocumentDownload` cross-tenant IDOR** ([H1 #2207248](https://hackerone.com/reports/2207248))
    - Subclass: IDOR on relay GID across tenants
    - Payload: `query { billingDocumentDownload(id:"gid://shopify/BillingInvoice/<other_shop_id>") { url } }`
    - Root cause: `BillingInvoice` resolver authorized the requester's shop but did not verify the invoice belonged to that shop
    - Year: 2024 — **$5,000**, 175 upvotes

7. **Shopify — Rate-limit bypass via negative cost** ([H1 #481518](https://hackerone.com/reports/481518))
    - Subclass: query-cost-calc abuse (sibling pattern to alias batching)
    - Payload: `query { products(first:-100) { … } }` — negative `first` produced a negative query-cost contribution, refilling the leaky-bucket each call
    - Root cause: query-cost calculator did not floor at zero; negative values subtracted from the consumed budget
    - Year: 2019 — **$1,000**

8. **Stripe — Cross-tenant IDOR via `UpdateAtlasApplicationPerson`** ([H1 #1066203](https://hackerone.com/reports/1066203))
    - Subclass: cross-tenant IDOR on mutation
    - Payload: `mutation { updateAtlasApplicationPerson(input:{personId:"<victim_person_id>", …}) }` — adding/modifying a co-founder on another merchant's Stripe Atlas application
    - Root cause: mutation scoped only to "is admin of some merchant," not "is admin of the merchant owning this person"
    - Year: 2020 — bounty undisclosed (resolved)

9. **EXNESS — SSRF in GraphQL `allTicks` query** ([H1 #1864188](https://hackerone.com/reports/1864188))
    - Subclass: SSRF via GraphQL argument
    - Payload shape: `allTicks(source:"https://UNIQUE.collab/")`. This report was **blind** — the resolver did not return the HTTP body. OOB is the proof. An IMDS URL counts only if the token body comes back (`hunt-ssrf`)
    - Root cause: GraphQL field accepted a URL arg and dereferenced it without scheme/host allowlist
    - Year: 2023 — **$3,000**

10. **EXNESS — missing batch/depth limits** ([H1 #2293642](https://hackerone.com/reports/2293642))
    - Historical case of unbounded batching on an unauthenticated `/graphql`. Do **not** send a nested batch or hold the connection open.
    - Safe test: one modest query a documented limit should reject. If it is accepted, note the missing control and stop. This harness does not prove DoS.

11. **GitLab — Malicious-runner attach via `runnerUpdate` (CVE-2023-2478)** ([Advisory](https://about.gitlab.com/releases/2023/05/05/critical-security-release-gitlab-15-11-2-released/))
    - Subclass: auth bypass on mutation / project-scope missing
    - Payload: `mutation { runnerUpdate(input:{id:"<attacker_runner_gid>", associatedProjects:["<victim_project_gid>"]}) }`
    - Root cause: `runnerUpdate` did not check that the caller had Maintainer on the target project — any user could bind their malicious runner and intercept CI jobs (build secrets, code execution)
    - Year: 2023 — Critical, CVSS 9.6. Vulnerable ranges are 15.4.0–15.9.6, 15.10.0–15.10.5, and 15.11.0–15.11.1. One runner attach on an in-scope project, then remove it.

12. **AS Watson — Auth bypass via unrestricted `createAdminUser` mutation** ([HackerOne blog](https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass))
    - Subclass: sensitive mutation reachable without authentication (introspection-aided discovery)
    - Payload: `mutation { createAdminUser(input:{email:"x@x", role:"ADMIN", password:"…"}) { token } }` invoked unauthenticated after schema enumeration via introspection
    - Root cause: schema lacked per-field authorization directives; `createAdminUser` exposed to public role
    - Year: 2023 — "Best Bug" prize at HackerOne Ambassador World Cup

---

## Related Skills & Chains

- **`hunt-idor`** — GraphQL `node(id:)` and global-relay-ID resolvers are IDOR factories: same shape, no scoping. Chain primitive: GraphQL introspection + IDOR (`node()` resolver) → cross-tenant data via base64-decoded type:id replay.
- **`hunt-sqli` / `hunt-nosqli`** — a GraphQL argument that body-diffs on `' AND 1=1` / `{"$gt":""}` is the same injection class; prove it under those skills, not as "GraphQL error".
- **`hunt-source-leak`** — `extensions.exception.stacktrace` / `_service { sdl }` is recon, not impact.
- **`hunt-api-misconfig`** — GraphQL mutations are mass-assignment magnets: clients send full input objects, server merges. Chain primitive: GraphQL mutation + extra fields (`isAdmin:true`, `verified:true`) → mass assignment → role escalation.
- **`hunt-business-logic`** — Two aliases of a one-time mutation in one request. A second success on an object you own is the bug; stop there.
- **`hunt-race-condition`** — When aliases run serially, one parallel duplicate is the race proof. Do not scale it.
- **`security-arsenal`** — Introspection query, suggestion probe, one alias pair, one 2-element batch. No depth bomb and no batch sized to exhaust the process.
- **`triage-validation`** — Apply the Body-Diff Rule: introspection alone is informational; require a concrete cross-tenant read or mutation-with-impact PoC before submitting.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
