#!/usr/bin/env python3
"""
notify.py — email notifier for the harness (verified+drafted findings, monitor alerts).

stdlib smtplib only. Config comes from the environment (the harness .env is sourced by the bridge
and scripts). Dry-run safe: if SMTP isn't configured it prints and returns False instead of raising,
so a hunt never crashes just because mail isn't set up yet.

Env:
  SMTP_HOST        smtp server host (empty => dry-run)
  SMTP_PORT        default 587
  SMTP_USER        login user (optional for open relays)
  SMTP_PASS        login password / app-password / API key
  SMTP_FROM        From address (falls back to SMTP_USER)
  SMTP_TO          default recipient(s), comma-separated
  SMTP_CC          default Cc recipient(s), comma-separated (optional)
  SMTP_BCC         default Bcc recipient(s), comma-separated (optional)
  SMTP_TLS         starttls (default) | ssl | none

CLI:
  python3 engine/notify.py send --subject "..." --body "..." [--to you@x.com]
  python3 engine/notify.py send --subject "..." --stdin        # body from stdin
  python3 engine/notify.py test                                # send a test mail (needs config)
  python3 engine/notify.py selftest                            # offline: message build + dry-run
"""
import argparse
import datetime
import json
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage


def site_alert(target, summary, base=None, kind=None):
    """Append an ON-SITE alert to the panel's feed (<base>/_alerts/feed.jsonl) — rendered in the
    dashboard's 'New-surface alerts' box via the bridge /novelty/feed. Used for stuck hunts,
    can't-register/needs-auth, and overload notices (site-only, no email). Best-effort; never raises."""
    base = base or os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
    try:
        d = os.path.join(os.path.expanduser(base), "_alerts")
        os.makedirs(d, exist_ok=True)
        entry = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "target": str(target),
                 "summary": summary if isinstance(summary, list) else [str(summary)]}
        if kind:
            entry["kind"] = kind
        with open(os.path.join(d, "feed.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return True
    except Exception:  # noqa: BLE001
        return False


_ENV_LOADED = False


def _load_env_file():
    """Best-effort: pull SMTP_* from the harness .env so email works regardless of how the caller
    was launched. Only fills keys NOT already in the environment. Override path with HUNT_ENV_FILE."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True
    path = os.environ.get("HUNT_ENV_FILE", os.path.expanduser("~/BugHunting_0xRay/harness/.env"))
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if (k.startswith("SMTP_") or k.startswith("HUNT_") or k.startswith("CURSOR_")) and k not in os.environ:
                os.environ[k] = v.strip()
    except OSError:
        pass


def cfg():
    _load_env_file()
    g = os.environ.get
    return {
        "host": g("SMTP_HOST", ""), "port": int(g("SMTP_PORT", "587") or 587),
        "user": g("SMTP_USER", ""), "pass": g("SMTP_PASS", ""),
        "from": g("SMTP_FROM", "") or g("SMTP_USER", "") or "hunt-harness@localhost",
        "to": g("SMTP_TO", ""), "cc": g("SMTP_CC", ""), "bcc": g("SMTP_BCC", ""),
        "tls": (g("SMTP_TLS", "starttls") or "starttls").lower(),
    }


def configured(c=None):
    c = c or cfg()
    return bool(c["host"] and c["to"])


def build(subject, body, to=None, c=None, html=None, cc=None, bcc=None):
    c = c or cfg()
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = c["from"]
    msg["To"] = to or c["to"]
    cc = c.get("cc", "") if cc is None else cc
    bcc = c.get("bcc", "") if bcc is None else bcc
    if cc:
        msg["Cc"] = cc
    if bcc:
        msg["Bcc"] = bcc                             # send_message delivers to Bcc, then strips the header
    msg.set_content(body or "")
    if html:
        msg.add_alternative(html, subtype="html")   # multipart/alternative: clients prefer the HTML
    return msg


def send(subject, body, to=None, c=None, html=None, cc=None, bcc=None):
    """Send mail. Returns True on success, False if not configured (dry-run). Raises on real SMTP errors.
    Cc/Bcc default to SMTP_CC / SMTP_BCC from the env, so every send honors them from one place."""
    c = c or cfg()
    recipient = to or c["to"]
    cc = c.get("cc", "") if cc is None else cc
    bcc = c.get("bcc", "") if bcc is None else bcc
    if not (c["host"] and (recipient or cc or bcc)):
        print(f"[notify] DRY-RUN (SMTP not configured) — would send: {subject!r} -> {recipient or '(no SMTP_TO)'}",
              file=sys.stderr)
        return False
    msg = build(subject, body, to=recipient, c=c, html=html, cc=cc, bcc=bcc)
    ctx = ssl.create_default_context()
    if c["tls"] == "ssl":
        srv = smtplib.SMTP_SSL(c["host"], c["port"], context=ctx, timeout=25)
    else:
        srv = smtplib.SMTP(c["host"], c["port"], timeout=25)
        if c["tls"] != "none":
            srv.starttls(context=ctx)
    try:
        if c["user"]:
            srv.login(c["user"], c["pass"])
        srv.send_message(msg)
    finally:
        try:
            srv.quit()
        except Exception:
            pass
    return True


def send_safe(subject, body, to=None, html=None, cc=None, bcc=None):
    """Never raises — for use inside the hunt loop. Returns True/False."""
    try:
        return send(subject, body, to=to, html=html, cc=cc, bcc=bcc)
    except Exception as e:  # noqa: BLE001
        print(f"[notify] send failed (non-fatal): {type(e).__name__}: {e}", file=sys.stderr)
        return False


# --------------------------------------------------------------- professional HTML templates
SEV_COLOR = {"critical": "#b00020", "high": "#d93025", "medium": "#f29900", "low": "#1a73e8",
             "info": "#5f6368", "unknown": "#5f6368"}


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def _badge(sev):
    color = SEV_COLOR.get(str(sev).lower(), "#5f6368")
    return (f'<span style="background:{color};color:#fff;padding:3px 10px;border-radius:12px;'
            f'font-size:11px;font-weight:700;letter-spacing:.3px;text-transform:uppercase">{_esc(sev)}</span>')


def _shell(inner):
    return (
        '<!doctype html><html><body style="margin:0;background:#eef0f3;'
        'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
        '<div style="max-width:640px;margin:0 auto;padding:24px">'
        '<div style="background:#0d1117;border-radius:12px 12px 0 0;padding:20px 24px">'
        '<div style="color:#fff;font-size:23px;font-weight:800;letter-spacing:.3px">'
        '<span style="color:#5a97ff">0x</span>Ray'
        '<span style="font-size:12px;font-weight:600;color:#8b949e;letter-spacing:1.5px;margin-left:8px">HUNT HARNESS</span></div>'
        '<div style="color:#8b949e;font-size:13px;margin-top:4px">Verified findings, ready for your review</div>'
        '</div>'
        '<div style="background:#fff;border-radius:0 0 12px 12px;padding:24px;'
        'box-shadow:0 1px 4px rgba(0,0,0,.08)">' + inner +
        '<p style="margin:26px 0 0;color:#9aa0a6;font-size:12px;text-align:center;'
        'border-top:1px solid #eee;padding-top:14px">Automated by your hunt harness · nothing is submitted '
        'without your approval</p></div></div></body></html>')


def finding_email(program, findings, public_url=None):
    """Return (subject, text, html) for a batch of verified+drafted findings.
    findings: [{vuln_class, url, severity, verdict, score, link(optional public URL)}]."""
    n = len(findings)
    subject = f"🎯 {n} finding{'s' if n != 1 else ''} ready to review — {program}"
    tlines = [f"{n} finding(s) verified + validated + drafted on {program}. Nothing submitted.", ""]
    rows = ""
    for f in findings:
        sev = f.get("severity", "unknown")
        link = f.get("link") or public_url
        tlines.append(f"- [{str(sev).upper()}] {str(f.get('vuln_class', '?')).upper()} @ {f.get('url', '')} "
                      f"(dedup {f.get('verdict', '?')})" + (f"  open: {link}" if link else ""))
        btn = (f'<a href="{_esc(link)}" style="background:#1a73e8;color:#fff;text-decoration:none;'
               f'padding:8px 14px;border-radius:6px;font-size:13px;white-space:nowrap">Open</a>') if link else "&nbsp;"
        rows += (
            '<tr>'
            f'<td style="padding:12px 8px;border-bottom:1px solid #eef0f3;vertical-align:top">{_badge(sev)}</td>'
            f'<td style="padding:12px 8px;border-bottom:1px solid #eef0f3">'
            f'<b style="font-size:14px">{_esc(str(f.get("vuln_class","?")).upper())}</b><br>'
            f'<span style="color:#5f6368;font-size:12px;font-family:monospace">{_esc(f.get("url",""))}</span></td>'
            f'<td style="padding:12px 8px;border-bottom:1px solid #eef0f3;font-size:12px;color:#5f6368">'
            f'{_esc(f.get("verdict","?"))}<br>score {_esc(f.get("score",""))}</td>'
            f'<td style="padding:12px 8px;border-bottom:1px solid #eef0f3;text-align:right">{btn}</td>'
            '</tr>')
    cta = (f'<div style="margin-top:22px;text-align:center">'
           f'<a href="{_esc(public_url)}" style="background:#0d1117;color:#fff;text-decoration:none;'
           f'padding:11px 22px;border-radius:8px;font-size:14px;font-weight:600">View all findings</a></div>'
           ) if public_url else ""
    inner = (
        f'<p style="margin:0 0 4px;font-size:15px;color:#202124"><b>{n}</b> finding(s) '
        f'verified + validated + drafted on <b>{_esc(program)}</b>.</p>'
        f'<p style="margin:0 0 18px;color:#5f6368;font-size:13px">Review each one, then approve before submitting.</p>'
        f'<table style="width:100%;border-collapse:collapse">{rows}</table>{cta}')
    return subject, "\n".join(tlines), _shell(inner)


def _cmd_send(a):
    body = sys.stdin.read() if a.stdin else (a.body or "")
    ok = send(a.subject, body, to=a.to)
    print("sent" if ok else "dry-run (SMTP not configured)")
    return 0


def _cmd_test(_a):
    c = cfg()
    if not configured(c):
        print("test: SMTP not configured — set SMTP_HOST and SMTP_TO (see harness/.env)", file=sys.stderr)
        return 1
    pub = os.environ.get("HUNT_PUBLIC_URL")
    subject, text, html = finding_email("sample-program", [
        {"vuln_class": "idor", "url": "https://example.com/api/v2/users/5/orders",
         "severity": "high", "verdict": "NOVEL", "score": 0.0, "link": pub}], public_url=pub)
    ok = send("[hunt] test — this is what finding emails look like", text, html=html)
    print("sent HTML test email to", c["to"] if ok else "(failed)")
    return 0 if ok else 1


def _cmd_selftest(_a):
    # hermetic: never load the real harness .env, never actually send
    global _ENV_LOADED
    os.environ["HUNT_ENV_FILE"] = "/nonexistent-selftest-env"
    _ENV_LOADED = False
    # offline: message builds correctly, and dry-run returns False without raising
    m = build("S", "B", to="x@y.z", c={"from": "a@b.c", "to": "x@y.z"})
    assert m["Subject"] == "S" and m["To"] == "x@y.z" and "B" in m.get_content()
    # Cc: an explicit arg sets the header, and a cfg default (SMTP_CC) applies when the caller passes none
    assert build("S", "B", to="x@y.z", cc="cc@y.z",
                 c={"from": "a@b.c", "to": "x@y.z"})["Cc"] == "cc@y.z", "explicit Cc must set header"
    assert build("S", "B",
                 c={"from": "a@b.c", "to": "x@y.z", "cc": "def@y.z"})["Cc"] == "def@y.z", "default SMTP_CC must apply"
    saved = {k: os.environ.pop(k, None) for k in ("SMTP_HOST", "SMTP_TO")}
    try:
        assert send("s", "b") is False                      # unconfigured => dry-run, no raise
        assert send_safe("s", "b") is False
        assert configured({"host": "", "to": ""}) is False
        assert configured({"host": "h", "to": "t@x"}) is True
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
    print("notify.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="harness email notifier")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("send")
    ps.add_argument("--subject", required=True)
    ps.add_argument("--body", default="")
    ps.add_argument("--to", default=None)
    ps.add_argument("--stdin", action="store_true")
    ps.set_defaults(fn=_cmd_send)
    sub.add_parser("test").set_defaults(fn=_cmd_test)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
