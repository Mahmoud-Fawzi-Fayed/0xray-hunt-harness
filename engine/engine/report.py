#!/usr/bin/env python3
"""
report.py — triager-grade finding reports for bug bounty platforms.

Generates both markdown (human-readable, pasting into H1/Bugcrowd) and JSON
(machine-readable, for API submission) from confirmed findings + engagement state.

CLI:
  python3 engine/engine/report.py format --file state.json --program X [--json] [--markdown]
  python3 engine/engine/report.py selftest
"""
import argparse
import json
import os
import re
import sys

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _severity_rank(s):
    return SEVERITY_ORDER.get((s or "unknown").lower(), 5)


def format_finding_markdown(f, index=1):
    """Format a single confirmed finding as triager-grade markdown."""
    lines = []
    cls = (f.get("vuln_class") or "unknown").upper()
    sev = (f.get("severity") or "unknown").capitalize()
    url = f.get("url", "")
    param = f.get("param", "")

    lines.append(f"## {index}. [{sev}] {cls} — {url}")
    if param:
        lines.append(f"**Parameter:** `{param}`")
    lines.append("")

    # Impact
    impact = f.get("evidence") or f.get("impact") or ""
    if impact:
        lines.append(f"### Impact")
        lines.append(impact)
        lines.append("")

    # Reproduction steps
    steps = f.get("steps") or []
    if isinstance(steps, str):
        steps = [s.strip() for s in steps.split("\n") if s.strip()]
    if steps:
        lines.append("### Steps to Reproduce")
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    # Request/Response evidence
    req = f.get("request") or ""
    if req:
        lines.append("### Request")
        lines.append(f"```http\n{req}\n```")
        lines.append("")

    resp = f.get("response") or ""
    if resp:
        lines.append("### Response")
        lines.append(f"```http\n{resp[:2000]}\n```")
        lines.append("")

    # Reproduction status
    rp = f.get("reproduction") or {}
    if rp.get("status"):
        label = {"reproduced": "Independently reproduced",
                 "inconclusive": "NOT independently reproduced — verify manually",
                 "disproved": "DISPROVED — do not submit"
                 }.get(rp["status"], rp["status"])
        lines.append(f"**Verification:** {label} ({rp.get('method', '')}) — {rp.get('signal', '')}")
        lines.append("")

    # Dedup
    dd = f.get("dedup") or {}
    if dd.get("verdict"):
        lines.append(f"**Dedup:** {dd['verdict']} (similarity {dd.get('score', 0):.2f})")
        if dd.get("matches"):
            near = dd["matches"][0]
            lines.append(f"  Nearest known: {near.get('title', '')[:80]} {near.get('link', '')}")
        lines.append("")

    # Scope warnings
    if f.get("scope_warning"):
        lines.append(f"**SCOPE WARNING:** PoC referenced out-of-scope host(s): "
                     f"`{'`, `'.join(f['scope_warning'])}` — verify the in-scope finding holds without them.")
        lines.append("")

    if f.get("proof_note"):
        lines.append(f"**Note:** {f['proof_note']}")
        lines.append("")

    return "\n".join(lines)


def format_finding_json(f):
    """Format a single finding as platform-ready JSON."""
    steps = f.get("steps") or []
    if isinstance(steps, str):
        steps = [s.strip() for s in steps.split("\n") if s.strip()]

    return {
        "title": f"{(f.get('vuln_class') or 'unknown').upper()} — {f.get('url', '')}",
        "severity": (f.get("severity") or "unknown").lower(),
        "vulnerability_type": (f.get("vuln_class") or "unknown").lower(),
        "url": f.get("url", ""),
        "parameter": f.get("param", ""),
        "impact": f.get("evidence") or f.get("impact") or "",
        "steps_to_reproduce": steps,
        "evidence": {
            "request": f.get("request", ""),
            "response": f.get("response", ""),
            "proof_note": f.get("proof_note", ""),
        },
        "verification": {
            "status": (f.get("reproduction") or {}).get("status", ""),
            "method": (f.get("reproduction") or {}).get("method", ""),
            "signal": (f.get("reproduction") or {}).get("signal", ""),
        },
        "dedup": {
            "verdict": (f.get("dedup") or {}).get("verdict", ""),
            "score": (f.get("dedup") or {}).get("score", 0),
        },
        "scope_warning": f.get("scope_warning") or [],
    }


def generate_report(findings, scope_name="engagement", in_scope=None, summary=None):
    """Generate a full engagement report in both markdown and JSON formats."""
    findings = sorted(findings, key=lambda f: _severity_rank(f.get("severity")))
    s = summary or {}

    md_lines = [
        f"# Engagement Report — {scope_name}",
        "",
        f"**In scope:** `{'`, `'.join(in_scope or [])}`",
        f"**Surface mapped:** {s.get('surface', '?')} | **Tested:** {s.get('tested', '?')} | "
        f"**Candidates:** {s.get('candidates', '?')} | **Confirmed:** {len(findings)}",
        "",
    ]

    if not findings:
        md_lines.append("No confirmed findings.")
        md_lines.append("")
    else:
        flagged = [f for f in findings if f.get("scope_warning")]
        if flagged:
            md_lines.append(f"> **{len(flagged)} finding(s) flagged:** PoC referenced out-of-scope "
                            f"host(s) — review before submitting.")
            md_lines.append("")

        for i, f in enumerate(findings, 1):
            md_lines.append(format_finding_markdown(f, i))

    json_output = {
        "engagement": scope_name,
        "in_scope": in_scope or [],
        "summary": s,
        "findings_count": len(findings),
        "findings": [format_finding_json(f) for f in findings],
    }

    return {
        "markdown": "\n".join(md_lines),
        "json": json_output,
    }


def write_report(findings, out_dir, scope_name="engagement", **kwargs):
    """Write report files to disk. Returns paths."""
    os.makedirs(out_dir, exist_ok=True)
    report = generate_report(findings, scope_name=scope_name, **kwargs)

    md_path = os.path.join(out_dir, "report.md")
    with open(md_path, "w") as f:
        f.write(report["markdown"])

    json_path = os.path.join(out_dir, "report.json")
    with open(json_path, "w") as f:
        json.dump(report["json"], f, indent=2)

    return {"markdown": md_path, "json": json_path}


# ------- CLI -------

def _cmd_format(a):
    if a.file:
        with open(a.file) as f:
            data = json.load(f)
    elif a.stdin:
        data = json.load(sys.stdin)
    else:
        print("ERROR: provide --file or --stdin", file=sys.stderr)
        return 1

    findings = data.get("confirmed") or data.get("findings") or []
    scope_name = a.program or data.get("name") or "engagement"
    report = generate_report(findings, scope_name=scope_name,
                             in_scope=data.get("in_scope"),
                             summary=data.get("summary"))

    if a.json_out:
        print(json.dumps(report["json"], indent=2))
    else:
        print(report["markdown"])
    return 0


def _cmd_selftest(_a):
    # Test with mock findings
    findings = [
        {
            "url": "https://api.acme.com/api/v1/users/123",
            "param": "id",
            "vuln_class": "idor",
            "severity": "high",
            "evidence": "User B can read User A's profile data including email and phone",
            "request": "GET /api/v1/users/123 HTTP/1.1\nHost: api.acme.com\nCookie: session=B_TOKEN",
            "steps": "1. Login as User A, note user ID 123\n2. Login as User B\n3. GET /api/v1/users/123 as User B\n4. Observe: B receives A's data",
            "reproduction": {"status": "reproduced", "method": "two-account-diff", "signal": "B reads A's data"},
            "dedup": {"verdict": "NOVEL", "score": 0.12, "corpus_size": 45, "matches": []},
        },
        {
            "url": "https://api.acme.com/search?q=test",
            "param": "q",
            "vuln_class": "xss",
            "severity": "medium",
            "evidence": "Reflected XSS in search results page",
            "request": "GET /search?q=<svg/onload=alert(1)> HTTP/1.1",
            "reproduction": {"status": "reproduced", "method": "live-retest", "signal": "payload reflected unencoded"},
            "dedup": {"verdict": "REVIEW", "score": 0.55, "corpus_size": 45,
                      "matches": [{"title": "XSS in search", "link": "https://h1.com/reports/999"}]},
            "scope_warning": ["evil.com"],
        },
    ]

    report = generate_report(findings, scope_name="acme",
                             in_scope=["*.acme.com"],
                             summary={"surface": 150, "tested": 120, "candidates": 5, "confirmed": 2})

    md = report["markdown"]
    assert "# Engagement Report" in md
    assert "IDOR" in md
    assert "XSS" in md
    assert "Independently reproduced" in md
    assert "SCOPE WARNING" in md
    assert "NOVEL" in md
    assert len(report["json"]["findings"]) == 2
    assert report["json"]["findings"][0]["severity"] == "high"
    assert report["json"]["findings"][0]["vulnerability_type"] == "idor"

    # Test format functions
    md_single = format_finding_markdown(findings[0])
    assert "IDOR" in md_single
    assert "api.acme.com" in md_single

    j_single = format_finding_json(findings[0])
    assert j_single["severity"] == "high"
    assert j_single["url"] == "https://api.acme.com/api/v1/users/123"
    assert j_single["verification"]["status"] == "reproduced"

    # Empty findings
    empty = generate_report([], scope_name="empty")
    assert "No confirmed findings" in empty["markdown"]
    assert empty["json"]["findings_count"] == 0

    # Write to disk
    import tempfile
    tmpdir = tempfile.mkdtemp()
    paths = write_report(findings, tmpdir, scope_name="acme",
                         in_scope=["*.acme.com"],
                         summary={"surface": 150, "tested": 120, "candidates": 5, "confirmed": 2})
    assert os.path.isfile(paths["markdown"])
    assert os.path.isfile(paths["json"])
    with open(paths["json"]) as f:
        loaded = json.load(f)
    assert loaded["findings_count"] == 2

    print("report.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="triager-grade finding reports")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("format", help="Format findings into a report")
    pf.add_argument("--file", help="State JSON file with confirmed findings")
    pf.add_argument("--stdin", action="store_true", help="Read from stdin")
    pf.add_argument("--program", help="Program name")
    pf.add_argument("--json", dest="json_out", action="store_true", help="Output JSON instead of markdown")
    pf.set_defaults(fn=_cmd_format)

    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
