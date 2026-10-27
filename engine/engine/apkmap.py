#!/usr/bin/env python3
"""
apkmap.py — extract the API attack surface from an Android APK (jadx preferred, apktool fallback).

For app-backed programs — especially ones whose live API is geo/IP-gated (a mobile backend you can't
reach from the hunt host) — the APK still ships the endpoints, hosts, params, and sometimes hardcoded
secrets/JWTs. Decompile once, grep the surface, then feed hosts -> scope.in_scope and paths ->
scope.endpoints, or request them via netget through a proxy.

Needs jadx or apktool on PATH.

CLI:
  python3 apkmap.py extract --apk app.apk [--out surface.json]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from shutil import which
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
PATH_RE = re.compile(r'["\'`](/[A-Za-z0-9_./{}:\-]{2,})["\'`]')
CALL_RE = re.compile(r"fetch|axios|httprequest|okhttp|retrofit|httpurlconnection", re.I)
SECRET_RE = [
    ("google_api", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("basic_auth_url", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@")),
]


def _decompile(apk, outdir):
    if which("jadx"):
        subprocess.run(["jadx", "-d", outdir, "--no-res", apk], capture_output=True, text=True, timeout=300)
        return os.path.join(outdir, "sources")
    if which("apktool"):
        subprocess.run(["apktool", "d", "-f", "-o", outdir, apk], capture_output=True, text=True, timeout=300)
        return outdir
    raise RuntimeError("need jadx or apktool on PATH")


def extract(apk, scan_dir=None):
    root = scan_dir or _decompile(apk, tempfile.mkdtemp())
    urls, paths, hosts, secrets = set(), set(), set(), []
    for dp, _, files in os.walk(root):
        for f in files:
            if not f.endswith((".java", ".kt", ".smali", ".xml", ".json", ".js")):
                continue
            try:
                txt = open(os.path.join(dp, f), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for m in URL_RE.findall(txt):
                urls.add(m[:200])
                h = urlparse(m).hostname
                if h:
                    hosts.add(h)
            for m in PATH_RE.finditer(txt):
                context = txt[max(0, m.start() - 300):m.end() + 300]
                if CALL_RE.search(context):
                    paths.add(m.group(1)[:150])
            for label, rx in SECRET_RE:
                for s in rx.findall(txt):
                    secrets.append({"type": label, "value": s[:64], "file": f})
    return {"hosts": sorted(hosts)[:200], "urls": sorted(urls)[:500],
            "api_paths": sorted(paths)[:500], "secrets": secrets[:100]}


def _main(argv=None):
    ap = argparse.ArgumentParser(description="APK -> API surface")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pe = sub.add_parser("extract"); pe.add_argument("--apk", required=True); pe.add_argument("--out")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    res = extract(a.apk)
    if a.out:
        json.dump(res, open(a.out, "w"), indent=2)
    print(json.dumps(res, indent=2)[:3000])
    print(f"\nhosts={len(res['hosts'])} urls={len(res['urls'])} api_paths={len(res['api_paths'])} "
          f"secrets={len(res['secrets'])} — feed hosts->scope.in_scope, paths->scope.endpoints.", file=sys.stderr)
    return 0


def _selftest():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "src"))
    open(os.path.join(d, "src", "Api.java"), "w").write(
        'String base="https://hpcs.example.eu/Mobile2/api/v1/"; String p="/api/v1/account/InfosPerso"; '
        'OkHttpClient.newCall(request); '
        'String k="AIzaSyA1234567890abcdefghijklmnopqrstuv"; String t="eyJabcdefghij.klmnopqrstuv.wxyz012345";')
    r = extract(None, scan_dir=d)
    assert "hpcs.example.eu" in r["hosts"], r["hosts"]
    assert any("/api/v1/account/InfosPerso" in p for p in r["api_paths"]), r["api_paths"]
    assert any(s["type"] in ("google_api", "jwt") for s in r["secrets"]), r["secrets"]
    print("apkmap.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
