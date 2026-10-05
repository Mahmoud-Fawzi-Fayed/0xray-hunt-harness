#!/usr/bin/env python3
"""
observe.py — best-effort surface observation for the novelty monitor.

Produces the observation dict that novelty.py consumes:
  {subdomains[], hosts[{url,status,title,tech}], js[{url,hash}], endpoints[], params[]}

Strategy (all steps optional + defensive — any failure yields a partial obs, never a crash):
  - subdomains : subfinder (passive) if installed, UNION existing recon/<target>/ files.
  - hosts      : httpx if installed, else a light curl -sI per subdomain (capped).
  - js         : fetch each live host root, extract <script src> .js URLs, sha256 the bytes
                 (a hash change = a redeploy = the highest-value novelty signal).
  - endpoints/params : read existing recon outputs if present (we do NOT crawl here).

Passive / read-only only — no fuzzing, no brute force (honors the workspace no-bruteforce rule).
stdlib + optional external CLIs (subfinder/httpx/curl). Importable and CLI-runnable.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urljoin, urlparse

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
_JS_SRC = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.I)


def _have(tool):
    return shutil.which(tool) is not None


def _run(cmd, timeout=60, inp=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=inp, errors="ignore")
        return p.stdout or ""
    except Exception:
        return ""


def _host_of(target):
    t = target if "://" in target else "//" + target
    return (urlparse(t, scheme="https").hostname or target).strip().lower()


def _apex(host):
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _recon_dirs(target, base):
    cands = [f"recon/{target}", os.path.expanduser(f"~/recon/{target}"),
             os.path.join(os.path.expanduser(base), "_recon", target)]
    return [d for d in cands if os.path.isdir(d)]


def _read_lines(path):
    try:
        return [ln.strip() for ln in open(path, encoding="utf-8", errors="ignore") if ln.strip()]
    except Exception:
        return []


def _from_recon(target, base):
    """Pull subdomains / endpoints / params from any existing recon/<target>/ outputs."""
    subs, endpoints, params = set(), set(), set()
    for d in _recon_dirs(target, base):
        for fn in ("subdomains.txt", "subs.txt", "live-hosts.txt", "hosts.txt"):
            subs.update(_host_of(x) for x in _read_lines(os.path.join(d, fn)))
        for fn in ("urls.txt", "katana.txt", "gau.txt", "endpoints.txt", "waybackurls.txt"):
            endpoints.update(_read_lines(os.path.join(d, fn)))
        for fn in ("params.txt", "parameters.txt"):
            params.update(_read_lines(os.path.join(d, fn)))
    return subs, endpoints, params


def observe(target, base=DEFAULT_BASE, live=True, cap_hosts=12, cap_js=40, timeout=120, deadline_s=120):
    """Build a surface observation. `deadline_s` is a wall-clock budget: the (potentially slow)
    live host/JS probing short-circuits once exceeded, so a monitor tick never hangs. Returns
    whatever was gathered so far — partial is fine, the diff still works."""
    t0 = time.time()
    host = _host_of(target)
    apex = _apex(host)
    subs, endpoints, params = _from_recon(target, base)
    subs.update({host, apex})

    if live and _have("subfinder"):
        for ln in _run(["subfinder", "-silent", "-d", apex], timeout=timeout).splitlines():
            ln = ln.strip().lower()
            if ln:
                subs.add(ln)
    subs = sorted(s for s in subs if s and "." in s)

    hosts = []
    if live and _have("httpx"):
        out = _run(["httpx", "-silent", "-json", "-status-code", "-title", "-td", "-no-color"],
                   timeout=timeout, inp="\n".join(subs))
        for ln in out.splitlines():
            try:
                j = json.loads(ln)
            except json.JSONDecodeError:
                continue
            url = j.get("url") or j.get("input")
            if url:
                hosts.append({"url": url, "status": j.get("status_code") or j.get("status-code"),
                              "title": j.get("title", ""), "tech": j.get("tech") or j.get("technologies") or []})
    elif live:
        for s in subs[:cap_hosts]:
            if time.time() - t0 > deadline_s:
                break
            code = _run(["curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10",
                         f"https://{s}"], timeout=15).strip()
            if code and code != "000":
                hosts.append({"url": f"https://{s}", "status": int(code) if code.isdigit() else code,
                              "title": "", "tech": []})
    if not hosts:
        hosts = [{"url": f"https://{host}", "status": None, "title": "", "tech": []}]

    js = {}
    if live:
        for h in hosts[:cap_hosts]:
            if time.time() - t0 > deadline_s:
                break
            url = h["url"]
            html = _run(["curl", "-sL", "-m", "12", url], timeout=15)
            for m in _JS_SRC.findall(html):
                if time.time() - t0 > deadline_s:
                    break
                ju = urljoin(url, m)
                if ju in js or len(js) >= cap_js:
                    continue
                body = _run(["curl", "-sL", "-m", "12", ju], timeout=15)
                if body:
                    js[ju] = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16]
            if len(js) >= cap_js:
                break

    return {
        "target": target,
        "subdomains": subs,
        "hosts": sorted(hosts, key=lambda x: x.get("url", "")),
        "js": [{"url": u, "hash": h} for u, h in sorted(js.items())],
        "endpoints": sorted(endpoints),
        "params": sorted(params),
    }


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="best-effort surface observation")
    ap.add_argument("--target", required=True)
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--offline", action="store_true", help="recon files only; run no external tools")
    a = ap.parse_args(argv)
    print(json.dumps(observe(a.target, base=a.base, live=not a.offline), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
