#!/usr/bin/env python3
"""
intake.py — universal program URL intake: H1 / Bugcrowd / YWH / Intigriti URL → scope → engagement.

Takes a program URL (or platform+slug), fetches scope via bb-platforms MCP,
converts it to engine scope.json, and creates the engagement directory.

CLI:
  python3 engine/engine/intake.py start "https://hackerone.com/acme"
  python3 engine/engine/intake.py start --platform hackerone --slug acme
  python3 engine/engine/intake.py selftest
"""
import argparse
import json
import os
import re
import subprocess
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
BB_PLATFORMS_URL = os.environ.get("BB_PLATFORMS_URL", "http://127.0.0.1:3333/call")

# Platform URL patterns → (platform, slug)
# Anchored to hostname boundary to prevent false matches
_PLATFORM_PATTERNS = [
    (re.compile(r"(?:^|://)(?:www\.)?hackerone\.com/(?:programs/)?([a-zA-Z0-9_-]+)/?(?:\?|#|$)", re.I), "hackerone"),
    (re.compile(r"(?:^|://)(?:www\.)?bugcrowd\.com/(?:engagements/)?([a-zA-Z0-9_-]+)/?(?:\?|#|$)", re.I), "bugcrowd"),
    (re.compile(r"(?:^|://)(?:www\.)?yeswehack\.com/programs/([a-zA-Z0-9_-]+)/?(?:\?|#|$)", re.I), "yeswehack"),
    (re.compile(r"(?:^|://)(?:www\.|app\.)?intigriti\.com/(?:company/)?programs?/([a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)?)/?(?:\?|#|$)", re.I), "intigriti"),
]


def _normalize_slug(slug):
    """Canonicalize slug: lowercase, strip unsafe chars, prevent path traversal."""
    slug = re.sub(r'[^a-zA-Z0-9_-]', '-', slug.strip().lower())
    slug = re.sub(r'-+', '-', slug).strip('-')
    if not slug or slug in ('.', '..') or '/' in slug:
        raise ValueError(f"Invalid program slug: {slug!r}")
    return slug[:80]


def parse_program_url(url):
    """Extract (platform, slug) from a program URL. Returns (None, None) if unrecognized."""
    url = url.strip()
    for pattern, platform in _PLATFORM_PATTERNS:
        m = pattern.search(url)
        if m:
            slug = m.group(1).rstrip("/")
            return platform, slug
    return None, None


def _mcp_call_bb(tool, args_dict, timeout=30):
    """Call a bb-platforms MCP tool via its HTTP endpoint. Returns parsed JSON or None."""
    import urllib.request
    import urllib.error
    try:
        payload = json.dumps({"tool": tool, "arguments": args_dict}).encode()
        req = urllib.request.Request(
            BB_PLATFORMS_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError, OSError, TimeoutError) as exc:
        import logging
        logging.getLogger("intake").debug("bb-platforms call %s failed: %s: %s", tool, type(exc).__name__, exc)
        return None


def fetch_scope_mcp(platform, slug, log=print):
    """Fetch scope from bb-platforms MCP. Returns raw scope blob or None."""
    log(f"intake: fetching scope for {platform}/{slug} via bb-platforms MCP...")
    data = _mcp_call_bb("get_scope", {"platform": platform, "program": slug})
    if data:
        log(f"intake: got scope blob with {len(json.dumps(data))} bytes")
        return data
    log("intake: bb-platforms MCP not available, trying search...")
    # NOTE: search_programs may paginate; we only check the first page here
    search = _mcp_call_bb("search_programs", {"query": slug, "platform": platform})
    if search:
        programs = search if isinstance(search, list) else search.get("programs", [])
        for p in programs:
            handle = p.get("handle") or p.get("slug") or p.get("code") or ""
            if handle.lower() == slug.lower():
                return _mcp_call_bb("get_scope", {"platform": platform, "program": handle})
    return None


def fetch_scope_file(path, log=print):
    """Load scope from a local file (JSON or pasted text)."""
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        log(f"intake: file not found: {path}")
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError:
        # Try scopeparse for pasted text
        try:
            import scopeparse
            with open(path) as f:
                text = f.read()
            return scopeparse.parse(text)
        except Exception:
            return None


def create_engagement(slug, scope_json, base=DEFAULT_BASE, log=print):
    """Create engagement directory with scope.json. Returns scope file path."""
    slug = _normalize_slug(slug)
    import scopefetch
    base = os.path.expanduser(base)
    converted = scopefetch.convert(scope_json, slug)

    # I07: validate conversion produced at least one in-scope host
    if not converted.get("in_scope"):
        raise RuntimeError(f"Scope for '{slug}' has no valid in-scope hosts after conversion")

    # Write scope.json
    eng_dir = os.path.join(base, slug)
    os.makedirs(eng_dir, exist_ok=True)
    scope_path = os.path.join(eng_dir, "scope.json")
    out = {k: v for k, v in converted.items() if not k.startswith("_")}
    with open(scope_path, "w") as f:
        json.dump(out, f, indent=2)

    # Also write to _targets/slug.json so guardrails/engine can load it
    targets_dir = os.path.join(base, "_targets")
    os.makedirs(targets_dir, exist_ok=True)
    with open(os.path.join(targets_dir, slug + ".json"), "w") as f:
        json.dump(out, f, indent=2)

    log(f"intake: created engagement {slug}")
    log(f"  scope: {len(out.get('in_scope', []))} in-scope, "
        f"{len(out.get('out_of_scope', []))} out-of-scope, "
        f"{len(out.get('seeds', []))} seeds")
    log(f"  path: {scope_path}")

    if converted.get("_dropped_non_host"):
        log(f"  dropped: {', '.join(converted['_dropped_non_host'][:5])}")

    return scope_path


def intake(url_or_slug, platform=None, base=DEFAULT_BASE, scope_file=None, launch=False, log=print):
    """Full intake pipeline: URL → scope → engagement → scope.json path.

    Returns dict with {slug, platform, scope_path, in_scope, seeds} or raises.
    """
    slug = None

    if scope_file:
        slug = url_or_slug.replace("https://", "").replace("http://", "").split("/")[-1]
        scope_blob = fetch_scope_file(scope_file, log=log)
    elif platform and url_or_slug:
        slug = url_or_slug
        scope_blob = fetch_scope_mcp(platform, slug, log=log)
    else:
        platform, slug = parse_program_url(url_or_slug)
        if not platform:
            # Treat as slug, try all platforms
            slug = url_or_slug.strip().lower()
            for p in ["hackerone", "bugcrowd", "yeswehack", "intigriti"]:
                scope_blob = fetch_scope_mcp(p, slug, log=log)
                if scope_blob:
                    platform = p
                    break
            else:
                scope_blob = None
        else:
            scope_blob = fetch_scope_mcp(platform, slug, log=log)

    if not scope_blob:
        # Fall back: check if scope file exists locally
        local_paths = [
            os.path.expanduser(f"~/{slug}-scope.json"),
            os.path.expanduser(f"~/.bughunter-engagements/{slug}/scope.json"),
            f"{slug}-scope.json",
        ]
        for lp in local_paths:
            if os.path.isfile(lp):
                log(f"intake: found local scope at {lp}")
                with open(lp) as f:
                    scope_blob = json.load(f)
                break

    # I08: warn if platform-returned name differs from slug
    if scope_blob and isinstance(scope_blob, dict):
        returned_name = scope_blob.get("name") or scope_blob.get("handle") or ""
        if returned_name and returned_name.lower() != (slug or "").lower():
            log(f"intake: warning — platform returned name '{returned_name}', expected '{slug}'")

    if not scope_blob:
        raise RuntimeError(
            f"Could not fetch scope for '{url_or_slug}'. Options:\n"
            f"  1. Ensure bb-platforms MCP is running\n"
            f"  2. Provide --scope-file with exported scope JSON\n"
            f"  3. Paste scope text into a file and use scopeparse.py"
        )

    scope_path = create_engagement(slug, scope_blob, base=base, log=log)

    # Load back to get resolved data
    with open(scope_path) as f:
        resolved = json.load(f)

    result = {
        "slug": slug,
        "platform": platform,
        "scope_path": scope_path,
        "in_scope": resolved.get("in_scope", []),
        "out_of_scope": resolved.get("out_of_scope", []),
        "seeds": resolved.get("seeds", []),
    }
    if launch:
        result["launch_cmd"] = f"python3 engine/engine/engine.py --scope {result['scope_path']} --base {base}"
        log(f"intake: to launch pipeline: {result['launch_cmd']}")
    return result


# ---------------------------------------------------------------- CLI

def _cmd_start(a):
    try:
        result = intake(
            a.url or a.slug,
            platform=a.platform,
            base=a.base,
            scope_file=a.scope_file,
            launch=getattr(a, "launch", False),
        )
        print(json.dumps(result, indent=2))
        return 0
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def _cmd_parse_url(a):
    platform, slug = parse_program_url(a.url)
    if platform:
        print(json.dumps({"platform": platform, "slug": slug}))
    else:
        print(f"Could not parse platform URL: {a.url}", file=sys.stderr)
        return 1
    return 0


def _cmd_selftest(_a):
    # Test URL parsing
    cases = [
        ("https://hackerone.com/acme", "hackerone", "acme"),
        ("https://hackerone.com/programs/acme-corp", "hackerone", "acme-corp"),
        ("https://bugcrowd.com/acme", "bugcrowd", "acme"),
        ("https://bugcrowd.com/engagements/acme-test", "bugcrowd", "acme-test"),
        ("https://yeswehack.com/programs/acme", "yeswehack", "acme"),
        ("https://app.intigriti.com/company/programs/acme", "intigriti", "acme"),
        ("https://random.com/acme", None, None),
        # I05: query params and fragments
        ("https://hackerone.com/acme?view=policy", "hackerone", "acme"),
        ("https://bugcrowd.com/acme#scope", "bugcrowd", "acme"),
    ]
    for url, exp_platform, exp_slug in cases:
        p, s = parse_program_url(url)
        assert p == exp_platform and s == exp_slug, \
            f"parse_program_url({url!r}) = ({p!r}, {s!r}), expected ({exp_platform!r}, {exp_slug!r})"

    # Test engagement creation with mock scope
    import tempfile
    tmpbase = tempfile.mkdtemp()
    mock_scope = {"in_scope": [{"asset": "*.acme.com", "asset_type": "url"},
                                {"asset": "api.acme.com", "asset_type": "api"}],
                  "out_of_scope": [{"asset": "staging.acme.com"}]}
    scope_path = create_engagement("acme-test", mock_scope, base=tmpbase, log=lambda *a: None)
    assert os.path.isfile(scope_path), f"scope.json not created at {scope_path}"
    with open(scope_path) as f:
        loaded = json.load(f)
    assert "*.acme.com" in loaded["in_scope"], f"missing wildcard: {loaded['in_scope']}"
    assert "api.acme.com" in loaded["in_scope"], f"missing api host: {loaded['in_scope']}"
    assert "staging.acme.com" in loaded["out_of_scope"], f"missing out: {loaded['out_of_scope']}"
    assert any("acme.com" in s for s in loaded["seeds"]), f"no seeds: {loaded['seeds']}"

    # I03: _targets/slug.json also written
    targets_path = os.path.join(tmpbase, "_targets", "acme-test.json")
    assert os.path.isfile(targets_path), f"_targets file not created at {targets_path}"

    print("intake.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="program URL intake → scope → engagement")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("start", help="Start engagement from program URL or slug")
    ps.add_argument("url", nargs="?", help="Program URL (e.g. https://hackerone.com/acme)")
    ps.add_argument("--platform", help="Platform name (hackerone/bugcrowd/yeswehack/intigriti)")
    ps.add_argument("--slug", help="Program slug (alternative to URL)")
    ps.add_argument("--scope-file", help="Local scope JSON file instead of MCP fetch")
    ps.add_argument("--base", default=DEFAULT_BASE)
    ps.add_argument("--launch", action="store_true", help="Include launch command in output")
    ps.set_defaults(fn=_cmd_start)

    pp = sub.add_parser("parse-url", help="Parse platform + slug from a URL")
    pp.add_argument("url")
    pp.set_defaults(fn=_cmd_parse_url)

    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
