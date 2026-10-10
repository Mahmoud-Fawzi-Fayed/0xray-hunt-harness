#!/usr/bin/env python3
"""
dedup.py — duplicate-avoidance oracle for bug-bounty findings.

The engine already de-duplicates its own *work units* (state.add_surface drops repeat
url|param|class). This module solves the OTHER duplication problem — the one that actually
costs payouts: reporting a bug that is ALREADY PUBLIC, or that YOU already reported. Now that
"everyone has AI + skills," the edge is novelty — don't burn a report slot (or a triager's
goodwill) on a known issue.

Two questions it answers:

  1. pre-submit  — "has THIS finding (class + endpoint + target) already been disclosed, or did
                   I already report it?" -> verdict NOVEL | REVIEW | LIKELY_DUP + nearest matches.
  2. pre-hunt    — down-rank surface that maps onto known issues so agent effort goes to the
                   surface nobody has picked over yet (engine.rank calls annotate()).

Design constraints (deliberate):
  - stdlib only, fully OFFLINE. This module NEVER makes a network call. Acquisition of the
    corpus (own YesWeHack reports via the bb-platforms MCP, public HackerOne Hacktivity /
    Bugcrowd crowdstream via WebFetch, own hunt-memory journal) is done by the agent/command
    layer and piped in here as JSON via `ingest`. That keeps scoring deterministic + testable
    and survives a restricted network.
  - corpus is per-program JSONL under <base>/_dedup/corpus/<program>.jsonl, append + id-dedup.
  - similarity = weighted, self-renormalizing blend of (vuln-class match, endpoint path/param
    overlap, title token Jaccard). No embeddings dependency; a hook is left for an optional
    semantic re-rank later, but the default must work with zero pip installs.

Corpus record schema (one JSON object per line):
  {
    "id":        "<stable 12-hex>",        # dedup key within a corpus file
    "source":    "ywh-own|h1-public|bugcrowd-public|ywh-public|own-memory|manual",
    "program":   "<program slug / name>",
    "title":     "IDOR on /api/v2/users/{id}/orders leaks other users' PII",
    "vuln_class":"idor",                    # normalized (see CLASS_CANON)
    "url":       "https://t/api/v2/users/5/orders",   # endpoint if known ("" if not)
    "status":    "resolved|triaged|duplicate|...",
    "severity":  "high",
    "date":      "2026-01-02",
    "link":      "https://hackerone.com/reports/123"
  }

CLI:
  python3 engine/dedup.py ingest --program X [--source S] [--file f.json | --stdin]
  python3 engine/dedup.py check  --program X --class idor --url U --title "..." [--json]
  python3 engine/dedup.py stats  [--program X]
  python3 engine/dedup.py selftest
"""
import argparse
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlparse

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# verdict thresholds on the top-match score (0..1). tuned in selftest().
T_LIKELY_DUP = 0.72   # >= this: almost certainly already known — do NOT draft without a diff
T_REVIEW = 0.45       # >= this: overlaps a known issue — draft only with a "why this differs" note

# signal weights (renormalized over whichever signals both sides actually have)
W_CLASS = 0.40
W_PATH = 0.35
W_TITLE = 0.25

# normalize the many human phrasings of a disclosed bug onto one slug for dedup.
# This is matching public reports, not a hunt menu.
CLASS_CANON = {
    "idor": "idor", "insecure-direct-object-reference": "idor",
    "insecure direct object reference": "idor", "insecure direct object references": "idor",
    "broken-access-control": "idor", "broken access control": "idor",
    "broken-object-level-authorization": "idor", "bola": "idor", "bfla": "idor",
    "improper-access-control-generic-cwe-284": "idor", "improper access control": "idor",
    "authorization": "idor", "access-control": "idor",
    "xss": "xss", "cross-site-scripting": "xss", "cross site scripting": "xss",
    "stored-xss": "xss", "reflected-xss": "xss", "dom-xss": "xss", "dom-based-xss": "xss",
    "sqli": "sqli", "sql-injection": "sqli", "sql injection": "sqli", "blind-sqli": "sqli",
    "nosqli": "nosqli", "nosql-injection": "nosqli", "nosql injection": "nosqli",
    "ssrf": "ssrf", "server-side-request-forgery": "ssrf", "server side request forgery": "ssrf",
    "rce": "rce", "remote-code-execution": "rce", "remote code execution": "rce",
    "command-injection": "rce", "os-command-injection": "rce", "code-injection": "rce",
    "ssti": "ssti", "server-side-template-injection": "ssti",
    "xxe": "xxe", "xml-external-entity": "xxe", "xml external entities": "xxe",
    "lfi": "lfi", "local-file-inclusion": "lfi", "path-traversal": "lfi",
    "directory-traversal": "lfi", "rfi": "lfi",
    "open-redirect": "open-redirect", "open redirect": "open-redirect",
    "csrf": "csrf", "cross-site-request-forgery": "csrf", "cross site request forgery": "csrf",
    "cors": "cors", "cors-misconfiguration": "cors",
    "auth-bypass": "auth-bypass", "authentication-bypass": "auth-bypass",
    "authentication bypass": "auth-bypass", "broken-authentication": "auth-bypass",
    "oauth": "oauth", "oauth-misconfiguration": "oauth",
    "saml": "saml", "mfa": "mfa", "2fa-bypass": "mfa", "mfa-bypass": "mfa",
    "graphql": "graphql",
    "deserialization": "deserialization", "insecure-deserialization": "deserialization",
    "file-upload": "file-upload", "unrestricted-file-upload": "file-upload",
    "host-header": "host-header", "host-header-injection": "host-header",
    "http-smuggling": "http-smuggling", "request-smuggling": "http-smuggling",
    "race-condition": "race-condition", "toctou": "race-condition",
    "business-logic": "business-logic", "business-logic-error": "business-logic",
    "info-leak": "info-leak", "information-disclosure": "info-leak",
    "information disclosure": "info-leak", "sensitive-information-disclosure": "info-leak",
    "sensitive-data-exposure": "info-leak", "secret": "info-leak", "secret-leak": "info-leak",
    "llm-ai": "llm-ai", "prompt-injection": "llm-ai", "ai": "llm-ai",
    "subdomain-takeover": "subdomain-takeover", "subdomain takeover": "subdomain-takeover",
    "privilege-escalation": "privilege-escalation", "privilege escalation": "privilege-escalation",
}

# generic words that carry no discriminative signal in a vuln title
_STOP = {
    "a", "an", "the", "of", "in", "on", "to", "via", "for", "and", "or", "is", "are", "with",
    "allows", "allow", "allowing", "leads", "lead", "due", "can", "could", "able", "attacker",
    "user", "users", "vulnerability", "vuln", "bug", "issue", "security", "unauthenticated",
    "authenticated", "remote", "arbitrary", "any", "other", "another", "endpoint", "parameter",
    "request", "response", "application", "app", "server", "client", "page", "feature",
}
_WORD = re.compile(r"[a-z0-9]+")
_HEX = re.compile(r"^[0-9a-f]{8,}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def norm_class(s):
    """Map a free-text / slug class onto a canonical engine class slug."""
    s = (s or "").strip().lower()
    if not s:
        return ""
    if s in CLASS_CANON:
        return CLASS_CANON[s]
    slug = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return CLASS_CANON.get(slug, slug)


def title_tokens(text):
    """Discriminative lowercase word tokens of a title (stopwords + pure-number dropped)."""
    out = set()
    for w in _WORD.findall((text or "").lower()):
        if w in _STOP or w.isdigit() or _HEX.match(w):
            continue
        out.add(w)
    return out


def path_tokens(url):
    """Normalized path-segment + param-name tokens of an endpoint.

    Volatile identifiers (numeric ids, UUIDs, long hex) collapse to '{id}' so
    /api/v2/users/5/orders and /api/v2/users/8123/orders compare equal; query param
    NAMES are kept (never values)."""
    if not url:
        return set()
    try:
        p = urlparse(url if "://" in url else "//" + url, scheme="https")
    except Exception:
        return set()
    out = set()
    for seg in (p.path or "").split("/"):
        seg = seg.strip().lower()
        if not seg:
            continue
        if seg.isdigit() or _UUID.match(seg) or _HEX.match(seg) or re.search(r"\d", seg):
            out.add("{id}")
        else:
            out.add(seg)
    for kv in (p.query or "").split("&"):
        if not kv:
            continue
        name = kv.split("=", 1)[0].strip().lower()
        if name:
            out.add("param:" + name)
    return out


def _jaccard(a, b):
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def signature(rec):
    """Precompute the comparable signature of a record/candidate dict."""
    return {
        "class": norm_class(rec.get("vuln_class", "")),
        "path": path_tokens(rec.get("url", "")),
        "title": title_tokens(rec.get("title", "")),
    }


def similarity(a, b):
    """Weighted 0..1 similarity between two signatures, renormalized over shared signals.

    - class contributes only if BOTH sides declare a class.
    - path contributes only if BOTH sides have path tokens (many public reports omit the URL).
    - title contributes whenever both have title tokens.
    Missing signals drop out of the denominator rather than scoring 0, so a URL-less public
    report is still matched on class + title alone."""
    parts = []
    if a["class"] and b["class"]:
        parts.append((W_CLASS, 1.0 if a["class"] == b["class"] else 0.0))
    if a["path"] and b["path"]:
        parts.append((W_PATH, _jaccard(a["path"], b["path"])))
    if a["title"] and b["title"]:
        parts.append((W_TITLE, _jaccard(a["title"], b["title"])))
    if not parts:
        return 0.0
    wsum = sum(w for w, _ in parts)
    return sum(w * s for w, s in parts) / wsum if wsum else 0.0


def record_id(rec):
    """Stable 12-hex id for corpus dedup. Prefers the canonical link; falls back to content."""
    key = "|".join([
        str(rec.get("source", "")), str(rec.get("program", "")),
        str(rec.get("link", "")) or (str(rec.get("title", "")) + "|" + str(rec.get("url", ""))),
    ]).lower()
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def _slug(program):
    return re.sub(r"[^a-z0-9._-]+", "-", (program or "unknown").strip().lower()).strip("-") or "unknown"


class Corpus:
    """Per-program known-issue store (JSONL). Append-only with id de-duplication."""

    def __init__(self, program, base=DEFAULT_BASE):
        self.program = program
        self.dir = os.path.join(os.path.expanduser(base), "_dedup", "corpus")
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, _slug(program) + ".jsonl")
        self._records = None

    @property
    def records(self):
        if self._records is None:
            self._records = []
            if os.path.isfile(self.path):
                for line in open(self.path, encoding="utf-8"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return self._records

    def ingest(self, items, source=None):
        """Add records (list of dicts), stamping program/source/id. Returns count added (new ids)."""
        have = {r.get("id") for r in self.records}
        added = 0
        if isinstance(items, dict):
            items = [items]
        with open(self.path, "a", encoding="utf-8") as fh:
            for it in (items or []):
                if not isinstance(it, dict):
                    continue                         # tolerate junk entries, never crash the ingest
                rec = dict(it)
                rec.setdefault("program", self.program)
                if source:
                    rec.setdefault("source", source)
                rec["id"] = record_id(rec)
                if rec["id"] in have:
                    continue
                have.add(rec["id"])
                self.records.append(rec)
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                added += 1
        return added

    def check(self, candidate, top=5):
        """Score a candidate finding against the whole corpus.

        candidate: {"vuln_class","url","title"}  (any subset; more fields = sharper verdict)
        returns:   {"verdict","score","matches":[{score,title,link,source,vuln_class,url}...]}"""
        sig = signature(candidate)
        scored = []
        for r in self.records:
            s = similarity(sig, signature(r))
            if s <= 0.0:
                continue
            scored.append((s, r))
        scored.sort(key=lambda x: -x[0])
        top_score = scored[0][0] if scored else 0.0
        if not self.records:
            verdict = "UNKNOWN"          # empty corpus => we CANNOT assert novelty (not a false NOVEL)
        else:
            verdict = ("LIKELY_DUP" if top_score >= T_LIKELY_DUP
                       else "REVIEW" if top_score >= T_REVIEW else "NOVEL")
        matches = [{
            "score": round(s, 3), "title": r.get("title", ""), "link": r.get("link", ""),
            "source": r.get("source", ""), "vuln_class": norm_class(r.get("vuln_class", "")),
            "url": r.get("url", ""), "status": r.get("status", ""),
        } for s, r in scored[:top]]
        return {"verdict": verdict, "score": round(top_score, 3), "matches": matches,
                "corpus_size": len(self.records)}


def annotate(program, findings, base=DEFAULT_BASE, top=3):
    """Attach a `dedup` block to each finding dict in-place; return the list.

    Used by engine.report() / engine.rank(). No-op-safe: an empty/absent corpus yields
    verdict NOVEL for everything, so callers behave identically when no corpus exists."""
    cp = Corpus(program, base=base)
    for f in findings:
        f["dedup"] = cp.check(
            {"vuln_class": f.get("vuln_class", ""), "url": f.get("url", ""), "title": f.get("title", "")},
            top=top,
        )
    return findings


# --------------------------------------------------------------------------- CLI
def _load_items(args):
    if args.stdin:
        raw = sys.stdin.read()
    elif args.file:
        raw = open(os.path.expanduser(args.file), encoding="utf-8").read()
    else:
        return []
    raw = raw.strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, dict):
        # accept {"reports":[...]} / {"items":[...]} wrappers or a single record
        for k in ("reports", "items", "data", "results"):
            if isinstance(data.get(k), list):
                return data[k]
        return [data]
    return data


def _cmd_ingest(args):
    items = _load_items(args)
    if not items:
        print("ingest: no items (use --file f.json or --stdin)", file=sys.stderr)
        return 1
    added = Corpus(args.program, base=args.base).ingest(items, source=args.source)
    print(f"ingest: {added} new / {len(items)} supplied -> {_slug(args.program)}.jsonl")
    return 0


def _cmd_check(args):
    res = Corpus(args.program, base=args.base).check(
        {"vuln_class": args.vuln_class, "url": args.url, "title": args.title})
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    icon = {"LIKELY_DUP": "⛔", "REVIEW": "⚠", "NOVEL": "✅", "UNKNOWN": "❔"}.get(res["verdict"], "❔")
    print(f"{icon} {res['verdict']}  score={res['score']}  (corpus={res['corpus_size']})")
    if res["verdict"] == "UNKNOWN":
        print("   -> corpus is EMPTY — dedup NOT performed. Ingest known reports (own via MCP + public "
              "H1/Bugcrowd) and re-check before you trust this as novel.")
    for m in res["matches"]:
        print(f"   {m['score']:.3f}  [{m['source']}/{m['vuln_class']}] {m['title'][:70]}")
        if m["link"]:
            print(f"          {m['link']}")
    if res["verdict"] == "LIKELY_DUP":
        print("   -> DO NOT draft without proving how yours differs from the match above.")
    elif res["verdict"] == "REVIEW":
        print("   -> Draft only with an explicit 'why this is not the known issue' paragraph.")
    return 0


def _cmd_stats(args):
    d = os.path.join(os.path.expanduser(args.base), "_dedup", "corpus")
    if not os.path.isdir(d):
        print("stats: no corpus yet")
        return 0
    files = sorted(f for f in os.listdir(d) if f.endswith(".jsonl"))
    if args.program:
        files = [f for f in files if f == _slug(args.program) + ".jsonl"]
    total = 0
    for f in files:
        cp = Corpus(f[:-6], base=args.base)
        by_src = {}
        for r in cp.records:
            by_src[r.get("source", "?")] = by_src.get(r.get("source", "?"), 0) + 1
        total += len(cp.records)
        src = ", ".join(f"{k}:{v}" for k, v in sorted(by_src.items()))
        print(f"  {f[:-6]:28.28s} {len(cp.records):5d}  [{src}]")
    print(f"stats: {len(files)} program(s), {total} known issue(s)")
    return 0


def _cmd_selftest(_):
    import tempfile
    base = tempfile.mkdtemp()
    cp = Corpus("acme", base=base)
    assert cp.check({"vuln_class": "idor", "url": "https://x/y", "title": "z"})["verdict"] == "UNKNOWN", \
        "empty corpus must be UNKNOWN (never a false NOVEL)"
    seed = [
        {"source": "ywh-own", "title": "IDOR on /api/v2/users/{id}/orders leaks other users' orders",
         "vuln_class": "idor", "url": "https://acme.test/api/v2/users/5/orders",
         "link": "https://ywh/report/1", "status": "resolved"},
        {"source": "h1-public", "title": "Reflected XSS in search box via q parameter",
         "vuln_class": "xss", "url": "https://acme.test/search?q=x", "link": "https://h1/reports/2"},
        {"source": "h1-public", "title": "Open redirect on login next parameter",
         "vuln_class": "open-redirect", "url": "https://acme.test/login?next=x", "link": "https://h1/reports/3"},
    ]
    assert cp.ingest(seed) == 3, "seed ingest"
    assert cp.ingest(seed) == 0, "re-ingest must be idempotent (id dedup)"

    # 1) same bug, different victim id + reworded title -> LIKELY_DUP
    r = cp.check({"vuln_class": "insecure direct object reference",  # alias of idor
                  "url": "https://acme.test/api/v2/users/8123/orders",
                  "title": "Access another user's orders through the v2 users orders API"})
    assert r["verdict"] == "LIKELY_DUP", r
    assert "report/1" in r["matches"][0]["link"], r

    # 2) same class, DIFFERENT endpoint, overlapping words -> REVIEW (not a clean dup)
    r2 = cp.check({"vuln_class": "idor", "url": "https://acme.test/api/v2/invoices/5/pdf",
                   "title": "IDOR lets a user read another user's invoices"})
    assert r2["verdict"] in ("REVIEW", "NOVEL"), r2
    assert r2["verdict"] == "REVIEW", r2

    # 3) genuinely new class + endpoint -> NOVEL
    r3 = cp.check({"vuln_class": "ssrf", "url": "https://acme.test/api/v3/webhook/validate",
                   "title": "Blind SSRF in webhook validator reaches cloud metadata"})
    assert r3["verdict"] == "NOVEL", r3

    # 4) empty corpus => UNKNOWN (we cannot assert novelty with nothing to compare — not a false NOVEL)
    empty = Corpus("nobody", base=base)
    assert empty.check({"vuln_class": "idor", "url": "x", "title": "y"})["verdict"] == "UNKNOWN"

    # 5) annotate attaches a dedup block without mutating other fields
    finds = [{"vuln_class": "xss", "url": "https://acme.test/search?q=1", "title": "XSS in q param"}]
    annotate("acme", finds, base=base)
    assert finds[0]["dedup"]["verdict"] == "LIKELY_DUP", finds[0]["dedup"]
    print("dedup.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="duplicate-avoidance oracle")
    ap.add_argument("--base", default=DEFAULT_BASE, help="engagement base dir (default ~/.bughunter-engagements)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ingest", help="add known-issue records to a program corpus")
    pi.add_argument("--program", required=True)
    pi.add_argument("--source", default=None, help="ywh-own|h1-public|bugcrowd-public|ywh-public|own-memory|manual")
    pi.add_argument("--file")
    pi.add_argument("--stdin", action="store_true")
    pi.set_defaults(fn=_cmd_ingest)

    pc = sub.add_parser("check", help="score a candidate finding against the corpus")
    pc.add_argument("--program", required=True)
    pc.add_argument("--class", dest="vuln_class", default="")
    pc.add_argument("--url", default="")
    pc.add_argument("--title", default="")
    pc.add_argument("--json", action="store_true")
    pc.set_defaults(fn=_cmd_check)

    ps = sub.add_parser("stats", help="show corpus sizes")
    ps.add_argument("--program", default=None)
    ps.set_defaults(fn=_cmd_stats)

    pt = sub.add_parser("selftest")
    pt.set_defaults(fn=_cmd_selftest)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
