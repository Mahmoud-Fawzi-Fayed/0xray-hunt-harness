#!/usr/bin/env python3
"""
yieldrank.py — "cover every class, hunt the most-findable first, and stop farming your own dups."

CLASS_WEIGHT in engine.py ranks by IMPACT (rce=100, sqli=90...). That is one axis. This module adds
the other axis the operator asked for: YIELD — how likely a class is to actually produce a finding —
and then LEARNS from your own outcomes so the order adapts:

  - start from frequency PRIORS (grounded in public bug-bounty disclosure frequency),
  - + a bonus for classes YOU have been confirming lately,
  - - a penalty for classes where YOU keep getting duplicated (so effort drifts to where dups are
    least likely — the whole point of this harness).

Every class stays in the ranking (nothing is dropped — "cover all types"); only the ORDER changes.

Learning sources (all optional, read-only, offline):
  - hunt-memory/journal.jsonl   -> per-class confirmed / duplicate counts (your real outcomes)
  - _dedup/corpus/*.jsonl       -> your own-source reports + any status=="duplicate"

CLI:
  python3 engine/yieldrank.py rank [--base DIR] [--tech next.js,graphql] [--json]
  python3 engine/yieldrank.py selftest
"""
import argparse
import json
import os
import sys

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# find-frequency priors (0..100). NOT impact — how often this class actually lands a finding.
PRIORS = {
    "info-leak": 80, "secret": 78, "xss": 78, "idor": 75, "api-misconfig": 70,
    "auth-bypass": 62, "ssrf": 60, "sqli": 58, "llm-ai": 58, "open-redirect": 55,
    "business-logic": 55, "oauth": 52, "subdomain-takeover": 52, "csrf": 50, "graphql": 50,
    "rce": 48, "file-upload": 46, "lfi": 45, "mfa": 45, "cors": 45, "race-condition": 42,
    "host-header": 38, "ssti": 36, "xxe": 34, "nosqli": 32, "deserialization": 32,
    "http-smuggling": 28, "saml": 26, "cache-poison": 40, "websocket": 30,
}

# tech fingerprint -> classes to boost for that stack
TECH_BOOST = {
    "next.js": ["ssrf", "open-redirect", "api-misconfig"], "node.js": ["rce", "api-misconfig", "ssrf"],
    "graphql": ["graphql", "idor", "api-misconfig"], "laravel": ["rce", "idor", "info-leak"],
    "spring": ["rce", "ssrf", "info-leak"], "wordpress": ["sqli", "idor", "info-leak"],
    "react": ["xss", "info-leak"], "asp.net": ["deserialization", "info-leak"],
}


def _find_journal(base):
    for p in ("hunt-memory/journal.jsonl", os.path.expanduser("~/hunt-memory/journal.jsonl"),
              os.path.join(os.path.expanduser(base), "hunt-memory", "journal.jsonl")):
        if os.path.isfile(p):
            return p
    return None


def _learn(base):
    """Return {class: {'confirmed':n,'dup':n,'reported':n}} from journal + own corpus."""
    stats = {}

    def bump(c, key, n=1):
        c = (c or "").strip().lower()
        if not c:
            return
        stats.setdefault(c, {"confirmed": 0, "dup": 0, "reported": 0})[key] += n

    jp = _find_journal(base)
    if jp:
        for line in open(jp, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            c = j.get("vuln_class") or j.get("class")
            res = (j.get("result") or j.get("status") or "").lower()
            if res.startswith("confirm"):
                bump(c, "confirmed")
            elif res.startswith("dup"):
                bump(c, "dup")

    cdir = os.path.join(os.path.expanduser(base), "_dedup", "corpus")
    if os.path.isdir(cdir):
        for fn in os.listdir(cdir):
            if not fn.endswith(".jsonl"):
                continue
            for line in open(os.path.join(cdir, fn), encoding="utf-8", errors="ignore"):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                src = (r.get("source") or "").lower()
                if src in ("ywh-own", "own-memory"):
                    bump(r.get("vuln_class"), "reported")
                if (r.get("status") or "").lower() == "duplicate":
                    bump(r.get("vuln_class"), "dup")
    return stats


class Model:
    def __init__(self, learned):
        self.learned = learned

    @classmethod
    def load(cls, base=DEFAULT_BASE):
        return cls(_learn(base))

    def _adj(self, c):
        """learned adjustment: + for classes you confirm, - for classes you get dup'd on."""
        s = self.learned.get(c)
        if not s:
            return 0.0
        denom = max(s["reported"] + s["confirmed"] + s["dup"], 1)
        dup_rate = s["dup"] / denom
        return min(s["confirmed"], 6) * 2.0 - dup_rate * 30.0

    def bonus(self, c):
        """Small ADDITIVE bump for engine.rank() (keeps impact baseline, nudges by yield). ~ -20..+52."""
        c = (c or "").strip().lower()
        if not c:
            return 0.0
        return round(PRIORS.get(c, 20) * 0.4 + self._adj(c), 1)

    def score(self, c, tech=None):
        """Full yield score for the /yield coverage list."""
        c = c.lower()
        base = PRIORS.get(c, 20) + self._adj(c)
        if tech:
            for t in tech:
                if c in TECH_BOOST.get((t or "").lower(), []):
                    base += 12
                    break
        return round(base, 1)

    def rank(self, tech=None):
        """All classes, highest yield first (covers everything)."""
        rows = []
        for c in PRIORS:
            s = self.learned.get(c, {})
            note = []
            if s.get("confirmed"):
                note.append(f"you confirmed x{s['confirmed']}")
            if s.get("dup"):
                note.append(f"dup'd x{s['dup']} (downranked)")
            if tech and any(c in TECH_BOOST.get((t or "").lower(), []) for t in tech):
                note.append("tech-match")
            rows.append({"class": c, "score": self.score(c, tech), "note": ", ".join(note)})
        rows.sort(key=lambda r: -r["score"])
        return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="yield-ordered class coverage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("rank")
    pr.add_argument("--base", default=DEFAULT_BASE)
    pr.add_argument("--tech", default="", help="comma-separated detected tech, e.g. next.js,graphql")
    pr.add_argument("--json", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)

    if a.cmd == "selftest":
        return _selftest()
    tech = [t.strip() for t in a.tech.split(",") if t.strip()]
    rows = Model.load(a.base).rank(tech)
    if a.json:
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'class':20s} {'yield':>6s}  note")
        for r in rows:
            print(f"{r['class']:20s} {r['score']:6.1f}  {r['note']}")
        print("\ncover all; hunt top-down. classes you keep getting dup'd on sink automatically.")
    return 0


def _selftest():
    import tempfile
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "hunt-memory"))
    with open(os.path.join(base, "hunt-memory", "journal.jsonl"), "w") as fh:
        # you confirm ssrf a lot, and keep getting dup'd on xss
        fh.write(json.dumps({"vuln_class": "ssrf", "result": "confirmed"}) + "\n")
        fh.write(json.dumps({"vuln_class": "ssrf", "result": "confirmed"}) + "\n")
        for _ in range(4):
            fh.write(json.dumps({"vuln_class": "xss", "result": "duplicate"}) + "\n")
    m = Model.load(base)
    rows = m.rank()
    order = [r["class"] for r in rows]
    # xss prior (78) is high, but 4 dups must drop it below ssrf (prior 60 + confirmed bonus)
    assert order.index("ssrf") < order.index("xss"), order[:8]
    # every class is present (coverage)
    assert len(rows) == len(PRIORS), (len(rows), len(PRIORS))
    # engine bonus is additive + bounded
    assert -20 <= m.bonus("ssrf") <= 60 and m.bonus("") == 0.0
    # tech boost moves graphql up when graphql stack present
    assert m.score("graphql", ["graphql"]) > m.score("graphql", None)
    print("yieldrank.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
