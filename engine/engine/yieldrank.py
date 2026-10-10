#!/usr/bin/env python3
"""
yieldrank.py — order THIS program's live surface from its own outcomes.

No global vuln-class menu. Bonus comes only from hunt-memory/journal.jsonl and
this program's dedup corpus: classes you confirmed recently rise; classes you
keep duplicating sink. rank() lists classes that actually appeared in that
journal — it does not emit a canned OWASP list.

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

# Kept empty so callers that still import PRIORS do not get a hunt catalog.
PRIORS = {}
TECH_BOOST = {}


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
        stats.setdefault(c, {"confirmed": 0, "dup": 0, "reported": 0, "bad": 0})[key] += n

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
            elif res.startswith("invalid") or res.startswith("false") or res in ("na", "informative"):
                bump(c, "bad")                          # operator marked it invalid/NA -> learn to deprioritize

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
        denom = max(s["reported"] + s["confirmed"] + s["dup"] + s.get("bad", 0), 1)
        dup_rate = s["dup"] / denom
        bad_rate = s.get("bad", 0) / denom                # operator-marked invalid/NA/informative
        return min(s["confirmed"], 6) * 2.0 - dup_rate * 30.0 - bad_rate * 20.0

    def bonus(self, c):
        """Additive bump from THIS journal only. Unknown / empty class → 0."""
        c = (c or "").strip().lower()
        if not c:
            return 0.0
        return round(self._adj(c), 1)

    def score(self, c, tech=None):
        """Yield score from this journal. `tech` is ignored (no stack→class table)."""
        return round(self._adj((c or "").lower()), 1)

    def rank(self, tech=None):
        """Classes that actually appeared in this journal, highest yield first."""
        rows = []
        for c, s in (self.learned or {}).items():
            note = []
            if s.get("confirmed"):
                note.append(f"you confirmed x{s['confirmed']}")
            if s.get("dup"):
                note.append(f"dup'd x{s['dup']} (downranked)")
            rows.append({"class": c, "score": self.score(c, tech), "note": ", ".join(note)})
        rows.sort(key=lambda r: -r["score"])
        return rows


def rank_targets(base=DEFAULT_BASE, running=None, include_running=False):
    """Rank REGISTERED targets by expected yield for filling a hunt slot — data-driven from each target's
    on-disk state (queued/untested surface, auth depth, past confirms/candidates) so it costs nothing (no
    live probing). Never-hunted targets get an 'explore' baseline so fresh programs get a turn. Returns
    [{program, score, ...}], best first — used to pick which targets fill the few slots a small box can run."""
    import glob
    base = os.path.expanduser(base)
    running = set(running or [])
    out = []
    for f in sorted(glob.glob(os.path.join(base, "_targets", "*.json"))):
        prog = os.path.basename(f)[:-5]
        if prog in running and not include_running:
            continue
        try:
            st = json.load(open(os.path.join(base, prog, "state.json")))
        except Exception:  # noqa: BLE001
            st = {}
        surface = len(st.get("surface") or [])
        tested = st.get("tested")
        ntested = len(tested) if isinstance(tested, (list, dict)) else 0
        untested = max(0, surface - ntested)
        confirmed = len(st.get("confirmed") or [])
        candidates = len(st.get("candidates") or [])
        authed = False
        try:
            import authn
            authed = bool(authn.configured(prog, base))
        except Exception:  # noqa: BLE001
            pass
        never = surface == 0
        # queued work dominates; confirms/candidates are strong signals; auth = deeper reach; a never-hunted
        # target gets an exploration baseline so fresh surface gets a turn before a picked-over one is re-run.
        score = (min(untested, 500) * 1.0 + surface * 0.05 + confirmed * 60 + candidates * 12
                 + (25 if authed else 0) + (40 if never else 0))
        reasons = []
        if never:
            reasons.append("never hunted (explore)")
        if untested:
            reasons.append(f"{untested} untested")
        if authed:
            reasons.append("authed")
        if confirmed:
            reasons.append(f"{confirmed} confirmed")
        if candidates:
            reasons.append(f"{candidates} candidate(s)")
        out.append({"program": prog, "score": round(score, 1), "surface": surface, "untested": untested,
                    "authed": authed, "confirmed": confirmed, "candidates": candidates,
                    "running": prog in running, "reasons": reasons or ["no state yet"]})
    out.sort(key=lambda x: -x["score"])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="yield-ordered class coverage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("rank")
    pr.add_argument("--base", default=DEFAULT_BASE)
    pr.add_argument("--tech", default="", help="comma-separated detected tech, e.g. next.js,graphql")
    pr.add_argument("--json", action="store_true")
    rt = sub.add_parser("rank-targets", help="rank registered targets by expected yield for a hunt slot")
    rt.add_argument("--base", default=DEFAULT_BASE)
    rt.add_argument("--json", action="store_true")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)

    if a.cmd == "selftest":
        return _selftest()
    if a.cmd == "rank-targets":
        rows = rank_targets(a.base)
        if a.json:
            print(json.dumps(rows, indent=2))
        else:
            print(f"{'program':16s} {'score':>7s}  why")
            for r in rows:
                print(f"{r['program']:16s} {r['score']:7.1f}  {', '.join(r['reasons'])}")
        return 0
    tech = [t.strip() for t in a.tech.split(",") if t.strip()]
    rows = Model.load(a.base).rank(tech)
    if a.json:
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'class':20s} {'yield':>6s}  note")
        for r in rows:
            print(f"{r['class']:20s} {r['score']:6.1f}  {r['note']}")
        print("\norder from this journal only — no canned class list.")
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
    assert order == ["ssrf", "xss"], order
    assert m.bonus("ssrf") > m.bonus("xss") and m.bonus("") == 0.0
    assert m.score("graphql", ["graphql"]) == m.score("graphql", None)
    print("yieldrank.py self-test: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
