#!/usr/bin/env python3
"""
findings.py — operator DISPOSITION marks for confirmed findings + the learning they drive.

You mark each finding with what happened to it (reported / accepted / triaged / duplicate / invalid /
na / informative / wontfix / pending). Marks live in <base>/_findings/marks.json and FEED THE LEARNING
LOOP so the hunt gets better:

  valid  (accepted/triaged/reported) -> record_outcome 'reported'       (yieldrank boosts that class)
  duplicate                          -> record_outcome 'duplicate'      (yieldrank penalizes)
  bad    (invalid/na/informative/wontfix) -> record_outcome 'invalid'   (yieldrank penalizes) + a LESSON

Every mark also appends a LESSON (program, class, url, status, reason) to <base>/_findings/lessons.jsonl.
Those lessons are injected into future hunts of that program/class (see learn/engine) so the agent stops
repeating what gets marked invalid and leans into what gets accepted — "learn from invalid and correct".
"""
import datetime
import json
import os
import re

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

STATUSES = ["pending", "reported", "accepted", "triaged", "duplicate",
            "invalid", "na", "informative", "wontfix"]
VALID_MARKS = {"reported", "accepted", "triaged"}          # it was a real, submittable bug
BAD_MARKS = {"invalid", "na", "informative", "wontfix"}    # it was not (learn from these)
# mark -> learning result fed to learn.record_outcome (yieldrank reads these)
_RESULT = {"reported": "reported", "accepted": "reported", "triaged": "reported",
           "duplicate": "duplicate", "invalid": "invalid", "na": "invalid",
           "informative": "invalid", "wontfix": "invalid"}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "unknown"


def _base(base=None):
    return os.path.expanduser(base or DEFAULT_BASE)


def _fdir(base):
    d = os.path.join(_base(base), "_findings")
    os.makedirs(d, exist_ok=True)
    return d


def _marks_path(base):
    return os.path.join(_fdir(base), "marks.json")


def _lessons_path(base):
    return os.path.join(_fdir(base), "lessons.jsonl")


def make_key(program, url, vuln_class):
    return f"{_slug(program)}|{url}|{(vuln_class or '').lower()}"


def _parse_key(key):
    """program|url|class  (url may itself contain '|', so split off program first and class last)."""
    program, _, rest = str(key or "").partition("|")
    url, _, vuln_class = rest.rpartition("|")
    return program, url, vuln_class


def _load_marks(base):
    try:
        return json.load(open(_marks_path(base)))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_marks(base, marks):
    p = _marks_path(base)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(marks, f, indent=2)
    os.replace(tmp, p)


def _iter_targets(base):
    b = _base(base)
    for name in sorted(os.listdir(b)) if os.path.isdir(b) else []:
        if name.startswith("_") or name.startswith("."):      # skip infra dirs (_findings,_review,_alerts…)
            continue
        sp = os.path.join(b, name, "state.json")
        if os.path.isfile(sp):
            try:
                yield name, json.load(open(sp))
            except (OSError, json.JSONDecodeError):
                continue


def list_findings(base=DEFAULT_BASE):
    """Every CONFIRMED finding across all targets, with its published page link + current operator mark."""
    marks = _load_marks(base)
    out = []
    for program, st in _iter_targets(base):
        links = st.get("draft_links") or {}
        for f in st.get("confirmed") or []:
            url = f.get("url", "")
            cls = (f.get("vuln_class") or "").lower()
            key = make_key(program, url, cls)
            m = marks.get(key) or {}
            out.append({
                "key": key, "program": program, "url": url, "vuln_class": cls,
                "severity": (f.get("severity") or "").lower(),
                "title": (f.get("evidence") or f.get("title") or "")[:160],
                "trust_dimensions": list(f.get("trust_dimensions") or []),
                "page": links.get("|".join((url, cls))) or "",
                "confirmed_ts": f.get("confirmed_ts") or f.get("ts") or "",
                "status": m.get("status", "pending"), "note": m.get("note", ""),
                "marked_ts": m.get("ts", ""),
            })
    # unmarked first (need attention), then by severity, newest first
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
    out.sort(key=lambda r: (r["status"] != "pending", sev_rank.get(r["severity"], 5),
                            r["confirmed_ts"]), reverse=False)
    return out


def set_mark(base, key, status, note=""):
    """Record the operator's disposition for a finding + drive the learning loop. Returns the mark."""
    status = (status or "").strip().lower()
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    program, url, vuln_class = _parse_key(key)
    marks = _load_marks(base)
    rec = {"status": status, "note": str(note or "")[:1000], "ts": _now(),
           "program": program, "url": url, "vuln_class": vuln_class}
    marks[key] = rec
    _save_marks(base, marks)
    if status != "pending":
        try:
            import learn
            matched = next((finding for finding in list_findings(base) if finding["key"] == key), {})
            dimensions = matched.get("trust_dimensions") or []
            learn.record_outcome(program, vuln_class, _RESULT.get(status, "invalid"),
                                 note=f"operator-mark:{status} {note}".strip(), base=_base(base),
                                 trust_dimension=dimensions[0] if dimensions else "")
        except Exception:  # noqa: BLE001
            pass
        # 2) a per-finding LESSON the next hunt reads (avoid invalids, repeat valids)
        try:
            with open(_lessons_path(base), "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": _now(), "program": program, "vuln_class": vuln_class,
                                     "url": url, "status": status,
                                     "valid": status in VALID_MARKS,
                                     "reason": str(note or "")[:400]}, ensure_ascii=False) + "\n")
        except OSError:
            pass
    return rec


def lessons_for(base, program, vuln_class=None, limit=6):
    """Recent operator-disposition lessons for a program (optionally one class), split valid vs invalid,
    for injection into the hunt task. Most-recent first."""
    program = _slug(program)
    vc = (vuln_class or "").lower()
    valid, invalid = [], []
    try:
        lines = open(_lessons_path(base), encoding="utf-8").read().splitlines()
    except OSError:
        return {"valid": [], "invalid": []}
    for ln in reversed(lines):
        try:
            r = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if r.get("program") != program:
            continue
        if vc and (r.get("vuln_class") or "") != vc:
            continue
        bucket = valid if r.get("valid") else invalid
        if len(bucket) >= limit:
            continue
        bucket.append({"vuln_class": r.get("vuln_class"), "status": r.get("status"),
                       "url": r.get("url"), "reason": r.get("reason")})
        if len(valid) >= limit and len(invalid) >= limit:
            break
    return {"valid": valid, "invalid": invalid}


def summary(base=DEFAULT_BASE):
    counts = {s: 0 for s in STATUSES}
    for f in list_findings(base):
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    counts["valid"] = sum(counts.get(s, 0) for s in VALID_MARKS)
    counts["bad"] = sum(counts.get(s, 0) for s in BAD_MARKS)
    return counts


def _selftest():
    import tempfile
    import shutil
    d = tempfile.mkdtemp()
    try:
        tdir = os.path.join(d, "acme")
        os.makedirs(tdir)
        json.dump({"confirmed": [{"url": "https://acme.test/a/1", "vuln_class": "idor",
                                  "severity": "high", "evidence": "cross-account read"}],
                   "draft_links": {"https://acme.test/a/1|idor": "https://pub/finding-x.html"}},
                  open(os.path.join(tdir, "state.json"), "w"))
        fs = list_findings(d)
        assert len(fs) == 1 and fs[0]["status"] == "pending" and fs[0]["page"], fs
        k = fs[0]["key"]
        set_mark(d, k, "invalid", "no cross-account proof, same account")
        assert _load_marks(d)[k]["status"] == "invalid"
        set_mark(d, k, "accepted", "triaged P2")
        les = lessons_for(d, "acme", "idor")
        assert les["valid"] and les["invalid"], les
        s = summary(d)
        assert s["total"] == 1 and s["valid"] == 1, s
        print("findings.py self-test: PASS")
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="finding disposition marks")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list")
    sub.add_parser("summary")
    sub.add_parser("selftest")
    pm = sub.add_parser("mark")
    pm.add_argument("--key", required=True)
    pm.add_argument("--status", required=True)
    pm.add_argument("--note", default="")
    a = ap.parse_args()
    if a.cmd == "selftest":
        _selftest()
    elif a.cmd == "mark":
        print(json.dumps(set_mark(a.base, a.key, a.status, a.note), indent=2))
    elif a.cmd == "summary":
        print(json.dumps(summary(a.base), indent=2))
    else:
        print(json.dumps(list_findings(a.base), indent=2))
