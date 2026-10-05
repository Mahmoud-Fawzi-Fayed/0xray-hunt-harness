#!/usr/bin/env python3
"""
learn.py — the harness teaching itself. When the hunter meets something it has no playbook for (an
unfamiliar framework, a vuln class with no matching skill, a new auth protocol), it records the gap,
researches it on the open web, and drafts a brand-new SKILL.md into the harness's learned-skills
directory so the *next* hunt already knows how to approach it. Every lesson (gap + outcome) is logged
to a journal you can review, and nothing is ever submitted or acted on blindly — new skills are
guidance for the agent, written in the standard SKILL.md shape and clearly marked auto-authored.

  autolearn(kind, name, context)   -> research + draft a skill if one doesn't exist (the one-call)
  record_gap(...) / gaps()         -> capability-gap journal
  have_skill(name) / find_skill()  -> is there already a playbook for this?
  draft_skill(...)                 -> write skills/learned/<slug>/SKILL.md + register it
  learn_from_outcome(...)          -> structured lesson from a hunt result

CLI:
  python3 engine/learn.py auto  --kind tech --name "RedwoodJS" --context "target runs RedwoodJS GraphQL"
  python3 engine/learn.py gaps
  python3 engine/learn.py skills
  python3 engine/learn.py selftest      # offline (no network): gap + draft + register
"""
import argparse
import datetime
import json
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(ENGINE)
sys.path.insert(0, ENGINE)
try:
    import websearch as WS
except Exception:  # noqa: BLE001
    WS = None

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
LEARNED_DIR = os.environ.get("HUNT_LEARNED_SKILLS_DIR", os.path.join(ROOT, "skills", "learned"))
# where to also look for existing skills so we don't re-draft something that already exists
SKILL_ROOTS = [
    os.path.join(ROOT, "skills"),
    os.path.expanduser("~/.claude/skills"),
    os.path.expanduser("~/.agents/skills"),
    os.path.expanduser("~/.cursor/skills-cursor"),
]


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").strip().lower()).strip("-") or "unnamed"


def _mem_dir(base):
    d = os.path.join(os.path.expanduser(base or DEFAULT_BASE), "hunt-memory")
    os.makedirs(d, exist_ok=True)
    return d


def _journal(base):
    return os.path.join(_mem_dir(base), "learning.jsonl")


def _yr_journal(base):
    """The journal yieldrank reads to learn per-class confirmed/duplicate rates."""
    return os.path.join(_mem_dir(base), "journal.jsonl")


def _append(path, rec):
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _read_jsonl(path):
    out = []
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        pass
    return out


# --------------------------------------------------------------- gaps + outcomes
def record_gap(kind, name, context="", base=DEFAULT_BASE):
    rec = {"ts": _now(), "type": "gap", "kind": str(kind or "")[:40], "name": str(name or "")[:120],
           "context": str(context or "")[:500]}
    _append(_journal(base), rec)
    return rec


def learn_from_outcome(program, vuln_class, result, note="", base=DEFAULT_BASE):
    rec = {"ts": _now(), "type": "outcome", "program": _slug(program), "vuln_class": str(vuln_class or "")[:40],
           "result": str(result or "")[:40], "note": str(note or "")[:500]}
    _append(_journal(base), rec)
    return rec


def record_outcome(program, vuln_class, result, note="", base=DEFAULT_BASE):
    """Close the learning loop: log a hunt result to BOTH the rich learning journal (shown in the panel)
    AND the yieldrank journal (so class ranking actually learns confirmed/duplicate/false-positive rates
    over time). `result`: confirmed | duplicate | false-positive | error | empty | reported. Never raises."""
    rec = learn_from_outcome(program, vuln_class, result, note, base)
    _append(_yr_journal(base), {"ts": _now(), "program": _slug(program),
            "vuln_class": str(vuln_class or "")[:40], "result": str(result or "")[:40]})
    return rec


def gaps(base=DEFAULT_BASE):
    return [r for r in _read_jsonl(_journal(base)) if r.get("type") == "gap"]


def journal(base=DEFAULT_BASE):
    return _read_jsonl(_journal(base))


# --------------------------------------------------------------- existing-skill lookup
def find_skill(name):
    """Return the path of an existing SKILL.md whose folder or name matches, else None."""
    want = _slug(name)
    for root in [LEARNED_DIR] + SKILL_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            if "SKILL.md" in files:
                folder = _slug(os.path.basename(dirpath))
                if want and (want in folder or folder in want):
                    return os.path.join(dirpath, "SKILL.md")
    return None


def have_skill(name):
    return find_skill(name) is not None


def learned_index():
    path = os.path.join(LEARNED_DIR, "index.json")
    try:
        return json.load(open(path))
    except (OSError, json.JSONDecodeError):
        return []


def _write_index(entries):
    os.makedirs(LEARNED_DIR, exist_ok=True)
    json.dump(entries, open(os.path.join(LEARNED_DIR, "index.json"), "w"), indent=2)


# --------------------------------------------------------------- skill drafting
def _skill_body(title, kind, name, context, research):
    refs = ""
    notes = ""
    if research:
        refs = "\n".join(f"- [{(r.get('title') or r.get('url') or '')[:90]}]({r.get('url','')})"
                         for r in research if r.get("url"))
        notes = "\n".join(f"- {(''.join((r.get('snippet') or '')[:200]))}" for r in research if r.get("snippet"))
    desc = (f"Playbook for {name} ({kind}). Auto-authored by the harness after it hit this as a gap. "
            f"Use when a target involves {name}. Review and refine before relying on it.").replace("\n", " ")
    return (
        f"---\nname: {_slug(name)}\n"
        f"description: {desc}\n"
        f"auto_authored: true\n"
        f"created: {_now()}\n---\n\n"
        f"# {title}\n\n"
        f"> Auto-drafted from a capability gap. Context that triggered it: {context or '(none recorded)'}\n\n"
        f"## When to use\n"
        f"- A target involves **{name}** ({kind}).\n"
        f"- The existing skills have no specific playbook for it.\n\n"
        f"## Recon / fingerprint\n"
        f"- Confirm {name} is in use (headers, JS bundles, error pages, docs, version strings).\n"
        f"- Map its endpoints, auth model, and any admin/debug surface.\n\n"
        f"## Likely weak points\n"
        f"- Known CVEs for the detected version (check NVD / GitHub advisories).\n"
        f"- Default configs, exposed debug/actuator/admin, verbose errors.\n"
        f"- The usual class bugs the stack is prone to (injection, authz, deserialization, SSRF).\n\n"
        f"## Validation discipline\n"
        f"- Prove impact concretely; no \"could potentially\". OOB confirmation for blind cases.\n"
        f"- Stay in-scope and read-only unless an authorized test account is provisioned.\n\n"
        f"## Research notes\n{notes or '- (add findings as you learn this stack)'}\n\n"
        f"## References\n{refs or '- (add links as you research)'}\n"
    )


def draft_skill(name, kind="tech", context="", research=None, base=DEFAULT_BASE):
    """Write a learned SKILL.md and register it. Returns the path. Never raises into the hunt."""
    slug = _slug(name)
    folder = os.path.join(LEARNED_DIR, slug)
    os.makedirs(folder, exist_ok=True)
    title = f"{name} — learned playbook"
    path = os.path.join(folder, "SKILL.md")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_skill_body(title, kind, name, context, research or []))
    except OSError as e:
        return {"error": str(e)}
    # register
    idx = [e for e in learned_index() if e.get("slug") != slug]
    idx.append({"slug": slug, "name": name, "kind": kind, "path": path, "created": _now(),
                "refs": len(research or [])})
    _write_index(idx)
    _append(_journal(base), {"ts": _now(), "type": "skill_authored", "slug": slug, "name": name, "path": path})
    return {"path": path, "slug": slug, "registered": True}


def autolearn(kind, name, context="", base=DEFAULT_BASE, research=True, max_results=5):
    """One call: if there's no skill for `name`, research it and draft one. Idempotent."""
    record_gap(kind, name, context, base=base)
    existing = find_skill(name)
    if existing and LEARNED_DIR not in existing:
        return {"skipped": True, "reason": "skill already exists", "path": existing}
    found = []
    if research and WS is not None:
        q = f"{name} {kind} security vulnerabilities CVE exploitation"
        try:
            found = WS.search(q, n=max_results)
        except Exception:  # noqa: BLE001
            found = []
    return draft_skill(name, kind=kind, context=context, research=found, base=base)


# --------------------------------------------------------------------------- CLI
def _cmd_auto(a):
    r = autolearn(a.kind, a.name, context=a.context, base=a.base, research=not a.offline)
    print(json.dumps(r, indent=2))
    return 0 if not r.get("error") else 3


def _cmd_gaps(a):
    for g in gaps(a.base):
        print(f"  {g.get('ts','')[:19]}  [{g.get('kind')}] {g.get('name')} :: {g.get('context','')[:70]}")
    return 0


def _cmd_skills(_a):
    for e in learned_index():
        print(f"  {e.get('slug'):28.28s} {e.get('kind'):8.8s} refs={e.get('refs',0)}  {e.get('path')}")
    print(f"learned skills: {len(learned_index())}")
    return 0


def _cmd_selftest(_a):
    import tempfile
    global LEARNED_DIR
    base = tempfile.mkdtemp()
    LEARNED_DIR = os.path.join(tempfile.mkdtemp(), "learned")

    record_gap("tech", "RedwoodJS", "target runs RedwoodJS", base=base)
    assert any(g["name"] == "RedwoodJS" for g in gaps(base))

    # draft offline (no network) and verify the file + frontmatter + registration
    r = autolearn("tech", "ZZQ Framework 9000", context="weird stack", base=base, research=False)
    assert r.get("registered"), r
    body = open(r["path"], encoding="utf-8").read()
    assert body.startswith("---\nname: zzq-framework-9000") and "description:" in body
    assert "auto_authored: true" in body and "## When to use" in body
    assert any(e["slug"] == "zzq-framework-9000" for e in learned_index())
    assert have_skill("ZZQ Framework 9000")                      # now findable
    # idempotent: second call doesn't duplicate the index entry
    autolearn("tech", "ZZQ Framework 9000", base=base, research=False)
    assert sum(1 for e in learned_index() if e["slug"] == "zzq-framework-9000") == 1

    learn_from_outcome("acme", "idor", "duplicate", "already disclosed", base=base)
    assert any(x.get("type") == "outcome" for x in journal(base))

    # record_outcome closes BOTH loops: rich journal + yieldrank journal, and yieldrank actually learns
    record_outcome("acme", "ssrf", "confirmed", base=base)
    record_outcome("acme", "ssrf", "confirmed", base=base)
    record_outcome("acme", "xss", "duplicate", base=base)
    assert os.path.isfile(_yr_journal(base)), "yieldrank journal written"
    sys.path.insert(0, ENGINE)
    import yieldrank as YR
    learned = YR.Model.load(base).learned
    assert learned.get("ssrf", {}).get("confirmed", 0) >= 2, learned
    assert learned.get("xss", {}).get("dup", 0) >= 1, learned

    # hostile input never raises
    for bad in (None, "", 123, {"x": 1}):
        record_gap(bad, bad, bad, base=base)                     # type: ignore
        _slug(bad)                                               # type: ignore
    print("learn.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="self-learning: capability gaps + auto skill-smith")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("auto")
    pa.add_argument("--kind", default="tech"); pa.add_argument("--name", required=True)
    pa.add_argument("--context", default=""); pa.add_argument("--offline", action="store_true")
    pa.set_defaults(fn=_cmd_auto)
    sub.add_parser("gaps").set_defaults(fn=_cmd_gaps)
    sub.add_parser("skills").set_defaults(fn=_cmd_skills)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
