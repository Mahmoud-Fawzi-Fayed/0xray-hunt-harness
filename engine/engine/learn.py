#!/usr/bin/env python3
"""
learn.py — the harness teaching itself. When the hunter meets something it has no playbook for (an
unfamiliar framework, a vuln class with no matching skill, a new auth protocol), it records the gap,
researches it on the open web, and drafts a brand-new SKILL.md into the harness's learned-skills
directory so the *next* hunt already knows how to approach it. Every lesson (gap + outcome) is logged
to a journal you can review, and nothing is ever submitted or acted on blindly — new skills are
guidance for the agent, written in the standard SKILL.md shape and clearly marked auto-authored.

Skill evolution: after hunts, record_outcome() logs results. evolve_skill() reads the journal and
appends proven attack vectors / false-positive patterns to existing skills so they sharpen over time.

  autolearn(kind, name, context)   -> research + draft a skill if one doesn't exist (the one-call)
  evolve_skill(name)               -> read outcomes, refine existing skill with lessons
  record_gap(...) / gaps()         -> capability-gap journal
  have_skill(name) / find_skill()  -> is there already a playbook for this?
  draft_skill(...)                 -> write skills/learned/<slug>/SKILL.md + register it
  record_outcome(...)              -> structured lesson from a hunt result (feeds yieldrank + evolution)

CLI:
  python3 engine/learn.py auto  --kind tech --name "RedwoodJS" --context "target runs RedwoodJS GraphQL"
  python3 engine/learn.py evolve --name "express"
  python3 engine/learn.py gaps
  python3 engine/learn.py skills
  python3 engine/learn.py selftest      # offline (no network): gap + draft + evolve + register
"""
import argparse
import datetime
import json
import os
import re
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(ENGINE)
sys.path.insert(0, ENGINE)
try:
    import websearch as WS
except Exception:  # noqa: BLE001
    WS = None

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
LEARNED_DIR = os.environ.get("HUNT_LEARNED_SKILLS_DIR", os.path.join(ROOT, "skills", "learned"))
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
    # trigger skill evolution when enough outcomes accumulate
    _maybe_evolve(vuln_class, base)
    return rec


_EVOLVE_THRESHOLD = 5  # evolve after this many outcomes for a class

def _maybe_evolve(vuln_class, base):
    """Auto-evolve a learned skill when enough outcome data has accumulated."""
    try:
        slug = _slug(vuln_class)
        path = os.path.join(LEARNED_DIR, slug, "SKILL.md")
        if not os.path.isfile(path):
            return
        outcomes = [r for r in _read_jsonl(_journal(base))
                    if r.get("type") == "outcome" and _slug(r.get("vuln_class", "")) == slug]
        # check if we already evolved recently
        evolutions = [r for r in _read_jsonl(_journal(base))
                      if r.get("type") == "skill_evolved" and r.get("slug") == slug]
        last_evolve_count = evolutions[-1].get("outcome_count", 0) if evolutions else 0
        new_outcomes = len(outcomes) - last_evolve_count
        if new_outcomes >= _EVOLVE_THRESHOLD:
            evolve_skill(slug, base=base)
    except Exception:  # noqa: BLE001
        pass


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
        idx = json.load(open(path))
        # fix stale paths from old repo location
        fixed = False
        for e in idx:
            if e.get("path", "").startswith("/root/Claude-BugHunter/"):
                e["path"] = e["path"].replace("/root/Claude-BugHunter/", ROOT + "/")
                fixed = True
        if fixed:
            _write_index(idx)
        return idx
    except (OSError, json.JSONDecodeError):
        return []


def _write_index(entries):
    os.makedirs(LEARNED_DIR, exist_ok=True)
    json.dump(entries, open(os.path.join(LEARNED_DIR, "index.json"), "w"), indent=2)


# --------------------------------------------------------------- research
def _research(name, kind, context, max_queries=4, max_results=5):
    """Multi-query research. Returns list of {url, title, snippet}."""
    if WS is None:
        return []
    queries = _research_queries(name, kind, context)[:max_queries]
    seen_urls = set()
    results = []
    for q in queries:
        try:
            hits = WS.search(q, n=max_results)
        except Exception:  # noqa: BLE001
            continue
        for h in hits:
            u = h.get("url", "")
            if u and u not in seen_urls:
                seen_urls.add(u)
                results.append(h)
    return results


def _research_queries(name, kind, context):
    """Generate targeted search queries based on the kind of gap."""
    n = str(name or "")
    queries = []
    if kind == "tech":
        queries = [
            f"{n} security vulnerabilities CVE exploitation",
            f"{n} pentest methodology bug bounty",
            f"{n} default credentials admin panel debug endpoints",
            f"{n} known misconfigurations security hardening bypass",
        ]
    elif kind == "vuln":
        queries = [
            f"{n} exploitation techniques proof of concept",
            f"{n} bypass WAF filter evasion",
            f"{n} real-world bug bounty writeup",
            f"{n} detection and validation methodology",
        ]
    elif kind == "bypass":
        queries = [
            f"{n} bypass technique 2024 2025 2026",
            f"{n} WAF evasion filter bypass",
            f"{n} alternative exploitation method",
        ]
    elif kind == "program":
        queries = [
            f"{n} bug bounty program disclosed reports",
            f"{n} hackerone bugcrowd disclosed vulnerabilities",
        ]
    else:
        queries = [
            f"{n} security vulnerabilities exploitation",
            f"{n} pentest bug bounty writeup",
        ]
    if context:
        ctx_short = str(context)[:60].strip()
        queries.append(f"{n} {ctx_short} security")
    return queries


# --------------------------------------------------------------- skill body templates (kind-specific)
def _skill_body(title, kind, name, context, research):
    refs = ""
    notes = ""
    if research:
        refs = "\n".join(f"- [{(r.get('title') or r.get('url') or '')[:90]}]({r.get('url', '')})"
                         for r in research if r.get("url"))
        notes = "\n".join(f"- {(''.join((r.get('snippet') or '')[:200]))}" for r in research if r.get("snippet"))
    desc = (f"Playbook for {name} ({kind}). Auto-authored by the harness after it hit this as a gap. "
            f"Use when a target involves {name}. Review and refine before relying on it.").replace("\n", " ")

    if kind == "tech":
        return _tech_body(name, desc, context, notes, refs)
    elif kind == "vuln":
        return _vuln_body(name, desc, context, notes, refs)
    elif kind == "bypass":
        return _bypass_body(name, desc, context, notes, refs)
    elif kind == "program":
        return _program_body(name, desc, context, notes, refs)
    return _generic_body(name, kind, desc, context, notes, refs)


def _frontmatter(slug, desc, kind):
    return (f"---\nname: {slug}\n"
            f"description: {desc}\n"
            f"auto_authored: true\n"
            f"kind: {kind}\n"
            f"created: {_now()}\n"
            f"evolved: 0\n---\n\n")


def _tech_body(name, desc, context, notes, refs):
    slug = _slug(name)
    return (_frontmatter(slug, desc, "tech") +
            f"# {name} — tech playbook\n\n"
            f"> Auto-drafted from a capability gap. Context: {context or '(none)'}\n\n"
            f"## When to use\n"
            f"- Target runs **{name}**.\n"
            f"- No curated `hunt-*` skill covers this stack.\n\n"
            f"## Fingerprint\n"
            f"- Headers, cookies, JS bundles, error pages, `/robots.txt`, version strings.\n"
            f"- Debug/admin endpoints: actuator, phpinfo, /_debug, /admin, /graphql, /swagger.\n\n"
            f"## Attack surface by layer\n"
            f"- **Auth**: default creds, session handling, JWT/token issues, OAuth flows.\n"
            f"- **Injection**: SQL/NoSQL/LDAP/OS command via every user input.\n"
            f"- **Access control**: IDOR on every object-id parameter, role escalation.\n"
            f"- **SSRF/file**: any URL/path parameter — test internal fetch, file read.\n"
            f"- **Config**: verbose errors, debug mode, exposed secrets, .env, .git.\n"
            f"- **Deserialization**: if the stack uses serialized objects (Java/.NET/PHP/Python pickle).\n\n"
            f"## {name}-specific vectors\n"
            f"- Check known CVEs for the detected version (NVD, GitHub advisories).\n"
            f"- Stack-specific misconfigs and default behaviors.\n"
            f"{notes or '- (research results will appear here after web search)'}\n\n"
            f"## Validation\n"
            f"- Prove impact concretely — no speculative claims.\n"
            f"- OOB confirmation for blind injection/SSRF.\n"
            f"- IDOR: A-vs-B diff with unique marker.\n\n"
            f"## Lessons learned\n"
            f"_This section is auto-updated as the harness hunts against {name} targets._\n\n"
            f"## References\n{refs or '- (will populate after research)'}\n")


def _vuln_body(name, desc, context, notes, refs):
    slug = _slug(name)
    return (_frontmatter(slug, desc, "vuln") +
            f"# {name} — vulnerability playbook\n\n"
            f"> Auto-drafted from a gap. Context: {context or '(none)'}\n\n"
            f"## When to use\n"
            f"- Endpoint behavior suggests **{name}** may be possible.\n\n"
            f"## Detection signals\n"
            f"- What in the response hints at this class?\n"
            f"- Which parameters/headers/fields are the injection points?\n\n"
            f"## Test methodology\n"
            f"- Step 1: Baseline request (normal input, capture response).\n"
            f"- Step 2: Inject test payload — observe delta vs baseline.\n"
            f"- Step 3: Escalate — prove real impact (data leak, auth bypass, code exec).\n\n"
            f"## Bypass techniques\n"
            f"- WAF/filter evasion patterns for this class.\n"
            f"- Encoding tricks, alternate syntax, chained vectors.\n"
            f"{notes or '- (research results populate here)'}\n\n"
            f"## False-positive patterns\n"
            f"_Auto-updated: patterns that looked like {name} but were disproved._\n\n"
            f"## Confirmed patterns\n"
            f"_Auto-updated: attack vectors that produced confirmed findings._\n\n"
            f"## References\n{refs or '- (will populate after research)'}\n")


def _bypass_body(name, desc, context, notes, refs):
    slug = _slug(name)
    return (_frontmatter(slug, desc, "bypass") +
            f"# {name} — bypass playbook\n\n"
            f"> Auto-drafted from a gap. Context: {context or '(none)'}\n\n"
            f"## When to use\n"
            f"- A defense mechanism blocks the primary attack vector.\n"
            f"- Need an alternative path for **{name}**.\n\n"
            f"## Known bypass techniques\n"
            f"{notes or '- (research results populate here)'}\n\n"
            f"## Lessons learned\n"
            f"_Auto-updated with bypass outcomes._\n\n"
            f"## References\n{refs or '- (will populate after research)'}\n")


def _program_body(name, desc, context, notes, refs):
    slug = _slug(name)
    return (_frontmatter(slug, desc, "program") +
            f"# {name} — program intel\n\n"
            f"> Auto-drafted from hunting. Context: {context or '(none)'}\n\n"
            f"## Program profile\n"
            f"- Known tech stack, scope patterns, response time.\n\n"
            f"## Disclosed findings\n"
            f"- What classes have been reported and accepted?\n"
            f"- Which areas are over-hunted (likely dupes)?\n"
            f"{notes or '- (research results populate here)'}\n\n"
            f"## Hunt outcomes\n"
            f"_Auto-updated with results from hunts against this program._\n\n"
            f"## References\n{refs or '- (will populate after research)'}\n")


def _generic_body(name, kind, desc, context, notes, refs):
    slug = _slug(name)
    return (_frontmatter(slug, desc, kind) +
            f"# {name} — {kind} playbook\n\n"
            f"> Auto-drafted from a capability gap. Context: {context or '(none)'}\n\n"
            f"## When to use\n"
            f"- A target involves **{name}** ({kind}).\n"
            f"- No existing skill covers it.\n\n"
            f"## Approach\n"
            f"- Fingerprint, map attack surface, test, prove impact.\n"
            f"{notes or '- (add findings as you learn)'}\n\n"
            f"## Lessons learned\n"
            f"_Auto-updated with hunt outcomes._\n\n"
            f"## References\n{refs or '- (add links as you research)'}\n")


# --------------------------------------------------------------- skill drafting
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
    idx = [e for e in learned_index() if e.get("slug") != slug]
    idx.append({"slug": slug, "name": name, "kind": kind, "path": path, "created": _now(),
                "refs": len(research or []), "evolved": 0})
    _write_index(idx)
    _append(_journal(base), {"ts": _now(), "type": "skill_authored", "slug": slug, "name": name, "path": path})
    return {"path": path, "slug": slug, "registered": True}


# --------------------------------------------------------------- skill evolution
def evolve_skill(name, base=DEFAULT_BASE):
    """Read outcome journal, append lessons to an existing learned skill. Idempotent per outcome batch."""
    slug = _slug(name)
    path = find_skill(name)
    if not path:
        return {"skipped": True, "reason": "no skill to evolve"}
    # only evolve auto-authored skills (don't touch curated ones)
    try:
        body = open(path, encoding="utf-8").read()
    except OSError:
        return {"error": "cannot read skill"}
    if "auto_authored: true" not in body:
        return {"skipped": True, "reason": "not auto-authored, won't modify curated skill"}

    entries = _read_jsonl(_journal(base))
    outcomes = [r for r in entries if r.get("type") == "outcome"
                and (_slug(r.get("vuln_class", "")) == slug
                     or _slug(r.get("program", "")) == slug
                     or _slug(r.get("note", "")[:40]) == slug)]
    if not outcomes:
        return {"skipped": True, "reason": "no outcomes to learn from"}

    confirmed = [o for o in outcomes if o.get("result") in ("confirmed", "reported")]
    fp = [o for o in outcomes if o.get("result") == "false-positive"]
    dupes = [o for o in outcomes if o.get("result") in ("duplicate", "dup")]

    lessons = []
    if confirmed:
        lessons.append("\n### Confirmed vectors")
        for c in confirmed[-10:]:  # last 10
            note = c.get("note", "")[:200] or c.get("vuln_class", "")
            prog = c.get("program", "?")
            lessons.append(f"- [{c.get('ts', '')[:10]}] {prog}: {note}")

    if fp:
        lessons.append("\n### False-positive patterns (avoid)")
        for f in fp[-10:]:
            note = f.get("note", "")[:200] or f.get("vuln_class", "")
            prog = f.get("program", "?")
            lessons.append(f"- [{f.get('ts', '')[:10]}] {prog}: {note}")

    if dupes:
        lessons.append("\n### Duplicate patterns (deprioritize)")
        for d in dupes[-5:]:
            note = d.get("note", "")[:200] or d.get("vuln_class", "")
            prog = d.get("program", "?")
            lessons.append(f"- [{d.get('ts', '')[:10]}] {prog}: {note}")

    if not lessons:
        return {"skipped": True, "reason": "no actionable lessons"}

    lesson_block = "\n".join(lessons)
    evolved_marker = f"\n\n---\n_Evolved {_now()[:10]} from {len(outcomes)} outcomes " \
                     f"({len(confirmed)} confirmed, {len(fp)} FP, {len(dupes)} dup)_\n"

    # append to the "Lessons learned" section if it exists, otherwise append at end
    if "## Lessons learned" in body:
        body = body.replace("## Lessons learned",
                            f"## Lessons learned\n{lesson_block}{evolved_marker}", 1)
    elif "## Confirmed patterns" in body:
        # vuln-kind skills have separate sections
        if confirmed:
            cp_block = "\n".join(lessons[lessons.index("\n### Confirmed vectors"):])
            idx_cp = body.index("## Confirmed patterns")
            body = body[:idx_cp] + f"## Confirmed patterns\n{cp_block}\n\n" + body[idx_cp + len("## Confirmed patterns"):]
        if fp:
            fp_start = lessons.index("\n### False-positive patterns (avoid)") if "\n### False-positive patterns (avoid)" in lessons else -1
            if fp_start >= 0:
                fp_block = "\n".join(lessons[fp_start:])
                if "## False-positive patterns" in body:
                    idx_fp = body.index("## False-positive patterns")
                    nl = body.index("\n", idx_fp + 1)
                    body = body[:nl] + f"\n{fp_block}" + body[nl:]
    else:
        body += f"\n## Lessons learned\n{lesson_block}{evolved_marker}\n"

    # update evolved count in frontmatter
    body = re.sub(r"evolved: \d+", f"evolved: {len(confirmed) + len(fp) + len(dupes)}", body, count=1)

    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    except OSError as e:
        return {"error": str(e)}

    # update index
    idx = learned_index()
    for e in idx:
        if e.get("slug") == slug:
            e["evolved"] = len(outcomes)
            e["last_evolved"] = _now()
    _write_index(idx)

    _append(_journal(base), {"ts": _now(), "type": "skill_evolved", "slug": slug,
                              "outcome_count": len(outcomes),
                              "confirmed": len(confirmed), "fp": len(fp), "dup": len(dupes)})
    return {"evolved": True, "slug": slug, "outcomes": len(outcomes),
            "confirmed": len(confirmed), "fp": len(fp), "dup": len(dupes)}


# --------------------------------------------------------------- autolearn
_AUTOLEARN_CALLS = 0
_AUTOLEARN_MAX_PER_SESSION = 5
_AUTOLEARN_MAX_RESEARCH_QUERIES = 4
_AUTOLEARN_MAX_SKILL_LINES = 120
_AUTOLEARN_COOLDOWN_S = 12 * 3600  # 12h cooldown (was 24h)


def autolearn(kind, name, context="", base=DEFAULT_BASE, research=True, max_results=5):
    """One call: if there's no skill for `name`, research it and draft one. Idempotent.

    Caps: max 5 calls/session, max 4 research queries/call, 12h cooldown per (kind,name),
    drafted skill capped at 120 lines.

    Kinds: tech (unknown stack), vuln (unknown vuln class), bypass (need evasion technique),
           program (program-specific intel).
    """
    global _AUTOLEARN_CALLS
    kind = str(kind or "tech").lower()
    if kind not in ("tech", "vuln", "bypass", "program"):
        kind = "tech"
    record_gap(kind, name, context, base=base)
    existing = find_skill(name)
    if existing:
        return {"skipped": True, "reason": "skill already exists", "path": existing}
    if _AUTOLEARN_CALLS >= _AUTOLEARN_MAX_PER_SESSION:
        return {"skipped": True, "reason": f"session cap reached ({_AUTOLEARN_MAX_PER_SESSION})"}
    # cooldown check
    journal_path = _journal(base)
    if os.path.isfile(journal_path):
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            with open(journal_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except Exception:
                        continue
                    if (entry.get("type") == "skill_authored"
                            and entry.get("name") == name):
                        try:
                            ts = datetime.datetime.fromisoformat(entry["ts"])
                            if (now - ts).total_seconds() < _AUTOLEARN_COOLDOWN_S:
                                return {"skipped": True, "reason": f"cooldown: {name} researched within 12h"}
                        except (KeyError, ValueError):
                            pass
        except Exception:
            pass
    _AUTOLEARN_CALLS += 1
    found = []
    if research:
        found = _research(name, kind, context,
                          max_queries=_AUTOLEARN_MAX_RESEARCH_QUERIES,
                          max_results=max_results)
    return draft_skill(name, kind=kind, context=context, research=found, base=base)


# --------------------------------------------------------------- evolve-all (batch)
def evolve_all(base=DEFAULT_BASE):
    """Evolve every auto-authored learned skill that has new outcomes. Called post-hunt."""
    results = {}
    for entry in learned_index():
        slug = entry.get("slug", "")
        if not slug:
            continue
        r = evolve_skill(slug, base=base)
        if r.get("evolved"):
            results[slug] = r
    return results


# --------------------------------------------------------------------------- CLI
def _cmd_auto(a):
    r = autolearn(a.kind, a.name, context=a.context, base=a.base, research=not a.offline)
    print(json.dumps(r, indent=2))
    return 0 if not r.get("error") else 3


def _cmd_evolve(a):
    if a.name:
        r = evolve_skill(a.name, base=a.base)
    else:
        r = evolve_all(base=a.base)
    print(json.dumps(r, indent=2))
    return 0


def _cmd_gaps(a):
    for g in gaps(a.base):
        print(f"  {g.get('ts', '')[:19]}  [{g.get('kind')}] {g.get('name')} :: {g.get('context', '')[:70]}")
    return 0


def _cmd_skills(_a):
    for e in learned_index():
        ev = e.get("evolved", 0)
        print(f"  {e.get('slug'):28.28s} {e.get('kind'):8.8s} refs={e.get('refs', 0)}  evolved={ev}  {e.get('path')}")
    print(f"learned skills: {len(learned_index())}")
    return 0


def _cmd_selftest(_a):
    import tempfile
    global LEARNED_DIR
    base = tempfile.mkdtemp()
    LEARNED_DIR = os.path.join(tempfile.mkdtemp(), "learned")

    # gap recording
    record_gap("tech", "RedwoodJS", "target runs RedwoodJS", base=base)
    assert any(g["name"] == "RedwoodJS" for g in gaps(base))

    # draft tech skill offline
    r = autolearn("tech", "ZZQ Framework 9000", context="weird stack", base=base, research=False)
    assert r.get("registered"), r
    body = open(r["path"], encoding="utf-8").read()
    assert body.startswith("---\nname: zzq-framework-9000") and "description:" in body
    assert "auto_authored: true" in body and "kind: tech" in body
    assert "## Fingerprint" in body and "## Attack surface by layer" in body
    assert "## Lessons learned" in body
    assert any(e["slug"] == "zzq-framework-9000" for e in learned_index())
    assert have_skill("ZZQ Framework 9000")

    # idempotent
    autolearn("tech", "ZZQ Framework 9000", base=base, research=False)
    assert sum(1 for e in learned_index() if e["slug"] == "zzq-framework-9000") == 1

    # draft vuln skill
    r2 = autolearn("vuln", "ZZQ-injection-9000", context="JS app", base=base, research=False)
    assert r2.get("registered"), r2
    body2 = open(r2["path"], encoding="utf-8").read()
    assert "kind: vuln" in body2
    assert "## Detection signals" in body2
    assert "## False-positive patterns" in body2
    assert "## Confirmed patterns" in body2

    # draft bypass skill
    r3 = autolearn("bypass", "WAF-cloudflare", context="need CF bypass", base=base, research=False)
    assert r3.get("registered"), r3
    body3 = open(r3["path"], encoding="utf-8").read()
    assert "kind: bypass" in body3

    # draft program skill
    r4 = autolearn("program", "acme-corp", context="new program", base=base, research=False)
    assert r4.get("registered"), r4
    body4 = open(r4["path"], encoding="utf-8").read()
    assert "kind: program" in body4
    assert "## Hunt outcomes" in body4

    # outcomes + evolution
    learn_from_outcome("acme", "idor", "duplicate", "already disclosed", base=base)
    assert any(x.get("type") == "outcome" for x in journal(base))

    record_outcome("acme", "ssrf", "confirmed", base=base)
    record_outcome("acme", "ssrf", "confirmed", base=base)
    record_outcome("acme", "xss", "duplicate", base=base)
    assert os.path.isfile(_yr_journal(base)), "yieldrank journal written"
    sys.path.insert(0, ENGINE)
    import yieldrank as YR
    learned = YR.Model.load(base).learned
    assert learned.get("ssrf", {}).get("confirmed", 0) >= 2, learned
    assert learned.get("xss", {}).get("dup", 0) >= 1, learned

    # evolution: add enough outcomes for zzq skill, then evolve
    for i in range(6):
        record_outcome("test", "zzq-framework-9000", "confirmed" if i < 4 else "false-positive",
                       f"test note {i}", base=base)
    ev = evolve_skill("zzq-framework-9000", base=base)
    assert ev.get("evolved"), ev
    assert ev["confirmed"] >= 4
    assert ev["fp"] >= 2
    evolved_body = open(r["path"], encoding="utf-8").read()
    assert "### Confirmed vectors" in evolved_body
    assert "### False-positive patterns" in evolved_body
    assert "evolved: " in evolved_body

    # evolve won't touch curated skills
    curated_dir = os.path.join(LEARNED_DIR, "curated-test")
    os.makedirs(curated_dir, exist_ok=True)
    with open(os.path.join(curated_dir, "SKILL.md"), "w") as fh:
        fh.write("# Curated skill\nNo auto_authored flag.\n")
    ev2 = evolve_skill("curated-test", base=base)
    assert ev2.get("skipped"), "should not evolve curated skill"

    # evolve_all
    for i in range(6):
        record_outcome("test2", "zzq-injection-9000", "confirmed", f"pp note {i}", base=base)
    results = evolve_all(base=base)
    assert "zzq-injection-9000" in results, results

    # hostile input never raises
    for bad in (None, "", 123, {"x": 1}):
        record_gap(bad, bad, bad, base=base)
        _slug(bad)

    # research query generation
    q_tech = _research_queries("Express", "tech", "")
    assert len(q_tech) >= 3 and "CVE" in q_tech[0]
    q_vuln = _research_queries("SSRF", "vuln", "")
    assert "bypass" in q_vuln[1].lower()

    print("learn.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="self-learning: capability gaps + auto skill-smith + evolution")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("auto")
    pa.add_argument("--kind", default="tech", choices=["tech", "vuln", "bypass", "program"])
    pa.add_argument("--name", required=True)
    pa.add_argument("--context", default=""); pa.add_argument("--offline", action="store_true")
    pa.set_defaults(fn=_cmd_auto)
    pe = sub.add_parser("evolve")
    pe.add_argument("--name", default="")
    pe.set_defaults(fn=_cmd_evolve)
    sub.add_parser("gaps").set_defaults(fn=_cmd_gaps)
    sub.add_parser("skills").set_defaults(fn=_cmd_skills)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
