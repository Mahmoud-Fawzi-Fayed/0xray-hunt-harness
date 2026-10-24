#!/usr/bin/env python3
"""
skill_map.py — attach hunt-* skills that already exist on disk.

There is no class→skill catalog and no payload catalog. A new hunt-* directory
is eligible the next call. Deep hunts invent the test from live bytes; these
paths are hints, not a menu.
"""
import os
import re

ENGINE = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(os.path.dirname(ENGINE), "skills")
_FALLBACK_DIRS = [os.path.expanduser("~/.claude/skills"),
                  os.path.expanduser("~/.agents/skills"),
                  os.path.expanduser("~/.cursor/skills-cursor")]


def _present():
    names = set()
    for d in [SKILLS_DIR] + _FALLBACK_DIRS:
        try:
            names.update(os.listdir(d))
        except Exception:
            pass
    return names


def _filter(names):
    present = _present()
    return [s for s in names if not present or s in present]


def installed():
    """Every hunt-* / methodology skill directory on disk. The agent may Read any of them."""
    names = []
    for n in sorted(_present()):
        if n.startswith("hunt-") or n in ("security-arsenal", "triage-rtfs", "triage-validation",
                                          "redteam-mindset", "bb-methodology", "dedup-novelty"):
            names.append(n)
    return names


def matching(url="", tech=None, analysis="", extra=""):
    """Skills whose names appear in the live URL, stack, or last analysis.

    This is a HINT for which SKILL.md to attach, not a closed list of vulns.
    """
    blob = " ".join([str(url or ""), " ".join(tech or []), str(analysis or ""), str(extra or "")]).lower()
    blob_n = re.sub(r"[^a-z0-9]+", "", blob)
    generic = {"http", "https", "www", "html", "xml", "json", "url", "web", "app", "info",
               "misc", "misconfig", "owasp", "api"}
    hits = []
    for name in installed():
        if not name.startswith("hunt-"):
            continue
        parts = [p for p in name.replace("hunt-", "").split("-") if len(p) > 2 and p not in generic]
        if parts and any(p in blob or re.sub(r"[^a-z0-9]+", "", p) in blob_n for p in parts):
            hits.append(name)
    return hits[:8]


def skills_for(vuln_class, tech=None, url="", analysis=""):
    """Skills on disk whose names match this URL/stack/class token. No built-in map."""
    extra = " ".join(x for x in (vuln_class, analysis) if x)
    hits = matching(url, tech, extra)
    slug = "hunt-" + str(vuln_class or "").replace("_", "-").lower()
    if vuln_class and vuln_class not in ("deep", "") and slug in _present() and slug not in hits:
        hits.append(slug)
    if hits:
        return hits
    # No class match — fall back to hypothesis-driven hunting
    if "hunt-hypothesis" in _present():
        return ["hunt-hypothesis"]
    return _filter(["hunt-misc"])


def tech_skills(tech):
    """Skills whose names appear in the detected stack strings. No tech→class table."""
    return matching("", tech=tech)


def skill_paths(vuln_class, tech=None, extra=("security-arsenal", "triage-rtfs"),
                url="", analysis=""):
    """Absolute SKILL.md paths that actually exist on disk."""
    names = skills_for(vuln_class, tech=tech, url=url, analysis=analysis)
    names += (tech_skills(tech) if tech else []) + list(extra)
    seen, out = set(), []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        for d in [SKILLS_DIR] + _FALLBACK_DIRS:
            p = os.path.join(d, n, "SKILL.md")
            if os.path.isfile(p):
                out.append(p)
                break
    return out


def probe_for(vuln_class, url, param=None):
    """A GET of the live URL. Payloads are invented from the response, not this function."""
    u = (url or "").replace("FUZZ", "1")
    return f'curl -s "{u}"'


if __name__ == "__main__":
    names = [n for n in installed() if n.startswith("hunt-")]
    print(f"skill_map: {len(names)} hunt-* skill(s) on disk (no class catalog)")
    print(f"  matching Next.js /api/users -> {matching('/api/users', ['Next.js'])}")
    print(f"  probe -> {probe_for('deep', 'https://t/?p=FUZZ', 'p')}")
