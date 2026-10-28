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
            for name in os.listdir(d):
                path = os.path.join(d, name, "SKILL.md")
                if os.path.isfile(path):
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        frontmatter = fh.read(4096)
                    if "review_status: proposed" in frontmatter:
                        continue
                names.add(name)
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
    """Skills on disk whose names match tech/analysis content. No class→skill map.

    URL is intentionally NOT passed to matching() — path segments that happen to
    look like vuln class names (e.g. /admin/xss/ssrf) must not bias skill selection.
    """
    extra = " ".join(x for x in (vuln_class, analysis) if x and x not in ("deep", "dynamic"))
    hits = matching(tech=tech, analysis=extra)
    if hits:
        return hits
    if "hunt-hypothesis" in _present():
        return ["hunt-hypothesis"]
    return _filter(["hunt-misc"])


def _methodology_paths():
    for root in [SKILLS_DIR] + _FALLBACK_DIRS:
        path = os.path.join(root, "hunt-methodology", "SKILL.md")
        if os.path.isfile(path):
            return [path]
    return []


def _live_observations(evidence_dir, case_id, observation_ids):
    if not evidence_dir or not case_id or not observation_ids:
        return []
    import evidence as EV
    requested = {str(value) for value in observation_ids if value}
    observations = EV.get_observations(evidence_dir, case_id=case_id)
    return [obs for obs in observations
            if obs.get("id") in requested and obs.get("resp_status", 0) != 0]


def for_hypothesis(hypothesis, profile=None, limit=4, evidence_dir=None,
                   case_id=None, observation_ids=None):
    """Select vulnerability references only after case-linked live evidence exists."""
    methodology = _methodology_paths()
    if not str(hypothesis or "").strip():
        return methodology
    if not _live_observations(evidence_dir, case_id, observation_ids):
        return methodology
    text = str(hypothesis).lower()
    profile = profile or {}
    text += " " + str(profile.get("action", "")) + " " + str(profile.get("resource", ""))
    text += " " + " ".join(profile.get("trust_dimensions") or [])
    text += " " + str(profile.get("protocol", ""))
    tokens = {w for w in re.findall(r"[a-z][a-z0-9_+-]{2,}", text)
              if w not in {"the", "and", "with", "from", "this", "that", "what", "when", "into", "does"}}
    ranked = []
    for name in installed():
        if not name.startswith("hunt-") or name in ("hunt-discovery", "hunt-dispatch", "hunt-hypothesis"):
            continue
        for root in [SKILLS_DIR] + _FALLBACK_DIRS:
            path = os.path.join(root, name, "SKILL.md")
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read(12000).lower()
            except OSError:
                continue
            score = sum(1 for token in tokens if token in content)
            if score:
                ranked.append((score, name, path))
            break
    ranked.sort(key=lambda item: (-item[0], item[1]))
    paths = methodology + [path for _, _, path in ranked[:limit]]
    return list(dict.fromkeys(paths))[:limit]


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
