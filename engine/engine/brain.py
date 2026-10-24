#!/usr/bin/env python3
"""
brain.py — per-program hunt memory that is NOT a vuln catalog.

Public harnesses that actually find bugs (Reaper attack graph, bountyhunter
waves, pentest-agents writeup-then-test) keep a live graph of what this
target did, what was tried, and what the next test should be. They do not
walk a fixed SQLi→IDOR→XSS list.

This file only stores what the live hunt observed. The next agent reads it
so it does not repeat an empty analysis, and so it can invent a test that
is not in any skill file.
"""
import json
import os
import time

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")


def path_for(slug, base=DEFAULT_BASE):
    return os.path.join(os.path.expanduser(base), slug, "brain.json")


def load(slug, base=DEFAULT_BASE):
    p = path_for(slug, base)
    try:
        d = json.load(open(p))
    except (OSError, json.JSONDecodeError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    d.setdefault("edges", {})
    d.setdefault("hypotheses", [])
    d.setdefault("reactive", [])
    d.setdefault("profile", {})
    d.setdefault("round", 0)
    return d


def save(slug, brain, base=DEFAULT_BASE):
    p = path_for(slug, base)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    brain["ts"] = time.time()
    json.dump(brain, open(p, "w"), indent=2)
    return p


def record_edge(slug, url, analysis="", classes=None, signals=None,
                result="nothing", hypotheses=None, base=DEFAULT_BASE):
    """Write what this URL actually did. Truncate so the next prompt stays small."""
    brain = load(slug, base)
    edges = brain["edges"]
    prev = edges.get(url) if isinstance(edges.get(url), dict) else {}
    edges[url] = {
        "last_analysis": str(analysis or prev.get("last_analysis") or "")[:800],
        "classes_considered": list(classes or prev.get("classes_considered") or [])[:12],
        "signals": list(signals or prev.get("signals") or [])[:12],
        "result": result or prev.get("result") or "nothing",
        "tested_at": time.time(),
    }
    for h in hypotheses or []:
        if isinstance(h, str) and h.strip():
            add_hypothesis(brain, h.strip(), url=url, source="agent")
        elif isinstance(h, dict) and (h.get("text") or h.get("hypothesis")):
            add_hypothesis(brain, h.get("text") or h.get("hypothesis"),
                           url=h.get("url") or url, source="agent")
    save(slug, brain, base)
    return brain


def add_hypothesis(brain, text, url="", source="agent"):
    text = str(text or "").strip()
    if not text:
        return
    blob = text.lower()[:200]
    for h in brain.get("hypotheses") or []:
        if str(h.get("text") or "").lower()[:200] == blob:
            return
    brain.setdefault("hypotheses", []).append({
        "text": text[:400],
        "url": url,
        "source": source,
        "status": "open",
        "ts": time.time(),
    })
    brain["hypotheses"] = brain["hypotheses"][-40:]


def mark_reactive(slug, lines, base=DEFAULT_BASE):
    brain = load(slug, base)
    keep = []
    seen = set()
    for ln in (lines or []) + list(brain.get("reactive") or []):
        s = str(ln or "").strip()
        if not s or s.lower() in seen:
            continue
        seen.add(s.lower())
        keep.append(s[:300])
    brain["reactive"] = keep[:20]
    save(slug, brain, base)
    return brain


def set_profile(slug, profile, base=DEFAULT_BASE):
    """Store what this product is. No vuln-class menu — narrative + flows + crown jewels."""
    brain = load(slug, base)
    if not isinstance(profile, dict):
        return brain
    keep = {
        "narrative": str(profile.get("narrative") or profile.get("app_narrative") or "")[:800],
        "tech_stack": list(profile.get("tech_stack") or [])[:20],
        "roles": list(profile.get("roles") or profile.get("user_roles") or [])[:12],
        "auth_mechanism": str(profile.get("auth_mechanism") or "")[:60],
        "crown_jewels": list(profile.get("crown_jewels") or [])[:12],
        "api_surface": [],
        "flows": [],
        "hidden_endpoints": list(profile.get("hidden_endpoints") or [])[:20],
        "deprioritized": list(profile.get("deprioritized") or [])[:12],
        "ts": time.time(),
    }
    for ep in (profile.get("api_surface") or [])[:50]:
        if isinstance(ep, dict) and ep.get("url"):
            keep["api_surface"].append({
                "method": str(ep.get("method") or "GET")[:10],
                "url": str(ep.get("url") or "")[:300],
                "function": str(ep.get("function") or "")[:200],
                "params": list(ep.get("params") or [])[:20],
                "auth_required": bool(ep.get("auth_required", True)),
            })
    for f in (profile.get("flows") or profile.get("high_value_flows") or [])[:12]:
        if isinstance(f, str) and f.strip():
            keep["flows"].append({"what": f.strip()[:200], "url": "", "why": ""})
        elif isinstance(f, dict):
            keep["flows"].append({
                "what": str(f.get("what") or f.get("flow") or "")[:200],
                "url": str(f.get("url") or f.get("endpoint") or "")[:240],
                "why": str(f.get("why") or f.get("why_interesting") or "")[:240],
            })
    brain["profile"] = keep
    for f in keep["flows"]:
        if f.get("why"):
            add_hypothesis(brain, f["why"], url=f.get("url") or "", source="profile")
    save(slug, brain, base)
    return brain


def profile_block(slug, base=DEFAULT_BASE):
    p = (load(slug, base).get("profile") or {})
    if not p.get("narrative") and not p.get("flows"):
        return ""
    lines = ["APP PROFILE (what this product is — attack from this, not from a class list)"]
    if p.get("narrative"):
        lines.append(p["narrative"])
    if p.get("roles"):
        lines.append("Roles: " + ", ".join(str(r) for r in p["roles"][:8]))
    if p.get("crown_jewels"):
        lines.append("Crown jewels: " + "; ".join(str(c) for c in p["crown_jewels"][:6]))
    for f in (p.get("flows") or [])[:6]:
        bit = f.get("what") or ""
        if f.get("url"):
            bit += f" @ {f['url']}"
        if f.get("why"):
            bit += f" — {f['why']}"
        if bit:
            lines.append("- " + bit)
    return "\n".join(lines) + "\n"


def prompt_block(slug, url, base=DEFAULT_BASE):
    """Text injected into the next hunt. Empty when there is nothing to remember."""
    brain = load(slug, base)
    parts = []
    edge = (brain.get("edges") or {}).get(url) or {}
    if edge.get("last_analysis"):
        parts.append("PREVIOUS LOOK AT THIS URL (do not repeat the same requests or the same "
                     "empty conclusion; invent a different test from the live response):\n"
                     + str(edge["last_analysis"])[:500])
        if edge.get("classes_considered"):
            parts.append("Classes already considered: "
                         + ", ".join(str(c) for c in edge["classes_considered"][:10]))
    react = [r for r in (brain.get("reactive") or []) if r]
    if react:
        parts.append("MISSED SIGNALS FROM EARLIER ROUNDS (attack these, they were seen and not proven):\n- "
                     + "\n- ".join(react[:8]))
    open_h = [h for h in (brain.get("hypotheses") or []) if h.get("status") == "open"]
    if open_h:
        parts.append("OPEN HYPOTHESES FOR THIS TARGET (test one if it fits this URL, or invent a better one):\n- "
                     + "\n- ".join(f"{h.get('text','')[:180]}" + (f" @{h.get('url')}" if h.get("url") else "")
                                   for h in open_h[:6]))
    prof = profile_block(slug, base)
    if prof:
        parts.insert(0, prof.rstrip())
    if not parts:
        return ""
    return "\nHUNT MEMORY (live graph for this program — not a vuln catalog)\n" + "\n".join(parts) + "\n"


def open_urls(slug, base=DEFAULT_BASE, limit=8):
    """Hypothesis URLs that have not been tested yet."""
    brain = load(slug, base)
    out, seen = [], set()
    for h in brain.get("hypotheses") or []:
        if h.get("status") != "open":
            continue
        u = h.get("url") or ""
        if u.startswith("http") and u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= limit:
            break
    return out


def enrich_edge(slug, url, base=DEFAULT_BASE):
    """Annotate a brain edge with token spend from ContextPilot telemetry (read-only, optional)."""
    CP_DB = os.path.expanduser("~/.context-pilot/telemetry.db")
    if not os.path.exists(CP_DB):
        return {}
    try:
        import sqlite3
        conn = sqlite3.connect(f"file:{CP_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT COUNT(*) as calls, SUM(payload_bytes) as bytes, "
            "SUM(duration_ms) as ms FROM events "
            "WHERE session_id = (SELECT id FROM sessions ORDER BY started_at DESC LIMIT 1) "
            "AND (tool_input LIKE ? OR tool_input LIKE ?)",
            (f"%{url}%", f"%{url.rstrip('/')}%"),
        ).fetchone()
        conn.close()
        if not row or not row["calls"]:
            return {}
        return {
            "tool_calls": row["calls"],
            "payload_bytes": row["bytes"] or 0,
            "duration_ms": row["ms"] or 0,
        }
    except Exception:
        return {}


def _selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="brain-")
    os.makedirs(os.path.join(d, "demo"), exist_ok=True)
    set_profile("demo", {"narrative": "expense app", "roles": ["user"],
                         "crown_jewels": ["receipts"],
                         "flows": [{"what": "upload", "url": "https://app.example/api/receipts",
                                    "why": "server fetches the file"}]}, base=d)
    record_edge("demo", "https://app.example/api/orders", analysis="JSON list of order ids",
                classes=["idor"], result="nothing", hypotheses=["swap order id as B"], base=d)
    mark_reactive("demo", ["refresh token still valid after logout"], base=d)
    blk = prompt_block("demo", "https://app.example/api/orders", base=d)
    assert "PREVIOUS LOOK" in blk and "swap order id" in blk and "refresh token" in blk, blk
    assert "expense app" in blk and "receipts" in blk, blk
    assert "https://app.example/api/orders" in open_urls("demo", base=d)
    b = load("demo", d)
    add_hypothesis(b, "try /api/me", url="https://app.example/api/me")
    save("demo", b, d)
    record_edge("demo", "https://app.example/api/me", analysis="x", hypotheses=[], base=d)
    b = load("demo", d)
    assert any("swap order id" in (h.get("text") or "") for h in b["hypotheses"])
    print("brain self-test: PASS")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
