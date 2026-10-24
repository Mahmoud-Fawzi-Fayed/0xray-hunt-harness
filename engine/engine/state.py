#!/usr/bin/env python3
"""
state.py — persistent, resumable engagement state.

Everything the engine learns lives on disk so a long run is auditable and can be
killed/resumed without losing progress. Layout:

  <base>/<name>/
    state.json      surface items, worklist, tested set, candidate + confirmed findings, phase
    engine.log      append-only run log
    evidence/       per-finding evidence files
    report.md       generated at the end
"""
import json
import os
import re
import time
from datetime import datetime, timezone

# Re-hunt window: a surface item tested >this-many-hours ago becomes eligible again (fresh model
# rotation gets another shot — an LLM "nothing" from one pass is low-confidence, not terminal).
# 0 or negative => never re-test (legacy "test once" behavior). Tune via HUNT_RETEST_HOURS.
try:
    RETEST_HOURS = float(os.environ.get("HUNT_RETEST_HOURS", "48") or 48)
except ValueError:
    RETEST_HOURS = 48.0


def _now():
    return datetime.now(timezone.utc).isoformat()


# Object ids in a path or query are one hunt, not one hunt per file. /v1 and short
# counters stay distinct so versioned routes and the selftest URLs are not collapsed.
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONGHEX_RE = re.compile(r"(?<=/)[0-9a-fA-F]{16,}(?=/|[?#]|$)")
_LONGNUM_RE = re.compile(r"(?<=/)\d{4,}(?=/|[?#]|$)")
_QVAL_RE = re.compile(r"([?&][^=&]+=)([^&]*)")
_IDVAL_RE = re.compile(r"^(?:[0-9a-fA-F]{16,}|\d{4,})$")


def url_pattern(url):
    """Concrete URL with UUIDs, long hex, and long numeric ids replaced by {id}."""
    if not url:
        return ""
    u = _UUID_RE.sub("{id}", str(url))
    u = _LONGHEX_RE.sub("{id}", u)
    u = _LONGNUM_RE.sub("{id}", u)

    def _qv(m):
        val = m.group(2)
        if _UUID_RE.search(val or "") or _IDVAL_RE.match(val or ""):
            return m.group(1) + "{id}"
        return m.group(0)

    return _QVAL_RE.sub(_qv, u)


def _as_epoch(v):
    """Coerce a stored 'tested' timestamp (epoch float, or legacy ISO string, or missing) to epoch."""
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def _slug(s):
    """Canonical on-disk name — matches targets._slug / agent._slug / the bridge so logs, activity,
    sessions and engagement state all resolve to the SAME directory for any target name."""
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "unknown"


class Engagement:
    def __init__(self, base, name):
        self.name = name
        self.dir = os.path.join(os.path.expanduser(base), _slug(name))   # slug => consistent everywhere
        os.makedirs(os.path.join(self.dir, "evidence"), exist_ok=True)
        self.state_path = os.path.join(self.dir, "state.json")
        self.log_path = os.path.join(self.dir, "engine.log")
        self.state = self._load()

    def _load(self):
        if os.path.isfile(self.state_path):
            return json.load(open(self.state_path))
        return {"name": self.name, "created": _now(), "phase": "init",
                "targets": [], "surface": [], "tested": [], "candidates": [], "confirmed": []}

    def save(self):
        tmp = self.state_path + ".tmp"
        json.dump(self.state, open(tmp, "w"), indent=2)
        os.replace(tmp, self.state_path)

    def log(self, msg):
        line = f"{_now()}  {msg}"
        with open(self.log_path, "a") as f:
            f.write(line + "\n")
        print("  " + msg, flush=True)

    # ---- phase ----
    def set_phase(self, phase):
        self.state["phase"] = phase
        self.save()

    # ---- surface (discovered, scope-checked endpoints/params) ----
    def add_surface(self, items):
        # Dedup on the URL *pattern* so /files/<uuid-1> and /files/<uuid-2> are one job.
        # The first concrete URL is what the agent actually requests.
        seen = {self._pat_key(s) for s in self.state["surface"]}
        added = 0
        for it in items:
            key = self._pat_key(it)
            if key not in seen:
                self.state["surface"].append(it)
                seen.add(key)
                added += 1
        self.save()
        return added

    def collapse_patterns(self):
        """Mark extra concrete URLs of the same pattern tested, leaving one representative huntable."""
        groups = {}
        for s in self.state["surface"]:
            groups.setdefault(self._pat_key(s), []).append(s)
        tested = self.state.get("tested")
        if not isinstance(tested, dict):
            tested = {str(k): 0.0 for k in (tested or [])}
            self.state["tested"] = tested
        now = time.time()
        n = 0
        for items in groups.values():
            if len(items) < 2:
                continue
            keep = max(items, key=lambda s: ((s.get("priority") or 0), s.get("url") or ""))
            for s in items:
                if s is keep:
                    continue
                k = self._key(s)
                if k not in tested:
                    tested[k] = now
                    n += 1
        if n:
            self.save()
        return n

    def hunt_note(self, item):
        return (self.state.get("hunt_notes") or {}).get(self._key(item)) or {}

    def note_hunt(self, item, analysis, classes=None):
        """Remember why an endpoint was nothing, so the next look does not repeat the same dead end."""
        notes = self.state.setdefault("hunt_notes", {})
        notes[self._key(item)] = {
            "analysis": str(analysis or "")[:600],
            "classes": [str(c) for c in (classes or [])][:8],
            "ts": time.time(),
        }
        self.save()

    def _tested_map(self):
        """{key: epoch_ts} from either the current dict form or a legacy list[str] (ts=0 => eligible).
        Indexes both new 4-field (METHOD|url|param|class) and legacy 3-field (url|param|class) keys
        so worklist lookups work regardless of which format the key was stored in."""
        t = self.state.get("tested")
        out = {}
        if isinstance(t, dict):
            for k, v in t.items():
                ts = _as_epoch(v)
                out[str(k)] = ts
                parts = str(k).split("|")
                if len(parts) == 4:
                    legacy = "|".join(parts[1:])
                    if legacy not in out:
                        out[legacy] = ts
                elif len(parts) == 3:
                    out[k] = ts
        elif isinstance(t, list):
            for k in t:
                out[str(k)] = 0.0
        return out

    def worklist(self):
        """Ranked surface items to hunt. UNTESTED items come FIRST — so coverage advances through the
        WHOLE surface before anything is re-hunted — then stale items (last test older than the re-hunt
        window), oldest-tested first. Without untested-first ordering a deep target re-hunts its
        top-priority slice forever and never reaches the long tail (e.g. paysafe stuck at 181/4606)."""
        tmap = self._tested_map()
        notes = self.state.get("hunt_notes") if isinstance(self.state.get("hunt_notes"), dict) else {}
        skipped = set((self.state.get("skipped") or {}).keys())
        now = time.time()
        ttl = RETEST_HOURS * 3600
        ranked = []                                # (group, -eff_priority, last_tested): sorts untested first
        for s in self.state["surface"]:
            k = self._key(s)
            if k in skipped:
                continue
            ep = -self._eff_priority(s)
            last = tmap.get(k)
            if last is None and k in notes:
                # A hunt_note is coverage. Relogin used to wipe `tested` and re-queue the same URL.
                ts = (notes[k] or {}).get("ts") if isinstance(notes[k], dict) else 0
                last = _as_epoch(ts) or now
            if last is None:
                ranked.append((0, ep, 0.0, s))                          # never tested -> cover it first
            elif ttl > 0 and (now - last) >= ttl:
                ranked.append((1, ep, last, s))                         # stale -> re-hunt, oldest first
            # else: tested / noted within the window -> not eligible this pass
        ranked.sort(key=lambda t: (t[0], t[1], -(1 if t[3].get("param") else 0), t[2]))
        return [t[3] for t in ranked]

    @staticmethod
    def _eff_priority(s):
        """Effective hunt priority. The agent-found FEEDBACK long-tail sinks below the core recon surface so
        the hunt covers high-value, session-applicable hosts first instead of a feedback rabbit-hole (which
        can be a 401-walled help-desk/Zendesk API that dead-ends without a session we don't hold)."""
        p = s.get("priority", 0)
        if s.get("source") == "agent-found":
            p -= 25
        return p

    @staticmethod
    def _key(s):
        return f"{s.get('method','GET')}|{s['url']}|{s.get('param','')}|{s.get('vuln_class','')}"

    @staticmethod
    def _legacy_key(s):
        return f"{s['url']}|{s.get('param','')}|{s.get('vuln_class','')}"

    @staticmethod
    def _pat_key(s):
        return (s.get("method", "GET"), url_pattern(s.get("url", "")), s.get("param") or "", s.get("vuln_class") or "")

    def mark_tested(self, item, checks=None):
        k = self._key(item)
        t = self.state.get("tested")
        if not isinstance(t, dict):                # migrate legacy list -> timestamped dict
            t = {str(x): 0.0 for x in (t or [])}
            self.state["tested"] = t
        t[k] = time.time()                         # record WHEN -> enables the re-hunt window
        if checks:
            tc = self.state.setdefault("tested_checks", {})
            existing = tc.get(k, [])
            for c in checks:
                if c and c not in existing:
                    existing.append(c)
            tc[k] = existing
        self.save()

    def mark_skipped(self, item, reason="unknown"):
        k = self._key(item)
        sk = self.state.get("skipped")
        if not isinstance(sk, dict):
            sk = {}
            self.state["skipped"] = sk
        sk[k] = {"reason": reason, "ts": time.time()}
        self.save()

    # ---- findings ----
    def add_candidate(self, finding):
        finding["ts"] = _now()
        self.state["candidates"].append(finding)
        self.save()

    def _finding_key(self, finding):
        return f"{finding.get('url','')}|{finding.get('vuln_class','')}"

    def rejected_keys(self):
        r = self.state.get("rejected")
        if isinstance(r, dict):
            return set(r)
        return set()

    def mark_rejected(self, finding, reason):
        """A candidate that was disproved, held, or out of scope is not sent back to the validator."""
        rec = self.state.setdefault("rejected", {})
        if not isinstance(rec, dict):
            rec = {}
            self.state["rejected"] = rec
        rec[self._finding_key(finding)] = str(reason or "")[:240]
        self.save()

    def confirm(self, finding, verdict):
        finding = {**finding, "verdict": verdict, "confirmed_ts": _now()}
        self.state["confirmed"].append(finding)
        self.save()

    def evidence_path(self, fname):
        return os.path.join(self.dir, "evidence", fname)

    # ---- progress ----
    def summary(self):
        t = self.state["tested"]
        # count only new-format keys (METHOD|url|param|class) to avoid double-counting legacy compat keys
        tested_count = sum(1 for k in (t if isinstance(t, dict) else t or [])
                          if str(k).count("|") >= 3) or len(t if isinstance(t, dict) else t or [])
        return {"surface": len(self.state["surface"]), "tested": tested_count,
                "candidates": len(self.state["candidates"]), "confirmed": len(self.state["confirmed"]),
                "phase": self.state["phase"]}


def _selftest():
    import tempfile, shutil
    d = tempfile.mkdtemp()
    try:
        e = Engagement(d, "demo")
        assert e.add_surface([{"url": "http://t/a", "param": "id", "vuln_class": "idor", "priority": 5},
                              {"url": "http://t/a", "param": "id", "vuln_class": "idor"}]) == 1  # dedup
        e.add_surface([{"url": "http://t/b", "param": "q", "vuln_class": "xss", "priority": 9}])
        wl = e.worklist()
        assert wl[0]["url"] == "http://t/b"            # higher priority first
        e.mark_tested(wl[0])
        assert all(s["url"] != "http://t/b" or s.get("param") != "q" for s in e.worklist())
        # re-hunt window: a stale tested item becomes eligible again (no permanent idling)
        globals()["RETEST_HOURS"] = 0.0001
        e.state["tested"]["GET|http://t/b|q|xss"] = time.time() - 3600   # tested an hour ago
        e.save()
        assert any(s.get("url") == "http://t/b" for s in e.worklist()), "stale item must re-queue"
        # coverage-first: the UNTESTED item (t/a, pri 5) must out-rank the STALE re-test (t/b, pri 9)
        assert e.worklist()[0]["url"] == "http://t/a", "untested must come before a stale re-test"
        globals()["RETEST_HOURS"] = 48.0
        # and with the window disabled, it stays excluded (legacy test-once)
        globals()["RETEST_HOURS"] = 0
        assert all(s["url"] != "http://t/b" or s.get("param") != "q" for s in e.worklist())
        globals()["RETEST_HOURS"] = 48.0
        e.add_candidate({"url": "http://t/a", "vuln_class": "idor", "evidence": "x"})
        e.confirm(e.state["candidates"][0], {"real": True})
        # resume: a fresh handle on the same dir sees persisted state
        e2 = Engagement(d, "demo")
        assert e2.summary() == {"surface": 2, "tested": 1, "candidates": 1, "confirmed": 1, "phase": "init"}
        # one file-id pattern is one hunt: the second UUID is not a new surface item
        u1 = "https://files.example/api/v1/files/11111111-1111-4111-8111-111111111111"
        u2 = "https://files.example/api/v1/files/22222222-2222-4222-8222-222222222222"
        assert e.add_surface([{"url": u1, "vuln_class": "deep"}, {"url": u2, "vuln_class": "deep"}]) == 1
        e3 = Engagement(d, "dup")
        e3.state["surface"] = [{"url": u1, "vuln_class": "deep"}, {"url": u2, "vuln_class": "deep"}]
        assert e3.collapse_patterns() == 1
        assert len(e3.worklist()) == 1
        kept = e3.worklist()[0]
        e3.note_hunt(kept, "static uuid file, no authz object", ["idor"])
        assert "static uuid" in e3.hunt_note(kept)["analysis"]
        kept_key = e3._key(kept)
        e3.state["tested"] = {}
        e3.save()
        assert all(e3._key(s) != kept_key for s in e3.worklist()), "a hunt_note is coverage — do not re-queue"
        e.mark_rejected({"url": "http://t/a", "vuln_class": "idor"}, "false positive")
        assert "http://t/a|idor" in e.rejected_keys()
        print("state.py self-test: PASS")
    finally:
        shutil.rmtree(d)


if __name__ == "__main__":
    _selftest()
