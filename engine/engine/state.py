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
        seen = {(s["url"], s.get("param", ""), s.get("vuln_class", "")) for s in self.state["surface"]}
        added = 0
        for it in items:
            key = (it["url"], it.get("param", ""), it.get("vuln_class", ""))
            if key not in seen:
                self.state["surface"].append(it)
                seen.add(key)
                added += 1
        self.save()
        return added

    def _tested_map(self):
        """{key: epoch_ts} from either the current dict form or a legacy list[str] (ts=0 => eligible)."""
        t = self.state.get("tested")
        if isinstance(t, dict):
            return {str(k): _as_epoch(v) for k, v in t.items()}
        if isinstance(t, list):
            return {str(k): 0.0 for k in t}       # legacy: unknown time -> re-hunt once, then TTL applies
        return {}

    def worklist(self):
        """Ranked surface items to hunt. UNTESTED items come FIRST — so coverage advances through the
        WHOLE surface before anything is re-hunted — then stale items (last test older than the re-hunt
        window), oldest-tested first. Without untested-first ordering a deep target re-hunts its
        top-priority slice forever and never reaches the long tail (e.g. paysafe stuck at 181/4606)."""
        tmap = self._tested_map()
        now = time.time()
        ttl = RETEST_HOURS * 3600
        ranked = []                                # (group, -priority, last_tested): sorts untested first
        for s in self.state["surface"]:
            k = self._key(s)
            if k not in tmap:
                ranked.append((0, -s.get("priority", 0), 0.0, s))       # never tested -> cover it first
            elif ttl > 0 and (now - tmap[k]) >= ttl:
                ranked.append((1, -s.get("priority", 0), tmap[k], s))   # stale -> re-hunt, oldest first
            # else: tested within the window -> not eligible this pass
        ranked.sort(key=lambda t: (t[0], t[1], t[2]))
        return [t[3] for t in ranked]

    @staticmethod
    def _key(s):
        return f"{s['url']}|{s.get('param','')}|{s.get('vuln_class','')}"

    def mark_tested(self, item):
        k = self._key(item)
        t = self.state.get("tested")
        if not isinstance(t, dict):                # migrate legacy list -> timestamped dict
            t = {str(x): 0.0 for x in (t or [])}
            self.state["tested"] = t
        t[k] = time.time()                         # record WHEN -> enables the re-hunt window
        self.save()

    # ---- findings ----
    def add_candidate(self, finding):
        finding["ts"] = _now()
        self.state["candidates"].append(finding)
        self.save()

    def confirm(self, finding, verdict):
        finding = {**finding, "verdict": verdict, "confirmed_ts": _now()}
        self.state["confirmed"].append(finding)
        self.save()

    def evidence_path(self, fname):
        return os.path.join(self.dir, "evidence", fname)

    # ---- progress ----
    def summary(self):
        return {"surface": len(self.state["surface"]), "tested": len(self.state["tested"]),
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
        e.state["tested"]["http://t/b|q|xss"] = time.time() - 3600   # tested an hour ago
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
        print("state.py self-test: PASS")
    finally:
        shutil.rmtree(d)


if __name__ == "__main__":
    _selftest()
