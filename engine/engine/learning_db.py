#!/usr/bin/env python3
"""
learning_db.py — SQLite evidence index for scenario learning.

An OPTIONAL parallel index alongside canonical JSONL journals. Adds structured
queries (by program, dimension, profile similarity) that linear JSONL scans
cannot efficiently serve. JSONL remains source of truth; SQLite is written in
parallel and can be rebuilt from JSONL at any time.

  - stdlib sqlite3: WAL mode, foreign keys, 5s busy timeout
  - Schema versioned with reversible migrations
  - Thread-safe via threading.local() per-thread connections
  - Cross-program queries redact credentials/evidence
  - Historical scenarios presented as "evaluate, adapt, or reject" — never commands
"""
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")
_DB_NAME = "learning.db"
_SCHEMA_VERSION = 1
_local = threading.local()


def _db_path(base=DEFAULT_BASE):
    d = os.path.join(os.path.expanduser(base or DEFAULT_BASE), "hunt-memory")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, _DB_NAME)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _conn(base=DEFAULT_BASE):
    key = _db_path(base)
    c = getattr(_local, "conns", None)
    if c is None:
        _local.conns = {}
        c = _local.conns
    if key not in c or c[key] is None:
        conn = sqlite3.connect(key, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        c[key] = conn
    return c[key]


def _close(base=DEFAULT_BASE):
    c = getattr(_local, "conns", None)
    if not c:
        return
    key = _db_path(base)
    conn = c.pop(key, None)
    if conn:
        try:
            conn.close()
        except Exception:
            pass


_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    vuln_class TEXT DEFAULT '',
    result TEXT NOT NULL,
    note TEXT DEFAULT '',
    trust_dimension TEXT DEFAULT '',
    profile_id TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    context TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hunt_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT DEFAULT '',
    failure_type TEXT NOT NULL,
    error TEXT DEFAULT '',
    tech_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT DEFAULT '',
    trust_dimension TEXT DEFAULT '',
    hypothesis TEXT NOT NULL,
    controls TEXT DEFAULT '',
    outcome TEXT NOT NULL,
    reproduction_status TEXT DEFAULT 'unreproduced',
    confidence REAL DEFAULT 0.0,
    profile_id TEXT DEFAULT '',
    evidence_json TEXT DEFAULT '{}',
    context_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    freshness_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dimension_outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT DEFAULT '',
    trust_dimension TEXT NOT NULL,
    outcome TEXT NOT NULL,
    profile_id TEXT DEFAULT '',
    hypothesis_text TEXT DEFAULT '',
    evidence_json TEXT DEFAULT '{}',
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT DEFAULT '',
    data_json TEXT DEFAULT '{}',
    provenance TEXT DEFAULT 'observed',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outcomes_program ON outcomes(program);
CREATE INDEX IF NOT EXISTS idx_outcomes_dimension ON outcomes(trust_dimension);
CREATE INDEX IF NOT EXISTS idx_gaps_kind ON gaps(kind);
CREATE INDEX IF NOT EXISTS idx_scenarios_program ON scenarios(program);
CREATE INDEX IF NOT EXISTS idx_scenarios_dimension ON scenarios(trust_dimension);
CREATE INDEX IF NOT EXISTS idx_dim_outcomes_program ON dimension_outcomes(program);
CREATE INDEX IF NOT EXISTS idx_dim_outcomes_dimension ON dimension_outcomes(trust_dimension);
CREATE INDEX IF NOT EXISTS idx_knowledge_program ON knowledge_items(program);
"""


def init_db(base=DEFAULT_BASE):
    conn = _conn(base)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
    if cur.fetchone() is None:
        conn.executescript(_SCHEMA_V1)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (_SCHEMA_VERSION,))
        conn.commit()
        return _SCHEMA_VERSION
    row = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
    current = row["version"] if row else 0
    if current < _SCHEMA_VERSION:
        _migrate(conn, current)
    return current


def _migrate(conn, from_version):
    """Apply migrations from from_version to _SCHEMA_VERSION. Extend as needed."""
    if from_version < 1:
        conn.executescript(_SCHEMA_V1)
        conn.execute("DELETE FROM schema_version")
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (_SCHEMA_VERSION,))
        conn.commit()


# ---------------------------------------------------------------- writers (dual-write targets)

def write_outcome(program, vuln_class="", result="", note="",
                  trust_dimension="", profile_id="", base=DEFAULT_BASE):
    try:
        init_db(base)
        conn = _conn(base)
        conn.execute(
            "INSERT INTO outcomes (program, vuln_class, result, note, trust_dimension, profile_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_slug(program), str(vuln_class or "")[:40], str(result or "")[:40],
             str(note or "")[:500], str(trust_dimension or "")[:80],
             str(profile_id or "")[:80], _now()))
        conn.commit()
        return True
    except Exception:
        return False


def write_gap(kind, name, context="", base=DEFAULT_BASE):
    try:
        init_db(base)
        conn = _conn(base)
        conn.execute(
            "INSERT INTO gaps (kind, name, context, created_at) VALUES (?, ?, ?, ?)",
            (str(kind or "")[:40], str(name or "")[:120], str(context or "")[:500], _now()))
        conn.commit()
        return True
    except Exception:
        return False


def write_hunt_failure(program, url="", failure_type="", error="", tech=None, base=DEFAULT_BASE):
    try:
        init_db(base)
        conn = _conn(base)
        conn.execute(
            "INSERT INTO hunt_failures (program, url, failure_type, error, tech_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_slug(program), str(url or "")[:300], str(failure_type or "")[:40],
             str(error or "")[:300], json.dumps(tech or []), _now()))
        conn.commit()
        return True
    except Exception:
        return False


def write_scenario(program, url="", trust_dimension="", hypothesis="",
                   controls="", outcome="", reproduction_status="unreproduced",
                   confidence=0.0, profile_id="", evidence=None, context=None,
                   base=DEFAULT_BASE):
    try:
        init_db(base)
        conn = _conn(base)
        now = _now()
        conn.execute(
            "INSERT INTO scenarios "
            "(program, url, trust_dimension, hypothesis, controls, outcome, "
            " reproduction_status, confidence, profile_id, evidence_json, context_json, "
            " created_at, freshness_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (_slug(program), str(url or "")[:300], str(trust_dimension or "")[:80],
             str(hypothesis or "")[:500], str(controls or "")[:500],
             str(outcome or "")[:40], str(reproduction_status or "")[:40],
             float(confidence or 0.0), str(profile_id or "")[:80],
             json.dumps(_redact(evidence or {})), json.dumps(context or {}),
             now, now))
        conn.commit()
        return True
    except Exception:
        return False


def write_dimension_outcome(program, url="", trust_dimension="", outcome="",
                            profile_id="", hypothesis_text="", evidence=None,
                            note="", base=DEFAULT_BASE):
    try:
        init_db(base)
        conn = _conn(base)
        conn.execute(
            "INSERT INTO dimension_outcomes "
            "(program, url, trust_dimension, outcome, profile_id, hypothesis_text, "
            " evidence_json, note, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (_slug(program), str(url or "")[:300], str(trust_dimension or "")[:80],
             str(outcome or "")[:40], str(profile_id or "")[:80],
             str(hypothesis_text or "")[:500], json.dumps(_redact(evidence or {})),
             str(note or "")[:500], _now()))
        conn.commit()
        return True
    except Exception:
        return False


def write_knowledge(program, kind, name="", data=None, provenance="observed", base=DEFAULT_BASE):
    try:
        init_db(base)
        conn = _conn(base)
        conn.execute(
            "INSERT INTO knowledge_items (program, kind, name, data_json, provenance, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_slug(program), str(kind or "")[:40], str(name or "")[:120],
             json.dumps(data or {}), str(provenance or "observed")[:20], _now()))
        conn.commit()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- readers

def query_scenarios(program, url=None, trust_dimension=None,
                    limit=10, cross_program=False, base=DEFAULT_BASE):
    """Retrieve relevant scenarios: current URL → same program → cross-program.

    Cross-program results are redacted (no credentials/evidence details).
    Results are suggestions with provenance, never commands.
    """
    try:
        init_db(base)
        conn = _conn(base)
        results = []
        slug = _slug(program)

        if url:
            rows = conn.execute(
                "SELECT * FROM scenarios WHERE program = ? AND url = ? "
                "ORDER BY freshness_at DESC LIMIT ?",
                (slug, str(url)[:300], limit)).fetchall()
            results.extend(_row_to_dict(r) for r in rows)

        if len(results) < limit:
            remain = limit - len(results)
            seen_ids = {r["id"] for r in results}
            params = [slug]
            where = "program = ?"
            if trust_dimension:
                where += " AND trust_dimension = ?"
                params.append(str(trust_dimension)[:80])
            params.append(remain)
            rows = conn.execute(
                f"SELECT * FROM scenarios WHERE {where} "
                f"ORDER BY freshness_at DESC LIMIT ?", params).fetchall()
            for r in rows:
                d = _row_to_dict(r)
                if d["id"] not in seen_ids:
                    results.append(d)

        if cross_program and len(results) < limit:
            remain = limit - len(results)
            seen_ids = {r["id"] for r in results}
            params = [slug]
            where = "program != ?"
            if trust_dimension:
                where += " AND trust_dimension = ?"
                params.append(str(trust_dimension)[:80])
            params.append(remain)
            rows = conn.execute(
                f"SELECT * FROM scenarios WHERE {where} "
                f"ORDER BY confidence DESC, freshness_at DESC LIMIT ?", params).fetchall()
            for r in rows:
                d = _row_to_dict(r)
                if d["id"] not in seen_ids:
                    d = _redact_cross_program(d)
                    d["_cross_program"] = True
                    results.append(d)

        return results
    except Exception:
        return []


def query_dimension_outcomes(program=None, trust_dimension=None,
                             limit=50, base=DEFAULT_BASE):
    """Query dimension outcomes for yieldrank or coverage analysis."""
    try:
        init_db(base)
        conn = _conn(base)
        conditions, params = [], []
        if program:
            conditions.append("program = ?")
            params.append(_slug(program))
        if trust_dimension:
            conditions.append("trust_dimension = ?")
            params.append(str(trust_dimension)[:80])
        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM dimension_outcomes WHERE {where} "
            f"ORDER BY created_at DESC LIMIT ?", params).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def query_outcomes(program=None, trust_dimension=None, result=None,
                   limit=100, base=DEFAULT_BASE):
    """Query outcome records (mirrors yieldrank journal reads)."""
    try:
        init_db(base)
        conn = _conn(base)
        conditions, params = [], []
        if program:
            conditions.append("program = ?")
            params.append(_slug(program))
        if trust_dimension:
            conditions.append("trust_dimension = ?")
            params.append(str(trust_dimension)[:80])
        if result:
            conditions.append("result = ?")
            params.append(str(result)[:40])
        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM outcomes WHERE {where} ORDER BY created_at DESC LIMIT ?",
            params).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def query_gaps(kind=None, limit=50, base=DEFAULT_BASE):
    """Query recorded gaps."""
    try:
        init_db(base)
        conn = _conn(base)
        if kind:
            rows = conn.execute(
                "SELECT * FROM gaps WHERE kind = ? ORDER BY created_at DESC LIMIT ?",
                (str(kind)[:40], limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM gaps ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def query_knowledge(program, kind=None, limit=20, base=DEFAULT_BASE):
    """Retrieve knowledge items for a program."""
    try:
        init_db(base)
        conn = _conn(base)
        conditions = ["program = ?"]
        params = [_slug(program)]
        if kind:
            conditions.append("kind = ?")
            params.append(str(kind)[:40])
        where = " AND ".join(conditions)
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM knowledge_items WHERE {where} ORDER BY created_at DESC LIMIT ?",
            params).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def outcome_stats(program=None, base=DEFAULT_BASE):
    """Aggregate outcome stats by dimension (for yieldrank integration)."""
    try:
        init_db(base)
        conn = _conn(base)
        params = []
        where = "1=1"
        if program:
            where = "program = ?"
            params.append(_slug(program))
        rows = conn.execute(
            f"SELECT trust_dimension, result, COUNT(*) as cnt "
            f"FROM outcomes WHERE {where} AND trust_dimension != '' "
            f"GROUP BY trust_dimension, result", params).fetchall()
        stats = {}
        for r in rows:
            dim = r["trust_dimension"]
            res = r["result"]
            s = stats.setdefault(dim, {"confirmed": 0, "dup": 0, "reported": 0, "bad": 0})
            if res == "confirmed":
                s["confirmed"] += r["cnt"]
            elif res.startswith("dup"):
                s["dup"] += r["cnt"]
            elif res in ("reported",):
                s["reported"] += r["cnt"]
            elif res in ("invalid", "false-positive", "na", "informative"):
                s["bad"] += r["cnt"]
        return stats
    except Exception:
        return {}


# ---------------------------------------------------------------- consistency

def consistency_check(base=DEFAULT_BASE):
    """Compare SQLite counts against JSONL for dual-write verification."""
    import re as _re
    mem_dir = os.path.join(os.path.expanduser(base or DEFAULT_BASE), "hunt-memory")
    report = {"ok": True, "details": {}}

    def _count_jsonl(path, type_filter=None):
        n = 0
        try:
            for line in open(path, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if type_filter is None or rec.get("type") == type_filter:
                    n += 1
        except OSError:
            pass
        return n

    try:
        init_db(base)
        conn = _conn(base)

        journal_path = os.path.join(mem_dir, "learning.jsonl")
        yr_path = os.path.join(mem_dir, "journal.jsonl")

        jsonl_outcomes = _count_jsonl(journal_path, "outcome")
        jsonl_gaps = _count_jsonl(journal_path, "gap")
        jsonl_failures = _count_jsonl(journal_path, "hunt_failure")

        sql_outcomes = conn.execute("SELECT COUNT(*) as c FROM outcomes").fetchone()["c"]
        sql_gaps = conn.execute("SELECT COUNT(*) as c FROM gaps").fetchone()["c"]
        sql_failures = conn.execute("SELECT COUNT(*) as c FROM hunt_failures").fetchone()["c"]

        report["details"] = {
            "outcomes": {"jsonl": jsonl_outcomes, "sqlite": sql_outcomes, "match": jsonl_outcomes == sql_outcomes},
            "gaps": {"jsonl": jsonl_gaps, "sqlite": sql_gaps, "match": jsonl_gaps == sql_gaps},
            "hunt_failures": {"jsonl": jsonl_failures, "sqlite": sql_failures, "match": jsonl_failures == sql_failures},
        }
        report["ok"] = all(d["match"] for d in report["details"].values())
    except Exception as e:
        report["ok"] = False
        report["error"] = str(e)
    return report


def rebuild_from_jsonl(base=DEFAULT_BASE):
    """Rebuild SQLite tables from canonical JSONL journals. Idempotent."""
    try:
        init_db(base)
        conn = _conn(base)
        conn.execute("DELETE FROM outcomes")
        conn.execute("DELETE FROM gaps")
        conn.execute("DELETE FROM hunt_failures")
        conn.commit()

        mem_dir = os.path.join(os.path.expanduser(base or DEFAULT_BASE), "hunt-memory")
        journal_path = os.path.join(mem_dir, "learning.jsonl")
        yr_path = os.path.join(mem_dir, "journal.jsonl")

        count = {"outcomes": 0, "gaps": 0, "hunt_failures": 0}
        try:
            for line in open(journal_path, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rtype = rec.get("type", "")
                ts = rec.get("ts", _now())
                if rtype == "outcome":
                    conn.execute(
                        "INSERT INTO outcomes (program, vuln_class, result, note, "
                        "trust_dimension, profile_id, created_at) VALUES (?,?,?,?,?,?,?)",
                        (rec.get("program", ""), rec.get("vuln_class", ""),
                         rec.get("result", ""), rec.get("note", ""),
                         rec.get("trust_dimension", ""), rec.get("profile_id", ""), ts))
                    count["outcomes"] += 1
                elif rtype == "gap":
                    conn.execute(
                        "INSERT INTO gaps (kind, name, context, created_at) VALUES (?,?,?,?)",
                        (rec.get("kind", ""), rec.get("name", ""), rec.get("context", ""), ts))
                    count["gaps"] += 1
                elif rtype == "hunt_failure":
                    conn.execute(
                        "INSERT INTO hunt_failures (program, url, failure_type, error, tech_json, created_at) "
                        "VALUES (?,?,?,?,?,?)",
                        (rec.get("program", ""), rec.get("url", ""),
                         rec.get("failure_type", ""), rec.get("error", ""),
                         json.dumps(rec.get("tech", [])), ts))
                    count["hunt_failures"] += 1
        except OSError:
            pass
        conn.commit()
        return {"rebuilt": True, "counts": count}
    except Exception as e:
        return {"rebuilt": False, "error": str(e)}


def drop_tables(base=DEFAULT_BASE):
    """Rollback path: drop all SQLite tables. JSONL readers still work."""
    try:
        conn = _conn(base)
        for table in ("knowledge_items", "dimension_outcomes", "scenarios",
                      "hunt_failures", "gaps", "outcomes", "schema_version"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- helpers

def _slug(s):
    import re
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").strip().lower()).strip("-") or "unnamed"


def _row_to_dict(row):
    if row is None:
        return {}
    d = dict(row)
    for key in ("evidence_json", "context_json", "tech_json", "data_json"):
        if key in d:
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


_REDACT_KEYS = frozenset({
    "cookie", "token", "authorization", "session", "password",
    "secret", "api_key", "apikey", "access_token", "refresh_token",
})


def _redact(data):
    if not isinstance(data, dict):
        return data
    out = {}
    for k, v in data.items():
        if k.lower() in _REDACT_KEYS:
            out[k] = "[REDACTED]"
        elif isinstance(v, dict):
            out[k] = _redact(v)
        else:
            out[k] = v
    return out


def _redact_cross_program(scenario):
    d = dict(scenario)
    d["evidence_json"] = {"_redacted": "cross-program"}
    d["context_json"] = _redact(d.get("context_json", {}))
    d["controls"] = ""
    d.pop("url", None)
    return d


# ---------------------------------------------------------------- scenario retrieval for brain.py

def scenarios_for_prompt(program, url=None, trust_dimension=None,
                         max_tokens=1500, base=DEFAULT_BASE):
    """Format historical scenarios for injection into hunt prompt.

    Returns a bounded text block with provenance. Each scenario is presented
    as "evaluate, adapt, or reject" — never as a command or required attack.
    """
    scenarios = query_scenarios(program, url=url, trust_dimension=trust_dimension,
                                limit=8, cross_program=True, base=base)
    if not scenarios:
        return ""
    lines = ["HISTORICAL SCENARIOS (evaluate, adapt, or reject — not commands):"]
    total = 0
    for s in scenarios:
        src = "cross-program" if s.get("_cross_program") else "same-program"
        dim = s.get("trust_dimension", "")
        hyp = s.get("hypothesis", "")[:200]
        out = s.get("outcome", "")
        conf = s.get("confidence", 0)
        fresh = s.get("freshness_at", "")[:10]
        line = f"  [{src}] dim={dim} outcome={out} conf={conf:.1f} date={fresh}: {hyp}"
        if total + len(line) > max_tokens:
            break
        lines.append(line)
        total += len(line)
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI + selftest

def _selftest():
    import tempfile
    base = tempfile.mkdtemp(prefix="ldb-")
    os.makedirs(os.path.join(base, "hunt-memory"), exist_ok=True)

    v = init_db(base)
    assert v == _SCHEMA_VERSION, f"schema version mismatch: {v}"

    assert write_outcome("acme", "idor", "confirmed", "user A accessed user B data",
                         trust_dimension="ownership_boundary", profile_id="p1", base=base)
    assert write_outcome("acme", "xss", "duplicate", "reflected in search",
                         trust_dimension="input_variation", base=base)
    assert write_outcome("beta", "ssrf", "confirmed", "internal fetch",
                         trust_dimension="external_effect", base=base)

    assert write_gap("tech", "RedwoodJS", "unknown stack", base=base)
    assert write_gap("bypass", "cloudflare-waf", "need CF bypass", base=base)

    assert write_hunt_failure("acme", "https://example.com/api", "timeout",
                              error="double-timeout", tech=["nextjs"], base=base)

    assert write_scenario("acme", url="https://example.com/api/users",
                          trust_dimension="ownership_boundary",
                          hypothesis="swap user_id parameter to access other user data",
                          controls="baseline with own user_id, test with other user_id",
                          outcome="confirmed", reproduction_status="reproduced",
                          confidence=0.9, profile_id="p1",
                          evidence={"request": "GET /api/users/2", "token": "secret123"},
                          base=base)

    assert write_scenario("beta", url="https://beta.example.com/api/files",
                          trust_dimension="external_effect",
                          hypothesis="SSRF via file_url parameter",
                          outcome="confirmed", confidence=0.8, base=base)

    assert write_dimension_outcome("acme", url="https://example.com/api/users",
                                   trust_dimension="ownership_boundary",
                                   outcome="confirmed", profile_id="p1",
                                   hypothesis_text="swap user_id", base=base)

    assert write_knowledge("acme", "observed", "auth_flow",
                           data={"type": "bearer_token", "header": "Authorization"},
                           base=base)

    # query outcomes
    outcomes = query_outcomes(program="acme", base=base)
    assert len(outcomes) == 2, f"expected 2 outcomes, got {len(outcomes)}"
    outcomes_dim = query_outcomes(trust_dimension="ownership_boundary", base=base)
    assert len(outcomes_dim) >= 1

    # query gaps
    all_gaps = query_gaps(base=base)
    assert len(all_gaps) == 2
    tech_gaps = query_gaps(kind="tech", base=base)
    assert len(tech_gaps) == 1

    # query scenarios — same program
    scenarios = query_scenarios("acme", base=base)
    assert len(scenarios) == 1
    assert scenarios[0]["hypothesis"].startswith("swap user_id")
    assert scenarios[0].get("evidence_json", {}).get("token") == "[REDACTED]"

    # query scenarios — cross program
    cross = query_scenarios("acme", trust_dimension="external_effect",
                            cross_program=True, base=base)
    cross_prog = [s for s in cross if s.get("_cross_program")]
    assert len(cross_prog) >= 1
    assert cross_prog[0]["evidence_json"] == {"_redacted": "cross-program"}

    # query dimension outcomes
    dim_out = query_dimension_outcomes(program="acme", base=base)
    assert len(dim_out) == 1

    # outcome stats
    stats = outcome_stats(program="acme", base=base)
    assert stats["ownership_boundary"]["confirmed"] == 1
    assert stats["input_variation"]["dup"] == 1

    # knowledge
    knowledge = query_knowledge("acme", base=base)
    assert len(knowledge) == 1

    # scenarios for prompt
    prompt = scenarios_for_prompt("acme", base=base)
    assert "evaluate, adapt, or reject" in prompt
    assert "ownership_boundary" in prompt

    # consistency check (SQLite written, no JSONL yet — counts won't match)
    check = consistency_check(base)
    assert not check["ok"]

    # rebuild from JSONL
    journal_path = os.path.join(base, "hunt-memory", "learning.jsonl")
    with open(journal_path, "w") as fh:
        fh.write(json.dumps({"type": "outcome", "ts": _now(), "program": "rebuild-test",
                              "vuln_class": "xss", "result": "confirmed", "note": "test"}) + "\n")
        fh.write(json.dumps({"type": "gap", "ts": _now(), "kind": "tech",
                              "name": "test-stack", "context": "ctx"}) + "\n")
    rebuild = rebuild_from_jsonl(base)
    assert rebuild["rebuilt"]
    assert rebuild["counts"]["outcomes"] == 1
    assert rebuild["counts"]["gaps"] == 1

    # concurrent writes (thread safety)
    errors = []
    def _writer(n):
        try:
            for i in range(10):
                write_outcome(f"thread-{n}", "test", "confirmed",
                              f"note-{i}", base=base)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=_writer, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"concurrent write errors: {errors}"
    thread_outcomes = query_outcomes(base=base)
    thread_count = sum(1 for o in thread_outcomes if o["program"].startswith("thread-"))
    assert thread_count == 40, f"expected 40 thread outcomes, got {thread_count}"

    # drop and rollback
    assert drop_tables(base)
    _close(base)

    # hostile input
    for bad in (None, "", 123, {"x": 1}, [1, 2]):
        write_outcome(bad, bad, bad, bad, base=base)
        write_gap(bad, bad, bad, base=base)
        query_scenarios(bad, base=base)
        query_outcomes(base=base)

    _close(base)
    print("learning_db.py self-test: PASS")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="SQLite learning index")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=lambda _: print(f"schema v{init_db()}"))
    sub.add_parser("check").set_defaults(fn=lambda _: print(json.dumps(consistency_check(), indent=2)))
    sub.add_parser("rebuild").set_defaults(fn=lambda _: print(json.dumps(rebuild_from_jsonl(), indent=2)))
    sub.add_parser("stats").set_defaults(fn=lambda _: print(json.dumps(outcome_stats(), indent=2)))
    sub.add_parser("selftest").set_defaults(fn=lambda _: _selftest())
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
