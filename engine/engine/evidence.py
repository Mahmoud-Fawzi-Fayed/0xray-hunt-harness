#!/usr/bin/env python3
"""
evidence.py — append-only HTTP observation and test-attempt evidence pipeline.

Transport-recorded proof of execution. Agent analysis is commentary linked to
observations, never proof. Only a real HttpObservation with matching case_id,
method, identity, and target may close a test case.

Storage (per-engagement, append-only JSONL):
  <engagement_dir>/evidence/observations.jsonl
  <engagement_dir>/evidence/attempts.jsonl

CLI:
  python3 evidence.py selftest
  python3 evidence.py show --slug <program> [--case <case_id>]
"""
import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import uuid

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# --- Attempt outcome statuses ---
PENDING = "PENDING"
TESTED = "TESTED"
DISPROVED = "DISPROVED"
CONFIRMED = "CONFIRMED"
INCONCLUSIVE = "INCONCLUSIVE"
BLOCKED = "BLOCKED"
ATTEMPT_STATUSES = {PENDING, TESTED, DISPROVED, CONFIRMED, INCONCLUSIVE, BLOCKED}

# --- Finding confidence levels ---
CONFIDENCE_CANDIDATE = "candidate"
CONFIDENCE_VALIDATED = "validated_by_rule"
CONFIDENCE_REPRODUCED = "independently_reproduced"
CONFIDENCE_READY = "report_ready"
CONFIDENCE_LEVELS = {
    CONFIDENCE_CANDIDATE, CONFIDENCE_VALIDATED,
    CONFIDENCE_REPRODUCED, CONFIDENCE_READY,
}

# --- Finding lifecycle states ---
FINDING_STATES = {
    "findings_candidate", "verified_by_rule", "independently_reproduced",
    "reported", "duplicate", "false_positive", "accepted", "rejected",
}

# Headers whose values are redacted in stored observations
_SENSITIVE_HEADERS = re.compile(
    r"^(authorization|cookie|set-cookie|x-[a-z]+-token|x-api-key|"
    r"x-[a-z]+-secret|proxy-authorization)$", re.I)

SCHEMA_VERSION = 2


def _gen_id():
    return uuid.uuid4().hex[:16]


def _now():
    return time.time()


def _hash_body(body):
    """SHA-256 of first 64KB of body bytes. Returns hex digest or None."""
    if body is None:
        return None
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    return hashlib.sha256(body[:65536]).hexdigest()


def _redact_excerpt(body, limit=16384):
    if body is None:
        return ""
    text = body if isinstance(body, str) else str(body)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1REDACTED", text)
    text = re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key|client[_-]?secret)(\"\s*:\s*\"|'\s*:\s*'|\s*=\s*)[^\"'\s&}]+",
                  r"\1\2REDACTED", text)
    text = re.sub(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}", "REDACTED_JWT", text)
    return text[:limit]


def _redact_headers(headers):
    """Return a copy with sensitive header values replaced by hash prefix."""
    if not headers:
        return {}
    out = {}
    for k, v in (headers if isinstance(headers, dict) else {}).items():
        if _SENSITIVE_HEADERS.match(k):
            h = hashlib.sha256(str(v).encode()).hexdigest()[:12]
            out[k] = f"REDACTED:{h}"
        else:
            out[k] = v
    return out


def _evidence_dir(engagement_dir):
    d = os.path.join(engagement_dir, "evidence")
    os.makedirs(d, exist_ok=True)
    return d


_WRITE_LOCK = threading.Lock()


def _append_jsonl(path, record):
    line = json.dumps(record, default=str) + "\n"
    with _WRITE_LOCK:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except ImportError:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)


def _read_jsonl(path):
    if not os.path.isfile(path):
        return []
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


# ---------------------------------------------------------------------------
# HttpObservation — transport-recorded request/response pair
# ---------------------------------------------------------------------------

def record_observation(engagement_dir, method, url, req_headers=None,
                       req_body=None, resp_status=0, resp_headers=None,
                       resp_body=None, identity=None, case_id=None,
                       policy_id=None, owner=None, accessor=None,
                       trace_id=None, egress_decision="allowed"):
    """Append one HttpObservation. Returns the observation ID."""
    obs_id = _gen_id()
    t_start = _now()
    obs = {
        "schema_version": SCHEMA_VERSION,
        "type": "HttpObservation",
        "id": obs_id,
        "trace_id": trace_id or _gen_id(),
        "timestamp_start": t_start,
        "timestamp_end": t_start,
        "method": (method or "GET").upper(),
        "url": url or "",
        "req_headers": _redact_headers(req_headers),
        "req_body_hash": _hash_body(req_body),
        "req_body_length": len(req_body) if req_body else 0,
        "req_body_excerpt": _redact_excerpt(req_body),
        "resp_status": resp_status,
        "resp_headers": _redact_headers(resp_headers),
        "resp_body_hash": _hash_body(resp_body),
        "resp_body_length": len(resp_body) if resp_body else 0,
        "resp_body_excerpt": _redact_excerpt(resp_body),
        "identity": identity,
        "owner": owner,
        "accessor": accessor,
        "case_id": case_id,
        "policy_id": policy_id,
        "egress_decision": egress_decision,
    }
    edir = _evidence_dir(engagement_dir)
    _append_jsonl(os.path.join(edir, "observations.jsonl"), obs)
    return obs_id


# ---------------------------------------------------------------------------
# TestAttempt — links observations to a test case with an outcome
# ---------------------------------------------------------------------------

def record_attempt(engagement_dir, case_id, observation_ids,
                   outcome=PENDING, agent_commentary="",
                   method=None, url=None, identity=None,
                   owner=None, accessor=None, confidence=None):
    """Append one TestAttempt. Returns the attempt ID."""
    if outcome not in ATTEMPT_STATUSES:
        raise ValueError(f"invalid outcome: {outcome!r}, must be one of {ATTEMPT_STATUSES}")
    if confidence and confidence not in CONFIDENCE_LEVELS:
        raise ValueError(f"invalid confidence: {confidence!r}")
    attempt_id = _gen_id()
    rec = {
        "schema_version": SCHEMA_VERSION,
        "type": "TestAttempt",
        "id": attempt_id,
        "case_id": case_id,
        "observation_ids": observation_ids or [],
        "outcome": outcome,
        "agent_commentary": agent_commentary,
        "method": method,
        "url": url,
        "identity": identity,
        "owner": owner,
        "accessor": accessor,
        "confidence": confidence,
        "timestamp": _now(),
    }
    edir = _evidence_dir(engagement_dir)
    _append_jsonl(os.path.join(edir, "attempts.jsonl"), rec)
    return attempt_id


# ---------------------------------------------------------------------------
# Query and validation
# ---------------------------------------------------------------------------

def get_observations(engagement_dir, case_id=None, identity=None):
    """Return observations, optionally filtered by case_id and/or identity."""
    edir = _evidence_dir(engagement_dir)
    obs = _read_jsonl(os.path.join(edir, "observations.jsonl"))
    if case_id is not None:
        obs = [o for o in obs if o.get("case_id") == case_id]
    if identity is not None:
        obs = [o for o in obs if o.get("identity") == identity]
    return obs


def get_attempts(engagement_dir, case_id=None):
    """Return attempts, optionally filtered by case_id."""
    edir = _evidence_dir(engagement_dir)
    att = _read_jsonl(os.path.join(edir, "attempts.jsonl"))
    if case_id is not None:
        att = [a for a in att if a.get("case_id") == case_id]
    return att


def validate_evidence(engagement_dir, case_id, method=None, identity=None,
                      url=None):
    """Check if a case has real transport observations (not just agent text).

    Returns (is_valid: bool, reason: str).
    A case is valid when at least one HttpObservation exists with matching
    case_id and a non-zero resp_status (real HTTP response received).
    """
    obs_list = get_observations(engagement_dir, case_id=case_id)
    if not obs_list:
        return False, "no transport observations for this case"
    real = [o for o in obs_list if o.get("resp_status", 0) != 0]
    if not real:
        return False, "all observations have status 0 (transport errors only)"
    if method:
        match = [o for o in real if o.get("method") == method.upper()]
        if not match:
            return False, f"no observation with method {method}"
        real = match
    if identity:
        match = [o for o in real if o.get("identity") == identity]
        if not match:
            return False, f"no observation with identity {identity}"
        real = match
    if url:
        match = [o for o in real if o.get("url") == url]
        if not match:
            return False, f"no observation matching URL {url}"
    return True, f"{len(real)} valid observation(s)"


def coverage_from_evidence(engagement_dir):
    """Derive tested coverage strictly from transport observations.

    Returns dict {case_id: {method, url, identity, observation_count, outcome}}.
    Only cases with at least one real HTTP observation count as tested.
    """
    obs_all = get_observations(engagement_dir)
    att_all = get_attempts(engagement_dir)

    # Group observations by case_id
    obs_by_case = {}
    for o in obs_all:
        cid = o.get("case_id")
        if cid:
            obs_by_case.setdefault(cid, []).append(o)

    # Best attempt outcome per case
    att_by_case = {}
    for a in att_all:
        cid = a.get("case_id")
        if cid:
            att_by_case.setdefault(cid, []).append(a)

    result = {}
    for cid, observations in obs_by_case.items():
        real = [o for o in observations if o.get("resp_status", 0) != 0]
        if not real:
            continue
        attempts = att_by_case.get(cid, [])
        best_outcome = PENDING
        for a in attempts:
            ao = a.get("outcome", PENDING)
            if ao in (CONFIRMED, TESTED, DISPROVED):
                best_outcome = ao
                break
            if ao not in (PENDING, BLOCKED):
                best_outcome = ao
        first = real[0]
        result[cid] = {
            "method": first.get("method"),
            "url": first.get("url"),
            "identity": first.get("identity"),
            "observation_count": len(real),
            "outcome": best_outcome,
        }
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _show(slug, case_id=None, base=None):
    base = os.path.expanduser(base or DEFAULT_BASE)
    edir = os.path.join(base, slug)
    if not os.path.isdir(edir):
        print(f"no engagement directory: {edir}", file=sys.stderr)
        return 1
    obs = get_observations(edir, case_id=case_id)
    att = get_attempts(edir, case_id=case_id)
    cov = coverage_from_evidence(edir)
    print(f"Observations: {len(obs)}")
    print(f"Attempts:     {len(att)}")
    print(f"Tested cases: {len(cov)}")
    if case_id:
        valid, reason = validate_evidence(edir, case_id)
        print(f"Case {case_id}: valid={valid}, {reason}")
    for cid, info in sorted(cov.items()):
        print(f"  {cid}: {info['method']} {info['url']} "
              f"[{info['outcome']}] ({info['observation_count']} obs)")
    return 0


def _main():
    ap = argparse.ArgumentParser(description="evidence pipeline")
    sub = ap.add_subparsers(dest="cmd")
    st = sub.add_parser("selftest")
    sh = sub.add_parser("show")
    sh.add_argument("--slug", required=True)
    sh.add_argument("--case")
    sh.add_argument("--base")
    args = ap.parse_args()
    if args.cmd == "selftest":
        return _selftest()
    if args.cmd == "show":
        return _show(args.slug, case_id=args.case, base=args.base)
    ap.print_help()
    return 1


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest():
    import tempfile

    base = tempfile.mkdtemp()
    edir = os.path.join(base, "test-engagement")
    os.makedirs(edir)

    # 1. Record a real observation
    oid1 = record_observation(
        edir, "GET", "https://api.example.com/users/1",
        req_headers={"Authorization": "Bearer secret123", "Accept": "application/json"},
        resp_status=200, resp_body='{"id":1,"name":"Alice"}',
        identity="A", case_id="case-001", policy_id="pol-abc",
        owner="A", accessor="B")
    assert oid1 and len(oid1) == 16, f"bad obs id: {oid1}"

    # 2. Verify sensitive headers are redacted
    obs = get_observations(edir, case_id="case-001")
    assert len(obs) == 1
    auth_val = obs[0]["req_headers"].get("Authorization", "")
    assert auth_val.startswith("REDACTED:"), f"auth not redacted: {auth_val}"
    accept_val = obs[0]["req_headers"].get("Accept", "")
    assert accept_val == "application/json", f"non-sensitive header mangled: {accept_val}"

    # 3. Body hashing works
    assert obs[0]["resp_body_hash"] is not None
    assert obs[0]["resp_body_length"] == len('{"id":1,"name":"Alice"}')

    # 4. Record second observation for same case with identity B
    oid2 = record_observation(
        edir, "GET", "https://api.example.com/users/1",
        resp_status=404, resp_body='{"error":"not found"}',
        identity="B", case_id="case-001", policy_id="pol-abc")
    assert oid2 != oid1

    # 5. Record a transport error (status 0 — should not count as tested)
    oid3 = record_observation(
        edir, "GET", "https://api.example.com/users/1",
        resp_status=0, identity="A", case_id="case-002")

    # 6. Record a test attempt with real observations
    aid1 = record_attempt(
        edir, "case-001", [oid1, oid2],
        outcome=CONFIRMED,
        agent_commentary="User A data returned to B → IDOR",
        method="GET", url="https://api.example.com/users/1",
        identity="B", owner="A", accessor="B",
        confidence=CONFIDENCE_REPRODUCED)
    assert aid1 and len(aid1) == 16

    # 7. Record attempt for transport-error case (should stay INCONCLUSIVE)
    aid2 = record_attempt(
        edir, "case-002", [oid3],
        outcome=INCONCLUSIVE,
        agent_commentary="transport error, no response")

    # 8. Validate evidence — case-001 should be valid, case-002 should not
    v1, r1 = validate_evidence(edir, "case-001")
    assert v1, f"case-001 should be valid: {r1}"
    v2, r2 = validate_evidence(edir, "case-002")
    assert not v2, f"case-002 should be invalid: {r2}"

    # 9. Validate with method filter
    v3, _ = validate_evidence(edir, "case-001", method="GET")
    assert v3
    v4, r4 = validate_evidence(edir, "case-001", method="POST")
    assert not v4, f"no POST observations should exist: {r4}"

    # 10. Validate with identity filter
    v5, _ = validate_evidence(edir, "case-001", identity="A")
    assert v5
    v6, _ = validate_evidence(edir, "case-001", identity="C")
    assert not v6

    # 11. Coverage from evidence — only case-001 has real observations
    cov = coverage_from_evidence(edir)
    assert "case-001" in cov, f"case-001 missing from coverage: {cov}"
    assert "case-002" not in cov, f"case-002 should not be in coverage (status 0)"
    assert cov["case-001"]["outcome"] == CONFIRMED

    # 12. Fake LLM payload must not count — no observation, just attempt
    aid3 = record_attempt(
        edir, "case-fake", [],
        outcome=TESTED,
        agent_commentary='{"request":"GET /x","vulnerable":true}')
    cov2 = coverage_from_evidence(edir)
    assert "case-fake" not in cov2, "fake LLM evidence must not count as tested"

    # 13. Non-existent case validates as invalid
    v7, r7 = validate_evidence(edir, "nonexistent")
    assert not v7

    # 14. Invalid outcome raises
    try:
        record_attempt(edir, "x", [], outcome="BOGUS")
        assert False, "should have raised"
    except ValueError:
        pass

    # Cleanup
    import shutil
    shutil.rmtree(base, ignore_errors=True)

    print("evidence.py self-test: PASS")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(_selftest())
    sys.exit(_main())
