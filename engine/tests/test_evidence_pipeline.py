#!/usr/bin/env python3
"""
test_evidence_pipeline.py — evidence module integration tests.

Proves that transport-recorded evidence is the only accepted proof,
agent-generated text is commentary not proof, and coverage is derived
strictly from real observations.

Run:
  python3 engine/tests/test_evidence_pipeline.py
"""
import json
import os
import sys
import tempfile
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(TESTS, "..", "engine")
sys.path.insert(0, ENGINE)

import evidence as EV

PASS = 0
FAIL = 0
RESULTS = []


def _record(test_id, name, status, detail=""):
    global PASS, FAIL
    if status == "PASS":
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append({"id": test_id, "name": name, "status": status, "detail": detail})
    mark = {"PASS": "✓", "FAIL": "✗"}[status]
    print(f"  [{mark} {status:13s}] {test_id}: {name}" + (f" — {detail}" if detail else ""))


def run_tests():
    eng_dir = tempfile.mkdtemp()

    print("\n--- Evidence Pipeline Tests ---")

    # T-EV-1: record_observation stores valid observation with all fields
    try:
        obs_id = EV.record_observation(
            eng_dir,
            method="GET",
            url="https://example.com/api/users/1",
            req_headers={"Authorization": "Bearer secret123", "Accept": "application/json"},
            req_body=None,
            resp_status=200,
            resp_headers={"content-type": "application/json"},
            resp_body='{"id":1,"name":"Alice"}',
            identity="A",
            case_id="case-001",
            policy_id="pol-abc",
            owner="A",
            accessor="B",
            egress_decision="allowed",
        )
        assert obs_id and len(obs_id) == 16, f"bad obs_id: {obs_id}"
        obs_file = os.path.join(eng_dir, "evidence", "observations.jsonl")
        assert os.path.isfile(obs_file), "observations file not created"
        with open(obs_file) as f:
            records = [json.loads(l) for l in f if l.strip()]
        assert len(records) == 1
        rec = records[0]
        assert rec["method"] == "GET"
        assert rec["url"] == "https://example.com/api/users/1"
        assert rec["resp_status"] == 200
        assert rec["identity"] == "A"
        assert rec["case_id"] == "case-001"
        assert rec["policy_id"] == "pol-abc"
        assert rec["type"] == "HttpObservation"
        assert rec["schema_version"] == EV.SCHEMA_VERSION
        assert rec["resp_body_hash"] is not None
        assert rec["req_body_length"] == 0
        _record("T-EV-1", "record_observation stores valid observation", "PASS")
    except Exception as e:
        _record("T-EV-1", "record_observation stores valid observation", "FAIL", str(e))

    # T-EV-2: record_attempt links observation IDs to case_id
    try:
        attempt_id = EV.record_attempt(
            eng_dir,
            case_id="case-001",
            observation_ids=[obs_id],
            outcome=EV.TESTED,
            agent_commentary="Agent found IDOR on /api/users/1",
            method="GET",
            url="https://example.com/api/users/1",
            identity="A",
            owner="A",
            accessor="B",
            confidence=EV.CONFIDENCE_CANDIDATE,
        )
        assert attempt_id and len(attempt_id) == 16, f"bad attempt_id: {attempt_id}"
        att_file = os.path.join(eng_dir, "evidence", "attempts.jsonl")
        assert os.path.isfile(att_file)
        with open(att_file) as f:
            records = [json.loads(l) for l in f if l.strip()]
        assert len(records) == 1
        rec = records[0]
        assert rec["case_id"] == "case-001"
        assert obs_id in rec["observation_ids"]
        assert rec["outcome"] == EV.TESTED
        assert rec["confidence"] == EV.CONFIDENCE_CANDIDATE
        _record("T-EV-2", "record_attempt links observations to case", "PASS")
    except Exception as e:
        _record("T-EV-2", "record_attempt links observations to case", "FAIL", str(e))

    # T-EV-3: validate_evidence returns False for case with no observations
    try:
        result = EV.validate_evidence(eng_dir, case_id="case-nonexistent")
        # API may return (bool, msg) tuple or bare bool or dict
        if isinstance(result, tuple):
            is_valid = result[0]
        elif isinstance(result, dict):
            is_valid = result.get("valid", True)
        else:
            is_valid = result
        assert not is_valid, f"expected invalid for missing case, got: {result}"
        _record("T-EV-3", "validate_evidence rejects case with no observations", "PASS")
    except Exception as e:
        _record("T-EV-3", "validate_evidence rejects case with no observations", "FAIL", str(e))

    # T-EV-4: validate_evidence returns True for case with matching transport observation
    try:
        result = EV.validate_evidence(
            eng_dir, case_id="case-001", method="GET", identity="A",
            url="https://example.com/api/users/1",
        )
        if isinstance(result, tuple):
            is_valid = result[0]
        elif isinstance(result, dict):
            is_valid = result.get("valid", False)
        else:
            is_valid = result
        assert is_valid, f"expected valid for case-001, got: {result}"
        _record("T-EV-4", "validate_evidence accepts case with real observation", "PASS")
    except Exception as e:
        _record("T-EV-4", "validate_evidence accepts case with real observation", "FAIL", str(e))

    # T-EV-5: Fake LLM payload — no real transport observation — must not count as tested
    fake_dir = tempfile.mkdtemp()
    try:
        # Record an attempt that has no observation IDs (only agent text)
        fake_attempt = EV.record_attempt(
            fake_dir,
            case_id="case-fake",
            observation_ids=[],
            outcome=EV.TESTED,
            agent_commentary='{"request":"GET /x","vulnerable":true}',
            method="GET",
            url="https://example.com/x",
            identity="A",
        )
        result = EV.validate_evidence(fake_dir, case_id="case-fake")
        is_valid = result is True or (isinstance(result, dict) and result.get("valid", False))
        assert not is_valid, f"fake LLM payload should NOT validate, got: {result}"
        _record("T-EV-5", "Fake LLM payload (no real observation) rejected", "PASS")
    except Exception as e:
        _record("T-EV-5", "Fake LLM payload (no real observation) rejected", "FAIL", str(e))

    # T-EV-6: coverage_from_evidence only counts cases with real transport observations
    try:
        cov = EV.coverage_from_evidence(eng_dir)
        assert isinstance(cov, dict), f"expected dict, got {type(cov)}"
        # coverage returns dict keyed by case_id for cases with real observations
        assert "case-001" in cov, f"case-001 should be in coverage: {list(cov.keys())}"

        # Fake dir (agent text only, no real observations) should have zero tested coverage
        fake_cov = EV.coverage_from_evidence(fake_dir)
        assert len(fake_cov) == 0, f"fake dir should have 0 tested cases, got {len(fake_cov)}: {list(fake_cov.keys())}"

        _record("T-EV-6", "coverage_from_evidence derives from observations only", "PASS")
    except Exception as e:
        _record("T-EV-6", "coverage_from_evidence derives from observations only", "FAIL", str(e))

    # T-EV-7: Sensitive headers are redacted in stored observations
    try:
        obs_file = os.path.join(eng_dir, "evidence", "observations.jsonl")
        with open(obs_file) as f:
            records = [json.loads(l) for l in f if l.strip()]
        rec = records[0]
        auth_val = rec["req_headers"].get("Authorization", "")
        assert "secret123" not in auth_val, f"Bearer token leaked: {auth_val}"
        assert auth_val.startswith("REDACTED:"), f"expected REDACTED prefix: {auth_val}"
        # Non-sensitive headers should be preserved
        accept_val = rec["req_headers"].get("Accept", "")
        assert accept_val == "application/json", f"Accept header should be preserved: {accept_val}"
        _record("T-EV-7", "Sensitive headers redacted in stored observations", "PASS")
    except Exception as e:
        _record("T-EV-7", "Sensitive headers redacted in stored observations", "FAIL", str(e))

    # T-EV-8: get_observations filters by case_id and identity
    try:
        # Add a second observation with different case_id
        EV.record_observation(
            eng_dir, method="POST", url="https://example.com/api/users",
            resp_status=201, identity="B", case_id="case-002",
        )
        obs_001 = EV.get_observations(eng_dir, case_id="case-001")
        obs_002 = EV.get_observations(eng_dir, case_id="case-002")
        obs_B = EV.get_observations(eng_dir, identity="B")
        assert len(obs_001) == 1 and obs_001[0]["case_id"] == "case-001"
        assert len(obs_002) == 1 and obs_002[0]["case_id"] == "case-002"
        assert len(obs_B) == 1 and obs_B[0]["identity"] == "B"
        all_obs = EV.get_observations(eng_dir)
        assert len(all_obs) == 2
        _record("T-EV-8", "get_observations filters by case_id and identity", "PASS")
    except Exception as e:
        _record("T-EV-8", "get_observations filters by case_id and identity", "FAIL", str(e))

    # T-EV-9: Observation with resp_status=0 (transport error) should not validate
    err_dir = tempfile.mkdtemp()
    try:
        err_obs_id = EV.record_observation(
            err_dir, method="GET", url="https://example.com/api/x",
            resp_status=0, identity="A", case_id="case-err",
        )
        EV.record_attempt(
            err_dir, case_id="case-err", observation_ids=[err_obs_id],
            outcome=EV.INCONCLUSIVE,
        )
        result = EV.validate_evidence(err_dir, case_id="case-err")
        is_valid = result is True or (isinstance(result, dict) and result.get("valid", False))
        assert not is_valid, f"transport error should not validate, got: {result}"
        _record("T-EV-9", "Transport error (status 0) does not validate", "PASS")
    except Exception as e:
        _record("T-EV-9", "Transport error (status 0) does not validate", "FAIL", str(e))

    print(f"\n{'='*70}")
    print(f"  EVIDENCE PIPELINE TEST RESULTS")
    print(f"  PASS={PASS}  FAIL={FAIL}")
    print(f"  Total: {len(RESULTS)}")
    print(f"{'='*70}")

    if FAIL > 0:
        print("\n  FAILED tests:")
        for r in RESULTS:
            if r["status"] == "FAIL":
                print(f"    {r['id']}: {r['name']} — {r['detail']}")

    report_path = os.path.join(TESTS, "..", "..", "artifacts", "release-validation")
    os.makedirs(report_path, exist_ok=True)
    with open(os.path.join(report_path, "evidence-pipeline-results.json"), "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pass": PASS, "fail": FAIL,
            "results": RESULTS,
        }, f, indent=2)

    return 1 if FAIL > 0 else 0


if __name__ == "__main__":
    print("Evidence Pipeline Tests")
    print("=" * 70)
    sys.exit(run_tests())
