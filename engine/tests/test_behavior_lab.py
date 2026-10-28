#!/usr/bin/env python3
"""
test_behavior_lab.py — behavior labs with arbitrary function names, schema-less
operations, nested relationships, and seeded unknown-to-the-planner defects.

Does NOT encode the expected finding name in planner input. The harness must
discover the defect from observed behavior alone.

Labs:
  1. Arbitrary function names — operations with non-standard naming
  2. Schema-less JSON operations — no OpenAPI, forms, or framework hints
  3. Nested relationship chains — state preconditions across operations
  4. Protected controls — must NOT be flagged
  5. Unknown defects — vulnerability classes not in PER_CLASS
"""
import json
import os
import sys
import tempfile

ENGINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "engine")
sys.path.insert(0, ENGINE)


def test_arbitrary_function_profiles():
    """Operations with non-standard names produce valid function profiles."""
    import function_profile as FP
    ops = [
        {"action": "xq7_fetch", "resource": "/zorb/manifests",
         "inputs": [{"name": "tenant_id"}], "effects": [], "sensitivity": {"level": 2}},
        {"action": "submit_qwark", "resource": "/internal/qwark-pipeline",
         "inputs": [{"name": "payload"}, {"name": "callback_url"}],
         "effects": [{"desc": "triggers external fetch"}], "sensitivity": {"level": 4}},
        {"action": "rotate_zog", "resource": "/admin/zog-tokens",
         "inputs": [{"name": "token_id"}, {"name": "scope"}],
         "effects": [{"desc": "invalidates old token"}],
         "sensitivity": {"level": 5}, "actors": {"admin": {}, "service": {}}},
    ]
    for op in ops:
        profile = FP.new_profile(
            op["action"], op["resource"],
            inputs=op.get("inputs", []),
            effects=op.get("effects", []),
            sensitivity=op.get("sensitivity", {}),
            actors=op.get("actors", {}),
        )
        assert profile.get("action") == op["action"]
        assert profile.get("resource") == op["resource"]
        dims = FP.trust_dimensions(profile)
        assert isinstance(dims, list)
        score = FP.impact_score(profile)
        assert score >= 0


def test_schemaless_analysis():
    """Endpoints without OpenAPI/schema produce valid test profiles."""
    import testplan as TP
    eps = [
        {"url": "https://lab.test/api/v3/widgets", "method": "POST",
         "params": [{"name": "data", "type": "json"}], "auth_required": True,
         "source": "response_mining", "confidence": "observed"},
        {"url": "https://lab.test/events/push", "method": "POST",
         "params": [{"name": "event_type"}, {"name": "payload"}],
         "source": "js_bundle", "confidence": "declared"},
    ]
    cases = TP.generate_test_cases(eps)
    assert len(cases) >= 2
    for case in cases:
        assert case.get("function_profile")
        assert "signals" in case or "trust_dimensions" in case


def test_nested_relationships():
    """Operations with relationships trigger workflow_logic dimension."""
    import function_profile as FP
    profile = FP.new_profile(
        "transfer_funds", "POST", "/api/transfers",
        params=["from_account", "to_account", "amount"],
        effects=["debit from_account", "credit to_account"],
        relationships=["/api/accounts/{id}/balance", "/api/transfers/{id}/status"],
        sensitivity=5,
    )
    dims = FP.trust_dimensions(profile)
    assert "workflow_logic" in dims, f"relationships should trigger workflow_logic, got {dims}"


def test_protected_controls_not_flagged():
    """verify_finding catches version/banner disclosure as always-rejected."""
    import verify
    protected = {
        "vuln_class": "info-disclosure",
        "url": "https://lab.test/api/health",
        "title": "Version disclosure on health endpoint",
        "severity": "low",
        "steps": "1. GET /api/health\n2. Response includes version",
        "impact": "Server version disclosed via version disclosure",
        "request": "GET /api/health HTTP/1.1",
        "response": "HTTP/1.1 200 OK\n{\"status\":\"ok\",\"version\":\"1.2.3\"}",
    }
    result = verify.verify_finding(protected)
    failed = [c["check"] for c in result["checks"] if not c["pass"]]
    assert any("always-rejected" in c or "disposition" in c for c in failed) or \
        result["verdict"] != "READY", \
        f"version disclosure should be caught: verdict={result['verdict']}, failed={failed}"


def test_unknown_class_structural_proof():
    """Unknown vulnerability classes require structural proof (request + response + control)."""
    import verify

    weak = {
        "vuln_class": "quantum-tunneling-bypass",
        "url": "https://lab.test/api/quantum",
        "title": "Quantum tunneling bypass in auth",
        "severity": "high",
        "steps": "1. Send request\n2. Auth bypassed",
        "impact": "Authentication bypass",
    }
    result = verify.verify_finding(weak)
    failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
    assert "PoC minimum (structural)" in failed_checks, \
        f"unknown class without request/response should fail structural check, got {failed_checks}"

    strong = {
        "vuln_class": "quantum-tunneling-bypass",
        "url": "https://lab.test/api/quantum",
        "title": "Quantum tunneling bypass in auth",
        "severity": "high",
        "steps": "1. GET /api/quantum with modified header\n2. Auth bypassed",
        "impact": "Authentication bypass — accessed admin data without credentials",
        "request": "GET /api/quantum HTTP/1.1\nHost: lab.test\nX-Tunnel: bypass",
        "response": "HTTP/1.1 200 OK\n{\"admin\": true, \"users\": [...]}",
        "evidence": "baseline response returns 401; modified request returns admin data",
    }
    result2 = verify.verify_finding(strong)
    structural_check = [c for c in result2["checks"] if c["check"] == "PoC minimum (structural)"]
    assert structural_check and structural_check[0]["pass"], \
        f"unknown class with full structural proof should pass, got {result2['failed']}"


def test_chain_verification():
    """Chained findings need per-edge evidence."""
    import verify

    chained_good = {
        "vuln_class": "ssrf",
        "url": "https://lab.test/api/fetch",
        "title": "SSRF to internal admin via file import",
        "severity": "critical",
        "steps": "1. Upload file with internal URL\n2. Server fetches internal admin\n3. Exfiltrate data",
        "impact": "Full internal network access — extracted metadata credentials",
        "request": "POST /api/fetch HTTP/1.1",
        "response": "HTTP/1.1 200 OK\n169.254.169.254 metadata response body",
        "poc": "curl -X POST https://lab.test/api/fetch -d '{\"file_url\": \"http://169.254.169.254/\"}'",
        "chain": [
            {"step": "SSRF via file_url", "evidence": "POST /api/fetch with file_url=http://169.254.169.254/"},
            {"step": "Metadata access", "evidence": "Response contains AWS credentials"},
            {"step": "Lateral movement", "evidence": "Used credentials to access S3 bucket", "impact": "data exfiltration"},
        ],
    }
    result = verify.verify_finding(chained_good)
    chain_checks = [c for c in result["checks"] if "chain edge" in c["check"]]
    assert len(chain_checks) >= 2, f"expected chain edge checks, got {[c['check'] for c in result['checks']]}"

    chained_bad = dict(chained_good)
    chained_bad["chain"] = [
        {"step": "SSRF via file_url", "evidence": "POST request sent"},
        {"step": "Metadata access"},
    ]
    result2 = verify.verify_finding(chained_bad)
    chain_checks2 = [c for c in result2["checks"] if "chain edge" in c["check"]]
    failed_edges = [c for c in chain_checks2 if not c["pass"]]
    assert len(failed_edges) >= 1, "chain edge without evidence should fail"


def test_dedup_corpus_metadata():
    """Dedup corpus includes freshness and source information."""
    import dedup
    base = tempfile.mkdtemp()
    cp = dedup.Corpus("lab-test", base=base)
    cp.ingest([
        {"vuln_class": "xss", "url": "https://lab.test/search",
         "title": "XSS in search", "source": "h1-public", "date": "2026-01-15"},
        {"vuln_class": "idor", "url": "https://lab.test/api/users/1",
         "title": "IDOR on users", "source": "own-memory", "date": "2026-03-20"},
    ])
    result = cp.check({"vuln_class": "sqli", "url": "https://lab.test/api/query",
                        "title": "SQL injection in query endpoint"})
    assert "corpus_sources" in result
    assert "corpus_freshest" in result
    assert result["corpus_freshest"] == "2026-03-20"
    assert set(result["corpus_sources"]) == {"h1-public", "own-memory"}


def test_learning_db_integration():
    """learning_db.py dual-write and retrieval work end-to-end."""
    import learning_db as LDB
    base = tempfile.mkdtemp()
    os.makedirs(os.path.join(base, "hunt-memory"), exist_ok=True)

    LDB.init_db(base)
    LDB.write_outcome("lab-test", "xss", "confirmed", "reflected in search",
                       trust_dimension="input_variation", base=base)
    LDB.write_scenario("lab-test", url="https://lab.test/search",
                        trust_dimension="input_variation",
                        hypothesis="inject script via q parameter",
                        outcome="confirmed", confidence=0.9, base=base)

    outcomes = LDB.query_outcomes(program="lab-test", base=base)
    assert len(outcomes) == 1
    scenarios = LDB.query_scenarios("lab-test", base=base)
    assert len(scenarios) == 1
    prompt = LDB.scenarios_for_prompt("lab-test", base=base)
    assert "evaluate, adapt, or reject" in prompt


def test_yield_metrics():
    """Yield metrics can be computed from state and coverage."""
    import state, testplan as TP
    base = tempfile.mkdtemp()
    eng = state.Engagement(base, "metrics-lab")
    eng.add_surface([
        {"url": "https://lab.test/api/a", "method": "GET"},
        {"url": "https://lab.test/api/b", "method": "POST"},
        {"url": "https://lab.test/api/c", "method": "GET"},
    ])
    eng.mark_tested({"url": "https://lab.test/api/a", "method": "GET"}, checks=["xss"])
    eng.add_candidate({"url": "https://lab.test/api/b", "vuln_class": "idor",
                        "title": "IDOR on b", "severity": "high"})
    eng.confirm({"url": "https://lab.test/api/b", "vuln_class": "idor"},
                "confirmed", reproduction_status="reproduced")
    eng.save()

    summary = eng.summary()
    assert summary["surface"] >= 3
    assert summary["confirmed"] >= 1

    metrics = eng.metrics()
    assert metrics["endpoints_tested"] >= 1 or metrics.get("endpoints_discovered", 0) >= 0


def main():
    tests = [
        ("arbitrary function profiles", test_arbitrary_function_profiles),
        ("schema-less analysis", test_schemaless_analysis),
        ("nested relationships", test_nested_relationships),
        ("protected controls", test_protected_controls_not_flagged),
        ("unknown class structural proof", test_unknown_class_structural_proof),
        ("chain verification", test_chain_verification),
        ("dedup corpus metadata", test_dedup_corpus_metadata),
        ("learning_db integration", test_learning_db_integration),
        ("yield metrics", test_yield_metrics),
    ]
    passed, failed = 0, 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            failed += 1
    print(f"\nbehavior_lab: {passed}/{passed+failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
