#!/usr/bin/env python3
"""Regression tests for the 2026-10 hunting correctness remediation."""
import json
import os
import sys
import tempfile

TESTS = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(TESTS, "..", "engine")
sys.path.insert(0, ENGINE)

import agent as A
import authz
import discovery
import egress
import engine as E
import evidence as EV
import featuremap
import orchestrator as O
import recon
import scope as SCMOD
import skill_map
import testplan as TP
import vulncatalog as VC

PASS = 0


def check(name, condition, detail=""):
    global PASS
    if not condition:
        raise AssertionError(f"{name}: {detail}")
    PASS += 1
    print(f"  [PASS] {name}")


def make_engine(mock=False, base=None):
    base = base or tempfile.mkdtemp()
    scope_path = os.path.join(base, "scope.json")
    scope_data = {"name": "demo-local", "in_scope": ["localhost", "127.0.0.1"],
                  "out_of_scope": [], "seeds": ["http://localhost:3002"]}
    with open(scope_path, "w") as fh:
        json.dump(scope_data, fh)
    eng = E.Engine(scope_path, base, "test", 8, 5, 1, mock=mock, parallel=1)
    return eng, base


def finding(reproduction="reproduced"):
    return {"vuln_class": "idor", "url": "http://localhost:3002/api/account?id=5",
            "method": "GET", "severity": "high",
            "evidence": "id=N returns other users' PII with cross-account access",
            "request": "GET /api/account?id=6", "response": '{"email":"a@example.test"}',
            "reproduction": {"status": reproduction, "method": "ownership-marker-replay",
                             "signal": "B received A's marker"}}


def test_case_identity_and_scheduler():
    eng, _ = make_engine()
    os.environ["HUNT_SKIP_WALLED"] = "0"
    item = {"url": "http://localhost:3002/api/users/1", "method": "GET",
            "params": ["id"], "vuln_class": "dynamic"}
    expected = eng.eng._key(item)
    eng._hunt_deep = lambda it, model=None, timeout=None: it
    result = eng._hunt_agent(item, model="test")
    check("deep mode preserves case identity", eng.eng._key(result) == expected)
    check("deep mode preserves original category", result["vuln_class"] == "dynamic")
    captured = {}
    original_run_agent = A.run_agent
    try:
        def capture_agent(task, **kwargs):
            captured["task"] = task
            return {"result": '{"vulnerable":false,"hypothesis_results":[]}'}
        A.run_agent = capture_agent
        structured = dict(item, params=[{"name": "id", "type": "string"}],
                          body_params=[{"name": "amount", "type": "number"}])
        deep_eng, _ = make_engine()
        deep_eng._hunt_deep(structured, model="test")
    finally:
        A.run_agent = original_run_agent
    check("deep hunt normalizes structured parameters",
          "known param(s): id" in captured["task"] and "body_params: amount" in captured["task"])
    eng._hunt_agent = lambda it, model=None, timeout=None: {"request": "GET fake", "analysis": "agent text"}
    result = eng._scheduled_hunt(item)
    status = eng.scheduler.status(expected)["status"]
    check("agent text cannot complete scheduler claim", status == "active", status)
    eng._finalize_scheduled(item, False, "no transport evidence")
    check("missing transport evidence fails scheduler claim", eng.scheduler.status(expected)["status"] == "failed")


def test_ownership_proof():
    def generic(url, method="GET", data=None, ident=None, slug=None, **kwargs):
        return 200, '{"status":"ok","message":"resource found"}', {}
    lead = authz.diff_one("GET", "https://example.test/orders/123", None, "x", _get=generic)
    check("generic A/B response is not BOLA", not lead["bola_suspect"] and not lead["ownership_proven"])

    def owned(url, method="GET", data=None, ident=None, slug=None, **kwargs):
        if "control" in url:
            return 200, '{"status":"ok"}', {}
        return 200, '{"owner":"alice","marker":"a1b2c3d4e5"}', {}
    proof = authz.prove_ownership("GET", "https://example.test/orders/123", None, "x",
                                  "a1b2c3d4e5", control_url="https://example.test/control", _get=owned)
    check("A-owned marker proves cross-account access", proof["confirmed"])
    check("short marker is rejected", not authz.prove_ownership(
        "GET", "https://example.test/orders/123", None, "x", "short", _get=owned)["confirmed"])
    check("negative control is mandatory", not authz.prove_ownership(
        "GET", "https://example.test/orders/123", None, "x", "a1b2c3d4e5", _get=owned)["confirmed"])


def test_draft_gates():
    eng, base = make_engine(mock=True)
    orc = O.Orchestrator(os.path.join(base, "scope.json"), base=base, mock=True)
    orc.eng.eng.state["confirmed"] = [finding()]
    drafted, held = orc.draft_gate()
    check("empty dedup corpus is held", not drafted and len(held) == 1)

    orc2 = O.Orchestrator(os.path.join(base, "scope.json"), base=base, mock=True)
    orc2.eng.eng.state["confirmed"] = [finding("inconclusive")]
    O.D.Corpus("demo-local", base=base).ingest([{"source": "h1-public", "vuln_class": "ssrf",
            "url": "http://localhost:3002/unrelated", "title": "Unrelated SSRF", "link": "https://h1/0"}])
    drafted2, _ = orc2.draft_gate()
    check("unreproduced finding cannot draft", not drafted2 and len(orc2._policy) == 1)

    orc3 = O.Orchestrator(os.path.join(base, "scope.json"), base=base, mock=True)
    one_tool = finding()
    one_tool["reproduction"]["tools"] = ["ownership-marker-replay"]
    orc3.eng.eng.state["confirmed"] = [one_tool]
    drafted3, _ = orc3.draft_gate()
    check("High/Critical needs two reproduction tools", not drafted3 and
          orc3._policy[0]["disposition"]["verdict"] == "HOLD_REPORT_READY")

    orc4 = O.Orchestrator(os.path.join(base, "scope.json"), base=base, mock=True)
    two_tools = finding()
    two_tools["reproduction"]["tools"] = ["curl_cffi", "requests"]
    orc4.eng.eng.state["confirmed"] = [two_tools]
    drafted4, _ = orc4.draft_gate()
    check("two-tool reproduced NOVEL finding can draft", len(drafted4) == 1)
    score, vector = O._cvss({"id_source": "not_required"}, "low")
    check("unauthenticated CVSS uses PR:N", vector.startswith("CVSS:3.1/AV:N/AC:L/PR:N") and score == "4.3")
    check("HTTP evidence normalizes escaped CRLF", "\\r" not in O._http_text("HTTP/1.0 302\\r\\nlocation: x\\r"))


def test_discovery_and_openapi():
    guessed = [{"url": f"https://api.test/{i}", "category": "api_endpoints", "confidence": "low",
                "provenance": "guessed_common_path"} for i in range(15)]
    summary = discovery._compute_coverage(guessed)["_summary"]
    check("guessed endpoints cannot satisfy discovery readiness",
          not summary["discovery_ready"] and summary["coverage_unknown"])
    documented = [{"url": "https://api.test/users", "category": "api_endpoints", "confidence": "high",
                   "provenance": "documented"}]
    check("documented operation is discovery-ready",
          discovery._compute_coverage(documented)["_summary"]["discovery_ready"])

    yaml_body = """openapi: 3.0.0
info: {title: Test}
security: [{bearerAuth: []}]
paths:
  /users/{id}:
    parameters:
      - $ref: '#/components/parameters/UserId'
    get:
      security: []
      responses: {'200': {description: ok}}
  /orgs/{orgId}:
    get:
      responses: {'200': {description: ok}}
components:
  parameters:
    UserId:
      name: id
      in: path
      required: true
      schema: {type: string, example: '42'}
"""
    old_probe = discovery._probe
    try:
        discovery._probe = lambda url, method="GET", timeout=12: (
            (200, yaml_body, {"content-type": "application/yaml"}) if url.endswith("/openapi.yaml") else (404, "", {}))
        sc = SCMOD.Scope(["api.test"], seeds=["https://api.test"])
        eps = discovery._discover_openapi(sc, log=lambda _m: None)
    finally:
        discovery._probe = old_probe
    user = next(ep for ep in eps if ep["url"].endswith("/users/42"))
    check("OpenAPI YAML refs and path examples resolve", user["method"] == "GET" and not user["auth_required"])
    check("unresolved OpenAPI template stays a lead",
          any(ep.get("unresolved_template") and ep["confidence"] == "low" for ep in eps))


def test_browser_novelty_transport():
    check("legacy browser source XHR is accepted",
          recon._browser_api_request({"url": "https://x.test/api/users", "source": "xhr"}))
    sc = SCMOD.Scope(["*.example.com"])
    policy = egress.EgressPolicy(scope=sc, allow_intrusive=False)
    check("read-only GraphQL POST allowed",
          policy.check_egress("POST", "https://api.example.com/graphql", body='{"query":"{me{id}}"}').allowed)
    check("GraphQL mutation remains blocked",
          not policy.check_egress("POST", "https://api.example.com/graphql", body='{"query":"mutation {x}"}').allowed)
    check("non-idempotent timeout cannot replay", not E.Engine._timeout_retry_allowed({"method": "POST"}))

    eng, base = make_engine(mock=True)
    orc = O.Orchestrator(os.path.join(base, "scope.json"), base=base, mock=True)
    first = {"subdomains": ["localhost"], "hosts": [], "js": [], "endpoints": [], "params": []}
    orc.novelty(obs=first)
    check("baseline does not inflate novelty worklist",
          not any(i.get("source") == "novelty" for i in orc.eng.eng.state["surface"]))
    second = {**first, "endpoints": ["http://localhost:3002/api/new"]}
    orc.novelty(obs=second)
    check("new endpoint enters novelty worklist",
          any(i.get("source") == "novelty" and i["url"].endswith("/api/new")
              for i in orc.eng.eng.state["surface"]))


def test_planning_taxonomy_evidence():
    surface = [{"url": "https://api.test/users/1", "method": "PATCH", "params": ["id", "name", "role"],
                "role": "member", "owner": "A", "accessor": "B", "auth_required": True}]
    endpoints = featuremap._endpoints_from_surface({"surface": surface})
    check("feature map preserves all params and identities",
          endpoints[0]["params"] == ["id", "name", "role"] and endpoints[0]["owner"] == "A")
    cases = TP.generate_test_cases(endpoints)
    check("plan emits stable case ID and multi-param case",
          cases[0]["case_id"] == TP.case_id(cases[0]) and len(cases[0]["params"]) == 3)
    check("taxonomy aliases resolve", VC.canonical_class("mfa-bypass") == "2fa-bypass"
          and VC.skill_name("dom") == "hunt-dom" and VC.canonical_class("bola") == "idor")

    edir = tempfile.mkdtemp()
    oid = EV.record_observation(edir, "POST", "https://api.test/login",
                                req_body='{"password":"supersecret"}', resp_status=200,
                                resp_body='{"token":"abc.def.ghi"}', case_id="case-x")
    obs = EV.get_observations(edir, case_id="case-x")[0]
    check("evidence is schema v2 with redacted excerpts",
          obs["schema_version"] == 2 and "supersecret" not in obs["req_body_excerpt"]
          and "abc.def.ghi" not in obs["resp_body_excerpt"] and oid)


def test_model_failover():
    old = os.environ.get("HUNT_MODELS")
    try:
        os.environ["HUNT_MODELS"] = "model-a,model-b"
        check("model failure advances to next approved runtime", A._next_model("model-a") == "model-b")
        check("model failover wraps within approved pool", A._next_model("model-b") == "model-a")
    finally:
        if old is None:
            os.environ.pop("HUNT_MODELS", None)
        else:
            os.environ["HUNT_MODELS"] = old


def test_proposed_skill_quarantine():
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "learned-x"))
    with open(os.path.join(root, "learned-x", "SKILL.md"), "w") as fh:
        fh.write("---\nname: learned-x\ndescription: test\nreview_status: proposed\n---\n")
    old = skill_map.SKILLS_DIR
    old_fallback = skill_map._FALLBACK_DIRS
    try:
        skill_map.SKILLS_DIR = root
        skill_map._FALLBACK_DIRS = []
        check("proposed learned skill is quarantined", "learned-x" not in skill_map._present())
    finally:
        skill_map.SKILLS_DIR = old
        skill_map._FALLBACK_DIRS = old_fallback


def main():
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n--- {name} ---")
            fn()
    print(f"\nREMEDIATION TESTS: {PASS} PASS, 0 FAIL")
    return 0


if __name__ == "__main__":
    sys.exit(main())
