#!/usr/bin/env python3
import json
import os
import sys
import tempfile

TESTS = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(TESTS, "..", "engine")
sys.path.insert(0, ENGINE)

import coverage as COV
import evidence as EV
import function_profile as FP
import skill_map as SM
import testplan as TP

PASS = 0


def check(name, condition, detail=""):
    global PASS
    if not condition:
        raise AssertionError(f"{name}: {detail}")
    PASS += 1
    print(f"  [PASS] {name}")


def test_skill_gate():
    base = tempfile.mkdtemp()
    case_id = "case-live"
    early = SM.for_hypothesis("another actor may receive the owner's marker")
    check("no vulnerability references before evidence",
          all(os.path.basename(os.path.dirname(path)) == "hunt-methodology" for path in early), early)
    obs = EV.record_observation(base, "GET", "https://api.test/orders/1",
                                resp_status=200, resp_body='{"owner":"A"}', case_id=case_id)
    paths = SM.for_hypothesis("another actor may receive the owner's marker", evidence_dir=base,
                              case_id=case_id, observation_ids=[obs])
    check("case-linked baseline unlocks hypothesis references", len(paths) > 1, paths)
    forged = SM.for_hypothesis("another actor may receive the owner's marker", evidence_dir=base,
                               case_id=case_id, observation_ids=["not-real"])
    check("forged observations do not unlock references",
          all(os.path.basename(os.path.dirname(path)) == "hunt-methodology" for path in forged), forged)
    wrong_case = SM.for_hypothesis("another actor may receive the owner's marker", evidence_dir=base,
                                   case_id="other-case", observation_ids=[obs])
    check("observations from another case do not unlock references",
          all(os.path.basename(os.path.dirname(path)) == "hunt-methodology" for path in wrong_case), wrong_case)


def dimensional_case():
    profile = FP.new_profile("update", "orders", actors={"owner": "A"},
                             inputs=[{"name": "amount", "location": "body"}],
                             effects=[{"type": "state_change"}], state={"mutates": True})
    return {"case_id": "dimension-case", "endpoint": "https://api.test/orders/1", "method": "PATCH",
            "category": "dynamic", "status": "tested", "function_profile": profile,
            "trust_dimensions": profile["trust_dimensions"], "role": "member",
            "owner": "A", "accessor": "B"}


def test_dimensional_coverage():
    base = tempfile.mkdtemp()
    case = dimensional_case()
    obs = EV.record_observation(base, "PATCH", case["endpoint"], resp_status=403,
                                case_id=case["case_id"], identity="B")
    outcome = TP.apply_hypothesis_results(case, [{
        "hypothesis": "the parser accepts an unexpected amount representation",
        "dimension": "input_variation", "status": "disproved",
        "observation_ids": [obs], "evidence": "server rejected the variation with 403",
    }], evidence_dir=base, case_key=case["case_id"])
    check("one evidence-linked dimension accepted", outcome["accepted"] == 1, outcome)
    check("only declared dimension is resolved", case["dimension_results"]["input_variation"]["status"] == "disproved")
    check("other dimensions remain unresolved", "state_and_sequence" not in case["dimension_results"])
    cov = TP.plan_coverage([case])
    check("dimensional coverage is not endpoint coverage",
          cov["coverage_pct"] == 100.0 and cov["dimension_coverage_pct"] < 100.0, cov)

    forged = dimensional_case()
    TP.apply_hypothesis_results(forged, [{
        "hypothesis": "sequence can be replayed", "dimension": "state_and_sequence",
        "status": "confirmed", "observation_ids": ["forged"], "evidence": "HTTP replay modified state",
    }], evidence_dir=base, case_key=forged["case_id"])
    check("forged dimensional evidence is blocked", forged["dimension_results"]["state_and_sequence"]["status"] == "blocked")
    multi = dimensional_case()
    TP.apply_hypothesis_results(multi, [{
        "hypothesis": "one observation attempts to close every dimension",
        "dimensions": ["input_variation", "state_and_sequence"], "status": "tested",
        "observation_ids": [obs], "evidence": "HTTP response received",
    }], evidence_dir=base, case_key=multi["case_id"])
    check("one result cannot blanket-close multiple dimensions",
          all(rec["status"] == "blocked" for rec in multi["dimension_results"].values()), multi["dimension_results"])

    slug = "dimensional"
    os.makedirs(os.path.join(base, slug))
    state = {"surface": [{"url": case["endpoint"], "method": "PATCH", "vuln_class": "dynamic"}],
             "tested": {}, "test_plan": [case]}
    with open(os.path.join(base, slug, "state.json"), "w") as fh:
        json.dump(state, fh)
    report = COV.report(slug, base)
    check("coverage reports independent dimension outcomes",
          report["trust_dimensions"]["input_variation"]["tested"] == 1 and
          report["trust_dimensions"]["state_and_sequence"]["unknown"] == 1, report["trust_dimensions"])
    check("role and ownership context retained", report["dimension_details"][0]["owner"] == "A" and
          report["dimension_details"][0]["accessor"] == "B")

    old = dimensional_case()
    old.pop("dimension_results", None)
    state["test_plan"] = [old]
    with open(os.path.join(base, slug, "state.json"), "w") as fh:
        json.dump(state, fh)
    legacy = COV.report(slug, base)
    check("legacy tested case does not blanket-cover dimensions",
          legacy["dimension_coverage_pct"] == 0.0 and
          legacy["trust_dimensions"]["input_variation"]["unknown"] == 1, legacy["trust_dimensions"])


def test_real_artifact_adapters():
    import target_adapters as TA
    sys.path.insert(0, os.path.join(TESTS, "..", "eval"))
    import run_dynamic_matrix as DM
    root = tempfile.mkdtemp()
    artifacts = DM.make_artifacts(root)
    with open(artifacts["cloud"]) as fh:
        cloud = TA.cloud_profiles(json.load(fh))
    check("keyed cloud resources normalize", len(cloud) == 1 and
          cloud[0]["actors"]["tenant"] == "tenant-a" and cloud[0]["confidence"] == "inferred")
    with open(artifacts["llm"]) as fh:
        llm = TA.llm_profiles(json.load(fh))
    check("LLM tools and keyed memory normalize", len(llm) == 2 and
          any(profile["resource"] == "order_history" for profile in llm))
    android_profiles = TA.android_profiles(artifacts["android"])
    external = {profile["resource"]: profile["actors"].get("external")
                for profile in android_profiles if profile["protocol"] == "android-ipc"}
    check("Android XML exported flags parsed structurally",
          external.get(".MainActivity") is True and external.get(".PrivateService") is False, external)
    ios = TA.ios_profiles(artifacts["ios"])
    check("binary IPA plist and entitlements parsed",
          any(profile["resource"] == "example-orders" for profile in ios) and
          any(profile["protocol"] == "ios-entitlements" for profile in ios))
    check("static artifacts remain inferred", all(profile["confidence"] == "inferred" for profile in ios))
    desktop = TA.adapt(artifacts["desktop"])
    check("desktop bundle is not misclassified as Android",
          desktop["adapter"] == "desktop" and any(p["protocol"] == "desktop-url-scheme" for p in desktop["profiles"]))
    terraform = TA.adapt(artifacts["terraform"])
    kubernetes = TA.adapt(artifacts["kubernetes"])
    check("infrastructure artifacts preserve declared fields",
          terraform["profiles"][0]["inputs"] and kubernetes["profiles"][0]["inputs"])
    contract = TA.adapt(artifacts["contract"])
    check("contract functions have behavior-derived state",
          len(contract["profiles"]) == 2 and
          {p["state"]["mutates"] for p in contract["profiles"]} == {False, True})
    nested = TP.generate_test_cases([{"url": "https://api.test/orders/42", "method": "PATCH",
                                      "params": [{"name": "id", "in": "path", "type": "string"}],
                                      "body_params": [{"name": "amount", "in": "body", "type": "number"}]}])[0]
    check("schema parameter objects normalize without losing profile detail",
          nested["params"] == ["id"] and nested["body_params"] == ["amount"] and
          nested["function_profile"]["inputs"][1]["type"] == "number", nested)
    check("structured parameters have stable case identity",
          TP.case_id(nested) == TP.case_id(dict(nested, params=[{"name": "id", "type": "string"}])) and
          TP.state_key(dict(nested, params=[{"name": "id"}])) == TP.state_key(nested))


def test_behavior_not_names():
    common = {"url": "https://api.test/same/lookalike", "method": "POST",
              "body_params": [{"name": "value", "location": "body"}], "confidence": "high"}
    first = FP.from_endpoint(dict(common, actors={"owner": "A", "tenant": "one"},
                                relationships=[{"type": "contains", "target": "child"}]))
    second = FP.from_endpoint(dict(common, protocol="event-stream", effects=[{"type": "callback"}],
                                   logic_invariants=["opened before finished"]))
    one = TP.generate_test_cases([dict(common, function_profile=first)])[0]
    two = TP.generate_test_cases([dict(common, function_profile=second)])[0]
    check("identical URLs produce different observed-behavior plans",
          one["trust_dimensions"] != two["trust_dimensions"] and
          "tenant_boundary" in one["trust_dimensions"] and "workflow_logic" in two["trust_dimensions"])
    check("URL and parameter names do not select vulnerability work",
          SM.skills_for("deep", url="https://api.test/admin/xss/ssrf") == [] and
          SM.skills_for("dynamic", url="https://api.test/admin/xss/ssrf") == [])
    check("preserved profile retains non-HTTP and workflow evidence",
          two["function_profile"]["profile_id"] == second["profile_id"] and
          two["function_profile"]["logic_invariants"])
    import discovery as D
    class ObservedScope:
        def in_scope_host(self, url):
            return url.startswith("https://api.test/")
    relationships = D._observation_operations({"unfamiliar": {"pointer": "/arbitrary"}},
                                               "https://api.test/root", ObservedScope())
    check("arbitrary nested relationship fields become unvalidated leads",
          relationships[0]["url"] == "https://api.test/arbitrary" and
          relationships[0]["provenance"] == "relationship_lead")


def main():
    test_skill_gate()
    test_dimensional_coverage()
    test_real_artifact_adapters()
    test_behavior_not_names()
    print(f"\nDYNAMIC HARNESS TESTS: {PASS} PASS, 0 FAIL")
    return 0


if __name__ == "__main__":
    sys.exit(main())
