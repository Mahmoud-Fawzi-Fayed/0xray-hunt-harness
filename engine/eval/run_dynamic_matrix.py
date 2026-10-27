#!/usr/bin/env python3
"""Exercise live targets and real artifact containers through the dynamic profile pipeline."""
import argparse
import json
import os
import plistlib
import sys
import tempfile
import time
import zipfile

EVAL = os.path.dirname(os.path.abspath(__file__))
ENGINE_ROOT = os.path.dirname(EVAL)
REPO = os.path.dirname(ENGINE_ROOT)
ENGINE = os.path.join(ENGINE_ROOT, "engine")
TESTS = os.path.join(ENGINE_ROOT, "tests")
sys.path.insert(0, ENGINE)
sys.path.insert(0, TESTS)

import discovery as D
import evidence as EV
import scope as S
import target_adapters as TA
import testplan as TP
from vuln_app import start_threaded, get_oos_requests


def endpoint_from_profile(profile):
    actors = profile.get("actors") or {}
    return {
        "url": (profile.get("metadata") or {}).get("url") or profile.get("resource"),
        "method": (profile.get("metadata") or {}).get("method") or "GET",
        "protocol": profile.get("protocol"), "action": profile.get("action"),
        "params": profile.get("inputs") or [], "auth_required": bool(actors.get("authenticated")),
        "role": (actors.get("roles") or [""])[0] if isinstance(actors.get("roles"), list) else actors.get("roles", ""),
        "owner": actors.get("owner", ""), "tenant": actors.get("tenant", ""),
        "effects": profile.get("effects") or [], "state": profile.get("state") or {},
        "function_profile": profile,
        "confidence": profile.get("confidence"), "provenance": (profile.get("provenance") or ["unknown"])[0],
    }


def verify_profiles(row, profiles, work):
    protocols = {profile.get("protocol") for profile in profiles}
    missing_protocols = set(row["protocols"]) - protocols
    if missing_protocols:
        raise AssertionError(f"missing protocols: {sorted(missing_protocols)}; got {sorted(protocols)}")
    endpoints = [endpoint_from_profile(profile) for profile in profiles]
    cases = TP.generate_test_cases(endpoints)
    if not cases:
        raise AssertionError("no test cases generated")
    dimensions = set().union(*(set(case.get("trust_dimensions") or []) for case in cases))
    missing = set(row.get("dimensions") or []) - dimensions
    if missing:
        raise AssertionError(f"missing trust dimensions: {sorted(missing)}; got {sorted(dimensions)}")
    coverage = TP.plan_coverage(cases)
    if coverage["dimension_total"] and coverage["dimension_tested"]:
        raise AssertionError("pending matrix cases claimed dimensional coverage")
    case = cases[0]
    applicable = case.get("trust_dimensions") or []
    accepted = 0
    if applicable:
        case_id = TP.case_id(case)
        obs = EV.record_observation(work, case.get("method"), case.get("endpoint"),
                                    resp_status=403, case_id=case_id)
        result = TP.apply_hypothesis_results(case, [{
            "hypothesis": "matrix control varies exactly one observed trust assumption",
            "dimension": applicable[0], "status": "disproved", "observation_ids": [obs],
            "evidence": "server rejected the control variation with 403",
        }], evidence_dir=work, case_key=case_id)
        accepted = result["accepted"]
        if accepted != 1:
            raise AssertionError("one matrix dimension did not accept matching evidence")
    return {"profiles": len(profiles), "cases": len(cases),
            "protocols": sorted(protocols), "trust_dimensions": sorted(dimensions),
            "dimension_results_accepted": accepted}


def make_artifacts(root):
    paths = {}
    paths["cloud"] = os.path.join(root, "cloud.json")
    with open(paths["cloud"], "w") as fh:
        json.dump({"resources": {"arn:example:orders": {
            "arn": "arn:example:orders", "account": "tenant-a", "owner": "service-orders",
            "permissions": ["read", "write"], "sensitivity": {"level": 3},
        }}}, fh)
    paths["llm"] = os.path.join(root, "llm.json")
    with open(paths["llm"], "w") as fh:
        json.dump({"authenticated": True, "tools": {"lookup_order": {
            "description": "Look up an order through the backend", "callback": "https://api.test/hooks/orders",
            "parameters": {"order_id": {"type": "string"}}, "action": "lookup",
        }}, "memory": {"order_history": {"schema": {"owner": "string", "orders": "array"},
                                          "sensitivity": {"level": 4}}}}, fh)
    paths["mcp"] = os.path.join(root, "mcp.json")
    with open(paths["mcp"], "w") as fh:
        json.dump({"protocol": "mcp", "tools": [{"name": "arbitrary_capability",
                   "parameters": {"value": {"type": "string"}}, "mutates": True}]}, fh)
    paths["terraform"] = os.path.join(root, "main.tf")
    with open(paths["terraform"], "w") as fh:
        fh.write('resource "example_collection" "alpha" {\n  owner = "tenant-a"\n  entries = ["one"]\n}\n')
    paths["kubernetes"] = os.path.join(root, "resources.yaml")
    with open(paths["kubernetes"], "w") as fh:
        fh.write("apiVersion: example/v1\nkind: ArbitraryWorkload\nmetadata:\n  name: alpha\nspec:\n  principal: tenant-a\n  replicas: 1\n")
    paths["android"] = os.path.join(root, "android")
    os.makedirs(paths["android"])
    with open(os.path.join(paths["android"], "AndroidManifest.xml"), "w") as fh:
        fh.write("""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.test">
<application><activity android:name=".MainActivity" android:exported="true"><intent-filter>
<action android:name="android.intent.action.VIEW"/><data android:scheme="example" android:host="orders"/>
</intent-filter></activity><service android:name=".PrivateService" android:exported="false"/></application></manifest>""")
    with open(os.path.join(paths["android"], "Api.kt"), "w") as fh:
        fh.write('val request = okhttp3.Request.Builder().url("https://api.test/orders").post(body).build()')
    paths["desktop"] = os.path.join(root, "Example.app")
    os.makedirs(os.path.join(paths["desktop"], "Contents"))
    with open(os.path.join(paths["desktop"], "Contents", "Info.plist"), "wb") as fh:
        fh.write(plistlib.dumps({"CFBundleIdentifier": "test.example.desktop",
                                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example-desktop"]}]}, fmt=plistlib.FMT_BINARY))
    paths["contract"] = os.path.join(root, "Program.sol")
    with open(paths["contract"], "w") as fh:
        fh.write("contract Arbitrary {\n function inspect(bytes32 record) external view returns (uint256) {}\n"
                 " function commit(bytes32 record, uint256 amount) external onlyHolder {}\n}\n")
    paths["ios"] = os.path.join(root, "Example.ipa")
    info = {"CFBundleIdentifier": "test.example", "CFBundleURLTypes": [
        {"CFBundleURLName": "orders", "CFBundleURLSchemes": ["example-orders"]}]}
    with zipfile.ZipFile(paths["ios"], "w") as archive:
        archive.writestr("Payload/Example.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        archive.writestr("Payload/Example.app/Example.entitlements",
                         plistlib.dumps({"application-identifier": "TEAM.test.example"}, fmt=plistlib.FMT_BINARY))
        archive.writestr("Payload/Example.app/main.js", 'fetch("https://api.test/ios/orders")')
    return paths


def run(matrix_path, out_path):
    with open(matrix_path) as fh:
        matrix = json.load(fh)
    work = tempfile.mkdtemp()
    artifacts = make_artifacts(work)
    port = 19879
    app, sink, _ = start_threaded(port)
    from adaptive_app import start_threaded as start_adaptive
    adaptive_app = start_adaptive(0)
    adaptive_port = adaptive_app.server_address[1]
    base = f"http://127.0.0.1:{port}"
    adaptive_base = f"http://127.0.0.1:{adaptive_port}"
    scope = S.Scope([f"127.0.0.1:{port}"], seeds=[base], name="dynamic-matrix")
    adaptive_scope = S.Scope([f"127.0.0.1:{adaptive_port}"], seeds=[adaptive_base], name="schema-less-matrix")
    adaptive_inventory = None
    results = []
    try:
        import netget
        netget.set_scope_guard(scope)
        for row in matrix["rows"]:
            started = time.time()
            try:
                adapter = row["adapter"]
                extra = {}
                if adapter == "http":
                    status, body, _ = netget.get(base + "/api/search?q=matrix")
                    if status != 200 or "matrix" not in body:
                        raise AssertionError(f"live HTTP baseline failed: {status}")
                    profiles = TA.http_profiles([{"url": base + "/api/search?q=matrix", "params": ["q"],
                                                   "provenance": "confirmed_live", "confidence": "high"}])
                elif adapter == "openapi":
                    endpoints = D._discover_openapi(scope, log=lambda _message: None)
                    profiles = TA.http_profiles(endpoints)
                elif adapter == "graphql":
                    import recon
                    scope.endpoints = [base + "/graphql"]
                    endpoints = recon.graphql_recon(scope, log=lambda _message: None)
                    profiles = TA.http_profiles(endpoints)
                elif adapter == "browser":
                    try:
                        import browser
                        captured = browser.capture(base, scope_hosts=["127.0.0.1"], scope=scope, wait=2, pages=2)
                    except ImportError as exc:
                        results.append({"id": row["id"], "kind": row["kind"], "status": "BLOCKED",
                                        "detail": str(exc)})
                        continue
                    profiles = TA.http_profiles(captured)
                elif adapter in ("schema-less", "json-rpc", "event-stream", "workflow"):
                    if adaptive_inventory is None:
                        os.environ["HUNT_DISCOVERY_BUDGET_SEC"] = "60"
                        adaptive_inventory = D.discover("schema-less-matrix", adaptive_scope,
                                                        base=work, log=lambda _message: None)
                    profiles = adaptive_inventory["coverage"]["function_profiles"]
                    if adapter == "json-rpc":
                        profiles = [profile for profile in profiles if profile.get("protocol") == "json-rpc"]
                    elif adapter == "event-stream":
                        profiles = [profile for profile in profiles if profile.get("protocol") == "event-stream"]
                    elif adapter == "workflow":
                        profiles = [profile for profile in profiles if "/transitions/" in profile.get("resource", "")]
                        netget.set_scope_guard(adaptive_scope, allow_intrusive=True)
                        status, body, _ = netget.get(adaptive_base + "/transitions/begin", method="POST",
                                                     data=json.dumps({"account": "local-a", "amount": 1}),
                                                     headers={"Content-Type": "application/json"})
                        created = json.loads(body)
                        if status != 201 or not created.get("next"):
                            raise AssertionError(f"workflow creation failed: {status} {body[:100]}")
                        status, body, _ = netget.get(adaptive_base + created["next"], method="POST", data="{}",
                                                     headers={"Content-Type": "application/json"})
                        if status != 200 or json.loads(body).get("state") != "finished":
                            raise AssertionError(f"workflow transition failed: {status} {body[:100]}")
                        extra["real_state_transition"] = True
                        netget.set_scope_guard(adaptive_scope)
                    extra["discovery_rounds"] = adaptive_inventory["discovery_rounds"]
                    extra["convergence"] = adaptive_inventory["convergence"]
                    extra["observed_operations"] = len(adaptive_inventory["inventory"])
                elif adapter in artifacts:
                    adapted = TA.adapt(artifacts[adapter], base_url=base)
                    if adapted["status"] not in ("completed", "partial"):
                        raise AssertionError(f"artifact adaptation failed: {adapted}")
                    profiles = adapted["profiles"]
                    extra = {"adapter_status": adapted["status"], "residuals": adapted["residuals"]}
                else:
                    raise AssertionError(f"unknown adapter {adapter}")
                detail = verify_profiles(row, profiles, work)
                results.append({"id": row["id"], "kind": row["kind"], "status": "PASS",
                                "elapsed_s": round(time.time() - started, 2), **detail, **extra})
            except Exception as exc:
                results.append({"id": row["id"], "kind": row["kind"], "status": "FAIL",
                                "detail": f"{type(exc).__name__}: {exc}"})
    finally:
        app.shutdown()
        adaptive_app.shutdown()
        if sink:
            sink.shutdown()
    failed = sum(row["status"] == "FAIL" for row in results)
    passed = sum(row["status"] == "PASS" for row in results)
    blocked = sum(row["status"] == "BLOCKED" for row in results)
    report = {"schema_version": 1, "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "summary": {"total": len(results), "passed": passed, "failed": failed, "blocked": blocked},
              "oos_requests": get_oos_requests(), "unsupported": matrix.get("explicitly_unsupported") or [],
              "results": results}
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    for row in results:
        print(f"[{row['status']}] {row['id']} ({row['kind']}): " +
              (str(row.get("profiles", row.get("detail", "")))))
    print(f"matrix: {passed} PASS, {failed} FAIL, {blocked} BLOCKED; OOS={len(report['oos_requests'])}")
    print(f"report: {out_path}")
    return 1 if failed or report["oos_requests"] else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", default=os.path.join(EVAL, "dynamic_matrix.json"))
    parser.add_argument("--out", default=os.path.join(REPO, "artifacts", "release-validation", "dynamic-matrix-results.json"))
    args = parser.parse_args()
    return run(args.matrix, args.out)


if __name__ == "__main__":
    sys.exit(main())
