#!/usr/bin/env python3
"""Render an evidence-weighted dynamic-harness assessment from actual gate artifacts."""
import json
import os
import time

EVAL = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(EVAL))
ARTIFACTS = os.path.join(REPO, "artifacts", "release-validation")


def load(name):
    with open(os.path.join(ARTIFACTS, name)) as fh:
        return json.load(fh)


def ratio(ok, total):
    return ok / max(total, 1)


def main():
    gate = load("release-gate.json")
    matrix = load("dynamic-matrix-results.json")
    families = load("model-family-results.json")
    rows = matrix["results"]
    live = [row for row in rows if row["kind"] == "live-target"]
    artifact = [row for row in rows if row["kind"] == "artifact-only"]
    breadth_units = sum(row["status"] == "PASS" for row in live) + 0.5 * sum(row["status"] == "PASS" for row in artifact)
    breadth_score = 20 * ratio(breadth_units, len(rows))
    discovery_rows = live
    discovery_score = 15 * ratio(sum(row["status"] == "PASS" for row in discovery_rows), len(discovery_rows))
    dynamic = gate["dynamic_regression"]
    dynamic_ratio = ratio(dynamic["passed"], dynamic["total"])
    family_rows = families["results"]
    behavior_checks = ("transport_observations", "baseline_observation_ids", "target_derived_hypotheses",
                       "dimensional_results_accepted", "scope_compliance", "claim_consistency",
                       "independent_reproduction", "draft_only_no_submission")
    behavior_ratio = ratio(sum(all(row.get("checks", {}).get(check) for check in behavior_checks)
                               for row in family_rows), len(family_rows))
    hypothesis_score = 15 * (0.5 * dynamic_ratio + 0.5 * behavior_ratio)
    dimensional_score = 20 * (0.4 * dynamic_ratio + 0.3 * behavior_ratio +
                              0.3 * ratio(matrix["summary"]["passed"], matrix["summary"]["total"]))
    requirement_rows = gate["requirements"]
    safety_ratio = ratio(sum(value == "PASS" for value in requirement_rows.values()), len(requirement_rows))
    safety_score = 20 * safety_ratio if not gate["oos_requests_total"] else 0
    family_ratio = ratio(families["summary"]["families_passed"], families["summary"]["families_total"])
    ping = gate["model_pool_ping"]
    ping_ratio = ratio(ping["working"], ping["working"] + ping["failed"])
    model_score = 10 * (0.8 * family_ratio + 0.2 * ping_ratio)
    categories = {
        "target_artifact_breadth": {"weight": 20, "score": round(breadth_score, 1),
                                    "evidence": f"{len(live)} live rows at full weight + {len(artifact)} artifact-only rows at half weight"},
        "adaptive_discovery": {"weight": 15, "score": round(discovery_score, 1),
                               "evidence": f"{sum(row['status'] == 'PASS' for row in discovery_rows)}/{len(discovery_rows)} live discovery rows"},
        "hypothesis_late_execution": {"weight": 15, "score": round(hypothesis_score, 1),
                                      "evidence": f"dynamic={dynamic_ratio:.2f}, live behavior={behavior_ratio:.2f}"},
        "dimensional_coverage": {"weight": 20, "score": round(dimensional_score, 1),
                                 "evidence": "per-dimension regression, matrix, and live model evidence"},
        "evidence_and_safety": {"weight": 20, "score": round(safety_score, 1),
                                "evidence": f"{sum(value == 'PASS' for value in requirement_rows.values())}/{len(requirement_rows)} requirements; OOS={gate['oos_requests_total']}"},
        "model_family_robustness": {"weight": 10, "score": round(model_score, 1),
                                    "evidence": f"families={families['summary']['families_passed']}/{families['summary']['families_total']}; ping={ping['working']}/{ping['working'] + ping['failed']}"},
    }
    total = round(sum(category["score"] for category in categories.values()), 1)
    gates_open = not (families["summary"]["families_failed"] or matrix["summary"]["failed"] or dynamic["failed"])
    report = {
        "schema_version": 1,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "score": total, "maximum": 100,
        "interpretation": "Engineering-validation score, not vulnerability yield or production-target coverage",
        "verdict": "PASS_WITH_LIMITS" if total >= 80 and gates_open else "NEEDS_WORK",
        "categories": categories,
        "remaining_limits": [
            "Live behavior was tested on a local deliberately vulnerable app, not diverse production applications",
            "Cloud, LLM/MCP, infrastructure, desktop, contract, Android, and iOS rows validate artifacts only; no corresponding live provider, device, chain, or desktop runtime was tested",
            "Unsupported target types remain unclaimed: " + ", ".join(matrix.get("unsupported") or []),
            "Every configured label, or one host-default case, was evaluated per scenario only on the active command; other AI runtimes were not tested",
            "Model outcomes and cost vary by run; earlier attempts include timeouts and differing claim conservatism",
            "Local lab solve behavior does not measure expert business-logic chaining or real-world bug yield",
            "Burp/MCP, bridge, n8n, and panel warnings in release-gate.json remain separate from these local checks",
            "Agent shell execution still lacks OS-level network containment",
        ],
        "sources": ["release-gate.json", "dynamic-matrix-results.json", "model-family-results.json"],
    }
    path = os.path.join(ARTIFACTS, "dynamic-harness-assessment.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"dynamic harness: {total}/100 ({report['verdict']})")
    print(f"report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
