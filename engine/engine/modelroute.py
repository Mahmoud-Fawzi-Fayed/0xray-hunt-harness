#!/usr/bin/env python3
"""
modelroute.py — dynamic model selection based on task complexity.

Routes tasks to the cheapest model that can handle them reliably.
Three tiers:
  Haiku 5.5  — simple/fast: recon, scope, dedup, novelty, parsing
  Sonnet 5.5 — balanced: mapping, planning, coverage, profiling
  Opus 4.6   — deep reasoning: vuln hunting, exploit verification, auth testing

Override with HUNT_MODEL_OVERRIDE env var to force a specific model for all tasks.
Per-tier override: HUNT_MODEL_HAIKU, HUNT_MODEL_SONNET, HUNT_MODEL_OPUS.

CLI:
  python3 engine/engine/modelroute.py route --task hunt
  python3 engine/engine/modelroute.py estimate --task hunt --params 8 --auth
  python3 engine/engine/modelroute.py usage
  python3 engine/engine/modelroute.py selftest
"""
import argparse
import json
import os
import sys
import threading

HAIKU = "claude-haiku-5-5"
SONNET = "claude-sonnet-5-5"
OPUS = "claude-opus-4-6"

TASK_MODELS = {
    # Haiku tier — simple, fast, cheap
    "recon": HAIKU,
    "novelty": HAIKU,
    "dedup": HAIKU,
    "scope_check": HAIKU,
    "dns": HAIKU,
    "parse": HAIKU,
    "filter": HAIKU,
    "observe": HAIKU,
    "intake": HAIKU,
    "tempmail": HAIKU,
    "sms_check": HAIKU,

    # Sonnet tier — balanced
    "map": SONNET,
    "plan": SONNET,
    "profile": SONNET,
    "explore": SONNET,
    "coverage": SONNET,
    "report_format": SONNET,
    "browser_analyze": SONNET,
    "inventory": SONNET,
    "learn": SONNET,
    "testplan": SONNET,

    # Opus tier — deep reasoning only
    "hunt": OPUS,
    "verify": OPUS,
    "exploit": OPUS,
    "auth_test": OPUS,
    "impact": OPUS,
    "bypass": OPUS,
    "report_draft": OPUS,
    "hunt_deep": OPUS,
    "validate": OPUS,
}

# Phases → task type
PHASE_TASK = {
    "recon": "recon",
    "novelty": "novelty",
    "map": "map",
    "plan": "plan",
    "explore": "explore",
    "hunt": "hunt",
    "validate": "verify",
    "report": "report_draft",
    "coverage": "coverage",
    "dedup": "dedup",
    "profile": "profile",
}

# Known standard vuln classes that Sonnet handles well
_STANDARD_CLASSES = frozenset({
    "xss", "reflected-xss", "stored-xss", "sqli", "sql-injection",
    "open-redirect", "csrf", "cors", "clickjacking", "info-disclosure",
    "directory-traversal", "path-traversal", "lfi", "rfi",
    "missing-headers", "verbose-error", "version-disclosure",
})

# Complex classes that need Opus
_COMPLEX_CLASSES = frozenset({
    "idor", "bac", "broken-access-control", "privilege-escalation",
    "auth-bypass", "authentication-bypass", "ssrf", "race-condition",
    "business-logic", "mass-assignment", "jwt-manipulation",
    "deserialization", "prototype-pollution", "cache-poisoning",
    "request-smuggling", "websocket-hijack",
})

DEFAULT_MODEL = SONNET


def _tier_model(tier):
    """Resolve tier to model, respecting per-tier env overrides."""
    if tier == HAIKU:
        return os.environ.get("HUNT_MODEL_HAIKU", HAIKU)
    if tier == OPUS:
        return os.environ.get("HUNT_MODEL_OPUS", OPUS)
    return os.environ.get("HUNT_MODEL_SONNET", SONNET)


def model_for(task, complexity=None):
    """Get the right model for a task.

    Args:
        task: task type string (e.g. "recon", "hunt", "map") or phase name
        complexity: optional override - "low", "medium", "high"

    Returns model ID string.
    """
    override = os.environ.get("HUNT_MODEL_OVERRIDE")
    if override:
        return override

    if complexity == "low":
        return _tier_model(HAIKU)
    elif complexity == "high":
        return _tier_model(OPUS)
    elif complexity == "medium":
        return _tier_model(SONNET)

    task_s = str(task or "")
    resolved = PHASE_TASK.get(task_s, task_s)
    base = TASK_MODELS.get(resolved, DEFAULT_MODEL)
    return _tier_model(base)


def model_for_phase(phase):
    """Convenience: get model for an engine phase name."""
    return model_for(PHASE_TASK.get(phase, phase))


def estimate_complexity(task, context=None):
    """Dynamically estimate task complexity based on context.

    Args:
        task: task type string
        context: optional dict with keys like:
            params (int), auth_required (bool), vuln_class (str),
            previous_result (str: "inconclusive"/"timeout"/"error"/None),
            framework (str), param_count (int)

    Returns "low", "medium", or "high".
    """
    ctx = context if isinstance(context, dict) else {}

    task = str(task or "")
    if task in ("recon", "novelty", "dedup", "scope_check", "dns",
                "parse", "filter", "observe", "intake"):
        return "low"

    vuln_class = (ctx.get("vuln_class") or "").lower().replace(" ", "-")
    param_count = ctx.get("params") or ctx.get("param_count") or 0
    auth_required = ctx.get("auth_required", False)
    prev = ctx.get("previous_result")

    # Escalation: previous attempt was inconclusive or timed out
    if prev in ("inconclusive", "timeout", "error"):
        return "high"

    # Complex vuln classes always need Opus
    if vuln_class in _COMPLEX_CLASSES:
        return "high"

    # Many params or auth-involved → higher complexity
    if param_count > 5 or auth_required:
        if vuln_class in _STANDARD_CLASSES:
            return "medium"
        return "high"

    # Standard OWASP on known patterns
    if vuln_class in _STANDARD_CLASSES:
        return "medium"

    if task in ("hunt", "verify", "exploit", "auth_test", "validate"):
        return "high"

    return "medium"


def smart_model(task, context=None):
    """Combined: estimate complexity then pick model."""
    c = estimate_complexity(task, context)
    return model_for(task, complexity=c), c


# ---------------------------------------------------------------------------
# Token usage tracking (process-local, thread-safe)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_usage = {"haiku": {"calls": 0, "input": 0, "output": 0},
          "sonnet": {"calls": 0, "input": 0, "output": 0},
          "opus": {"calls": 0, "input": 0, "output": 0}}

# Approximate per-token costs (USD per 1M tokens, as of 2026)
_COSTS = {
    "haiku":  {"input": 0.80, "output": 4.00},
    "sonnet": {"input": 3.00, "output": 15.00},
    "opus":   {"input": 15.00, "output": 75.00},
}


def _tier_of(model):
    m = (model or "").lower()
    if "haiku" in m:
        return "haiku"
    if "opus" in m:
        return "opus"
    return "sonnet"


def track_usage(model, input_tokens=0, output_tokens=0):
    """Record token usage for a model call."""
    tier = _tier_of(model)
    with _lock:
        _usage[tier]["calls"] += 1
        _usage[tier]["input"] += input_tokens
        _usage[tier]["output"] += output_tokens


def usage_summary():
    """Return usage stats with estimated costs and savings vs all-Opus."""
    with _lock:
        snap = {k: dict(v) for k, v in _usage.items()}

    total_cost = 0.0
    opus_equivalent = 0.0
    for tier, u in snap.items():
        inp_cost = u["input"] * _COSTS[tier]["input"] / 1_000_000
        out_cost = u["output"] * _COSTS[tier]["output"] / 1_000_000
        total_cost += inp_cost + out_cost
        opus_inp = u["input"] * _COSTS["opus"]["input"] / 1_000_000
        opus_out = u["output"] * _COSTS["opus"]["output"] / 1_000_000
        opus_equivalent += opus_inp + opus_out
        snap[tier]["cost_usd"] = round(inp_cost + out_cost, 4)

    saved = opus_equivalent - total_cost
    return {
        "tiers": snap,
        "total_cost_usd": round(total_cost, 4),
        "all_opus_cost_usd": round(opus_equivalent, 4),
        "saved_usd": round(max(0, saved), 4),
        "saving_pct": round(saved / opus_equivalent * 100, 1) if opus_equivalent > 0 else 0,
    }


def reset_usage():
    """Reset counters (for testing)."""
    with _lock:
        for v in _usage.values():
            v["calls"] = v["input"] = v["output"] = 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cmd_route(a):
    m = model_for(a.task, complexity=a.complexity)
    print(json.dumps({"task": a.task, "complexity": a.complexity, "model": m}))
    return 0


def _cmd_estimate(a):
    ctx = {}
    if a.params:
        ctx["params"] = a.params
    if a.auth:
        ctx["auth_required"] = True
    if a.vuln_class:
        ctx["vuln_class"] = a.vuln_class
    if a.previous:
        ctx["previous_result"] = a.previous
    m, c = smart_model(a.task, ctx)
    print(json.dumps({"task": a.task, "context": ctx, "complexity": c, "model": m}))
    return 0


def _cmd_usage(_a):
    print(json.dumps(usage_summary(), indent=2))
    return 0


def _cmd_selftest(_a):
    # Basic routing
    assert model_for("recon") == HAIKU, model_for("recon")
    assert model_for("map") == SONNET, model_for("map")
    assert model_for("hunt") == OPUS, model_for("hunt")
    assert model_for("unknown_task") == SONNET  # default

    # Complexity override
    assert model_for("recon", complexity="high") == OPUS
    assert model_for("hunt", complexity="low") == HAIKU

    # Phase mapping
    assert model_for_phase("recon") == HAIKU
    assert model_for_phase("validate") == OPUS
    assert model_for_phase("plan") == SONNET

    # Env override
    os.environ["HUNT_MODEL_OVERRIDE"] = "custom-model"
    assert model_for("hunt") == "custom-model"
    del os.environ["HUNT_MODEL_OVERRIDE"]

    # Per-tier override
    os.environ["HUNT_MODEL_HAIKU"] = "claude-haiku-5-5-custom"
    assert model_for("recon") == "claude-haiku-5-5-custom"
    del os.environ["HUNT_MODEL_HAIKU"]

    # Complexity estimation
    assert estimate_complexity("recon") == "low"
    assert estimate_complexity("hunt", {"vuln_class": "idor"}) == "high"
    assert estimate_complexity("hunt", {"vuln_class": "xss"}) == "medium"
    assert estimate_complexity("hunt", {"vuln_class": "xss", "params": 8}) == "medium"
    assert estimate_complexity("hunt", {"vuln_class": "unknown", "params": 8, "auth_required": True}) == "high"
    assert estimate_complexity("hunt", {"previous_result": "inconclusive"}) == "high"
    assert estimate_complexity("hunt", {"previous_result": "timeout"}) == "high"
    assert estimate_complexity("map") == "medium"

    # Smart model (combined)
    m, c = smart_model("hunt", {"vuln_class": "xss"})
    assert m == SONNET and c == "medium", (m, c)
    m, c = smart_model("hunt", {"vuln_class": "idor"})
    assert m == OPUS and c == "high", (m, c)
    m, c = smart_model("recon")
    assert m == HAIKU and c == "low", (m, c)

    # Escalation: previous inconclusive → Opus
    m, c = smart_model("hunt", {"vuln_class": "xss", "previous_result": "inconclusive"})
    assert m == OPUS and c == "high", (m, c)

    # Token tracking
    reset_usage()
    track_usage(HAIKU, 1000, 500)
    track_usage(SONNET, 2000, 1000)
    track_usage(OPUS, 500, 200)
    s = usage_summary()
    assert s["tiers"]["haiku"]["calls"] == 1
    assert s["tiers"]["sonnet"]["calls"] == 1
    assert s["tiers"]["opus"]["calls"] == 1
    assert s["total_cost_usd"] < s["all_opus_cost_usd"]
    assert s["saved_usd"] > 0
    assert s["saving_pct"] > 0
    reset_usage()

    # Hostile input
    for bad in (None, "", 123, {"x": 1}):
        model_for(bad)
        estimate_complexity(bad, bad)

    print("modelroute.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="smart model routing for hunt harness")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("route", help="Get model for a task")
    pr.add_argument("--task", required=True)
    pr.add_argument("--complexity", choices=["low", "medium", "high"], default=None)
    pr.set_defaults(fn=_cmd_route)

    pe = sub.add_parser("estimate", help="Estimate complexity and model")
    pe.add_argument("--task", required=True)
    pe.add_argument("--params", type=int, default=None)
    pe.add_argument("--auth", action="store_true")
    pe.add_argument("--vuln-class", default=None)
    pe.add_argument("--previous", default=None)
    pe.set_defaults(fn=_cmd_estimate)

    pu = sub.add_parser("usage", help="Show token usage summary")
    pu.set_defaults(fn=_cmd_usage)

    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
