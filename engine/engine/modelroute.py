#!/usr/bin/env python3
"""Select opaque labels from the active model pool and derive effort budgets.

Model names are never mapped to providers or price tiers. With no configured
pool, model=None delegates selection to the active runtime's default.
"""
import argparse
import json
import os
import threading

PHASE_TASK = {
    "recon": "recon", "novelty": "novelty", "map": "map", "plan": "plan",
    "explore": "explore", "hunt": "hunt", "validate": "verify", "report": "report_format",
    "coverage": "coverage", "dedup": "dedup", "profile": "profile", "discover": "discover",
}
TASK_EFFORT = {
    "recon": "low", "novelty": "low", "dedup": "low", "scope_check": "low",
    "dns": "low", "parse": "low", "filter": "low", "observe": "low",
    "intake": "low", "tempmail": "low", "sms_check": "low",
    "map": "medium", "plan": "medium", "profile": "medium", "explore": "medium",
    "coverage": "medium", "report_format": "medium", "browser_analyze": "medium",
    "inventory": "medium", "learn": "medium", "testplan": "medium",
    "hunt": "high", "verify": "high", "exploit": "high", "auth_test": "high",
    "impact": "high", "bypass": "high", "report_draft": "high", "hunt_deep": "high",
    "validate": "high", "discover": "high", "hypothesize": "high", "creative_bypass": "high",
}
TOKEN_BUDGETS = {
    "low": {"max_tokens": 1024, "thinking_budget": 0},
    "medium": {"max_tokens": 4096, "thinking_budget": 2048},
    "high": {"max_tokens": 16384, "thinking_budget": 8192},
}
_EFFORTS = ("low", "medium", "high")


def model_for(task, complexity=None):
    """Return an override/pool label, or None for the active host default."""
    del task, complexity
    override = os.environ.get("HUNT_MODEL_OVERRIDE")
    if override:
        return override
    import agent
    return agent._pick_model()


def model_for_phase(phase):
    return model_for(PHASE_TASK.get(phase, phase))


def effort_for(task, complexity=None):
    override = os.environ.get("HUNT_EFFORT_OVERRIDE")
    if override in TOKEN_BUDGETS:
        return override
    if complexity in TOKEN_BUDGETS:
        return complexity
    task = str(task or "")
    return TASK_EFFORT.get(PHASE_TASK.get(task, task), "medium")


def budget_for(task, complexity=None):
    budget = dict(TOKEN_BUDGETS[effort_for(task, complexity)])
    cap = os.environ.get("HUNT_MAX_TOKENS")
    if cap:
        try:
            budget["max_tokens"] = min(budget["max_tokens"], int(cap))
        except ValueError:
            pass
    return budget


def route(task, context=None):
    model, complexity = smart_model(task, context)
    effort = effort_for(task, complexity)
    return model, effort, budget_for(task, complexity)


def route_for_phase(phase, context=None):
    return route(PHASE_TASK.get(phase, phase), context)


def escalate(current_model, current_effort):
    """Increase effort on the same host/model; never switch provider by tier."""
    try:
        effort = _EFFORTS[_EFFORTS.index(current_effort) + 1]
    except (ValueError, IndexError):
        return None
    return current_model, effort


def estimate_complexity(task, context=None):
    context = context if isinstance(context, dict) else {}
    task = str(task or "")
    if task in ("recon", "novelty", "dedup", "scope_check", "dns",
                "parse", "filter", "observe", "intake"):
        return "low"
    parameters = context.get("params") or context.get("param_count") or 0
    try:
        parameters = int(parameters)
    except (TypeError, ValueError):
        parameters = 0
    try:
        sensitivity = int(context.get("sensitivity", 0) or 0)
        boundaries = int(context.get("boundaries", 0) or 0)
    except (TypeError, ValueError):
        sensitivity = boundaries = 0
    if context.get("previous_result") in ("inconclusive", "timeout", "error"):
        return "high"
    if parameters > 5 or context.get("auth_required") or sensitivity >= 3 or boundaries >= 3:
        return "high"
    return "medium"


def smart_model(task, context=None):
    complexity = estimate_complexity(task, context)
    return model_for(task, complexity=complexity), complexity


_lock = threading.Lock()
_usage = {}


def track_usage(model, input_tokens=0, output_tokens=0):
    label = str(model or "host-default")
    with _lock:
        record = _usage.setdefault(label, {"calls": 0, "input": 0, "output": 0})
        record["calls"] += 1
        record["input"] += int(input_tokens or 0)
        record["output"] += int(output_tokens or 0)


def usage_summary():
    with _lock:
        snapshot = {label: dict(values) for label, values in _usage.items()}
    return {"models": snapshot, "total_calls": sum(values["calls"] for values in snapshot.values()),
            "cost_usd": None, "cost_status": "unknown_without_runtime_metering",
            "effort_levels": dict(TOKEN_BUDGETS)}


def reset_usage():
    with _lock:
        _usage.clear()


_BUDGET_LIMITS = {
    "max_calls": int(os.environ.get("HUNT_MAX_MODEL_CALLS", "500") or 500),
    "max_input_tokens": int(os.environ.get("HUNT_MAX_INPUT_TOKENS", "5000000") or 5_000_000),
}


def budget_exceeded():
    """Return a reason string if any engagement budget is exceeded, None otherwise."""
    with _lock:
        total_calls = sum(v["calls"] for v in _usage.values())
        total_input = sum(v["input"] for v in _usage.values())
    if total_calls >= _BUDGET_LIMITS["max_calls"]:
        return f"model call limit reached ({total_calls}/{_BUDGET_LIMITS['max_calls']})"
    if total_input >= _BUDGET_LIMITS["max_input_tokens"]:
        return f"input token limit reached ({total_input}/{_BUDGET_LIMITS['max_input_tokens']})"
    return None


def _cmd_route(args):
    model = model_for(args.task, complexity=args.complexity)
    print(json.dumps({"task": args.task, "complexity": args.complexity, "model": model,
                      "effort": effort_for(args.task, args.complexity),
                      "budget": budget_for(args.task, args.complexity)}))
    return 0


def _cmd_estimate(args):
    context = {}
    if args.params:
        context["params"] = args.params
    if args.auth:
        context["auth_required"] = True
    if args.vuln_class:
        context["vuln_class"] = args.vuln_class
    if args.previous:
        context["previous_result"] = args.previous
    model, complexity = smart_model(args.task, context)
    print(json.dumps({"task": args.task, "context": context, "complexity": complexity,
                      "model": model, "effort": effort_for(args.task, complexity),
                      "budget": budget_for(args.task, complexity)}))
    return 0


def _cmd_usage(_args):
    print(json.dumps(usage_summary(), indent=2))
    return 0


def _cmd_selftest(_args):
    saved = {key: os.environ.get(key) for key in ("HUNT_MODELS", "HUNT_MODEL_OVERRIDE",
                                                   "HUNT_EFFORT_OVERRIDE", "HUNT_MAX_TOKENS")}
    try:
        os.environ["HUNT_MODELS"] = "opaque-a,opaque-b"
        os.environ.pop("HUNT_MODEL_OVERRIDE", None)
        assert model_for("recon") in ("opaque-a", "opaque-b")
        assert model_for("hunt", complexity="high") in ("opaque-a", "opaque-b")
        os.environ["HUNT_MODEL_OVERRIDE"] = "custom-label"
        assert model_for("hunt") == "custom-label"
        os.environ.pop("HUNT_MODEL_OVERRIDE", None)
        os.environ.pop("HUNT_MODELS", None)
        assert model_for("anything") is None
        assert estimate_complexity("recon") == "low"
        assert estimate_complexity("hunt", {"params": 8}) == "high"
        assert estimate_complexity("hunt", {"previous_result": "timeout"}) == "high"
        assert effort_for("recon") == "low" and effort_for("hunt") == "high"
        assert escalate("opaque-a", "low") == ("opaque-a", "medium")
        assert escalate("opaque-a", "medium") == ("opaque-a", "high")
        assert escalate("opaque-a", "high") is None
        reset_usage()
        track_usage("opaque-a", 100, 50)
        track_usage("host-default", 200, 100)
        usage = usage_summary()
        assert usage["models"]["opaque-a"]["calls"] == 1
        assert usage["models"]["host-default"]["output"] == 100
        assert usage["cost_usd"] is None
        assert budget_exceeded() is None
        old_limits = dict(_BUDGET_LIMITS)
        _BUDGET_LIMITS["max_calls"] = 2
        track_usage("test-a", 10, 5)
        track_usage("test-a", 10, 5)
        assert budget_exceeded() is not None and "call limit" in budget_exceeded()
        _BUDGET_LIMITS.update(old_limits)
        reset_usage()
        os.environ["HUNT_EFFORT_OVERRIDE"] = "low"
        assert effort_for("hunt") == "low"
        os.environ.pop("HUNT_EFFORT_OVERRIDE", None)
        os.environ["HUNT_MAX_TOKENS"] = "2048"
        assert budget_for("hunt")["max_tokens"] == 2048
        for bad in (None, "", 123, {"x": 1}):
            model_for(bad)
            estimate_complexity(bad, bad)
            effort_for(bad)
            route(bad, bad)
    finally:
        reset_usage()
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    print("modelroute.py generic self-test: PASS")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="active-host model and effort routing")
    commands = parser.add_subparsers(dest="cmd", required=True)
    route_parser = commands.add_parser("route")
    route_parser.add_argument("--task", required=True)
    route_parser.add_argument("--complexity", choices=["low", "medium", "high"])
    route_parser.set_defaults(fn=_cmd_route)
    estimate_parser = commands.add_parser("estimate")
    estimate_parser.add_argument("--task", required=True)
    estimate_parser.add_argument("--params", type=int)
    estimate_parser.add_argument("--auth", action="store_true")
    estimate_parser.add_argument("--vuln-class")
    estimate_parser.add_argument("--previous")
    estimate_parser.set_defaults(fn=_cmd_estimate)
    usage_parser = commands.add_parser("usage")
    usage_parser.set_defaults(fn=_cmd_usage)
    commands.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
