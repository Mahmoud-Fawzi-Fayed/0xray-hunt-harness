"""Protocol-neutral function model derived from observed target behavior.

This module contains no vulnerability classes. It describes what a function does,
which actors/resources interact, and which trust dimensions still need evidence.
"""
import hashlib
import json

SCHEMA_VERSION = 1


def _list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value not in (None, "") else []


def _records(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _dict(value):
    return dict(value) if isinstance(value, dict) else {}


def profile_id(profile):
    canonical = json.dumps({
        "protocol": profile.get("protocol", ""),
        "action": profile.get("action", ""),
        "resource": profile.get("resource", ""),
        "actors": profile.get("actors", {}),
        "inputs": profile.get("inputs", []),
        "state": profile.get("state", {}),
        "relationships": profile.get("relationships", []),
        "logic_invariants": profile.get("logic_invariants", []),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:20]


def new_profile(action, resource, protocol="http", **kwargs):
    profile = {
        "schema_version": SCHEMA_VERSION,
        "protocol": protocol or "unknown",
        "action": action or "unknown",
        "resource": resource or "unknown",
        "actors": _dict(kwargs.get("actors")),
        "inputs": _records(kwargs.get("inputs")),
        "outputs": _dict(kwargs.get("outputs")),
        "effects": _records(kwargs.get("effects")),
        "preconditions": _records(kwargs.get("preconditions")),
        "relationships": _records(kwargs.get("relationships")),
        "logic_invariants": _list(kwargs.get("logic_invariants")),
        "residuals": _records(kwargs.get("residuals")),
        "state": _dict(kwargs.get("state")),
        "sensitivity": _dict(kwargs.get("sensitivity")),
        "provenance": _list(kwargs.get("provenance") or ["observed"]),
        "observations": _list(kwargs.get("observations")),
        "confidence": kwargs.get("confidence", "observed"),
        "metadata": _dict(kwargs.get("metadata")),
    }
    profile["trust_dimensions"] = trust_dimensions(profile)
    profile["trust_dimensions"] = list(dict.fromkeys(
        profile["trust_dimensions"] + _list(kwargs.get("additional_dimensions"))))
    profile["profile_id"] = profile_id(profile)
    return profile


def trust_dimensions(profile):
    dimensions = []
    actors = profile.get("actors") or {}
    if actors.get("authenticated") or actors.get("roles") or actors.get("identities"):
        dimensions.append("actor_variation")
    if actors.get("owner") or actors.get("tenant") or actors.get("ownership"):
        dimensions.append("ownership_boundary")
    if actors.get("tenant") or actors.get("organization"):
        dimensions.append("tenant_boundary")
    if profile.get("inputs"):
        dimensions.append("input_variation")
    inputs = profile.get("inputs") or []
    if any((i.get("location") if isinstance(i, dict) else "") in ("body", "file", "header", "cookie") for i in inputs):
        dimensions.append("content_and_parser_variation")
    if profile.get("effects") or profile.get("preconditions") or (profile.get("state") or {}).get("mutates"):
        dimensions.append("state_and_sequence")
    effects = profile.get("effects") or []
    if any((e.get("type") if isinstance(e, dict) else str(e)) in
           ("external_call", "callback", "webhook", "second_order", "integration") for e in effects):
        dimensions.append("external_effect")
    if any((i.get("type") if isinstance(i, dict) else "") == "file" for i in inputs):
        dimensions.append("file_handling")
    if actors.get("roles"):
        dimensions.append("role_transition")
    if profile.get("protocol") and profile["protocol"] != "http":
        dimensions.append("protocol_behavior")
    if profile.get("relationships"):
        dimensions.append("relationship_boundary")
    if (profile.get("logic_invariants") or profile.get("relationships")
            or profile.get("preconditions") or profile.get("effects") or profile.get("state")):
        dimensions.append("workflow_logic")
    if (profile.get("sensitivity") or {}).get("level", 0):
        dimensions.append("data_confidentiality")
    return list(dict.fromkeys(dimensions))


def impact_score(profile):
    """Rank business impact and untested trust, never a vulnerability label or URL name."""
    score = 0
    sensitivity = profile.get("sensitivity") or {}
    score += min(int(sensitivity.get("level", 0) or 0), 5) * 12
    score += len(profile.get("trust_dimensions") or []) * 8
    score += min(len(profile.get("effects") or []), 4) * 7
    actors = profile.get("actors") or {}
    score += 10 if actors.get("tenant") or actors.get("owner") else 0
    score += 8 if (profile.get("state") or {}).get("mutates") else 0
    score += 6 if profile.get("protocol") not in ("http", "unknown") else 0
    if profile.get("confidence") in ("inferred", "low", "unknown"):
        score = min(score, 25)
    return score


def from_endpoint(endpoint):
    """Normalize a discovered endpoint/artifact without using its URL as a class signal."""
    actors = _dict(endpoint.get("actors"))
    if endpoint.get("auth_required"):
        actors["authenticated"] = True
    if endpoint.get("role"):
        actors["roles"] = _list(endpoint["role"])
    if endpoint.get("owner"):
        actors["owner"] = endpoint["owner"]
    if endpoint.get("tenant"):
        actors["tenant"] = endpoint["tenant"]
    if endpoint.get("accessor"):
        actors["accessor"] = endpoint["accessor"]
    inputs = []
    for values, default_location in (
            (endpoint.get("params") or ([endpoint["param"]] if endpoint.get("param") else []), "query"),
            (endpoint.get("body_params") or [], "body")):
        if isinstance(values, (str, dict)):
            values = [values]
        for value in values:
            item = dict(value) if isinstance(value, dict) else {"name": str(value)}
            item.setdefault("name", "unnamed")
            item.setdefault("location", item.get("in") or default_location)
            item.setdefault("type", "scalar")
            inputs.append(item)
    if endpoint.get("accepts_file"):
        inputs.append({"name": "content", "location": "file", "type": "file"})
    effects = list(endpoint.get("effects") or [])
    method = str(endpoint.get("method") or "GET").upper()
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        effects.append({"type": "state_change", "method": method})
    sensitivity = _dict(endpoint.get("sensitivity"))
    sensitivity.setdefault("level", 0)
    state = _dict(endpoint.get("state"))
    state.setdefault("mutates", method in ("POST", "PUT", "PATCH", "DELETE"))
    provenance = endpoint.get("provenance") or endpoint.get("confidence") or "observed"
    return new_profile(
        action=endpoint.get("function") or endpoint.get("action") or method,
        resource=endpoint.get("resource") or endpoint.get("url") or endpoint.get("path") or "unknown",
        protocol=endpoint.get("protocol") or "http",
        actors=actors, inputs=inputs, outputs=endpoint.get("outputs") or {},
        effects=effects, preconditions=endpoint.get("preconditions") or [],
        relationships=endpoint.get("relationships") or [],
        logic_invariants=endpoint.get("logic_invariants") or [],
        residuals=endpoint.get("residuals") or [],
        additional_dimensions=endpoint.get("additional_dimensions") or [],
        state=state, sensitivity=sensitivity,
        provenance=[provenance], observations=endpoint.get("observations") or [],
        confidence=endpoint.get("confidence", "observed"),
        metadata={"url": endpoint.get("url", ""), "method": method,
                  "source": endpoint.get("source", ""), "tags": endpoint.get("tags") or []},
    )


def merge_profiles(profiles):
    merged = []
    seen = set()
    for profile in profiles:
        key = profile.get("profile_id") or profile_id(profile)
        if key not in seen:
            seen.add(key)
            merged.append(profile)
    return merged
