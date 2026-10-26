# Evidence Schema

## Overview

The evidence pipeline (`evidence.py`) records two types of structured evidence:

1. **HttpObservation** — transport-level request/response pair, recorded by the HTTP client
2. **TestAttempt** — links observations to a test case with an outcome verdict

Storage: append-only JSONL files per engagement under `<engagement_dir>/evidence/`.

Schema version: 1

## HttpObservation

File: `evidence/observations.jsonl`

```json
{
  "id": "obs_a1b2c3d4",
  "schema_version": 1,
  "ts": "2026-10-26T12:00:00Z",
  "method": "GET",
  "url": "https://api.example.com/users/123/orders",
  "req_headers": {
    "Authorization": "[REDACTED]",
    "Accept": "application/json"
  },
  "req_body_hash": "e3b0c44298fc1c14...",
  "resp_status": 200,
  "resp_headers": {
    "Content-Type": "application/json"
  },
  "resp_body_hash": "a1b2c3d4e5f67890...",
  "identity": "A",
  "case_id": "f0e1d2c3b4a59687",
  "policy_id": null,
  "owner": "user_a",
  "accessor": "user_b",
  "trace_id": "trace_xyz",
  "egress_decision": "allowed"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique observation ID (UUID-based) |
| `schema_version` | int | Always 1 for current schema |
| `ts` | string | ISO 8601 timestamp |
| `method` | string | HTTP method |
| `url` | string | Full request URL |
| `req_headers` | object | Request headers (sensitive values redacted) |
| `req_body_hash` | string? | SHA-256 of first 64KB of request body |
| `resp_status` | int | HTTP response status code (0 = transport error) |
| `resp_headers` | object | Response headers |
| `resp_body_hash` | string? | SHA-256 of first 64KB of response body |
| `resp_body_length` | int | Length of response body in bytes (0 if empty) |
| `identity` | string? | Identity used (A, B, or null) |
| `case_id` | string? | Test case ID this observation belongs to |
| `policy_id` | string? | Scope policy identifier |
| `owner` | string? | Resource owner identity |
| `accessor` | string? | Identity attempting access |
| `trace_id` | string? | Correlation ID for chained requests |
| `egress_decision` | string | "allowed" or "blocked" |

### Header Redaction

These header patterns are automatically redacted to `[REDACTED]`:
- `Authorization`, `Cookie`, `Set-Cookie`
- `Proxy-Authorization`
- `X-*-Token`, `X-Api-Key`, `X-*-Secret`

## TestAttempt

File: `evidence/attempts.jsonl`

```json
{
  "id": "att_d4c3b2a1",
  "schema_version": 1,
  "ts": "2026-10-26T12:00:01Z",
  "case_id": "f0e1d2c3b4a59687",
  "observation_ids": ["obs_a1b2c3d4"],
  "outcome": "CONFIRMED",
  "confidence": "independently_reproduced",
  "agent_commentary": "Response body contains user_a's order data when accessed as user_b",
  "method": "GET",
  "url": "https://api.example.com/users/123/orders",
  "identity": "B",
  "owner": "user_a",
  "accessor": "user_b"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique attempt ID |
| `schema_version` | int | Always 1 |
| `ts` | string | ISO 8601 timestamp |
| `case_id` | string | Test case this attempt belongs to |
| `observation_ids` | string[] | HttpObservation IDs backing this attempt |
| `outcome` | string | One of: PENDING, TESTED, DISPROVED, CONFIRMED, INCONCLUSIVE, BLOCKED |
| `confidence` | string? | One of: candidate, validated_by_rule, independently_reproduced, report_ready |
| `agent_commentary` | string | Agent's analysis text (NOT evidence — linked to observations) |
| `method` | string? | HTTP method tested |
| `url` | string? | URL tested |
| `identity` | string? | Identity used |
| `owner` | string? | Resource owner |
| `accessor` | string? | Accessing identity |

## Outcome Statuses

| Status | Meaning |
|--------|---------|
| `PENDING` | Test case created, not yet executed |
| `TESTED` | Executed, result recorded |
| `DISPROVED` | Hypothesis disproved — no vulnerability |
| `CONFIRMED` | Vulnerability confirmed with transport proof |
| `INCONCLUSIVE` | Ambiguous result, needs manual review |
| `BLOCKED` | Could not execute (auth wall, rate limit, etc.) |

## Confidence Levels

| Level | Meaning |
|-------|---------|
| `candidate` | Initial hypothesis from agent analysis |
| `validated_by_rule` | Passed automated validation rules |
| `independently_reproduced` | Confirmed by separate test execution |
| `report_ready` | Full evidence chain, ready for report |

## Validation Rules

`validate_evidence(engagement_dir, case_id)` returns `(is_valid, reason)`:

1. At least one HttpObservation must exist for the case_id
2. At least one observation must have `resp_status != 0` (real HTTP response)
3. If `method` specified, at least one observation must match the method
4. If `identity` specified, at least one observation must match the identity
5. If `url` specified, at least one observation must match the URL

Zero real observations = invalid. Agent commentary without transport proof = rejected.

## Coverage Derivation

`coverage_from_evidence()` returns per-case coverage strictly from observations:

```python
{
  "case_id": {
    "method": "GET",
    "url": "/api/users/123/orders",
    "identity": "B",
    "observation_count": 3,
    "outcome": "CONFIRMED"
  }
}
```

Only cases with at least one real HTTP observation (status != 0) appear in coverage.
