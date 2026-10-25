# Operation and Test Schemas

## State Key Format (`state.py`)

Tests are keyed in `state.json["tested"]` as pipe-delimited strings:

```
METHOD|URL|PARAM|VULN_CLASS
```

Example: `GET|https://api.example.com/users|id|idor`

- **METHOD**: HTTP method (GET, POST, PATCH, etc.)
- **URL**: Full absolute URL
- **PARAM**: First parameter name (legacy — see migration below)
- **VULN_CLASS**: Vulnerability class slug (idor, xss, sqli, deep, etc.)

### Migration: 4-field → 5-field keys

`testplan.py::state_key()` now produces 5-field keys:

```
METHOD|URL|PARAMS|CATEGORY|ROLE
```

- **PARAMS**: All parameters sorted and `|`-joined (e.g. `amount|id|to`)
- **ROLE**: Role/identity used (e.g. `admin`, `user_a`, empty string for default)

**Backward compatibility**: `coverage.py::_parse_tested()` handles both formats:
- 5-field: `(parts[0], parts[1], parts[3], parts[2], parts[4])`
- 4-field: `(parts[0], parts[1], parts[3], parts[2], "")`
- 3-field (legacy): `("*", parts[0], parts[2], "", "")`

**Known limitation**: `|` is used as both field separator and multi-param joiner. A parameter named `|` would corrupt the key. Future: hash-based case IDs.

## Test Plan Case Format (`testplan.py`)

```json
{
  "method": "GET",
  "endpoint": "https://api.example.com/users/1",
  "params": ["id"],
  "category": "idor",
  "priority": "high",
  "role": "user_a",
  "status": "pending",
  "evidence": null,
  "owner": "A",
  "accessor": "B"
}
```

### Valid Statuses

`pending` → `running` → `tested` | `blocked` | `inconclusive` | `disproved` | `confirmed`

- **pending**: Not yet attempted
- **running**: Currently executing
- **tested**: Executed with analysis, no vulnerability found
- **blocked**: Could not execute (auth wall, rate limit, etc.)
- **inconclusive**: Executed but result unclear
- **disproved**: Negative control confirms not vulnerable
- **confirmed**: Independently verified vulnerability (set by validate phase, never by hunt agent)

### Evidence Requirements

Statuses `tested`, `confirmed`, `disproved`, `inconclusive` require evidence text.
`confirmed` additionally requires both request evidence AND demonstrated impact.

## Coverage Tuple Format (`coverage.py`)

Internal records keyed as 5-tuple:

```python
(method, url, vuln_class, param, role)
```

- Wildcard method `*` matches any method (legacy compat)
- Empty param/role matches any (backward compat for old state files)

### Coverage Report Fields

```json
{
  "surface": 42,
  "tested": 18,
  "security_tested": 12,
  "candidates": 3,
  "confirmed": 1,
  "coverage_by_class": {"idor": {"total": 8, "tested": 5, "endpoints": 4}},
  "coverage_by_role": {"default": {"operations": 30, "tested": 15}},
  "blind_spots": ["csrf", "xxe"],
  "operations": [{"method": "GET", "url": "...", "classes": {"idor": {"status": "tested"}}}]
}
```

## Finding Lifecycle

```
hunt agent reports candidate
    │
    ▼
CANDIDATE ──── verify.py quality checks ──── rejected (ALWAYS_REJECT, low quality)
    │
    ▼
CANDIDATE ──── validate phase (independent replay) ──── DISPROVED (protected control)
    │                                                     │
    ▼                                                     ▼
CONFIRMED (independent evidence)                     INCONCLUSIVE
    │
    ▼
dedup.py ──── LIKELY_DUP → STOP
    │
    ▼
verify_finding() ──── quality gate (repro steps, impact, PoC, scope)
    │
    ▼
DRAFT REPORT ──── operator approval required ──── SUBMIT (manual only)
```

### Finding Fields

```json
{
  "vuln_class": "idor",
  "url": "https://api.example.com/users/1",
  "method": "GET",
  "param": "id",
  "severity": "high",
  "evidence": "User B accessed User A's data...",
  "request": "GET /api/users/1 — as B",
  "proof_note": "Response contains A's email and secret",
  "attacker_holds": "own_session",
  "id_source": "in_scope_oracle",
  "disposition": {},
  "scope_warning": null
}
```

## Surface Item Format (`state.py`)

```json
{
  "url": "https://api.example.com/users/1",
  "method": "GET",
  "param": "id",
  "vuln_class": "idor",
  "source": "recon",
  "auth_required": true,
  "role": "default"
}
```

Deduplicated in `add_surface()` by `(method, url_pattern, param, vuln_class)` — the `_pat_key` 4-tuple.
