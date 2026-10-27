# Known Issues and Remediation Log

Baseline: `c48fa14` (2026-10-25)

## Fixed This Session

| Issue ID | Severity | Root Cause | Fix | Test ID | Status |
|---|---|---|---|---|---|
| SCOPE-01 | P0 | `scope.py::_match` bare domain matched all subdomains (`host == p or host.endswith('.' + p)`) | `scope.py:30` — bare domain = exact match only; `*.domain` required for subdomains | T1.1, selftest | PASS |
| SCOPE-02 | P0 | `scope.py::_match` `re:` used `re.search` (partial match) | `scope.py:38` — changed to `re.fullmatch` | T1.4, selftest | PASS |
| SCOPE-03 | P1 | `scope.py::_host_of` didn't strip userinfo (`evil@host`) | `scope.py:22` — strips `@` from netloc | T1.5, selftest | PASS |
| SCOPE-04 | P1 | `scope.py::_match` didn't normalize trailing dots | `scope.py:30` — `.rstrip(".")` on both pattern and host | T1.5, selftest | PASS |
| GUARD-01 | P0 | `guardrails.py::in_scope` fell back to weak local matcher on `import scope` failure | `guardrails.py:101` — `except: return False` (fail-closed) | T2.2 | PASS |
| GUARD-02 | P0 | `guardrails.py::check` only scope-checked `register/login/tempmail-verify` actions | `guardrails.py:186` — all actions with a URL are scope-checked | T2.1 | PASS |
| GUARD-03 | P1 | `guardrails.py::in_scope` didn't pass `out_path_restrictions` to Scope | `guardrails.py:100` — passes both path restriction dicts | T1.3 | PASS |
| ENGINE-01 | P0 | `engine.py::hunt` priority map missing `critical` (defaulted to sort position 3) | `engine.py:1369` — `{"critical": 0, "high": 1, "medium": 2, "low": 3}` | T5.4 | PASS |
| ENGINE-02 | P0 | `engine.py` `mark_tested(it)` ran before result classification | `engine.py:1477+` — moved after vulnerable/skipped/nothing branches | selfcheck | PASS |
| ENGINE-03 | P0 | `engine.py` plan cases marked `"confirmed"` by hunt agent alone | `engine.py:1506` — uses `"tested"` status, confirmation in validate phase | selfcheck | PASS |
| ENGINE-04 | P0 | `engine.py` `mark_tested` accepted any truthy analysis text | `engine.py:1537` — requires `classes_considered`, `request` field, or `_model` attribution | selfcheck | PASS |
| ENGINE-05 | P1 | `engine.py` plan key reconstruction used only first param, no role | `engine.py:1548` — uses preserved `_plan_key` or reconstructs with all params + role | selfcheck | PASS |
| ENGINE-06 | P1 | `engine.py::_hunt_agent` HUNT_DEEP overwrote vuln_class silently | `engine.py:1674` — preserves `_original_vuln_class` | N/A | PASS |
| ENGINE-07 | P1 | `engine.py` hunt prompt sent only first param | `engine.py:1599` — sends all params from `it.get("params")` | N/A | PASS |
| COV-01 | P0 | `coverage.py::_parse_tested` keyed by 3-tuple `(method, url, class)` — merged param/role | `coverage.py:35` — 5-tuple `(method, url, class, param, role)` | selftest, T6.3 | PASS |
| COV-02 | P1 | `coverage.py::_is_tested` didn't match on param/role | `coverage.py:73` — matches exact 5-tuple, falls back to empty param/role | selftest | PASS |
| COV-03 | P1 | `coverage.py` headline `unique_tested` double-counted legacy keys | `coverage.py:162` — uses `len(tested_records)` | selftest | PASS |
| PLAN-01 | P1 | `testplan.py::state_key` used first param only, no role | `testplan.py:376` — all params sorted + role field | selftest, T5.2 | PASS |
| FMAP-01 | P1 | `featuremap.py::_host_matches_scope` used `endswith` (wildcard-by-default) | `featuremap.py:116` — delegates to canonical `scope.Scope.in_scope_host` | selftest | PASS |
| FMAP-02 | P1 | `featuremap.py` hardcoded `auth_required: True`, `confidence: observed` | `featuremap.py:49,110` — defaults to `None`/`unknown`, infers from source | N/A | PASS |
| VERIFY-01 | P1 | `verify.py::_in_scope` created Scope without path restrictions | `verify.py:255` — passes `path_restrictions` and `out_path_restrictions` | T9.1 | PASS |
| RECON-01 | P1 | `recon.py` stdlib fallback validated only final redirect URL | `recon.py:102` — custom `HTTPRedirectHandler` validates each hop | selftest | PASS |
| RECON-02 | P1 | `recon.py::auth_enforcement_sweep` didn't check scope before requests | `recon.py` — added `_recon_scope` check | selftest | PASS |

## Hunting Correctness Remediation

| Area | Fix | Verification |
|---|---|---|
| Orchestration | Discovery restored to the real phase list; case IDs immutable; scheduler completes only after evidence validation | `test_remediation.py`, orchestrator selftest |
| Authorization | Similarity-only BOLA removed; A-owned markers and controls required | ownership regression tests |
| Discovery | Guessed paths separated from validated surface; YAML/refs/auth/template handling; browser XHR fixed | discovery/OpenAPI/browser tests |
| Novelty/transport | Novelty feeds ranked work; direct target fetches use scope-guarded transport; uncontained crawler disabled | novelty/egress tests |
| Reporting | Reproduction, two-tool High/Critical, scope, dedup UNKNOWN/REVIEW, and READY gates enforced | draft-gate tests |
| Coverage/taxonomy | Canonical aliases and class rules; role/hypothesis-aware coverage; notes no longer count as coverage | taxonomy/coverage tests |
| Evidence/learning | Redacted excerpts, schema v2, reproduced-only yield, proposed-skill quarantine | evidence/learning tests |
| Concurrency | Fix-chat log read-modify-write made atomic | fixchat selftest |

## Verification Status and Residual Risks

| Issue ID | Severity | Description | Status |
|---|---|---|---|
| E2E-LIVE | P0 | Live model hunt → independent reproduction → dedup → report draft on local vulnerable app | PASS — see `artifacts/release-validation/release-gate.json` |
| BURP-MCP | P1 | Burp MCP integration tested end-to-end | NOT VERIFIED — requires running Burp Pro |
| AGENT-SANDBOX | P1 | Agent CLIs can execute arbitrary local tools; prompt/transport rules are not OS-level network containment | RESIDUAL RISK — use OS sandboxing for untrusted agents; built-in transports and dangerous flags are guarded |
