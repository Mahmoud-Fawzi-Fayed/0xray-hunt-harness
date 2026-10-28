# 0xRay Hunt Harness — 10/10 Release Engineering Contract

## Objective

Harden the 0xRay Hunt Harness to release quality: every safety invariant
enforced in code, every claim backed by transport-level evidence, every phase
gate tested, and the system auditable from intake through report.

## Priority Tiers

| Tier | Scope | Gate Rule |
|------|-------|-----------|
| **P0** | Safety & correctness (§1–§6) | Any FAIL blocks release |
| **P1** | Quality & integration (§7–§11) | At most 1 non-critical FAIL |
| **P2** | Usability & docs (§12) | FAIL noted, not blocking |

---

## P0 — Safety & Correctness

### §1 netget.py standalone CLI
Load scope policy from `--scope-file` or `--slug`. Fail-closed for non-localhost.
**Gate**: `python3 netget.py GET <url> --scope-file <path>` succeeds; missing scope exits 1.
**Status**: DONE

### §2 browser.py CLI
Require scope policy. Exit nonzero without it.
**Gate**: `python3 browser.py --url <url>` without `--scope`/`--slug` prints ERROR, exits 1.
**Status**: DONE

### §3 Safe redirects
`allow_redirects=False` hardcoded in both transport backends. `follow_redirects()` re-authorizes each hop, strips credentials on origin change.
**Gate**: redirect to OOS host blocked; credential stripping verified.
**Status**: DONE

### §4 Deterministic A/B authorization
`_authz_closeout()` accepts method/body/owner/accessor. `_hunt_deep()` emits executable test_spec.
**Gate**: A/B test with role swap produces different outcomes.
**Status**: DONE

### §5 Evidence pipeline
`evidence.py`: HttpObservation (transport-recorded), TestAttempt (case-linked). `validate_evidence()` rejects cases with zero real observations.
**Gate**: selftest PASS; fabricated observation rejected.
**Status**: DONE

### §6 Phase states
NOT_STARTED/RUNNING/PASS/BLOCKED/FAILED/PARTIAL/CANCELLED. `phase_can_proceed()` enforces DAG. `reconcile_stale_running()` recovers crashes.
**Gate**: selftest PASS; blocked dependency prevents hunt.
**Status**: DONE

## P1 — Quality & Integration

### §7 Discovery reliability
Source/operation validation and independent trust-dimensional coverage, with explicit residuals. Source provenance on every operation.
**Gate**: coverage matches transport-observed reality; no category or schema is treated as universal; provenance field non-empty.
**Status**: DONE

### §8 Runtime capability & permissions
Agent subprocess permissions scoped. `_cmd()` validates capabilities. Dangerous flags trigger warnings.
**Gate**: agent cannot invoke disallowed tools.
**Status**: DONE

### §9 Auth lifecycle
Session expiration detection. `valid()` checks TTL. Re-provision on expiry.
**Gate**: expired session triggers re-provision or BLOCKED.
**Status**: DONE

### §10 Detection & dedup quality
Dedup confidence thresholds enforced. Corpus-aware dedup scoring.
**Gate**: known-duplicate produces LIKELY_DUP; novel finding produces NOVEL.
**Status**: DONE

### §11 CI & golden benchmark
`test_policy_egress.py` and `test_evidence_pipeline.py` in CI. Push/PR triggers.
**Gate**: selfcheck, local/comprehensive E2E, policy-egress, evidence, remediation, dynamic, and matrix script gates pass in CI.
**Status**: DONE

## P2 — Usability & Observability

### §12 Docs, UX, performance
Operator runbook, schema docs, threat model, CLI help text, reasonable latency.
**Gate**: all deliverable docs present; `--help` works on every CLI module.
**Status**: DONE

---

## Benchmark (§13)

Local E2E run against `vuln_app.py` exercising:
- Scope enforcement (in-scope allowed, OOS blocked)
- Redirect safety (OOS redirect stopped, credentials stripped)
- Evidence pipeline (observations recorded, fabricated rejected)
- A/B authorization (owner/accessor differentiated)
- Coverage gate (low coverage blocks hunt)
- Dedup gate (known issue blocked)
- Phase state machine (dependency enforcement, crash recovery)

## Scorecard (§14)

| Verdict | Meaning |
|---------|---------|
| **PASS** | Requirement met with evidence |
| **FAIL** | Requirement not met |
| **BLOCKED** | Cannot test (missing dependency) |
| **NOT_VERIFIED** | Not yet tested |

## Delivery Phases (§15)

| Phase | Content |
|-------|---------|
| A | Tag baseline, capture schemas, build module map |
| B | P0 fixes (§1–§6) |
| C | P1 fixes (§7–§11) |
| D | P2 (§12), benchmark fixture |
| E | Full benchmark run, scorecard |
| F | Docs, release-gate.json, final validation |

## Architectural Decisions

1. **Scope guard in subprocess** — `netget.py` loads scope from `--scope-file`/`--slug` before any request as CLI, rather than inheriting a process-local variable.
2. **Redirect safety** — `allow_redirects=False` hardcoded in both transports. `follow_redirects()` re-authorizes each hop.
3. **Evidence chain** — `evidence.py` separates transport-level observations from agent analysis. Coverage derived from real HTTP responses, not agent claims.
4. **Phase state machine** — `state.py` tracks explicit phase statuses with atomic checkpoint writes and dependency enforcement.
5. **Coverage dimensions** — sources, validated operations, workflows, and trust dimensions are independent. Sparse results and unresolved residuals remain visible; no fixed breadth percentage implies completeness.
6. **Discovery provenance** — Every endpoint carries `confidence` (high/medium/low) and normalized `provenance` (structured dict: `{level, source, round, evidence}`).

## Deliverables (§16)

| File | Purpose |
|------|---------|
| `docs/RELEASE-CONTRACT.md` | This document |
| `docs/THREAT-MODEL.md` | Harness threat model |
| `docs/TEST-CASE-SCHEMA.md` | TestCase schema reference |
| `docs/EVIDENCE-SCHEMA.md` | Evidence pipeline schema |
| `docs/OPERATOR-RUNBOOK.md` | Operational guide |
| `artifacts/release-validation/release-gate.json` | Machine-readable gate results |
| `artifacts/release-validation/dynamic-matrix-results.json` | Live-target and artifact adapter matrix |
| `artifacts/release-validation/model-family-results.json` | Opt-in model-family behavior and independent reproduction |
| `artifacts/release-validation/dynamic-harness-assessment.json` | Evidence-weighted rating and residual limits |
| `.github/workflows/ci.yml` | CI (push + PR triggers) |

## Test Results

Release status is generated from the current verification run; historical pass counts are not acceptance evidence. See `artifacts/release-validation/release-gate.json` for the current result and any unverified live-model/Burp checks.

## Final Acceptance Rule (§17)

The release is accepted when:
1. All P0 sections PASS
2. At most 1 P1 section has a non-critical FAIL
3. P2 FAILs are documented
4. `release-gate.json` is generated from actual test runs
5. All deliverable documents are present and accurate

Baseline tag: `baseline-pre-release` at commit `7d5af11`
