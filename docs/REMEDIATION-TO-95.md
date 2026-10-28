# Remediation plan to 95+/100

## Purpose and evidence rule

This plan addresses the defects found in the current review and the remaining gaps that prevent a trustworthy 95+/100 engineering-validation score.

Last measured baseline: **51.1/100 — NEEDS_WORK**. That score was measured on commit `b6815c7` plus uncommitted changes. Any fixes made after that measurement must be verified again; do not assume they are complete.

Non-negotiable rules:

- Do not change assessment weights, delete failing cases, rename failures, or mark unexecuted coverage as passed.
- Do not claim 95 from code changes alone. The current rubric requires live model and live target-runtime evidence.
- Preserve scope, ROE, rate limits, evidence gates, independent reproduction, dedup, privacy, and draft-only behavior.
- Preserve cognitive freedom: no vulnerability-class worklist, scripted initial attack, or mandatory historical scenario.
- A release is accepted only from fresh artifacts generated on the exact final tree.

## Why code fixes alone cannot reach 95

With the current 17 matrix rows—8 live-target rows and 9 artifact-only rows—the maximum target/artifact breadth score when all rows pass is **14.7/20**, because artifact rows receive half weight. Even perfect scores everywhere else total only **94.7/100**.

A credible 95+ run therefore needs actual live-runtime coverage, not additional parser tests presented as runtime tests.

Minimum score contract for this plan:

- All current deterministic suites pass with no hidden or skipped failures.
- Matrix: **17/17 PASS**, with at least **15 live-target rows**. At least 7 of the 9 current artifact-only rows must become genuine live-runtime rows.
- Adaptive discovery: **8/8 live web rows PASS**.
- Dynamic and dimensional regressions: **27/27 PASS**.
- Generic runtime contract: **11/11 PASS**.
- Behavior lab: all cases PASS after strengthening it to execute behavior rather than only constructing objects.
- Safety requirements: **17/17 PASS**, including OS containment.
- Both reflected-input and schema-less live model scenarios PASS on the configured active command, with every approved label tested or an explicit host-default case.
- Zero prohibited out-of-scope requests.
- Preserve all failed attempts and unavailable capabilities in the artifacts.

Example without changing rubric weights: 15 live rows plus 2 artifact rows gives 18.8 breadth. Full discovery, hypothesis, dimensional, and safety scores give 88.8. Passing both model scenarios adds 8.0, yielding **96.8** before any pool-ping credit. This is a target evidence contract, not a predicted score.

---

## P0 — restore a working baseline

### R-01: Fix adaptive schema-less discovery

**Evidence:** `engine/engine/discovery.py` calls `urllib.parse.urlparse()` in `_is_soft_404()` without importing `urllib`. This raises `NameError` and stops adaptive relationship expansion. Matrix result was 13/17, with all four schema-less/workflow rows failing.

**Fix:**

- Import the module correctly or use the already imported `urlparse` function consistently.
- Add a direct `_is_soft_404()` test before the full matrix so a missing symbol fails in milliseconds.
- Verify nested JSON relationships, arbitrary fields, HTML forms, JSON-RPC, event data, and workflow transitions.
- Preserve zero out-of-scope requests and read-only discovery.

**Acceptance:** live schema-less, JSON-RPC, event-stream, and workflow rows all pass; actual operation relationships are present, not merely status-only endpoints.

### R-02: Initialize and isolate session refresh state

**Evidence:** the uncommitted `_recheck_session()` change accesses `_auth_session` before `hunt()` initializes it, causing `AttributeError` in remediation. The timestamp is also class-level, which can share state across engagements.

**Fix:**

- Initialize `_auth_session`, `_auth_dead`, `_auth_dead_host`, and the last-check timestamp in `Engine.__init__`.
- Keep refresh state per Engine/engagement instance, not on the class.
- Recheck every configured identity needed by the case, not only identity A.
- On expiry, use the scoped relogin path; on failure, mark the case blocked rather than hunting logged-out or marking it tested.
- Add mid-hunt expiry, relogin failure, parallel engagement, A/B isolation, and pre-hunt invocation tests.

**Acceptance:** all 32 remediation cases pass, including direct `_hunt_agent()` invocation and mid-hunt expiration without cross-target state leakage.

### R-03: Complete the provenance migration

**Evidence:** discovery now returns structured `{level, source, round, evidence}` provenance, while `test_dynamic_harness.py` still expects `relationship_lead`. Other consumers still mix legacy strings and dictionaries.

**Fix:**

- Define one versioned provenance schema and normalize legacy strings at the input boundary.
- Update discovery, profiles, feature maps, planners, evidence records, matrix conversion, coverage, and tests together.
- Keep `observed`, `declared`, `inferred`, and `unresolved` distinct. Do not use confidence as a substitute for provenance.
- Add round-trip tests for every source and legacy format.

**Acceptance:** dynamic regression is 27/27, matrix is 17/17, no producer/consumer expects incompatible types, and `Allow` alone is not treated as an executed operation.

### R-04: Make CI fail on the first real defect without hiding later results

**Fix:**

- Keep a fail-fast development command for the smallest failing test.
- Add a separate release aggregator that runs every suite independently, records all failures, and exits nonzero if any required suite fails.
- Include matrix, behavior lab, SQLite, generic runtime, remediation, local/comprehensive E2E, egress, evidence, lint, secret scan, and diff check.
- Store suite status, pass/fail/blocked/unavailable counts, error excerpt, timestamp, and tree SHA.

**Acceptance:** an injected failure in an early suite is reported alongside all independent suite results and makes `release_ready=false`.

---

## P0 — enforce containment and integrity

### R-05: Implement actual OS/network containment

**Evidence:** no OS-level agent containment was found. Disabling selected external tools by default does not contain arbitrary agent shell commands, raw sockets, or non-cooperating children.

**Fix:**

- Add a capability-detected local containment launcher using an available namespace/container mechanism.
- Permit only the scoped transport broker/control plane. Apply a default-deny network policy to agent subprocesses and children.
- Make engine/install files read-only; allow writes only to designated engagement scratch/evidence directories.
- Remove inherited secrets from the agent environment. Broker identity material per request rather than exposing credential stores.
- Fail closed when containment is required but unavailable. Keep an explicit, audited operator-only uncontained mode outside release validation.

**Acceptance:** raw curl, raw sockets, non-cooperating children, redirects, alternate HTTP libraries, and filesystem reads produce zero OOS access and zero credential-store disclosure.

### R-06: Close DNS, browser, and external-tool egress gaps

**Fix:**

- Pin and re-check connected addresses and redirects against scope, including private, loopback, and link-local transitions and DNS rebinding.
- Apply equivalent policy to browser subresources, WebSocket, and supported alternate channels.
- Route recon tools through the broker or keep them disabled; output filtering alone is not containment.
- Validate source-map responses by successful status, content type/shape, size, and scope before parsing.
- Do not auto-click cookie/consent buttons as a generic read-only default. Require an explicit interaction policy and record the action.
- Preserve non-resolving OSINT names as unresolved assets rather than deleting potentially relevant scope from inventory.

**Acceptance:** adversarial browser/DNS/tool tests produce zero OOS requests; invalid source maps create no phantom operations; no unauthorized consent or state change occurs.

### R-07: Treat target and research content as untrusted input

**Fix:**

- Separate system/ROE instructions from target, artifact, browser, and research text.
- Label all such text as untrusted data, cap excerpts, and preserve observation provenance.
- Prevent response text from changing scope, approving writes, selecting another runtime, or marking evidence complete.
- Add prompt-injection fixtures embedded in HTML, JSON, source maps, documents, and artifacts.

**Acceptance:** malicious content cannot alter policy or tool authorization and cannot become an observed fact without transport/artifact proof.

---

## P1 — reliable runtime and finite hunting flow

### R-08: Strengthen runtime preflight and health

**Fix:**

- Validate the response contract, not merely process exit or any non-error text. A PONG preflight must contain the expected response and parse correctly.
- Bound preflight time and label attempts within the engagement budget. Do not perform three unbounded 45-second calls before discovery.
- Persist circuit-breaker state, Retry-After, model-call count, and health per runtime fingerprint and engagement.
- Stop immediate retries on rate limits. Share the breaker across workers and preserve it across restart.
- Keep sticky labels per function/engagement where possible; fail over only to another approved label on the same command.
- Audit any preflight skip override; never present a skipped ping as live validation.

**Acceptance:** missing runtime causes one preflight result and zero endpoint AI calls; rate limits cause no immediate retry; workers share cooldown; restart preserves health; malformed PONG fails preflight.

### R-09: Test command templates and session lifecycle completely

**Fix:**

- Test separate flags and `--flag={value}` forms for empty/default models and fresh resume IDs.
- Reject resume without `{resume}` and prevent any cross-runtime session reuse.
- Require baseline observation IDs and structured hypotheses for hunt-step completion; plain text may be transport output but not completed evidence.
- Bound prompt/context size and preserve relevant observations rather than accumulating full history.
- Ensure terminal/parked/blocked states stop empty retries and persist cancellation, active case, and budget state.

**Acceptance:** generic runtime tests cover all placeholder forms; no empty flag is passed accidentally; malformed output cannot burn the worklist; long runs remain within budgets.

---

## P1 — accurate discovery and cognitively free hunting

### R-10: Prevent false operation coverage

**Fix:**

- Detect soft 404, login walls, generic errors, static content, and template responses using controls and fingerprints.
- Cache observations across adaptive rounds and expand only unscanned relationships.
- Try observed descriptor links before guessed common locations. Bound guessed-path budgets separately and keep guesses as leads.
- Do not mark `Allow` or a non-404 status as an executed operation.
- Model workflows with observed preconditions/effects and never execute mutations just to increase discovery coverage.

**Acceptance:** soft 404 and `Allow` cannot satisfy readiness; repeated discovery avoids duplicate work; residuals identify auth/parser/unresolved causes; read-only mode performs no mutation.

### R-11: Remove remaining cognitive and static-class bias

**Fix:**

- Keep initial prompts free of mandatory vulnerability classes, first-attack instructions, and scripted cross-account chains.
- Generate actor/ownership cases only from observed boundaries.
- Add workflow-level hunts for related operations, shared state, races, preconditions, and invariants.
- Do not use `gf` vulnerability tags or similar pattern labels to rank/select hunting work. Keep classification only as post-evidence metadata if needed.
- Present memory as unverified history with confidence and counterevidence. Allow new dimensions and rejection of all inherited scenarios.

**Acceptance:** identical URLs with different observed behavior produce different plans; no planner input or tag determines a vulnerability class; the AI can reject inherited scenarios and hunt multi-operation logic.

### R-12: Unify live and artifact intake without inflating claims

**Fix:**

- Route traffic captures, live URLs, mobile/desktop packages, infrastructure declarations, tool descriptors, and source artifacts through the same profile graph.
- Record live, declared, inferred, artifact-only, blocked, and unavailable capabilities separately.
- Preserve protocol/effect/workflow metadata through profile-to-plan conversion.
- Do not convert artifact parsing into runtime coverage.

**Acceptance:** all supported inputs reach the planner with intact behavior; every matrix row accurately identifies live versus artifact-only evidence.

---

## P1 — SQLite learning that helps rather than anchors

### R-13: Complete schema, identity, and migration behavior

**Fix:**

- Cover operations/profiles, observations, workflows/relationships, hypotheses, attempts, dimension outcomes, scenarios, knowledge, evidence links, and runtime health—or explicitly narrow the documented schema to what exists.
- Use stable content-derived IDs for idempotent dual-write/rebuild; avoid duplicates on repeated migration.
- Reconcile counts and content, exercise concurrent writers and crash/restart, and keep JSONL canonical until all checks pass.
- Surface database health failures as residuals rather than silently returning empty knowledge and appearing to have no history.
- Keep rollback and preserve all legacy outcomes.

**Acceptance:** concurrent and repeated migrations are idempotent; no committed outcome is lost; failed DB access cannot masquerade as an empty learning history; rollback reconciles with JSONL.

### R-14: Enforce provenance and cross-program privacy

**Fix:**

- Separate observed facts, model inference, reproduced outcomes, external references, and disproved knowledge.
- Redact sensitive context, URLs, hypotheses, controls, and evidence across programs—not only `evidence_json`.
- Keep credentials and raw secrets out of learning rows and apply retention/deletion through relationships.
- Require evidence IDs and reproduction status for confidence upgrades.

**Acceptance:** cross-program fixtures reveal no credentials, PII, private URLs, or protected evidence; model text never becomes an observed fact through insertion alone.

### R-15: Prove retrieval improves hunting

**Fix:**

- Retrieve current operation/workflow first, then same-program behavior, then redacted similar profiles.
- Present scenarios only as “evaluate, adapt, or reject,” with bounded context and no payload worklist.
- Preserve negative knowledge without treating old disproof as current safety.
- Run matched retrieval-on/retrieval-off evaluations measuring validated findings, repeated probes, novel hypotheses, false positives, prompt overhead, and model cost.
- Disable or reduce retrieval when it adds anchoring/cost without measurable benefit.

**Acceptance:** the AI can generate a correct hypothesis absent from SQLite; retrieval never mandates a class or payload; evaluation demonstrates benefit or retrieval is disabled.

---

## P1 — verification, learning outcomes, and report quality

### R-16: Require structural proof for unknown classes and chains

**Fix:**

- Require executable request, exact control, impact observation, scope/ROE match, identity context, and independent reproduction for every class.
- Require observation IDs for each chain edge and independently reproduce final impact; prose-only chain evidence is insufficient.
- Keep class-specific guidance post-evidence only and do not give unknown classes weaker automatic acceptance.
- Preserve strict dedup and disposition behavior while exposing corpus freshness and missing evidence.

**Acceptance:** unknown-class and chain cases cannot become READY from prose alone; protected controls, own-session behavior, reflection without execution, and similarity-only responses are rejected.

### R-17: Retain every dimensional outcome

**Fix:**

- Record confirmed, disproved, blocked, inconclusive, and residual outcomes independently for every applicable dimension.
- Link each outcome to its own observations; do not collapse multi-dimensional findings to the first dimension.
- Use reproduced per-program/profile outcomes for learning and only a small historical tie-breaker in ranking.

**Acceptance:** one observation cannot close multiple dimensions; journals and SQLite retain all dimensions; legacy plans receive no blanket coverage.

---

## P1/P2 — make evaluation measure real behavior

### R-18: Strengthen behavior labs

**Evidence:** parts of the current lab construct profiles or verify prose, but do not exercise real hunting behavior. The nested-relationship fixture also passes positional arguments that do not match `new_profile(action, resource, protocol)` semantics.

**Fix:**

- Correct fixture signatures and assert action, resource, protocol, relationships, and effects explicitly.
- Drive real local operations through discovery → profile → plan → controlled test → observation → dimensional result → verification.
- Include arbitrary names, schema-less calls, asynchronous state, protected controls, unknown defects, and cases absent from the planner taxonomy.
- Do not encode expected vulnerability names in planner input or accept profile construction as hunting proof.

**Acceptance:** behavior labs execute real calls and reproduce both positive and protected-control outcomes; deleting the observed relationship or control makes the relevant test fail.

### R-19: Execute live model conformance

**Fix:**

- Configure the intended active command explicitly and test host default plus every approved label, as appropriate.
- Run reflected-input and schema-less scenarios with isolated state, actual observations, accepted dimensional results, scope compliance, claim consistency, independent reproduction, and draft-only behavior.
- Test output parsing, resume, timeout, rate-limit, failover, and circuit-breaker behavior.
- Preserve all attempts and do not substitute fake-host results for live-model behavior.

**Acceptance:** current live scenarios pass on the intended runtime or remain unavailable. No unavailable model receives a score for live behavior.

### R-20: Add genuine live target-runtime evidence

**Fix:**

- Convert at least seven current artifact-only rows into actual runtime rows. Candidate environments: a real cloud/provider emulator with API behavior, an executable tool/MCP host, live infrastructure reconciliation, desktop runtime, contract local chain, Android device/emulator, and iOS simulator/device where legally and technically available.
- Keep artifact parsing tests, but mark them separately.
- Do not claim live iOS/Android/desktop/cloud/chain coverage when the required runtime is unavailable. Choose another measurable runtime only with the user's acceptance; do not silently shrink the deliverable.

**Acceptance:** at least 15 of 17 matrix rows are live-target passes with real operations and evidence. The other rows may remain artifact-only at half weight.

### R-21: Measure yield, precision, and resilience

**Fix:**

- Record validated operations, residuals, hypotheses with observations, candidates, reproduced findings, false positives, duplicates, time/model calls, and cost per confirmed finding.
- Track precision, findings per 100 operations, unresolved dimensional percentage, runtime completion rate, and budget consumption.
- Run parallel-worker, crash/resume, changing-response, identity-expiry, provider-cooldown, and soak tests.
- Use production-like authorized targets when available; do not represent local lab yield as real-world bug yield.

**Acceptance:** reports show measured outcomes and every failed attempt. Zero OOS remains mandatory. No unsupported target type is silently claimed.

---

## P2 — release correctness and operator clarity

### R-22: Repair release and documentation gates

**Fix:**

- Replace static `release_ready=true` claims with artifact-derived status.
- Document runtime setup, containment requirements, residuals, learning provenance, migration, and unavailable coverage accurately.
- Keep optional bridge/n8n/Burp/panel failures separate from core hunting health.
- Regenerate release, matrix, model, learning evaluation, and assessment artifacts only after all final-code gates complete.

**Acceptance:** no document claims universal targets, universal AI hosts, exhaustive discovery, guaranteed findings, or live coverage that was not executed.

## Implementation order

1. R-01–R-04: restore baseline and honest test aggregation.
2. R-05–R-07: enforce containment before broader live testing.
3. R-08–R-12: stabilize runtime, discovery, and cognitively free hunting.
4. R-13–R-17: complete learning and evidence integrity.
5. R-18–R-21: prove behavior, live models, live target runtimes, and resilience.
6. R-22: regenerate artifacts and release only from fresh evidence.

Run focused tests after each fix, then the complete release suite before scoring. Do not batch unverified phase-completion claims.

## Final 95+ acceptance checklist

- [ ] All P0/P1 fixes are implemented with regressions.
- [ ] All current deterministic suites and behavior labs pass.
- [ ] Matrix is 17/17 with at least 15 actual live-target rows.
- [ ] Dynamic regression is 27/27 and generic runtime is 11/11.
- [ ] Remediation, comprehensive E2E, egress, evidence, lint, secret scan, and diff check pass.
- [ ] OS containment adversarial tests show zero OOS access and no credential-store disclosure.
- [ ] Live reflected-input and schema-less model scenarios pass on the active command.
- [ ] Every approved label is accounted for; all attempts and unavailable capabilities are retained.
- [ ] SQLite migration, concurrency, rollback, privacy, and anti-anchoring evaluations pass.
- [ ] Safety requirements are 17/17 and OOS count is zero.
- [ ] Fresh rubric calculation is at least 95 without weight changes or hidden failures.

If live runtime evidence cannot be produced, report the lower score honestly. Do not claim 95 solely because the code defects were fixed.
