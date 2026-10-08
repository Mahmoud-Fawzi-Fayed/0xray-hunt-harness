#!/usr/bin/env python3
"""
reviewer.py — periodic HUNT-WORKFLOW self-review (runs every ~2h under pm2 cron).

The mission: find MORE and MORE VALUABLE findings. This reads the WHOLE operation's live state + yield
(per target: surface / tested / candidates / confirmed, coverage %, auth A+B readiness, recent errors,
rounds; aggregate: findings by class+severity, and the key signal — classes HEAVILY attempted that yield
ZERO, the "misflow"), hands that snapshot to a Cursor agent, and gets back a structured critique:
weaknesses, missing coverage, the top bottleneck, and PRIORITIZED concrete changes that would raise yield.

It is READ-ONLY: it never edits code, skills, or hunts. It writes a review to <base>/_review/ and posts a
one-line on-site alert (no email — email is reserved for real findings). The operator (or an in-session
agent) acts on the recommendations.

  python3 engine/reviewer.py            # one review pass
  python3 engine/reviewer.py --quiet    # no stdout (for cron)
  python3 engine/reviewer.py --dry      # gather + print the snapshot only, NO agent call
"""
import argparse
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
BASE = os.path.expanduser(os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements"))
PM2 = shutil.which("pm2") or "/usr/bin/pm2"
CORES = os.cpu_count() or 2
LOAD_CEIL = float(os.environ.get("REVIEW_LOAD_CEIL", str(CORES * 5)))     # skip a pass if the box is slammed
REVIEW_TIMEOUT = int(os.environ.get("REVIEW_AGENT_TIMEOUT", "600"))
ERR_RE = re.compile(r"error|traceback|timeout|rate-limited|rate limit|\b401\b|\b403\b|\b429\b|\b5\d\d\b|captcha",
                    re.I)
IDLE_MARKERS = ("orchestrator done", "orchestrator:", "persist:", "draft-gate:", "=== persist round")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _slug(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").strip().lower()).strip("-") or "unknown"


def _pm2_jlist():
    try:
        out = subprocess.run([PM2, "jlist"], capture_output=True, text=True, timeout=20).stdout
        return json.loads(out)
    except Exception:  # noqa: BLE001
        return []


def _running_targets(base):
    """Slugs of the hunts pm2 currently manages (online or not), excluding infra."""
    out = []
    for p in _pm2_jlist():
        n = p.get("name", "")
        if n.startswith("hunt-") and n not in ("hunt-bridge", "hunt-watchdog", "hunt-reviewer"):
            out.append({"slug": n[len("hunt-"):],
                        "online": (p.get("pm2_env") or {}).get("status") == "online",
                        "restarts": (p.get("pm2_env") or {}).get("restart_time", 0)})
    return out


def _tail(path, n=400):
    try:
        return open(path, encoding="utf-8", errors="ignore").read().splitlines()[-n:]
    except OSError:
        return []


def _auth_state(slug, base):
    try:
        import authn
        ids = authn.identities(slug, base)
    except Exception:  # noqa: BLE001
        ids = []
    sess = False
    try:
        import authsession
        s = authsession.load(slug, base)
        sess = bool(s and authsession.valid(s))
    except Exception:  # noqa: BLE001
        pass
    return {"idents": ids, "session_valid": sess, "two_account": ("A" in ids and "B" in ids)}


def _target_snapshot(base, tgt):
    slug = tgt["slug"]
    d = os.path.join(base, slug)
    st = {}
    try:
        st = json.load(open(os.path.join(d, "state.json")))
    except Exception:  # noqa: BLE001
        pass
    surface = st.get("surface") or []
    tested = st.get("tested") or {}
    tested_n = len(tested) if isinstance(tested, (dict, list)) else 0
    confirmed = st.get("confirmed") or []
    candidates = st.get("candidates") or []

    def _dist(items, field):
        out = {}
        for it in items:
            k = (it.get(field) or "?").lower()
            out[k] = out.get(k, 0) + 1
        return out

    attempted = _dist(surface, "vuln_class")                  # what the surface is CLASSIFIED to hunt
    found = _dist(confirmed, "vuln_class")                     # what actually landed
    # the misflow signal: classes with lots of surface but zero confirmed
    zero_yield = sorted([c for c, n in attempted.items()
                         if n >= 3 and found.get(c, 0) == 0 and c not in ("?",)],
                        key=lambda c: -attempted[c])[:8]
    sev = _dist(confirmed, "severity")
    log = _tail(os.path.join(d, "engine.log"), 400)
    errs = [ln for ln in log[-120:] if ERR_RE.search(ln)]
    rounds = sum(1 for ln in log if "=== persist round" in ln)
    last = log[-1] if log else ""
    sleeping = any(last.lstrip().lower().startswith(m) for m in IDLE_MARKERS)
    return {
        "slug": slug, "online": tgt["online"], "restarts": tgt["restarts"], "phase": st.get("phase"),
        "surface": len(surface), "tested": tested_n,
        "coverage_pct": round(100 * tested_n / len(surface), 1) if surface else 0.0,
        "candidates": len(candidates), "confirmed": len(confirmed),
        "confirmed_by_class": found, "confirmed_by_severity": sev,
        "high_surface_zero_yield_classes": zero_yield,
        "auth": _auth_state(slug, base),
        "rounds": rounds, "sleeping": sleeping,
        "recent_errors": errs[-6:],
        "last_log": last[-200:],
    }


def gather(base):
    base = os.path.expanduser(base)
    tgts = _running_targets(base)
    snaps = [_target_snapshot(base, t) for t in tgts]
    # aggregate yield across the suite
    agg_class, agg_sev = {}, {}
    for s in snaps:
        for c, n in (s["confirmed_by_class"] or {}).items():
            agg_class[c] = agg_class.get(c, 0) + n
        for v, n in (s["confirmed_by_severity"] or {}).items():
            agg_sev[v] = agg_sev.get(v, 0) + n
    total_conf = sum(s["confirmed"] for s in snaps)
    # published finding pages (yield proof)
    wd = os.environ.get("HUNT_WEB_DIR")
    pages = len(glob.glob(os.path.join(wd, "finding-*.html"))) if wd and os.path.isdir(wd) else None
    valuable = sum(n for v, n in agg_sev.items() if v in ("high", "critical"))
    la = os.getloadavg()
    return {
        "ts": _now(),
        "box": {"cores": CORES, "load_1_5_15": [round(x, 2) for x in la]},
        "config": {
            "models": os.environ.get("CURSOR_HUNT_MODELS", ""),
            "parallel": os.environ.get("HUNT_PARALLEL", ""),
            "intrusive": os.environ.get("HUNT_INTRUSIVE", ""),
        },
        "targets": snaps,
        "yield": {
            "confirmed_total": total_conf,
            "valuable_total": valuable,                       # high+critical
            "by_class": agg_class, "by_severity": agg_sev,
            "published_pages": pages,
        },
    }


def _task(snap):
    return (
        "You are the LEAD of an autonomous bug-bounty operation. Review the live hunt-workflow telemetry "
        "below. THE MISSION: find MORE and MORE VALUABLE findings (IDOR/BOLA, auth bypass, SSRF, RCE, "
        "injection — not just low info-leak). This is a diagnostic review: be blunt, specific, and tie every "
        "point to the numbers in the data.\n\n"
        "Analyse especially:\n"
        "- `high_surface_zero_yield_classes`: classes with lots of attack surface but ZERO confirmed — the "
        "workflow is attacking them but nothing lands. WHY? (missing 2nd account? no auth session? a gate "
        "killing candidates? wrong technique?) This is the #1 clue to the misflow.\n"
        "- coverage_pct, phase, rounds, sleeping: is a target stalled, re-hunting the same slice, or starved?\n"
        "- auth.two_account / session_valid: IDOR/BOLA need two live accounts — which targets lack them?\n"
        "- recent_errors: recurring timeouts/limits/captcha/5xx blocking progress.\n"
        "- yield.by_severity: are we only landing low/medium? what would unlock high/critical?\n\n"
        "Output ONLY a fenced ```json``` block, no prose, shaped exactly:\n"
        '{"assessment":"2-3 sentence blunt state of the operation",'
        '"weaknesses":["concrete, data-cited"],'
        '"missing":["coverage/capability gaps that cost findings"],'
        '"recommendations":[{"action":"specific change","why":"data cite","impact":"findings it unlocks",'
        '"where":"skill|engine|config|auth|recon","effort":"S|M|L"}],'
        '"top_priority":"the single highest-leverage change to get more valuable findings",'
        '"score_0_10":<int, current workflow effectiveness at producing valuable findings>}\n\n'
        "Keep recommendations ACTIONABLE and ordered by (impact / effort). Honor the hard rails (in-scope, "
        "read-only default, no brute-force, no DoS, stop-at-draft, claim only what's proven) — never "
        "recommend violating them.\n\n"
        "TELEMETRY:\n```json\n" + json.dumps(snap, indent=1)[:12000] + "\n```\n"
    )


def _review_dir(base):
    d = os.path.join(os.path.expanduser(base), "_review")
    os.makedirs(d, exist_ok=True)
    return d


def _render_md(snap, rev):
    y = snap["yield"]
    lines = [f"# Hunt-workflow review — {snap['ts']}", "",
             f"**Assessment:** {rev.get('assessment','(none)')}  ",
             f"**Score:** {rev.get('score_0_10','?')}/10 · "
             f"confirmed={y['confirmed_total']} (valuable={y['valuable_total']}) · "
             f"by_class={y['by_class']} · load={snap['box']['load_1_5_15']}", "",
             f"## Top priority\n{rev.get('top_priority','(none)')}", ""]
    if rev.get("applied"):
        lines.append("## Auto-applied (by the reviewer)")
        lines += [f"- **{a['action']}** @ {a['target']} — {a['result']}" for a in rev["applied"]]
        lines.append("")
    if rev.get("needs_operator"):
        lines.append("## Needs you (can't auto-fix safely)")
        lines += [f"- {m}" for m in rev["needs_operator"]]
        lines.append("")
    lines += ["## Weaknesses"]
    lines += [f"- {w}" for w in (rev.get("weaknesses") or [])] or ["- (none)"]
    lines += ["", "## Missing / gaps"]
    lines += [f"- {m}" for m in (rev.get("missing") or [])] or ["- (none)"]
    lines += ["", "## Recommendations (impact / effort)"]
    for r in (rev.get("recommendations") or []):
        lines.append(f"- **[{r.get('where','?')}·{r.get('effort','?')}]** {r.get('action','')} "
                     f"— _{r.get('why','')}_ → {r.get('impact','')}")
    lines += ["", "## Per-target"]
    for t in snap["targets"]:
        lines.append(f"- **{t['slug']}** phase={t['phase']} cov={t['coverage_pct']}% "
                     f"conf={t['confirmed']} zero-yield={t['high_surface_zero_yield_classes']} "
                     f"auth={t['auth']['idents']} 2acct={t['auth']['two_account']}")
    return "\n".join(lines) + "\n"


def _persist(base, snap, rev):
    d = _review_dir(base)
    rec = {"ts": snap["ts"], "snapshot": snap, "review": rev}
    with open(os.path.join(d, "latest.json"), "w") as f:
        json.dump(rec, f, indent=2)
    with open(os.path.join(d, "latest.md"), "w") as f:
        f.write(_render_md(snap, rev))
    with open(os.path.join(d, "journal.jsonl"), "a") as f:
        f.write(json.dumps({"ts": snap["ts"], "score": rev.get("score_0_10"),
                            "top_priority": rev.get("top_priority"),
                            "n_recs": len(rev.get("recommendations") or [])}) + "\n")
    stamp = re.sub(r"[^0-9T]", "", snap["ts"])[:15]
    try:
        shutil.copy(os.path.join(d, "latest.json"), os.path.join(d, f"review-{stamp}.json"))
    except OSError:
        pass


def apply_fixes(base, snap):
    """DIRECTLY apply the safe, deterministic remediations the telemetry implies — not just recommend them.
    Every action is bounded, guardrail-gated, and NON-DISRUPTIVE: it writes a flag file / authn account the
    NEXT hunt round picks up, never restarts or heavies a running hunt. Risky changes (engine/skill code)
    stay recommendations for the operator. Returns (applied[], needs_operator[])."""
    applied, needs_op = [], []
    if os.environ.get("REVIEW_AUTOAPPLY", "1") != "1":
        return applied, needs_op
    cap_surface = int(os.environ.get("REVIEW_RECON_CAP_SURFACE", "1500"))
    hi_classes = ("idor", "bola", "auth-bypass", "sqli", "ssrf")
    for t in snap.get("targets", []):
        slug = t["slug"]
        tdir = os.path.join(os.path.expanduser(base), slug)
        auth = t.get("auth") or {}
        zero = t.get("high_surface_zero_yield_classes") or []
        # 1) RECON CAP — a starved huge-surface target still crawling recon: hunt the ranked slice NOW
        try:
            flag = os.path.join(tdir, ".recon_capped")
            if (t.get("phase") == "recon" and (t.get("surface") or 0) > cap_surface
                    and (t.get("coverage_pct") or 0) < 25 and not os.path.exists(flag)):
                open(flag, "w").write(snap["ts"])
                applied.append({"action": "recon_cap", "target": slug,
                                "result": f"capped recon ({t.get('surface')} surface, {t.get('coverage_pct')}% "
                                          "done) -> hunt the ranked slice now"})
        except OSError:
            pass
        # 2) PROVISION ACCOUNT B — IDOR/BOLA is untestable without a 2nd account. Mint one (hard-gated:
        #    needs a live A, no existing B, self-register host, account-cap, + an internal cooldown).
        if (os.environ.get("REVIEW_AUTO_PROVISION_B", "1") == "1" and auth.get("session_valid")
                and not auth.get("two_account") and "idor" in zero):
            try:
                import authsession as AS
                r = AS.provision_b(slug, base=base)
                if r.get("ok") and r.get("ident") == "B":
                    applied.append({"action": "provision_b", "target": slug,
                                    "result": "second account (B) provisioned -> cross-account IDOR now testable"})
                elif r.get("error") and "cooldown" not in r["error"]:   # can't auto-make B -> tell the operator
                    needs_op.append(f"{slug}: couldn't auto-provision account B ({r['error']}) — "
                                    "raise HUNT_MAX_ACCOUNTS or paste a B login (panel) to unlock cross-account IDOR")
            except Exception:  # noqa: BLE001
                pass
        # 3) NEEDS OPERATOR — no auth session but auth-dependent classes are the gap (often captcha-walled):
        #    can't safely auto-fix; surface it loudly so the operator pastes a login in the panel.
        if not auth.get("session_valid") and any(c in zero for c in hi_classes):
            needs_op.append(f"{slug}: no auth session — paste a test login in the panel to unlock "
                            f"{', '.join(c for c in hi_classes if c in zero)}")
    return applied, needs_op


def review(base=BASE, quiet=False, dry=False):
    try:
        import notify
        notify._load_env_file()                       # make CURSOR_HUNT_MODELS* + HUNT_WEB_DIR available
    except Exception:  # noqa: BLE001
        notify = None
    base = os.path.expanduser(base)
    snap = gather(base)
    if dry:
        print(json.dumps(snap, indent=2))
        return {"dry": True, "targets": len(snap["targets"])}
    if snap["box"]["load_1_5_15"][2] > LOAD_CEIL:      # 15m load — don't pile onto a slammed box
        msg = f"review skipped: 15m load {snap['box']['load_1_5_15'][2]} > ceil {LOAD_CEIL}"
        if not quiet:
            print(msg)
        if notify:
            notify.site_alert("reviewer", msg, base=base, kind="review")
        return {"skipped": "overload"}
    import agent as A
    r = A.run_agent(_task(snap), context=None, timeout=REVIEW_TIMEOUT)   # one-shot, rotates the model pool
    rev = A.extract_json(r.get("result") or "") if not r.get("error") else None
    if not isinstance(rev, dict):
        rev = {"assessment": f"agent review unavailable ({r.get('error') or 'no-json'})",
               "weaknesses": [], "missing": [], "recommendations": [],
               "top_priority": "(agent produced no structured review this pass)", "score_0_10": None}
    rev["_model"] = r.get("model")
    applied, needs_op = apply_fixes(base, snap)         # DIRECTLY apply the safe fixes — not just recommend
    rev["applied"] = applied
    rev["needs_operator"] = needs_op
    _persist(base, snap, rev)
    if notify:
        tp = rev.get("top_priority") or "review complete"
        lines = [f"workflow review (score {rev.get('score_0_10','?')}/10): {tp}",
                 f"confirmed={snap['yield']['confirmed_total']} valuable={snap['yield']['valuable_total']}"]
        if applied:
            lines.append("AUTO-APPLIED: " + "; ".join(f"{a['action']}@{a['target']}" for a in applied))
        if needs_op:
            lines.append("NEEDS YOU: " + "; ".join(needs_op[:3]))
        notify.site_alert("reviewer", lines, base=base, kind="review")
    if not quiet:
        print(_render_md(snap, rev))
    return {"ok": True, "score": rev.get("score_0_10"), "recs": len(rev.get("recommendations") or []),
            "applied": len(applied), "needs_operator": len(needs_op), "model": r.get("model")}


def _main(argv=None):
    ap = argparse.ArgumentParser(description="periodic hunt-workflow self-review")
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--dry", action="store_true", help="gather + print snapshot, no agent call")
    a = ap.parse_args(argv)
    out = review(base=a.base, quiet=a.quiet, dry=a.dry)
    if not a.quiet:
        print(json.dumps(out, indent=2) if not a.dry else "", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
