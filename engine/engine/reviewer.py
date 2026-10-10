#!/usr/bin/env python3
"""
reviewer.py — periodic HUNT-WORKFLOW self-review (every 40 minutes).

pm2 wakes the process every 10 minutes. This file exits immediately unless 40 minutes
have passed since the last completed pass, so the real review lands on a 40-minute cadence.

The mission: find MORE and MORE VALUABLE findings. This reads the WHOLE operation's live state + yield
(per target: surface / tested / candidates / confirmed, coverage %, auth A+B readiness, recent errors,
rounds; aggregate: findings by class+severity, and the key signal — classes HEAVILY attempted that yield
ZERO, the "misflow"), hands that snapshot to a Cursor agent, and gets back a structured critique:
weaknesses, missing coverage, the top bottleneck, and PRIORITIZED concrete changes that would raise yield.

Every pass also runs the same expert checks used on a live hunt (repeat validation, crawl-instead-of-
session, own-session OAuth, a parse failure locked for 6h) and WRITES the fix: a per-target directive
the next phase reads, plus a session-file correction. It does not rewrite engine code with an agent.
The narrative review still goes to <base>/_review/ and a one-line on-site alert (no email).

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
REVIEW_INTERVAL_MIN = int(os.environ.get("REVIEW_INTERVAL_MIN", "40"))
HEAL_SEC = int(os.environ.get("REVIEW_HEAL_SEC", "60"))
WAKE_COOL = int(os.environ.get("REVIEW_WAKE_COOL", "180"))
ERR_RE = re.compile(r"error|traceback|timeout|rate-limited|rate limit|\b401\b|\b403\b|\b429\b|\b5\d\d\b|captcha",
                    re.I)
IDLE_MARKERS = ("orchestrator done", "orchestrator:", "persist:", "draft-gate:", "=== persist round")
# Any of these changing means the running process is stale until pm2 restarts it.
HUNT_MODULES = ("engine.py", "authsession.py", "skill_map.py", "recon.py", "orchestrator.py",
                "yieldrank.py", "brain.py")
SITE_MODULES = ("bridge.py", "authsession.py", "yieldrank.py", "dedup.py")


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
        "expert": expert_signals(base, slug),
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
    if rev.get("autofixed"):
        lines.append("## Auto-fixed (recommendation implemented)")
        lines += [f"- [{a.get('where','?')}] **{a['rec']}** — {a['result']}" for a in rev["autofixed"]]
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


def _log_tail(base, slug, n=800):
    return _tail(os.path.join(os.path.expanduser(base), slug, "engine.log"), n)


def _log_has(base, slug, needle):
    """True if needle appears anywhere in the hunt log. The tail alone hides a deep run
    once the process has moved on to sleeping and remapping."""
    path = os.path.join(os.path.expanduser(base), slug, "engine.log")
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if needle in line:
                    return True
    except OSError:
        return False
    return False


def expert_signals(base, slug):
    """The same measurements used when a hunt has burned hours without a valid finding."""
    base = os.path.expanduser(base)
    lines = _log_tail(base, slug, 800)
    repeats = {}
    gau = mine = nothing = 0
    for ln in lines:
        if "params: gau" in ln:
            gau += 1
        if "session-mine:" in ln:
            mine += 1
        if "hunt: nothing" in ln:
            nothing += 1
        if "validate: ✗" in ln or "validate: HELD" in ln:
            m = re.search(r"@ (\S+)", ln)
            if m:
                repeats[m.group(1)] = repeats.get(m.group(1), 0) + 1
    repeated = [{"url": u, "times": n} for u, n in sorted(repeats.items(), key=lambda kv: -kv[1]) if n >= 3]
    st = {}
    try:
        st = json.load(open(os.path.join(base, slug, "state.json")))
    except (OSError, json.JSONDecodeError):
        st = {}
    confirmed = st.get("confirmed") or []
    candidates = st.get("candidates") or []
    own = []
    try:
        import disposition as D
        for c in list(confirmed) + list(candidates):
            if isinstance(c, dict) and D.own_session_oauth(c):
                own.append({"url": c.get("url"), "vuln_class": c.get("vuln_class") or ""})
    except Exception:  # noqa: BLE001
        pass
    oos = []
    scope_path = os.path.join(base, "_targets", slug + ".json")
    try:
        import scope as S
        sc = S.Scope.load(scope_path)
        for c in candidates:
            if isinstance(c, dict) and c.get("url") and not sc.in_scope_host(c["url"]):
                oos.append({"url": c.get("url"), "vuln_class": c.get("vuln_class") or ""})
    except Exception:  # noqa: BLE001
        pass
    surface = st.get("surface") or []
    try:
        import state as ST
        pats = {}
        for s in surface:
            k = ST.url_pattern(s.get("url") or "")
            pats[k] = pats.get(k, 0) + 1
        uuid_dupes = sum(n - 1 for n in pats.values() if n > 1)
    except Exception:  # noqa: BLE001
        uuid_dupes = 0
    notes = len(st.get("hunt_notes") or {})
    tested = st.get("tested") or {}
    tested_n = len(tested) if isinstance(tested, (dict, list)) else 0
    coverage = round(100 * tested_n / len(surface), 1) if surface else 0.0
    sess = {}
    try:
        sess = json.load(open(os.path.join(base, "_identity", slug + "-session.json")))
    except (OSError, json.JSONDecodeError):
        sess = {}
    err = str(sess.get("error") or "")
    parse_lock = (not sess.get("success")) and ("parse" in err) and (not sess.get("transient"))
    auth = _auth_state(slug, base)
    junk_untested = untested_real = 0
    try:
        import engine as HUNTENG
        junk_re = HUNTENG._REVIEW_JUNK
    except Exception:  # noqa: BLE001
        junk_re = re.compile(r"$^")
    tested_map = tested if isinstance(tested, dict) else {}
    for s in surface:
        if not isinstance(s, dict):
            continue
        url = s.get("url") or ""
        key = f"{url}|{s.get('param','')}|{s.get('vuln_class','')}"
        if key in tested_map:
            continue
        if junk_re.search(url):
            junk_untested += 1
        else:
            untested_real += 1
    authz_logged = _log_has(base, slug, "authz:")
    deep_ran = _log_has(base, slug, "deep-pentest")
    return {
        "slug": slug,
        "repeated_validation": repeated[:8],
        "gau_lines": gau,
        "mine_lines": mine,
        "nothing": nothing,
        "hunt_notes": notes,
        "uuid_dupes": uuid_dupes,
        "coverage_pct": coverage,
        "own_session_oauth": own[:8],
        "out_of_scope_candidates": oos[:8],
        "parse_locked": parse_lock,
        "session_valid": auth.get("session_valid"),
        "two_account": auth.get("two_account"),
        "junk_untested": junk_untested,
        "untested_real": untested_real,
        "authz_logged": authz_logged,
        "deep_ran": deep_ran,
        "session_error": err[:160],
    }


def _mine_in_progress(base, slug):
    """True when a session-mine started and has not logged its result yet."""
    last_start = last_done = -1
    for i, ln in enumerate(_log_tail(base, slug, 60)):
        if "mining logged-in object ids" in ln:
            last_start = i
        if "session-mine:" in ln:
            last_done = i
    return last_start > last_done


def heal_runtime(base, slugs=None, probe=True, rejected_override=None):
    """Fix the failures a person would otherwise have to notice — then wake the hunt
    and the panel so the fix is what is running, not a file waiting for persist sleep.

    Detects and applies: dead/revived session, auth-wall marked tested, empty persist
    loop, leftover vuln-class slots, wildcard-vs-apex scope, holding-until-paste while
    the login is live, and a park on a target that should still hunt.
    """
    base = os.path.expanduser(base)
    if slugs is None:
        slugs = [t["slug"] for t in _running_targets(base) if t.get("online")]
    applied = []
    wake_session, wake_apex, wake_heal = [], [], []
    hdir = os.path.join(base, "_review", "heals")
    os.makedirs(hdir, exist_ok=True)
    try:
        import authsession as AS
        import engine as HUNTENG
    except Exception:  # noqa: BLE001
        return applied
    for slug in slugs:
        actions = []
        heal = {}
        sp = os.path.join(base, "_identity", slug + "-session.json")
        try:
            sess = json.load(open(sp))
        except (OSError, json.JSONDecodeError):
            sess = {}
        if probe and _try_revive(sess, slug, base, AS):
            try:
                sess = json.load(open(sp))
            except (OSError, json.JSONDecodeError):
                pass
            actions.append("restored a login the old path-catalog had marked dead")
            wake_session.append(slug)
        rejected = False
        if rejected_override and slug in rejected_override:
            rejected = bool(rejected_override[slug])
        elif probe and AS.valid(sess):
            try:
                rejected = bool(AS.site_rejects(sess, program=slug, base=base))
            except Exception:  # noqa: BLE001
                rejected = False
        live = AS.valid(sess) and not rejected
        if rejected:
            rel = {}
            try:
                rel = AS.relogin(slug, ident="A", base=base) if probe else {}
            except Exception:  # noqa: BLE001
                rel = {}
            if rel.get("ok"):
                try:
                    sess = json.load(open(sp))
                except (OSError, json.JSONDecodeError):
                    sess = {}
                rejected = False
                live = AS.valid(sess)
                actions.append("auto-relogin with stored operator credentials")
                wake_session.append(slug)
                try:
                    AS.relogin(slug, ident="B", base=base)
                except Exception:  # noqa: BLE001
                    pass
        if rejected and sess.get("success"):
            sess["success"] = False
            sess["error"] = "site rejected the stored session"
            sess["transient"] = True
            sess["ts"] = time.time()
            try:
                json.dump(sess, open(sp, "w"), indent=2)
                os.chmod(sp, 0o600)
            except OSError:
                pass
            try:
                import authn
                store = authn.load(slug, base)
                if "A" in store:
                    store.pop("A", None)
                    ap = authn.path_for(slug, base)
                    if store:
                        json.dump(store, open(ap, "w"), indent=2)
                        os.chmod(ap, 0o600)
                    elif os.path.isfile(ap):
                        os.remove(ap)
            except Exception:  # noqa: BLE001
                pass
            actions.append("stored login rejected by the site — marked dead; paste a fresh session")
            wake_session.append(slug)
        # A park that only sleeps is wrong when the target has no finding, or still has a login.
        dp = os.path.join(base, "_review", "directives", slug + ".json")
        try:
            directive = json.load(open(dp))
        except (OSError, json.JSONDecodeError):
            directive = {}
        try:
            st = json.load(open(os.path.join(base, slug, "state.json")))
        except (OSError, json.JSONDecodeError):
            st = {}
        confirmed = st.get("confirmed") or []
        confirmed_n = len(confirmed) if isinstance(confirmed, list) else int(confirmed or 0)
        if float(directive.get("park_until") or 0) > time.time() and (confirmed_n == 0 or live):
            directive["park_until"] = 0
            try:
                json.dump(directive, open(dp, "w"), indent=2)
                actions.append("cleared a park on a target that should still be hunting")
            except OSError:
                pass
        notes = st.get("hunt_notes") or {}
        tested = st.get("tested") if isinstance(st.get("tested"), dict) else {}
        walls = 0
        if isinstance(notes, dict):
            for key, note in notes.items():
                analysis = (note or {}).get("analysis") if isinstance(note, dict) else ""
                if key in tested and HUNTENG._logged_out_result(analysis):
                    walls += 1
        if walls:
            heal["reopen_auth_wall"] = True
            actions.append(f"reopen {walls} url(s) closed on a login wall")
        surface = st.get("surface") or []
        untested_real = 0
        try:
            junk_re = HUNTENG._REVIEW_JUNK
        except Exception:  # noqa: BLE001
            junk_re = re.compile(r"$^")
        for s in surface:
            if not isinstance(s, dict):
                continue
            url = s.get("url") or ""
            key = f"{url}|{s.get('param','')}|{s.get('vuln_class','')}"
            if key in tested:
                continue
            if not junk_re.search(url):
                untested_real += 1
        mine_ts = float(st.get("mine_agent_ts") or 0)
        idle_mine = (live and untested_real == 0
                     and (not mine_ts or (time.time() - mine_ts) > 1800)
                     and not _mine_in_progress(base, slug))
        if idle_mine:
            heal["reset_mine"] = True
            heal["hypothesize"] = True
            actions.append("empty worklist with a live session — mine timer reset and invent next tests")
        leftover = 0
        if os.environ.get("HUNT_DEEP", "1") == "1":
            for s in surface:
                if not isinstance(s, dict) or s.get("source") == "secret":
                    continue
                cls = (s.get("vuln_class") or "").lower()
                if cls and cls not in ("deep",):
                    leftover += 1
            if leftover:
                heal["coerce_deep"] = True
                actions.append(f"coerce {leftover} leftover class slot(s) to deep")
        apex_added = _ensure_apex(base, slug)
        if apex_added:
            actions.append("added in-scope apex host(s) the wildcard did not match: " + ", ".join(apex_added[:6]))
            wake_apex.append(slug)
        holding = any("until a live session is pasted" in ln for ln in _log_tail(base, slug, 40))
        if live and holding:
            actions.append("hunt is holding a host even though the session is live — waking it")
            wake_session.append(slug)
        if heal:
            heal["ts"] = _now()
            try:
                json.dump(heal, open(os.path.join(hdir, slug + ".json"), "w"), indent=2)
            except OSError:
                pass
            wake_heal.append(slug)
        if actions:
            applied.append({"action": "heal", "target": slug, "result": "; ".join(actions)})
    woken = []
    woken += _wake_hunts(base, wake_session, reason="session")
    woken += _wake_hunts(base, wake_apex, reason="apex")
    woken += _wake_hunts(base, wake_heal, reason="heal")
    if woken:
        applied.append({"action": "wake", "target": ",".join(sorted(set(woken))),
                        "result": "hunt restarted so the heal/session/scope is what is running"})
    _publish_live(base, applied)
    return applied


def expert_apply(base, snaps, reload=True):
    """Write the fix for each signal. Directives are read by the hunt on its next phase.
    A parse-failure lock is corrected on the session file immediately. Hunts are restarted
    only when engine.py is newer than the last reload, so a code fix actually loads."""
    base = os.path.expanduser(base)
    applied = heal_runtime(base, slugs=[(t["slug"] if isinstance(t, dict) and t.get("slug") else t)
                                        for t in snaps])
    ddir = os.path.join(base, "_review", "directives")
    os.makedirs(ddir, exist_ok=True)
    signals = []
    for t in snaps:
        slug = t["slug"] if isinstance(t, dict) and t.get("slug") else t
        sig = expert_signals(base, slug)
        signals.append(sig)
        close = []
        for item in sig["repeated_validation"]:
            close.append({"url": item["url"], "vuln_class": "",
                          "reason": f"validated {item['times']} times without becoming a finding"})
        for item in sig["out_of_scope_candidates"]:
            close.append({**item, "reason": "out of scope — workflow review closed it"})
        for item in sig["own_session_oauth"]:
            close.append({**item, "reason": "own-session oauth — workflow review closed it"})
        # one close per url+class
        seen, uniq = set(), []
        for c in close:
            k = (c.get("url"), c.get("vuln_class") or "")
            if c.get("url") and k not in seen:
                seen.add(k)
                uniq.append(c)
        crawl_instead = (sig["session_valid"] and sig["gau_lines"] > 0 and sig["mine_lines"] == 0
                         and sig["coverage_pct"] >= 80)
        rounds = t.get("rounds") if isinstance(t, dict) else 0
        confirmed_n = 0
        if isinstance(t, dict):
            c = t.get("confirmed")
            confirmed_n = c if isinstance(c, int) else (len(c) if isinstance(c, list) else 0)
        # Park only a target that already confirmed something and has no live session.
        # A zero-yield target, or one that still has a login, stays in the hunt.
        park = (sig["coverage_pct"] >= 98 and sig["untested_real"] == 0 and (rounds or 0) >= 4
                and confirmed_n > 0 and not sig.get("session_valid"))
        directive = {
            "ts": _now(), "ts_epoch": time.time(),
            "close": uniq,
            "skip_crawl": bool(crawl_instead),
            "skip_junk": True,
            "park_until": (time.time() + 45 * 60) if park else 0,
        }
        with open(os.path.join(ddir, slug + ".json"), "w") as f:
            json.dump(directive, f, indent=2)
        if uniq or crawl_instead or sig["junk_untested"] or park:
            applied.append({"action": "directive", "target": slug,
                            "result": (f"close={len(uniq)} skip_crawl={bool(crawl_instead)} "
                                       f"skip_junk={sig['junk_untested']} park={bool(park)}")})
        if sig["uuid_dupes"] >= 3:
            try:
                import state as ST
                eng_state = ST.State(base, slug)
                n = eng_state.collapse_patterns()
                if n:
                    applied.append({"action": "uuid_collapse", "target": slug,
                                    "result": f"collapsed {n} duplicate object-id URLs in state"})
            except Exception:  # noqa: BLE001
                pass
        if sig["parse_locked"]:
            path = os.path.join(base, "_identity", slug + "-session.json")
            try:
                sess = json.load(open(path))
                sess["transient"] = True
                json.dump(sess, open(path, "w"))
                applied.append({"action": "parse_retry", "target": slug,
                                "result": "parse failure is a 30-minute retry, not a 6-hour lock"})
            except (OSError, json.JSONDecodeError):
                pass
    track = os.path.join(base, "_review", "expert.jsonl")
    os.makedirs(os.path.dirname(track), exist_ok=True)
    with open(track, "a") as f:
        f.write(json.dumps({"ts": _now(), "signals": signals, "applied": applied}) + "\n")
    reloaded = _reload_if_engine_changed(base, [s["slug"] for s in signals]) if reload else False
    if reloaded:
        applied.append({"action": "reload", "target": ",".join(s["slug"] for s in signals),
                        "result": "hunts/bridge restarted so the current code is what is running"})
    return applied, signals


def _started_epoch(slug):
    """When the pm2 hunt process was started, in seconds. 0 if it is not in the process list."""
    return _started_named("hunt-" + slug)


def _started_named(name):
    for p in _pm2_jlist():
        if p.get("name") != name:
            continue
        up = (p.get("pm2_env") or {}).get("pm_uptime") or 0
        try:
            up = float(up)
        except (TypeError, ValueError):
            return 0
        if up > 1e12:
            up /= 1000.0
        return up
    return 0


def _pm2_restart(name):
    try:
        subprocess.run([PM2, "restart", name], capture_output=True, text=True, timeout=40)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _modules_mtime(names):
    latest = 0.0
    for n in names:
        try:
            latest = max(latest, os.path.getmtime(os.path.join(ENGINE, n)))
        except OSError:
            continue
    return latest


def _hunt_sleeping(base, slug):
    last = " ".join(_log_tail(base, slug, 8)).lower()
    return any(m in last for m in ("persist:", "sleeping", "orchestrator done", "=== persist round"))


def _publish_live(base, applied):
    """Panel + alert feed see a heal as soon as it is written, not after the 40-minute narrative."""
    if not applied:
        return
    base = os.path.expanduser(base)
    rec = {"ts": _now(), "applied": applied}
    try:
        json.dump(rec, open(os.path.join(_review_dir(base), "live.json"), "w"), indent=2)
    except OSError:
        pass
    latest_p = os.path.join(_review_dir(base), "latest.json")
    try:
        latest = json.load(open(latest_p))
        rev = latest.setdefault("review", {}) if isinstance(latest, dict) else {}
        prev = list(rev.get("applied") or [])
        for a in applied:
            if a not in prev:
                prev.insert(0, a)
        rev["applied"] = prev[:40]
        latest["live"] = rec
        json.dump(latest, open(latest_p, "w"), indent=2)
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    try:
        import notify
        lines = [f"{a.get('action')}@{a.get('target')}: {a.get('result')}" for a in applied[:8]]
        notify.site_alert("reviewer", ["AUTO-HEAL (live)"] + lines, base=base, kind="review")
    except Exception:  # noqa: BLE001
        pass


def _wake_hunts(base, slugs, reason="heal"):
    """Restart a hunt so an on-disk heal / new session / new scope is what is running.

    A hunt that is mid deep-pentest is left alone unless the reason is session or code —
    killing a 20-minute agent for a coerce is worse than waiting for persist sleep.
    """
    if not slugs:
        return []
    base = os.path.expanduser(base)
    markp = os.path.join(_review_dir(base), "wake.json")
    try:
        last = json.load(open(markp))
    except (OSError, json.JSONDecodeError):
        last = {}
    now = time.time()
    woken = []
    urgent = reason in ("session", "code", "apex")
    for slug in slugs:
        if now - float(last.get(slug) or 0) < WAKE_COOL:
            continue
        if not urgent and not _hunt_sleeping(base, slug):
            continue
        if _pm2_restart("hunt-" + slug):
            last[slug] = now
            woken.append(slug)
    try:
        json.dump(last, open(markp, "w"))
    except OSError:
        pass
    return woken


def _ensure_apex(base, slug):
    """`*.district.in` does not match `district.in`. Add the bare apex when the wildcard is in-scope
    and the apex is not out-of-scope. No hardcoded hosts."""
    path = os.path.join(os.path.expanduser(base), "_targets", slug + ".json")
    try:
        sc = json.load(open(path))
    except (OSError, json.JSONDecodeError):
        return []
    ins = list(sc.get("in_scope") or [])
    oos = {str(x).lower() for x in (sc.get("out_of_scope") or [])}
    have = {str(x).lower() for x in ins}
    added = []
    for item in list(ins):
        s = str(item or "")
        if not s.startswith("*."):
            continue
        apex = s[2:].strip().lower()
        if not apex or "." not in apex:
            continue
        if apex in have or apex in oos or ("*." + apex) in oos:
            continue
        ins.append(apex)
        have.add(apex)
        added.append(apex)
    if not added:
        return []
    sc["in_scope"] = ins
    try:
        json.dump(sc, open(path, "w"), indent=2)
    except OSError:
        return []
    return added


def _try_revive(sess, slug, base, AS):
    """A static-path health check used to mark a still-good login dead. If the file still
    has cookies/headers and the NEW probe/surface check accepts it, restore success."""
    if sess.get("success"):
        return False
    if not (sess.get("cookies") or sess.get("headers")):
        return False
    err = str(sess.get("error") or "").lower()
    if "site rejected" not in err and "logged out" not in err:
        return False
    trial = dict(sess)
    trial["success"] = True
    if not AS.valid(trial):
        return False
    try:
        if AS.site_rejects(trial, program=slug, base=base):
            return False
    except Exception:  # noqa: BLE001
        return False
    trial.pop("error", None)
    trial.pop("transient", None)
    trial["ts"] = time.time()
    try:
        AS.save(slug, trial, base)
    except Exception:  # noqa: BLE001
        return False
    return True


def _reload_if_engine_changed(base, slugs):
    """Restart hunts and the panel bridge when the code they imported is newer than the process."""
    hunt_m = _modules_mtime(HUNT_MODULES)
    site_m = _modules_mtime(SITE_MODULES)
    markp = os.path.join(os.path.expanduser(base), "_review", "engine_loaded.json")
    try:
        stamp = json.load(open(markp))
    except (OSError, json.JSONDecodeError, TypeError):
        stamp = {}
    loaded_hunt = float(stamp.get("mtime") or 0)
    loaded_site = float(stamp.get("site_mtime") or 0)
    online = {t["slug"] for t in _running_targets(base) if t.get("online")}
    stale_hunts = []
    for slug in slugs:
        if slug not in online:
            continue
        started = _started_epoch(slug)
        if started and started + 1 < hunt_m:
            stale_hunts.append(slug)
    restarted = False
    applied_extra = []
    if hunt_m > loaded_hunt or stale_hunts:
        for slug in slugs:
            if slug not in online:
                continue
            if _pm2_restart("hunt-" + slug):
                restarted = True
        if restarted:
            applied_extra.append({"action": "reload", "target": ",".join(sorted(online)),
                                  "result": "hunts restarted onto the current engine modules"})
    bridge_started = _started_named("hunt-bridge")
    stale_bridge = bool(bridge_started and bridge_started + 1 < site_m)
    if site_m > loaded_site or stale_bridge:
        if _pm2_restart("hunt-bridge"):
            restarted = True
            applied_extra.append({"action": "reload-site", "target": "hunt-bridge",
                                  "result": "panel bridge restarted onto the current session/check code"})
    try:
        json.dump({"mtime": hunt_m, "site_mtime": site_m, "ts": _now()}, open(markp, "w"))
    except OSError:
        pass
    if applied_extra:
        _publish_live(base, applied_extra)
    return restarted


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
        # Deep mode stores every job as class "deep", so an auth gap never shows up as idor/bola.
        auth_gap = any(c in zero for c in hi_classes) or ("deep" in zero)
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
                and not auth.get("two_account") and auth_gap):
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
        if not auth.get("session_valid") and auth_gap:
            err = ""
            try:
                err = str(json.load(open(os.path.join(base, "_identity", slug + "-session.json"))).get("error") or "")
            except (OSError, json.JSONDecodeError):
                err = ""
            if any(k in err.lower() for k in ("429", "rate", "timeout", "parse", "signup")):
                needs_op.append(f"{slug}: no session yet ({err[:90]}). Signup retries after its cooldown; "
                                "a pasted login is only needed if that retry does not return a site.")
            else:
                needs_op.append(f"{slug}: no auth session — paste a test login in the panel to unlock "
                                f"{', '.join(c for c in list(hi_classes) + ['deep'] if c in zero)}")
    return applied, needs_op


def _selfcheck_ok():
    """True iff the full selfcheck gauntlet still passes — the gate that lets an auto-fix stay."""
    import subprocess
    try:
        r = subprocess.run(["python3", "/root/Claude-BugHunter/scripts/selfcheck.py"],
                           capture_output=True, text=True, timeout=300)
        return "0 failed" in (r.stdout + r.stderr)
    except Exception:  # noqa: BLE001
        return False


def _rec_sig(rec):
    import hashlib
    key = (rec.get("where", "") + "|" + " ".join((rec.get("action", "") or "").lower().split()[:8]))
    return hashlib.md5(key.encode()).hexdigest()[:12]


_AUTOFIX_DIRS = ["/root/Claude-BugHunter/engine", "/root/Claude-BugHunter/scripts",
                 os.path.expanduser("~/.claude/skills")]


def autofix(base, rev):
    """ACTUALLY IMPLEMENT the review's recommendations — not just list them. Guarded hard: one rec per run
    (S/M effort), skips ones already done, snapshots engine+scripts+skills, runs the agent, then GATES on the
    full selfcheck and AUTO-REVERTS if it fails or errors. Does NOT restart hunts (avoids overload); engine
    edits take effect on the next natural restart, skills/flags take effect immediately. Off: REVIEW_AUTOFIX=0.
    Returns [{rec, where, result}]."""
    out = []
    if os.environ.get("REVIEW_AUTOFIX", "1") != "1":
        return out
    # SAFE scope only: skill (markdown). Engine/config auto-edits over-reach (an agent will rewrite 6 files
    # for "one rec") and can slip triager-grade violations past a structural selfcheck — those stay surfaced
    # for supervised/in-session application. recon/auth are already handled deterministically in apply_fixes.
    recs = [r for r in (rev.get("recommendations") or [])
            if (r.get("effort") or "").upper() in ("S", "M")
            and (r.get("where") or "").lower() == "skill"]
    donep = os.path.join(_review_dir(base), "autofix_done.json")
    try:
        done = set(json.load(open(donep)))
    except Exception:  # noqa: BLE001
        done = set()
    rec = next((r for r in recs if _rec_sig(r) not in done), None)
    if not rec:
        return out
    import shutil as _sh
    import tempfile
    snap = tempfile.mkdtemp(prefix="autofix-")
    for s in _AUTOFIX_DIRS:                              # snapshot for revert
        try:
            _sh.copytree(s, os.path.join(snap, os.path.basename(s)))
        except Exception:  # noqa: BLE001
            pass
    task = (
        "You are improving the 0xRay bug-hunting harness. Implement EXACTLY this ONE recommendation, "
        "minimally and safely — nothing else:\n"
        f"  ACTION: {rec.get('action')}\n  WHY: {rec.get('why')}\n  WHERE: {rec.get('where')}\n\n"
        "HARD RULES:\n"
        "- Make the SMALLEST change that achieves it; keep it backward-compatible.\n"
        "- Preserve ALL safety rails (in-scope only, read-only by default, NO brute-force/cracking, NO DoS, "
        "stop-at-draft, triager-grade honesty). Never weaken them.\n"
        "- Do NOT break the selfcheck. After editing, run `python3 /root/Claude-BugHunter/scripts/selfcheck.py` "
        "yourself and make sure it still prints '0 failed'.\n"
        "- Edit files only under /root/Claude-BugHunter/engine, /root/Claude-BugHunter/scripts, or "
        f"{os.path.expanduser('~/.claude/skills')}.\n"
        "End with a fenced ```json``` block: {\"changed_files\":[...],\"summary\":\"...\"}")
    try:
        import agent as A
        A.run_agent(task, context=None, timeout=int(os.environ.get("REVIEW_AUTOFIX_TIMEOUT", "900")))
    except Exception:  # noqa: BLE001
        pass
    # over-reach guard: a minimal skill fix must touch very few files; many changed => revert even if selfcheck
    # passes (agents will quietly rewrite half the tree for "one rec").
    import subprocess as _sp
    nchanged = 0
    for s in _AUTOFIX_DIRS:
        b = os.path.join(snap, os.path.basename(s))
        if os.path.isdir(b):
            try:
                rr = _sp.run(["diff", "-rq", b, s], capture_output=True, text=True, timeout=60)
                nchanged += len([ln for ln in rr.stdout.splitlines() if ln.strip()])
            except Exception:  # noqa: BLE001
                nchanged += 99
    maxf = int(os.environ.get("REVIEW_AUTOFIX_MAXFILES", "3"))
    sc_ok = _selfcheck_ok()
    if sc_ok and nchanged <= maxf:
        done.add(_rec_sig(rec))
        try:
            json.dump(list(done), open(donep, "w"))
        except OSError:
            pass
        out.append({"rec": rec.get("action"), "where": rec.get("where"),
                    "result": "APPLIED (selfcheck passed; engine edits take effect on next hunt restart)"})
    else:                                               # revert — a broken auto-fix must never reach hunting
        for s in _AUTOFIX_DIRS:
            b = os.path.join(snap, os.path.basename(s))
            if os.path.isdir(b):
                _sh.rmtree(s, ignore_errors=True)
                try:
                    _sh.copytree(b, s)
                except Exception:  # noqa: BLE001
                    pass
        reason = "selfcheck failed" if not sc_ok else f"over-reach ({nchanged} files > {maxf})"
        out.append({"rec": rec.get("action"), "where": rec.get("where"),
                    "result": f"REVERTED ({reason} — change discarded, harness untouched)"})
    _sh.rmtree(snap, ignore_errors=True)
    return out


def _coerce_review(agent_result):
    """The review object inside an agent reply, or None. Accepts a fenced block, a bare object,
    or a result that is already a dict. Ignores replies that are not a review."""
    if not isinstance(agent_result, dict):
        return None
    text = agent_result.get("result") or ""
    if isinstance(text, dict):
        rev = text
    else:
        try:
            import agent as A
            rev = A.extract_json(text) if text else None
        except Exception:  # noqa: BLE001
            rev = None
    if not isinstance(rev, dict):
        return None
    if rev.get("assessment") or rev.get("top_priority") or rev.get("score_0_10") is not None:
        return rev
    return None


def _next_model(failed):
    pool = [m.strip() for m in os.environ.get("CURSOR_HUNT_MODELS", "").split(",") if m.strip()]
    for m in pool:
        if m != failed:
            return m
    return None


def _last_run_epoch(base):
    path = os.path.join(_review_dir(base), "last_run.json")
    try:
        return float(json.load(open(path)).get("epoch") or 0)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0.0


def _stamp_run(base):
    try:
        json.dump({"epoch": time.time(), "ts": _now()},
                  open(os.path.join(_review_dir(base), "last_run.json"), "w"))
    except OSError:
        pass


def _too_soon(base):
    elapsed = time.time() - _last_run_epoch(base)
    return elapsed < REVIEW_INTERVAL_MIN * 60


def review(base=BASE, quiet=False, dry=False, force=False, apply_only=False):
    try:
        import notify
        notify._load_env_file()                       # make CURSOR_HUNT_MODELS* + HUNT_WEB_DIR available
    except Exception:  # noqa: BLE001
        notify = None
    base = os.path.expanduser(base)
    if not dry and not force and _too_soon(base):
        if not quiet:
            print(f"review skipped: last pass was under {REVIEW_INTERVAL_MIN} min ago")
        return {"skipped": "interval"}
    lock = os.path.join(_review_dir(base), "review.lock")
    try:
        if os.path.exists(lock) and time.time() - os.path.getmtime(lock) < 1800:
            if not quiet:
                print("review skipped: another pass is still running")
            return {"skipped": "locked"}
        open(lock, "w").write(_now())
    except OSError:
        lock = ""
    try:
        return _review_body(base, quiet, dry, apply_only, notify)
    finally:
        if lock:
            try:
                os.remove(lock)
            except OSError:
                pass


def _review_body(base, quiet, dry, apply_only, notify):
    snap = gather(base)
    if dry:
        print(json.dumps(snap, indent=2)[:4000])
        return {"dry": True, "targets": len(snap["targets"])}
    # The expert fixes do not call a model. They run even when the box is too loaded for the narrative review.
    expert_applied, expert_sigs = expert_apply(base, snap.get("targets") or [])
    if apply_only:
        applied, needs_op = apply_fixes(base, snap)
        applied = list(expert_applied) + list(applied)
        _stamp_run(base)
        if not quiet:
            print(json.dumps({"apply_only": True, "applied": applied, "needs_operator": needs_op}, indent=2))
        return {"ok": True, "apply_only": True, "applied": len(applied), "needs_operator": len(needs_op)}
    if snap["box"]["load_1_5_15"][2] > LOAD_CEIL:      # 15m load — don't pile onto a slammed box
        msg = (f"review skipped: 15m load {snap['box']['load_1_5_15'][2]} > ceil {LOAD_CEIL}"
               + (f" — expert fixes still applied ({len(expert_applied)})" if expert_applied else ""))
        if not quiet:
            print(msg)
        if notify:
            notify.site_alert("reviewer", msg, base=base, kind="review")
        _stamp_run(base)
        return {"skipped": "overload"}
    import agent as A
    task = _task(snap)
    r = A.run_agent(task, context=None, timeout=REVIEW_TIMEOUT)   # one-shot, rotates the model pool
    rev = _coerce_review(r)
    if rev is None:                                   # envelope parse miss OR prose-only reply: one other model
        alt = _next_model(r.get("model"))
        if alt:
            r = A.run_agent(task, context=None, model=alt, timeout=REVIEW_TIMEOUT, attempts=1)
            rev = _coerce_review(r)
    if not isinstance(rev, dict):
        tail = (r.get("result") or "").strip().replace("\n", " ")[-180:]
        rev = {"assessment": f"agent review unavailable ({r.get('error') or 'no-json'})"
                             + (f" — {tail}" if tail else ""),
               "weaknesses": [], "missing": [], "recommendations": [],
               "top_priority": "(agent produced no structured review this pass)", "score_0_10": None}
    rev["_model"] = r.get("model")
    rev["expert"] = expert_sigs
    applied, needs_op = apply_fixes(base, snap)         # DIRECTLY apply the safe, deterministic fixes
    applied = list(expert_applied) + list(applied)
    rev["applied"] = applied
    rev["needs_operator"] = needs_op
    rev["autofixed"] = autofix(base, rev)               # IMPLEMENT a recommendation (selfcheck-gated, auto-revert)
    _persist(base, snap, rev)
    _stamp_run(base)
    if notify:
        tp = rev.get("top_priority") or "review complete"
        lines = [f"workflow review (score {rev.get('score_0_10','?')}/10): {tp}",
                 f"confirmed={snap['yield']['confirmed_total']} valuable={snap['yield']['valuable_total']}"]
        if applied:
            lines.append("AUTO-APPLIED: " + "; ".join(f"{a['action']}@{a['target']}" for a in applied))
        if rev["autofixed"]:
            lines.append("AUTO-FIX: " + "; ".join(f"{a['result'].split('(')[0].strip()} — {a['rec'][:50]}"
                                                   for a in rev["autofixed"]))
        if needs_op:
            lines.append("NEEDS YOU: " + "; ".join(needs_op[:3]))
        notify.site_alert("reviewer", lines, base=base, kind="review")
    if not quiet:
        print(_render_md(snap, rev))
    return {"ok": True, "score": rev.get("score_0_10"), "recs": len(rev.get("recommendations") or []),
            "applied": len(applied), "autofixed": len(rev["autofixed"]),
            "needs_operator": len(needs_op), "model": r.get("model")}


def _selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="review-expert-")
    slug = "demo"
    os.makedirs(os.path.join(d, slug))
    os.makedirs(os.path.join(d, "_identity"))
    os.makedirs(os.path.join(d, "_targets"))
    open(os.path.join(d, slug, "engine.log"), "w").write("\n".join([
        "validate: ✗ rejected oauth @ https://evil.example/a — no impact",
        "validate: ✗ rejected oauth @ https://evil.example/a — no impact",
        "validate: ✗ rejected oauth @ https://evil.example/a — no impact",
    ]))
    json.dump({"surface": [{"url": "https://app.example/api/orders", "vuln_class": "deep"}],
               "tested": {}, "confirmed": [], "hunt_notes": {},
               "candidates": [{"url": "https://mcp.example/a", "vuln_class": "oauth", "evidence": "x"}]},
              open(os.path.join(d, slug, "state.json"), "w"))
    json.dump({"name": "demo", "in_scope": ["app.example"], "out_of_scope": ["mcp.example"]},
              open(os.path.join(d, "_targets", "demo.json"), "w"))
    json.dump({"success": False, "error": "agent: parse:no-json", "transient": False},
              open(os.path.join(d, "_identity", "demo-session.json"), "w"))
    try:
        applied, sigs = expert_apply(d, [{"slug": slug}], reload=False)
        directive = json.load(open(os.path.join(d, "_review", "directives", "demo.json")))
        urls = [c["url"] for c in directive["close"]]
        assert "https://evil.example/a" in urls, urls
        assert "https://mcp.example/a" in urls, urls
        assert json.load(open(os.path.join(d, "_identity", "demo-session.json")))["transient"] is True
        assert any(a["action"] == "parse_retry" for a in applied), applied
        assert sigs[0]["repeated_validation"][0]["times"] == 3
        assert directive.get("skip_junk") is True
        # 40-minute gate: a fresh stamp skips, a stale stamp does not
        _stamp_run(d)
        assert _too_soon(d) is True
        json.dump({"epoch": time.time() - (REVIEW_INTERVAL_MIN * 60 + 5)},
                  open(os.path.join(d, "_review", "last_run.json"), "w"))
        assert _too_soon(d) is False
        # a rejected login, a login-wall close, and a park on a zero-yield target are healed offline
        key = "https://app.example/api/orders||deep"
        st = json.load(open(os.path.join(d, slug, "state.json")))
        st["tested"] = {key: 1}
        st["hunt_notes"] = {key: {"analysis": "unauthenticated 401, auth enforced before lookup"}}
        st["mine_agent_ts"] = time.time() - 4000
        st["mine_agent_added"] = 0
        st["surface"] = [{"url": "https://app.example/api/orders", "vuln_class": "deep"}]
        json.dump(st, open(os.path.join(d, slug, "state.json"), "w"))
        json.dump({"success": True, "host": "app.example", "cookies": {"sid": "x"}},
                  open(os.path.join(d, "_identity", "demo-session.json"), "w"))
        os.makedirs(os.path.join(d, "_auth"), exist_ok=True)
        json.dump({"A": {"cookie": "sid=x"}}, open(os.path.join(d, "_auth", "demo.json"), "w"))
        json.dump({"park_until": time.time() + 3600, "close": []},
                  open(os.path.join(d, "_review", "directives", "demo.json"), "w"))
        healed = heal_runtime(d, slugs=[slug], probe=False, rejected_override={slug: True})
        assert healed and healed[0]["target"] == slug, healed
        assert json.load(open(os.path.join(d, "_identity", "demo-session.json")))["success"] is False
        assert json.load(open(os.path.join(d, "_review", "directives", "demo.json")))["park_until"] == 0
        hfile = json.load(open(os.path.join(d, "_review", "heals", "demo.json")))
        assert hfile.get("reopen_auth_wall") is True, hfile
        assert not os.path.exists(os.path.join(d, "_auth", "demo.json"))
        json.dump({"name": "demo", "in_scope": ["*.app.example"], "out_of_scope": ["mcp.example"]},
                  open(os.path.join(d, "_targets", "demo.json"), "w"))
        added = _ensure_apex(d, slug)
        assert "app.example" in added, added
        ins = json.load(open(os.path.join(d, "_targets", "demo.json")))["in_scope"]
        assert "app.example" in ins and "*.app.example" in ins
        json.dump({"name": "demo", "in_scope": ["*.mcp.example"], "out_of_scope": ["mcp.example"]},
                  open(os.path.join(d, "_targets", "demo.json"), "w"))
        assert _ensure_apex(d, slug) == []
        print("reviewer expert self-test: PASS")
        return 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _main(argv=None):
    ap = argparse.ArgumentParser(description="periodic hunt-workflow self-review")
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--dry", action="store_true", help="gather + print snapshot, no agent call")
    ap.add_argument("--selftest", action="store_true", help="offline check of the expert apply path")
    ap.add_argument("--force", action="store_true", help="run even if the last pass was under 40 minutes ago")
    ap.add_argument("--apply-only", action="store_true",
                    help="apply the expert fixes and skip the narrative agent")
    ap.add_argument("--loop", action="store_true",
                    help="stay up and run a review every REVIEW_INTERVAL_MIN (default 40)")
    a = ap.parse_args(argv)
    if a.selftest:
        return _selftest()
    if a.loop:
        while True:
            try:
                # Heals + stale-code reload run every minute so a dead login, a leftover
                # class slot, or an engine edit hits the panel and the hunt without waiting
                # for the 40-minute narrative review.
                for act in heal_runtime(a.base):
                    print(f"review heal: {act.get('target')} — {act.get('result')}", flush=True)
                slugs = [t["slug"] for t in _running_targets(a.base)]
                if _reload_if_engine_changed(a.base, slugs):
                    print("review reload: hunts/bridge restarted onto current code", flush=True)
                review(base=a.base, quiet=True, force=False)
            except Exception as e:  # noqa: BLE001
                print(f"review loop error: {type(e).__name__}: {e}", flush=True)
            time.sleep(max(15, HEAL_SEC))
        return 0
    out = review(base=a.base, quiet=a.quiet, dry=a.dry, force=a.force, apply_only=a.apply_only)
    if not a.quiet:
        print(json.dumps(out, indent=2) if not a.dry else "", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
