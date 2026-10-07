#!/usr/bin/env python3
"""
orchestrator.py — top-level anti-duplicate hunt pipeline. Stops at DRAFT; never submits.

Chains every piece of the harness into one auditable, resumable run:

  novelty  ->  recon  ->  rank(yield + dedup)  ->  hunt  ->  validate  ->  DRAFT-GATE  ->  STOP

- novelty     : observe the target's surface, diff vs the last snapshot. Fresh/changed surface is
                the lowest-dup, highest-signal place to spend effort (logged + stored for the hunt).
- recon..validate : delegated to engine.Engine (deterministic control flow; the LLM is used only for
                the hunt + adversarial validation steps). rank() already blends impact, yield, and a
                dedup down-rank, so known-issue surface sinks automatically.
- DRAFT-GATE  : every CONFIRMED finding is scored by disposition.py first (HOLD_RTFS /
                HOLD_INFORMATIVE are not drafted), then by the dedup oracle. LIKELY_DUP is HELD
                unless you flag it a regression; NOVEL / REVIEW become platform-ready drafts.
- STOP        : writes the drafts + an approval.md that lists exactly what a human must approve and
                the bb-platforms MCP calls to draft/submit. No submission is EVER performed here.

Autonomy contract (matches the operator's choice): fully automatic up to DRAFT; submitting is always
a separate, explicit human step. This module contains no submit path by construction.

  python3 engine/orchestrator.py --scope engine/engagement.example.json --mock        # dry-run the chain
  python3 engine/orchestrator.py --scope my.json --hunt --obs recon/obs.json           # live (needs agents)
  python3 engine/orchestrator.py selftest
"""
import argparse
import json
import os
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
import engine as E        # noqa: E402  (reuse the deterministic phase runner)
import dedup as D         # noqa: E402
import novelty as N       # noqa: E402

SEV_CVSS = {"critical": "9.1", "high": "8.1", "medium": "5.3", "low": "3.1", "unknown": "5.0"}


def _title(f):
    url = f.get("url", "")
    path = url.split("://", 1)[-1]
    path = "/" + path.split("/", 1)[1] if "/" in path else path
    cls = (f.get("vuln_class") or "issue").upper()
    actor = "an authenticated user" if "auth" not in (f.get("vuln_class") or "") else "an attacker"
    return f"{cls} in {path} allows {actor} to {('impact: ' + (f.get('evidence','')[:48]) or 'cause harm')}".strip()


def _draft_md(f, verdict):
    sev = (f.get("severity") or "unknown").lower()
    lines = [
        f"# {_title(f)}", "",
        f"**Severity:** {sev}  ·  **CVSS (starting point):** {SEV_CVSS.get(sev, '5.0')}",
        f"**Dedup verdict:** {verdict['verdict']} (score {verdict['score']}, corpus {verdict['corpus_size']})",
    ]
    if verdict["verdict"] == "UNKNOWN":
        lines.append("> ⚠ Dedup NOT performed — the corpus for this program is EMPTY. Refresh it (own reports "
                     "via the bb-platforms MCP + public H1/Bugcrowd) and re-check before submitting.")
    if verdict["verdict"] not in ("NOVEL", "UNKNOWN") and verdict.get("matches"):
        m = verdict["matches"][0]
        lines.append(f"> ⚠ Overlaps a known issue: {m.get('title','')} {m.get('link','')}")
        lines.append("> State the differentiator below (different endpoint/param/impact, or fix-bypass) or HOLD.")
    lines += [
        "", "## Summary", "",
        f"{f.get('evidence','(describe the attacker-attainable impact in one sentence)')}",
        "", "## Steps to reproduce", "",
        "```http", f"{f.get('request','(exact HTTP request)')}", "```",
        "", "## Impact", "", f"{f.get('evidence','')}",
        "", "## Remediation", "", "(1-2 concrete sentences)",
    ]
    if f.get("proof_note"):
        lines += ["", f"> Proof note: {f['proof_note']}"]
    if f.get("scope_warning"):
        lines += ["", f"> ⚠ SCOPE: PoC referenced out-of-scope host(s): {', '.join(f['scope_warning'])}"]
    return "\n".join(lines)


class Orchestrator:
    def __init__(self, scope_path, base="~/.bughunter-engagements",
                 mock=False, do_hunt=True, parallel=3, model="claude-sonnet-4-6"):
        self.base = base
        self.mock = mock
        self.do_hunt = do_hunt
        # Tunables (env-configurable so multiple concurrent hunts don't starve one Cursor account):
        #   timeout  — a step reads big skill files + tests, so give it room to COMPLETE (a timed-out
        #              step yields nothing); but cap it so a stuck agent can't hold a round forever.
        #   parallel — lower this when several targets hunt at once (less quota contention => fewer
        #              rate-limits/timeouts => more steps actually finish => more real candidates).
        agent_timeout = int(os.environ.get("HUNT_AGENT_TIMEOUT", "300"))
        max_hunts = int(os.environ.get("HUNT_MAX_HUNTS", "24"))   # items tested per round (cover more surface)
        parallel = int(os.environ.get("HUNT_PARALLEL", str(parallel)))
        self.eng = E.Engine(scope_path, base, model, max_hunts, 40, agent_timeout, mock, False, parallel, False)

    # ---- step 1: novelty-first targeting --------------------------------------
    def novelty(self, obs=None):
        seeds = self.eng.scope.seeds or []
        if not seeds:
            return None
        from urllib.parse import urlparse
        target = urlparse(seeds[0]).hostname or seeds[0]
        if obs is None and not self.mock:
            try:
                import observe as O
                obs = O.observe(target, base=self.base)
            except Exception as e:
                self.eng.eng.log(f"novelty: observe skipped ({e})")
                return None
        if obs is None:
            return None
        diff = N.Novelty(target, base=self.base).watch(obs)
        tag = "baseline" if diff.get("baseline") else ("CHANGES" if diff.get("has_changes") else "no change")
        self.eng.eng.log(f"novelty: {target} -> {tag}; " + " | ".join(N.summarize(diff))[:200])
        return diff

    # ---- step 3: draft gate (dedup) -------------------------------------------
    def draft_gate(self):
        confirmed = self.eng.eng.state.get("confirmed", [])
        cp = D.Corpus(self.eng.scope.name, base=self.base)
        drafts_dir = os.path.join(self.eng.eng.dir, "drafts")
        held_dir = os.path.join(self.eng.eng.dir, "held")
        os.makedirs(drafts_dir, exist_ok=True)
        os.makedirs(held_dir, exist_ok=True)
        import disposition as DP
        drafted, held, policy = [], [], []
        for i, f in enumerate(confirmed, 1):
            name = f"{i:02d}-{(f.get('vuln_class') or 'finding')}.md"
            disp = DP.check(f)
            if disp["verdict"] != "PASS":
                body = ("# HELD — " + disp["verdict"] + "\n\n" + disp["reason"] + "\n\n"
                        + "\n".join(f"- **{r['id']}:** {r['reason']}" for r in disp.get("rules") or []))
                open(os.path.join(held_dir, name), "w").write(body + "\n")
                policy.append({"finding": f, "disposition": disp, "file": os.path.join(held_dir, name)})
                E._lrn("record_outcome", self.eng.scope.name, f.get("vuln_class"),
                       "held-" + disp["verdict"].lower().replace("_", "-"),
                       disp.get("reason", ""), base=self.base)
                continue
            v = cp.check({"vuln_class": f.get("vuln_class", ""), "url": f.get("url", ""),
                          "title": f.get("evidence", "")})
            md = _draft_md(f, v)
            if v["verdict"] == "LIKELY_DUP":
                open(os.path.join(held_dir, name), "w").write(md)
                held.append({"finding": f, "dedup": v, "file": os.path.join(held_dir, name)})
                E._lrn("record_outcome", self.eng.scope.name, f.get("vuln_class"), "duplicate",
                       f"held: {v.get('score')}", base=self.base)
            else:
                open(os.path.join(drafts_dir, name), "w").write(md)
                link = self._publish(f, v, md, i)          # public HTML page (finding.redtracefai.com)
                drafted.append({"finding": f, "dedup": v, "file": os.path.join(drafts_dir, name), "link": link})
                E._lrn("record_outcome", self.eng.scope.name, f.get("vuln_class"), "reported",
                       v.get("verdict", ""), base=self.base)
        self._policy = policy
        self._write_index(drafted)
        self._approval(drafted, held, policy)
        return drafted, held

    # ---- publish findings to the public viewer -------------------------------
    @staticmethod
    def _brandbar():
        """The 0xRay logo + wordmark row for the top of every public finding page."""
        mark = ('<svg width="22" height="22" viewBox="0 0 64 64" fill="none" style="vertical-align:middle">'
                '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
                '<stop offset="0" stop-color="#5a97ff"/><stop offset="1" stop-color="#2f6ae0"/></linearGradient></defs>'
                '<path d="M32 8l20.8 12v24L32 56 11.2 44V20L32 8z" stroke="url(#bg)" stroke-width="3" stroke-linejoin="round"/>'
                '<path d="M32 13v8M32 43v8M13 32h8M43 32h8" stroke="#5a97ff" stroke-width="3" stroke-linecap="round"/>'
                '<circle cx="32" cy="32" r="5" fill="url(#bg)"/></svg>')
        return ('<div style="display:flex;align-items:center;gap:9px;margin-bottom:12px">' + mark +
                '<span style="font-weight:800;font-size:15px;letter-spacing:.3px">'
                '<span style="color:#5a97ff">0x</span>Ray</span>'
                '<span style="color:#6b7482;font-size:11px;margin-left:auto">Hunt Harness · draft — not submitted</span></div>')

    @staticmethod
    def _finding_html(scope_name, f, v, md):
        import html as H
        sev = (f.get("severity") or "unknown").lower()
        color = {"critical": "#b00020", "high": "#d93025", "medium": "#f29900",
                 "low": "#1a73e8"}.get(sev, "#5f6368")
        return (
            '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<link rel="icon" type="image/svg+xml" href="favicon.svg"><meta name="theme-color" content="#0b0e14">'
            f'<title>0xRay · {H.escape((f.get("vuln_class") or "finding"))} — {H.escape(scope_name)}</title></head>'
            '<body style="margin:0;background:#eef0f3;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif">'
            '<div style="max-width:820px;margin:0 auto;padding:24px">'
            '<div style="background:#0d1117;border-radius:12px 12px 0 0;padding:18px 24px;color:#fff">'
            + Orchestrator._brandbar() +
            f'<span style="background:{color};color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;'
            f'font-weight:700;text-transform:uppercase">{H.escape(sev)}</span>'
            f'<span style="font-size:18px;font-weight:700;margin-left:10px">{H.escape((f.get("vuln_class") or "finding").upper())}</span>'
            f'<div style="color:#8b949e;font-size:13px;margin-top:6px;font-family:monospace">{H.escape(f.get("url",""))}</div></div>'
            '<div style="background:#fff;border-radius:0 0 12px 12px;padding:10px 24px 24px">'
            f'<p style="color:#5f6368;font-size:13px">Dedup: <b>{H.escape(v["verdict"])}</b> (score {v["score"]}) '
            '· status: <b>draft — not submitted</b></p>'
            '<pre style="white-space:pre-wrap;word-wrap:break-word;background:#f6f8fa;border:1px solid #e1e4e8;'
            f'border-radius:8px;padding:16px;font-size:13px;line-height:1.55">{H.escape(md)}</pre>'
            '</div></div></body></html>')

    def _publish(self, f, v, md, idx):
        wd, base = os.environ.get("HUNT_WEB_DIR"), os.environ.get("HUNT_PUBLIC_URL")
        if not wd:
            return None
        try:
            os.makedirs(wd, exist_ok=True)
            slug = f"finding-{self.eng.scope.name}-{idx:02d}-{(f.get('vuln_class') or 'x')}".replace("/", "-")
            open(os.path.join(wd, slug + ".html"), "w", encoding="utf-8").write(
                self._finding_html(self.eng.scope.name, f, v, md))
            return (base.rstrip("/") + "/" + slug + ".html") if base else None
        except Exception as e:  # noqa: BLE001
            self.eng.eng.log(f"publish: skipped ({e})")
            return None

    def _write_index(self, drafted):
        wd = os.environ.get("HUNT_WEB_DIR")
        if not wd or not drafted:
            return
        try:
            import html as H
            items = ""
            for d in drafted:
                f, link = d["finding"], d.get("link") or "#"
                items += (f'<li style="margin:8px 0"><a href="{H.escape(link)}">'
                          f'[{H.escape((f.get("severity") or "?").upper())}] '
                          f'{H.escape((f.get("vuln_class") or "?").upper())} — {H.escape(f.get("url",""))}</a></li>')
            open(os.path.join(wd, "index.html"), "w", encoding="utf-8").write(
                '<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">'
                '<link rel="icon" type="image/svg+xml" href="favicon.svg"><meta name="theme-color" content="#0b0e14">'
                f'<title>0xRay · Findings — {H.escape(self.eng.scope.name)}</title>'
                '<body style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:820px;margin:0 auto;padding:24px;background:#eef0f3">'
                '<div style="background:#0d1117;border-radius:12px;padding:16px 22px;color:#fff;margin-bottom:18px">'
                + Orchestrator._brandbar() +
                f'<div style="font-size:17px;font-weight:700">{H.escape(self.eng.scope.name)} — {len(drafted)} draft finding(s)</div></div>'
                f'<ul style="line-height:1.9">{items}</ul></body>')
        except Exception as e:  # noqa: BLE001
            self.eng.eng.log(f"index: skipped ({e})")

    def _approval(self, drafted, held, policy=None):
        policy = policy or []
        p = os.path.join(self.eng.eng.dir, "approval.md")
        lines = [f"# Approval gate — {self.eng.scope.name}", "",
                 f"Pipeline stopped at DRAFT. **Nothing has been submitted.** "
                 f"{len(drafted)} draft(s) ready, {len(held)} held as likely-duplicate, "
                 f"{len(policy)} held by the disposition gate (RTFS / Informative).", "",
                 "## Ready to review -> approve -> submit", ""]
        if not drafted:
            lines.append("_No novel findings drafted._")
        for d in drafted:
            f, v = d["finding"], d["dedup"]
            lines += [f"- **{(f.get('vuln_class') or '?').upper()}** @ `{f.get('url','')}` "
                      f"— {f.get('severity','?')} — dedup {v['verdict']} ({v['score']}) — `{d['file']}`"]
        lines += ["", "## Held by disposition (RTFS / Informative — do NOT draft)", ""]
        if not policy:
            lines.append("_None._")
        for h in policy:
            f, d = h["finding"], h["disposition"]
            lines += [f"- **{(f.get('vuln_class') or '?').upper()}** @ `{f.get('url','')}` "
                      f"— {d.get('verdict')} — {d.get('reason','')} — `{h['file']}`"]
        lines += ["", "## Held (likely duplicate — do NOT submit without a differentiator)", ""]
        if not held:
            lines.append("_None._")
        for h in held:
            f, v = h["finding"], h["dedup"]
            m = v["matches"][0] if v.get("matches") else {}
            lines += [f"- **{(f.get('vuln_class') or '?').upper()}** @ `{f.get('url','')}` "
                      f"— matches {m.get('link','?')} ({v['score']}) — `{h['file']}`"]
        lines += ["", "## To submit an approved draft (human step)", "",
                  "1. Refresh the corpus and re-check: `python3 engine/dedup.py check --program "
                  f"{self.eng.scope.name} --class <cls> --url <u> --title <t>`",
                  "2. Draft on the platform via the bb-platforms MCP: `draft_yeswehack(...)` / `draft_bugcrowd(...)`.",
                  "3. Only after YOUR review: `submit_yeswehack` / `submit_bugcrowd` "
                  "(hard-gated by BB_ALLOW_SUBMIT + explicit per-report approval).", ""]
        open(p, "w").write("\n".join(lines))
        self.eng.eng.log(f"draft-gate: {len(drafted)} draft(s), {len(held)} held -> {p} (STOP: awaiting approval)")
        return p

    # ---- notify (verified + validated + drafted -> email) ---------------------
    def _email_drafts(self, drafted):
        import notify
        findings = [{"vuln_class": d["finding"].get("vuln_class"), "url": d["finding"].get("url"),
                     "severity": d["finding"].get("severity"), "verdict": d["dedup"]["verdict"],
                     "score": d["dedup"]["score"], "link": d.get("link")} for d in drafted]
        subject, text, html = notify.finding_email(self.eng.scope.name, findings,
                                                   public_url=os.environ.get("HUNT_PUBLIC_URL"))
        sent = notify.send_safe(subject, text, html=html)
        self.eng.eng.log(f"notify: {len(drafted)} draft(s) -> "
                         + ("emailed (HTML)" if sent else "dry-run (set SMTP_* in harness/.env)"))

    # ---- run ------------------------------------------------------------------
    def run(self, obs=None):
        try:
            import notify
            notify._load_env_file()          # pull SMTP_* + HUNT_PUBLIC_URL/HUNT_WEB_DIR from harness/.env
        except Exception:
            pass
        self.novelty(obs=obs)
        # authenticated hunting: provision a disposable test session once (sandbox signup) so the hunt
        # reaches behind-login surface where IDOR/authz/business-logic bugs actually live.
        if os.environ.get("HUNT_AUTH") == "1" and self.do_hunt and not self.mock:
            try:
                import authsession as AS
                sess = AS.load(self.eng.scope.name, self.base)
                if AS.valid(sess):
                    pass                                    # already have a working session
                elif AS.recent_attempt(self.eng.scope.name, self.base):
                    self.eng.eng.log("auth: recent signup attempt failed (cooldown) — hunting unauthenticated "
                                     "(target likely has no open self-service signup; provide creds to go deeper)")
                else:
                    self.eng.eng.log("auth: no session yet — provisioning a disposable test account (sandbox signup)…")
                    r = AS.provision(self.eng.scope.name, base=self.base)
                    if AS.valid(r):
                        self.eng.eng.log(f"auth: session captured on {r.get('host')} as {r.get('user')} "
                                         f"— hunting AUTHENTICATED")
                    else:
                        _retry = "~30 min (transient timeout — will keep trying)" if r.get("transient") else \
                                 "6h (no open self-service signup — provide creds to go deeper)"
                        self.eng.eng.log(f"auth: could not provision a session ({r.get('error')}: "
                                         f"{str(r.get('notes',''))[:140]}) — hunting unauthenticated; retry in {_retry}")
                        try:                                # ON-SITE notification (panel feed), not email
                            import notify
                            notify.site_alert(self.eng.scope.name,
                                ["Can't register a test account \u2014 hunting UNAUTHENTICATED. Most paying bugs "
                                 "(IDOR/BOLA/auth) need login. Provide a test login (cookies/token) to go deeper.",
                                 f"reason: {r.get('error')}"],
                                base=self.base, kind="needs-auth")
                        except Exception:  # noqa: BLE001
                            pass
            except Exception as e:  # noqa: BLE001
                self.eng.eng.log(f"auth: provisioning skipped ({type(e).__name__}: {e})")
        phases = ["recon", "rank", "map"] + (["hunt", "validate", "chain"] if self.do_hunt else [])
        self.eng.run(phases)
        drafted, held = self.draft_gate()
        if drafted:
            self._email_drafts(drafted)
        elif not self.eng.eng.state.get("confirmed"):
            self.eng.eng.log("orchestrator: no confirmed finding THIS pass — NOT a conclusion. "
                             "Rotate classes / re-recon for new surface (redteam-mindset: DO NOT STOP).")
        summary = {**self.eng.eng.summary(), "drafted": len(drafted), "held_dups": len(held),
                   "held_policy": len(getattr(self, "_policy", []) or []),
                   "submitted": 0, "dir": self.eng.eng.dir}
        self.eng.eng.log(f"orchestrator done | {summary}")
        return summary

    def _status_email(self, msg):
        # Email is reserved for findings — operational/crash status goes ON-SITE (panel bell), not mail.
        try:
            import notify
            notify.site_alert(self.eng.scope.name, [msg], base=self.base, kind="ops")
        except Exception:  # noqa: BLE001
            pass

    def run_persist(self, obs=None, rounds=0, interval=0, max_errors=5, backoff=30):
        """Keep hunting in rounds — crash-safe and never silently quits.

        Each round RE-OBSERVES live (new subdomains / redeployed JS become new surface) and hunts only
        the untested items, so coverage grows over time. Guarantees:
          - 'no finding this round' is a STATUS, never a stop (it rotates classes + re-recons).
          - a round that raises is caught, logged, backed off, and the loop CONTINUES (no crash-out).
          - after `max_errors` consecutive crashes it emails you, then keeps retrying.
        State is persisted every step, so if the whole process is killed, a pm2 restart resumes here."""
        r = errors = empty = 0
        drafted_total = 0
        while True:
            r += 1
            self.eng.eng.log(f"=== persist round {r} ===")
            try:
                s = self.run(obs=None)               # obs=None -> re-observe live each round
                errors = 0
                drafted_total += s.get("drafted", 0)
                empty = empty + 1 if (s.get("drafted", 0) == 0 and not s.get("confirmed")) else 0
                if empty:
                    E._lrn("record_outcome", self.eng.scope.name, "", "empty",
                           f"round {r}: no finding (surface={s.get('surface')}, tested={s.get('tested')})",
                           base=self.base)
                if empty and empty % 10 == 0:
                    self.eng.eng.log(f"persist: {empty} empty round(s) — STILL hunting, not concluding "
                                     "'no vuln' (re-reconning for new surface, rotating classes by yield).")
            except KeyboardInterrupt:
                self.eng.eng.log("persist: stopped by operator")
                break
            except Exception as e:  # noqa: BLE001 — a crashing round must never kill the hunt
                errors += 1
                E._lrn("record_outcome", self.eng.scope.name, "", "error",
                       f"round {r} crashed: {type(e).__name__}: {e}", base=self.base)
                self.eng.eng.log(f"persist round {r} CRASHED (non-fatal, will retry): {type(e).__name__}: {e}")
                if errors >= max_errors:
                    self._status_email(f"Hunt on {self.eng.scope.name} hit {errors} consecutive errors "
                                       f"(last: {type(e).__name__}: {e}). Still retrying — check the harness/bridge.")
                    errors = 0
                if backoff:
                    time.sleep(min(backoff * (errors + 1), 300))
                if rounds and r >= rounds:
                    break
                continue
            if rounds and r >= rounds:
                break
            if interval:
                nxt = time.strftime("%H:%M", time.gmtime(time.time() + interval))
                self.eng.eng.log(f"persist: round {r} done — sleeping {int(interval/60)}m, next round ~{nxt} UTC")
                time.sleep(interval)
        return {"rounds": r, "drafted_total": drafted_total, "dir": self.eng.eng.dir}


def _selftest():
    import tempfile
    base = tempfile.mkdtemp()
    # sandbox: never load the real harness .env, never email, never write to the live /var/www viewer
    os.environ["HUNT_ENV_FILE"] = "/nonexistent-selftest-env"
    os.environ["HUNT_WEB_DIR"] = os.path.join(base, "web")
    os.environ.pop("HUNT_PUBLIC_URL", None)
    for _k in ("SMTP_HOST", "SMTP_TO"):
        os.environ.pop(_k, None)
    scope = os.path.join(ENGINE, "engagement.example.json")
    obs = {"subdomains": ["localhost"], "hosts": [{"url": "http://localhost:3002", "status": 200}],
           "js": [], "endpoints": ["http://localhost:3002/api/account"], "params": []}
    orc = Orchestrator(scope, base=base, mock=True, do_hunt=True)
    s = orc.run(obs=obs)
    assert s["confirmed"] >= 1, s                     # mock IDOR confirms
    assert s["drafted"] >= 1, s                       # and becomes a draft (NOVEL, no corpus)
    assert s["submitted"] == 0, s                     # never submits
    assert os.path.isfile(os.path.join(s["dir"], "approval.md")), "approval gate written"
    drafts = os.listdir(os.path.join(s["dir"], "drafts"))
    assert any(d.endswith(".md") for d in drafts), drafts
    # with a matching corpus, the same finding is HELD, not drafted
    D.Corpus("demo-local", base=base).ingest([{"source": "h1-public", "vuln_class": "idor",
             "url": "http://localhost:3002/api/account?id=1", "title": "IDOR on account id param",
             "link": "https://h1/1"}])
    import shutil
    shutil.rmtree(os.path.join(base, "demo-local"))   # fresh engagement so hunt re-runs
    orc2 = Orchestrator(scope, base=base, mock=True, do_hunt=True)
    s2 = orc2.run(obs=obs)
    assert s2["held_dups"] >= 1 and s2["drafted"] == 0, s2

    # crash-safety: a round that raises must NOT stop the persist loop
    orc3 = Orchestrator(scope, base=tempfile.mkdtemp(), mock=True, do_hunt=True)
    calls = {"n": 0}
    real_run = orc3.run

    def _boom(obs=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("injected round crash")
        return real_run(obs=obs)

    orc3.run = _boom
    res = orc3.run_persist(rounds=2, backoff=0)
    assert res["rounds"] == 2 and calls["n"] >= 2, (res, calls)
    print("orchestrator.py self-test: PASS")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "selftest":
        return _selftest()
    ap = argparse.ArgumentParser(description="anti-duplicate hunt pipeline (stops at draft)")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--base", default="~/.bughunter-engagements")
    ap.add_argument("--obs", help="precomputed observation JSON for the novelty step")
    ap.add_argument("--hunt", action="store_true", help="run the live hunt+validate (default: recon+rank+map only)")
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--persist", action="store_true",
                    help="keep hunting in rounds (re-recon each round; never concludes 'no vuln')")
    ap.add_argument("--rounds", type=int, default=0, help="with --persist: stop after N rounds (0 = until killed)")
    ap.add_argument("--interval", type=int, default=0, help="with --persist: seconds between rounds")
    a = ap.parse_args(argv)
    obs = json.load(open(os.path.expanduser(a.obs))) if a.obs else None
    orc = Orchestrator(a.scope, base=a.base, mock=a.mock, do_hunt=a.hunt or a.mock, parallel=a.parallel)
    if a.persist:
        print("\n" + json.dumps(orc.run_persist(obs=obs, rounds=a.rounds, interval=a.interval), indent=2))
    else:
        print("\n" + json.dumps(orc.run(obs=obs), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
