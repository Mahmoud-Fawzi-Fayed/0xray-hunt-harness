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

SEV_CVSS = {
    "critical": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high": ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "medium": ("5.4", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    "low": ("3.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
}


def _title(f):
    if f.get("title"):
        return f["title"]
    url = f.get("url", "")
    path = url.split("://", 1)[-1]
    path = "/" + path.split("/", 1)[1] if "/" in path else path
    cls = (f.get("vuln_class") or "issue").upper()
    evidence = " ".join((f.get("evidence") or "unauthorized access").split())
    return f"{cls} in {path}: {evidence[:120]}"


def _cvss(f, severity):
    score, vector = SEV_CVSS.get(severity, ("not scored", "not scored"))
    unauthenticated = (f.get("id_source") == "not_required" or
                       f.get("attacker_holds") in ("nothing", "not_required", "no_auth"))
    if unauthenticated and severity != "unknown":
        vector = vector.replace("PR:L", "PR:N")
        score = {"critical": "9.8", "high": "8.6", "medium": "6.1", "low": "4.3"}.get(severity, score)
    return score, vector


def _http_text(value):
    return str(value or "").replace("\\r\\n", "\n").replace("\\r", "\n")


def _draft_md(f, verdict):
    sev = (f.get("severity") or "unknown").lower()
    score, vector = _cvss(f, sev)
    lines = [
        f"# {_title(f)}", "",
        f"**Severity:** {sev}  ·  **CVSS:** {score} ({vector})",
        f"**Dedup verdict:** {verdict['verdict']} (score {verdict.get('score', 0)}, corpus {verdict.get('corpus_size', 0)})",
        f"**Verification:** {(f.get('reproduction') or {}).get('method') or f.get('reproduction_status', 'reproduced')}",
    ]
    if verdict["verdict"] == "REVIEW":
        lines.append(f"**Differentiator:** {f.get('differentiator', '')}")
        if verdict.get("matches"):
            m = verdict["matches"][0]
            lines.append(f"Nearest known issue: {m.get('title','')} {m.get('link','')}")
    steps = f.get("steps") or [f.get("request", "")]
    if isinstance(steps, str):
        steps = [steps]
    lines += ["", "## Summary", "", f.get("evidence", ""),
              "", "## Steps to reproduce", ""]
    lines += [f"{i}. {step}" for i, step in enumerate(steps, 1)]
    lines += ["", "### Request", "", "```http", _http_text(f.get("request")), "```"]
    if f.get("response"):
        lines += ["", "### Response (redacted evidence)", "", "```http", _http_text(f["response"]), "```"]
    lines += ["", "## Impact", "", f.get("impact") or f.get("evidence", ""),
              "", "## Remediation", ""]
    cls = (f.get("vuln_class") or "").lower()
    remediations = {
        "idor": "Enforce object-level authorization using the authenticated tenant and resource owner; do not trust client IDs. Add cross-account regression tests.",
        "bola": "Enforce object-level authorization using the authenticated tenant and resource owner; do not trust client IDs. Add cross-account regression tests.",
        "open-redirect": "Allow only approved relative or absolute redirect destinations. Canonicalize before validation and reject external schemes and hosts.",
        "xss": "Encode output for its exact HTML/JavaScript context, sanitize unsafe markup, and add browser-execution regression tests.",
        "ssrf": "Allowlist outbound schemes, hosts, and IP ranges; re-check redirects and DNS resolution before every server-side fetch.",
        "sqli": "Use parameterized queries and ORM bindings; never concatenate untrusted input into SQL. Add injection regression tests.",
    }
    remediation = remediations.get(cls, "Validate the affected operation server-side and add a regression test that proves the demonstrated attack is rejected without weakening legitimate functionality.")
    lines.append(remediation)
    if f.get("proof_note"):
        lines += ["", f"> Proof note: {f['proof_note']}"]
    return "\n".join(lines)


class Orchestrator:
    def __init__(self, scope_path, base="~/.bughunter-engagements",
                 mock=False, do_hunt=True, parallel=3, model=None):
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
        import modelroute as MR
        model = model or MR.model_for("hunt")
        self.eng = E.Engine(scope_path, base, model, max_hunts, 40, agent_timeout, mock, False, parallel, False)

    # ---- step 1: novelty-first targeting --------------------------------------
    def novelty(self, obs=None):
        seeds = self.eng.scope.seeds or []
        if not seeds:
            return None
        from urllib.parse import urlparse
        target = urlparse(seeds[0]).hostname or seeds[0]
        if obs is None and not self.mock:
            merged = {"subdomains": set(), "endpoints": set(), "params": set()}
            hosts, js = {}, {}
            try:
                import observe as O
                for seed in seeds:
                    host = urlparse(seed).hostname or seed
                    current = O.observe(host, base=self.base, scope=self.eng.scope)
                    for key in ("subdomains", "endpoints", "params"):
                        merged[key].update(current.get(key) or [])
                    for item in current.get("hosts") or []:
                        if item.get("url"):
                            hosts[item["url"]] = item
                    for item in current.get("js") or []:
                        if item.get("url"):
                            js[item["url"]] = item
                obs = {**merged, "hosts": list(hosts.values()), "js": list(js.values())}
            except Exception as e:
                self.eng.eng.log(f"novelty: observe skipped ({e})")
                return None
        if obs is None:
            return None
        diff = N.Novelty(target, base=self.base).watch(obs)
        tag = "baseline" if diff.get("baseline") else ("CHANGES" if diff.get("has_changes") else "no change")
        self.eng.eng.log(f"novelty: {target} -> {tag}; " + " | ".join(N.summarize(diff))[:200])
        self.eng.eng.state["last_novelty"] = {
            "new_js": list(diff.get("new_js") or [])[:20],
            "changed_js": list(diff.get("changed_js") or [])[:20],
            "new_endpoints": list(diff.get("new_endpoints") or [])[:100],
            "new_params": list(diff.get("new_params") or [])[:100],
            "new_hosts": list(diff.get("new_hosts") or [])[:30],
            "has_changes": bool(diff.get("has_changes")), "ts": time.time(),
        }
        candidates = [] if diff.get("baseline") else list(diff.get("new_endpoints") or []) + list(diff.get("new_params") or [])
        candidates += [] if diff.get("baseline") else [h.get("url") for h in (diff.get("new_hosts") or []) if h.get("url")]
        items = []
        for url in dict.fromkeys(candidates):
            if url and self.eng.scope.in_scope_host(url):
                items.append({"url": url, "method": "GET", "vuln_class": "deep",
                              "source": "novelty", "priority": 140, "confidence": "observed"})
        if items:
            added = self.eng.eng.add_surface(E._deepen(items))
            self.eng.eng.log(f"novelty: queued {added} new/changed surface item(s) at elevated priority")
        self.eng.eng.save()
        return diff

    # ---- step 3: draft gate (dedup) -------------------------------------------
    @staticmethod
    def _finding_identity(f):
        import hashlib
        canonical = json.dumps({
            "method": f.get("method") or "GET", "url": f.get("url") or "",
            "params": sorted(f.get("params") or ([f["param"]] if f.get("param") else [])),
            "role": f.get("role") or "", "class": f.get("vuln_class") or "",
            "chain": f.get("chain") or "",
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:20]

    def draft_gate(self):
        confirmed = self.eng.eng.state.get("confirmed", [])
        cp = D.Corpus(self.eng.scope.name, base=self.base)
        drafts_dir = os.path.join(self.eng.eng.dir, "drafts")
        held_dir = os.path.join(self.eng.eng.dir, "held")
        os.makedirs(drafts_dir, exist_ok=True)
        os.makedirs(held_dir, exist_ok=True)
        import disposition as DP
        import verify as VF
        drafted_keys = {str(k) for k in (self.eng.eng.state.get("drafted_keys") or [])}
        links = dict(self.eng.eng.state.get("draft_links") or {})
        drafted, held, policy = [], [], []
        for i, f in enumerate(confirmed, 1):
            name = f"{i:02d}-{(f.get('vuln_class') or 'finding')}.md"
            key = self._finding_identity(f)
            legacy_key = "|".join((f.get("url", ""), f.get("vuln_class", "")))
            disp = DP.check(f)
            reproduction = (f.get("reproduction") or {}).get("status") or f.get("reproduction_status")
            if reproduction != "reproduced":
                disp = {"verdict": "HOLD_REPRODUCTION", "reason": "independent reproduction is required", "rules": []}
            elif f.get("scope_warning"):
                disp = {"verdict": "HOLD_SCOPE", "reason": "unresolved out-of-scope evidence", "rules": []}
            v = cp.check({"vuln_class": f.get("vuln_class", ""), "url": f.get("url", ""),
                          "title": f.get("evidence", "")})
            f["dedup"] = v
            if disp["verdict"] == "PASS" and v["verdict"] in ("UNKNOWN", "LIKELY_DUP"):
                md = _draft_md(f, v)
                open(os.path.join(held_dir, name), "w").write(md + "\n")
                held.append({"finding": f, "dedup": v, "file": os.path.join(held_dir, name)})
                if v["verdict"] == "LIKELY_DUP":
                    E._lrn("record_outcome", self.eng.scope.name, f.get("vuln_class"), "duplicate",
                           f"held: {v.get('score')}", base=self.base)
                continue
            if disp["verdict"] == "PASS" and v["verdict"] == "REVIEW" and not f.get("differentiator"):
                disp = {"verdict": "HOLD_DEDUP_REVIEW", "reason": "a concrete differentiator is required", "rules": []}
            if disp["verdict"] != "PASS":
                body = "# HELD — " + disp["verdict"] + "\n\n" + disp["reason"] + "\n"
                open(os.path.join(held_dir, name), "w").write(body)
                policy.append({"finding": f, "disposition": disp, "file": os.path.join(held_dir, name)})
                continue
            report_f = dict(f)
            report_f.update({
                "title": _title(f), "steps": f.get("steps") or [f.get("request", "")],
                "impact": f.get("impact") or f.get("evidence", ""),
                "response": f.get("response") or f.get("evidence", ""),
                "poc": f.get("poc") or f.get("request", ""),
            })
            readiness = VF.verify_finding(report_f, program=self.eng.scope.name, base=self.base)
            f["report_readiness"] = readiness
            if readiness.get("verdict") != "READY":
                reason = "; ".join(readiness.get("failed") or ["report evidence incomplete"])
                disp = {"verdict": "HOLD_REPORT_READY", "reason": reason, "rules": []}
                open(os.path.join(held_dir, name), "w").write("# HELD — report not ready\n\n" + reason + "\n")
                policy.append({"finding": f, "disposition": disp, "file": os.path.join(held_dir, name)})
                continue
            md = _draft_md(f, v)
            open(os.path.join(drafts_dir, name), "w").write(md + "\n")
            is_new = key not in drafted_keys and legacy_key not in drafted_keys
            link = self._publish(f, v, md, i) if is_new else links.get(key) or links.get(legacy_key)
            if link:
                links[key] = link
            drafted.append({"finding": f, "dedup": v, "file": os.path.join(drafts_dir, name),
                            "link": link, "new": is_new})
            if is_new:
                drafted_keys.add(key)
                E._lrn("record_outcome", self.eng.scope.name, f.get("vuln_class"), "reported",
                       v.get("verdict", ""), base=self.base)
        self.eng.eng.state["drafted_keys"] = sorted(drafted_keys)
        self.eng.eng.state["draft_links"] = links
        self.eng.eng.save()
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
        wd = os.environ.get("HUNT_WEB_DIR")
        if not wd:
            return None
        try:
            drafts = os.path.join(self.eng.eng.dir, "drafts")
            os.makedirs(drafts, exist_ok=True)
            slug = f"finding-{self.eng.scope.name}-{idx:02d}-{(f.get('vuln_class') or 'x')}".replace("/", "-")
            path = os.path.join(drafts, slug + ".html")
            open(path, "w", encoding="utf-8").write(
                self._finding_html(self.eng.scope.name, f, v, md))
            return path
        except Exception as e:  # noqa: BLE001
            self.eng.eng.log(f"publish: skipped ({e})")
            return None

    def approve_finding(self, filename):
        """Copy an approved draft finding to the public web dir after explicit approval."""
        wd = os.environ.get("HUNT_WEB_DIR")
        if not wd:
            return False
        src = os.path.join(self.eng.eng.dir, "drafts", filename)
        dst = os.path.join(wd, filename)
        if os.path.isfile(src):
            import shutil
            os.makedirs(wd, exist_ok=True)
            shutil.copy2(src, dst)
            return True
        return False

    def _write_index(self, drafted, approved_only=True):
        if approved_only:
            drafted = [d for d in drafted if d.get("approved")]
        # Write to private engagement dir, not public web dir
        wd = self.eng.eng.dir
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
        phases = ["recon", "discover", "explore", "rank", "map", "plan"] + (["hunt", "validate", "chain"] if self.do_hunt else [])
        engine_result = self.eng.run(phases) or {}
        failed = engine_result.get("failed_phases") or []
        if failed:
            self.eng.eng.log(f"orchestrator: engine phases failed: {failed} — results may be incomplete")
        drafted, held = self.draft_gate()
        new_drafts = [d for d in drafted if d.get("new")]
        if new_drafts:
            self._email_drafts(new_drafts)
        elif not self.eng.eng.state.get("confirmed"):
            self.eng.eng.log("orchestrator: no confirmed finding THIS pass — NOT a conclusion. "
                             "Invent the next test from live bytes / re-recon for new surface "
                             "(redteam-mindset: DO NOT STOP).")
        status = "partial" if failed else "done"
        summary = {**self.eng.eng.summary(), "status": status,
                   "failed_phases": failed,
                   "drafted": len(drafted), "held_dups": len(held),
                   "held_policy": len(getattr(self, "_policy", []) or []),
                   "submitted": 0, "dir": self.eng.eng.dir}
        self.eng.eng.log(f"orchestrator {status} | {summary}")
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
            park = self._review_park_seconds()
            if park > 30:
                self.eng.eng.log(f"persist: parked by workflow review for {int(park/60)}m "
                                 "— covered, and there is no live session to mine")
                time.sleep(min(park, interval or 600))
                continue
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

    def _review_park_seconds(self):
        """Seconds left on a workflow-review park. 0 means hunt this round."""
        path = os.path.join(os.path.expanduser(self.base), "_review", "directives",
                            self.eng.scope.name + ".json")
        try:
            until = float(json.load(open(path)).get("park_until") or 0)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return 0
        return max(0.0, until - time.time())


def _selftest():
    import tempfile
    base = tempfile.mkdtemp()
    # sandbox: never load the real harness .env, never email, never write to the live /var/www viewer
    os.environ["HUNT_ENV_FILE"] = "/nonexistent-selftest-env"
    os.environ["HUNT_WEB_DIR"] = os.path.join(base, "web")
    os.environ.pop("HUNT_PUBLIC_URL", None)
    for _k in ("SMTP_HOST", "SMTP_TO", "HUNT_PARALLEL", "HUNT_MAX_HUNTS", "HUNT_AGENT_TIMEOUT"):
        os.environ.pop(_k, None)
    os.environ.pop("HUNT_SKIP_COVERAGE_GATE", None)
    scope = os.path.join(ENGINE, "engagement.example.json")
    obs = {"subdomains": ["localhost"], "hosts": [{"url": "http://localhost:3002", "status": 200}],
           "js": [], "endpoints": ["http://localhost:3002/api/account"], "params": []}
    D.Corpus("demo-local", base=base).ingest([{"source": "h1-public", "vuln_class": "ssrf",
             "url": "http://localhost:3002/unrelated", "title": "Unrelated SSRF report", "link": "https://h1/0"}])
    orc = Orchestrator(scope, base=base, mock=True, do_hunt=True)
    s = orc.run(obs=obs)
    assert s["confirmed"] >= 1, s                     # mock IDOR confirms
    assert s["drafted"] >= 1, s                       # and becomes a draft (NOVEL corpus)
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
        result = orc.run_persist(obs=obs, rounds=a.rounds, interval=a.interval)
    else:
        result = orc.run(obs=obs)
    print("\n" + json.dumps(result, indent=2))
    if result.get("status") == "blocked":
        return 3
    return 1 if result.get("status") == "partial" or result.get("failed_phases") else 0


if __name__ == "__main__":
    sys.exit(main())
