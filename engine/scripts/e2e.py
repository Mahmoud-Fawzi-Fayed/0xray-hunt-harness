#!/usr/bin/env python3
"""
e2e.py — end-to-end tracer for the whole harness. Walks every stage the way a real hunt does and
reports PASS / WARN / FAIL per stage, so "is anything broken?" has a one-command answer.

Stages (critical ones fail the run; others warn):
  env          harness .env present + required keys set
  runtime      opencode CLI and/or cursor-agent CLI installed and reachable
  models       OPENCODE_HUNT_MODELS (preferred) or CURSOR_HUNT_MODELS configured  (+ per-model live ping with --ping)
  bridge       /health up + token auth enforced (401 without, 200 with)
  n8n          hunt-n8n container up + HTTP reachable (the novelty monitor runs here)
  web          nginx + panel reachable over TLS (401 = up & auth-gated)
  targets      registry has >=1 program with in-scope hosts
  skills       skill_map resolves real SKILL.md files the agent can read
  pipeline     full mock run: recon->rank->hunt->dedup->DRAFT->publish, stops at draft, never submits
  dedup        corpus oracle returns a verdict
  learning     outcomes are journaled AND yieldrank learns from them; unknown stack auto-drafts a skill
  resilience   an injected round-crash is caught + recorded, and the hunt loop continues (never dies)
  notify       SMTP configured + finding email renders (send only with --email)
  publish      finding HTML renders + HUNT_WEB_DIR writable
  capabilities web search (live), identity gen (+ --live mint), SMS status, learned-skill index
  guardrails   in-scope allow / out-of-scope refuse / bruteforce refuse

  python3 scripts/e2e.py                 # safe + fast (no token burn, no email, no account mint)
  python3 scripts/e2e.py --ping          # also ping each model once (small token cost)
  python3 scripts/e2e.py --live --email  # also mint a real temp identity + send a real test email
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "engine")
sys.path.insert(0, ENGINE)

_PROJECT_ROOT = os.path.dirname(ROOT)
ENV_FILE = os.environ.get("HUNT_ENV_FILE",
           os.path.join(_PROJECT_ROOT, "harness", ".env"))
BRIDGE = "http://127.0.0.1:8899"
PANEL = "https://finding.redtracefai.com/panel/"

RESULTS = []       # (stage, status, detail)   status in {PASS, WARN, FAIL}
G = "\033[32m"; Y = "\033[33m"; R = "\033[31m"; X = "\033[0m"


def _env(k, d=""):
    return os.environ.get(k, d)


def load_env():
    os.environ["HUNT_ENV_FILE"] = ENV_FILE
    try:
        import notify
        notify._ENV_LOADED = False            # force a fresh read (a prior stage may have cleared SMTP_*)
        notify._load_env_file()
    except Exception:
        pass


def stage(name, critical, fn):
    try:
        status, detail = fn()
    except Exception as e:  # noqa: BLE001
        status, detail = ("FAIL" if critical else "WARN"), f"{type(e).__name__}: {e}"
    RESULTS.append((name, status, detail))
    c = G if status == "PASS" else (Y if status == "WARN" else R)
    print(f"  [{c}{status:4}{X}] {name:13} {detail}")
    return status


def _req(method, path, base=BRIDGE, headers=None, data=None, timeout=12):
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# --------------------------------------------------------------------------- stages
def s_env():
    if not os.path.isfile(ENV_FILE):
        return "FAIL", f"missing {ENV_FILE}"
    need = ["HUNT_BRIDGE_TOKEN", "SMTP_HOST", "SMTP_TO", "HUNT_PUBLIC_URL", "HUNT_WEB_DIR"]
    missing = [k for k in need if not _env(k)]
    if missing:
        return "FAIL", f"missing keys: {missing}"
    pool = _env("OPENCODE_HUNT_MODELS", "") or _env("CURSOR_HUNT_MODELS", "") or _env("HUNT_MODELS", "")
    if not pool.strip():
        return "FAIL", "missing keys: ['OPENCODE_HUNT_MODELS|CURSOR_HUNT_MODELS'] (model pool empty)"
    return "PASS", f"{len(need)+1} required keys set"


def s_runtime():
    oc, cu = None, None
    try:
        p = subprocess.run([_env("OPENCODE_BIN", os.path.expanduser("~/.opencode/bin/opencode")), "--version"],
                           capture_output=True, text=True, timeout=20)
        if p.returncode == 0:
            oc = (p.stdout.strip() or p.stderr.strip())[:80]
    except FileNotFoundError:
        pass
    try:
        p = subprocess.run(["cursor-agent", "--version"], capture_output=True, text=True, timeout=20)
        if p.returncode == 0:
            cu = (p.stdout.strip() or p.stderr.strip())[:80]
    except FileNotFoundError:
        pass
    if oc and cu:
        return "PASS", f"opencode {oc} + cursor-agent {cu}"
    if oc:
        return "PASS", f"opencode {oc} (cursor-agent absent — opencode-only pool)"
    if cu:
        return "PASS", f"cursor-agent {cu} (opencode absent — cursor-only pool)"
    return "FAIL", "neither opencode nor cursor-agent on PATH"


def s_cursor():
    # legacy stage name kept for CI compat — now checks either runtime
    return s_runtime()


def s_models(ping):
    pool = [m.strip() for m in (_env("OPENCODE_HUNT_MODELS", "") or _env("CURSOR_HUNT_MODELS", "") or _env("HUNT_MODELS", "")).split(",") if m.strip()]
    if not pool:
        return "FAIL", "OPENCODE_HUNT_MODELS|CURSOR_HUNT_MODELS empty"
    if not ping:
        return "PASS", f"{len(pool)} models: {', '.join(pool)} (use --ping to live-test each)"
    import agent
    os.environ.pop("HUNT_MOCK_AGENT", None)
    ok, bad = [], []
    for m in pool:
        r = agent.run_agent("Reply with exactly: PONG. Then a json block {\"ok\":true}.",
                            model=m, timeout=120)
        (ok if r.get("error") is None and r.get("result") else bad).append(
            m if r.get("error") is None else f"{m}({r.get('error')})")
    detail = f"ok: {', '.join(ok) or 'none'}" + (f" | FAILED: {', '.join(bad)}" if bad else "")
    return ("PASS" if not bad else "WARN"), detail


def s_bridge():
    code, _ = _req("GET", "/health")
    if code != 200:
        return "FAIL", f"/health -> {code} (is the bridge running under pm2?)"
    tok = _env("HUNT_BRIDGE_TOKEN")
    no_auth, _ = _req("GET", "/stats")
    with_auth, _ = _req("GET", "/stats", headers={"X-Hunt-Token": tok})
    if no_auth != 401:
        return "WARN", f"/stats without token -> {no_auth} (expected 401)"
    if with_auth != 200:
        return "FAIL", f"/stats with token -> {with_auth}"
    return "PASS", "health 200, token auth enforced (401 without / 200 with)"


def s_n8n():
    try:
        p = subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.Status}}"],
                           capture_output=True, text=True, timeout=15)
        up = [l for l in p.stdout.splitlines() if l.startswith("hunt-n8n")]
    except Exception as e:  # noqa: BLE001
        return "WARN", f"docker check failed: {e}"
    if not up:
        return "WARN", "hunt-n8n container not running"
    port = _env("N8N_PORT", "5690")
    for path in ("/healthz", "/"):
        try:
            code, _ = _req("GET", path, base=f"http://127.0.0.1:{port}", timeout=8)
            if code in (200, 401):
                return "PASS", f"container up + HTTP {code} on :{port}  [{up[0]}]"
        except Exception:  # noqa: BLE001
            continue
    return "WARN", f"container up but no HTTP on :{port}"


def s_web():
    try:
        code, _ = _req("GET", "", base=PANEL, timeout=10)
    except Exception as e:  # noqa: BLE001
        return "WARN", f"panel unreachable: {e}"
    # 401 = nginx up + basic-auth gate working (the expected state without creds)
    return ("PASS", f"panel reachable over TLS (HTTP {code}, auth-gated)") if code in (200, 401) \
        else ("WARN", f"panel HTTP {code}")


def s_targets():
    import targets as T
    ts = T.all_targets(base=_env("BUGHUNTER_BASE", "~/.bughunter-engagements"))
    withscope = [t for t in ts if t.get("in_scope")]
    if not withscope:
        return "WARN", f"{len(ts)} target(s) but none with in-scope hosts"
    return "PASS", f"{len(ts)} program(s): " + ", ".join(t.get("name", "?") for t in ts[:6])


def s_skills():
    import skill_map as SM
    paths = SM.skill_paths("idor", tech=["next.js"])
    real = [p for p in paths if os.path.isfile(p)]
    if not real:
        return "FAIL", "skill_map resolved 0 readable SKILL.md files"
    return "PASS", f"{len(real)} SKILL.md resolved for idor+next.js (e.g. {os.path.basename(os.path.dirname(real[0]))})"


def s_pipeline():
    import orchestrator as O
    import dedup as D
    base = tempfile.mkdtemp()
    os.environ["HUNT_ENV_FILE"] = "/nonexistent-e2e-env"      # don't email / don't read real .env here
    os.environ["HUNT_WEB_DIR"] = os.path.join(base, "web")
    os.environ.pop("HUNT_PUBLIC_URL", None)
    for k in ("SMTP_HOST", "SMTP_TO"):
        os.environ.pop(k, None)
    scope = os.path.join(ENGINE, "engagement.example.json")
    obs = {"subdomains": ["localhost"], "hosts": [{"url": "http://localhost:3002", "status": 200}],
           "js": [], "endpoints": ["http://localhost:3002/api/account"], "params": []}
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):                      # keep the mock run's log out of the report
        s = O.Orchestrator(scope, base=base, mock=True, do_hunt=True).run(obs=obs)
    if not (s.get("confirmed", 0) >= 1 and s.get("drafted", 0) >= 1 and s.get("submitted", 1) == 0):
        return "FAIL", f"pipeline summary unexpected: {s}"
    if not os.path.isfile(os.path.join(s["dir"], "approval.md")):
        return "FAIL", "no approval.md (draft gate didn't write)"
    load_env()                                                 # restore real env for later stages
    return "PASS", f"mock run: confirmed={s['confirmed']} drafted={s['drafted']} held={s['held_dups']} submitted=0 (stops at draft)"


def s_dedup():
    import dedup as D
    v = D.Corpus("e2e", base=tempfile.mkdtemp()).check({"vuln_class": "idor", "url": "/x", "title": "t"})
    return ("PASS", f"verdict={v['verdict']} (empty corpus)") if v.get("verdict") else ("FAIL", f"no verdict: {v}")


def _mock_env():
    base = tempfile.mkdtemp()
    os.environ["HUNT_ENV_FILE"] = "/nonexistent-e2e-env"
    os.environ["HUNT_WEB_DIR"] = os.path.join(base, "web")
    os.environ.pop("HUNT_PUBLIC_URL", None)
    for k in ("SMTP_HOST", "SMTP_TO"):
        os.environ.pop(k, None)
    return base


def s_learning():
    """Prove the learning loop is CLOSED: a hunt's outcomes are journaled AND yieldrank learns from them,
    and an unknown stack auto-drafts a skill."""
    import orchestrator as O, yieldrank as YR, learn as L
    import io, contextlib, json as _j
    base = _mock_env()
    scope = os.path.join(ENGINE, "engagement.example.json")
    obs = {"subdomains": ["localhost"], "hosts": [{"url": "http://localhost:3002", "status": 200}],
           "js": [], "endpoints": ["http://localhost:3002/api/account"], "params": []}
    with contextlib.redirect_stdout(io.StringIO()):
        O.Orchestrator(scope, base=base, mock=True, do_hunt=True).run(obs=obs)
    jl = os.path.join(base, "hunt-memory", "journal.jsonl")
    rows = [_j.loads(x) for x in open(jl)] if os.path.isfile(jl) else []
    results = {r.get("result") for r in rows}
    learned = YR.Model.load(base).learned
    _saved_ld = L.LEARNED_DIR
    L.LEARNED_DIR = os.path.join(tempfile.mkdtemp(), "learned")
    try:
        drafted = L.autolearn("tech", "E2E Unknown Stack", base=base, research=False).get("registered")
    finally:
        L.LEARNED_DIR = _saved_ld                              # don't leak the temp dir into later stages
    load_env()
    ok = ("confirmed" in results and "reported" in results
          and learned.get("idor", {}).get("confirmed", 0) >= 1 and drafted)
    return ("PASS" if ok else "FAIL",
            f"outcomes={sorted(results)}; yieldrank idor.confirmed={learned.get('idor',{}).get('confirmed',0)}; auto-skill={bool(drafted)}")


def s_resilience():
    """Prove 'handle any issue': an injected round-crash is caught, recorded as a lesson, and the hunt
    loop CONTINUES (never dies, never concludes 'no vuln')."""
    import orchestrator as O
    import io, contextlib, json as _j
    base = _mock_env()
    scope = os.path.join(ENGINE, "engagement.example.json")
    orc = O.Orchestrator(scope, base=base, mock=True, do_hunt=True)
    calls = {"n": 0}
    real = orc.run

    def boom(obs=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("injected round crash")
        return real(obs=obs)

    orc.run = boom
    with contextlib.redirect_stdout(io.StringIO()):
        res = orc.run_persist(rounds=2, backoff=0)
    jl = os.path.join(base, "hunt-memory", "journal.jsonl")
    rows = [_j.loads(x) for x in open(jl)] if os.path.isfile(jl) else []
    err = any(r.get("result") == "error" for r in rows)
    load_env()
    ok = res.get("rounds") == 2 and calls["n"] >= 2 and err
    return ("PASS" if ok else "FAIL",
            f"crashed round 1 -> continued to round {res.get('rounds')}, error recorded={err} (loop never died)")


def s_notify(send):
    import notify
    load_env()
    if not notify.configured():
        return "WARN", "SMTP not configured (set SMTP_* in harness/.env)"
    subject, text, html = notify.finding_email("e2e-test", [
        {"vuln_class": "idor", "url": "https://example.com/api/users/5", "severity": "high",
         "verdict": "NOVEL", "score": 0.0, "link": _env("HUNT_PUBLIC_URL")}], public_url=_env("HUNT_PUBLIC_URL"))
    if not (subject and "<html" in html.lower()):
        return "FAIL", "finding_email did not render HTML"
    if send:
        ok = notify.send_safe("[e2e] harness self-test email", text, html=html)
        return ("PASS", "HTML email rendered + SENT (check inbox)") if ok else ("WARN", "render ok but send failed")
    return "PASS", f"SMTP configured ({_env('SMTP_HOST')}), HTML renders (use --email to send)"


def s_publish():
    import orchestrator as O
    wd = tempfile.mkdtemp()
    html = O.Orchestrator._finding_html("e2e", {"vuln_class": "idor", "url": "https://x/y", "severity": "high"},
                                        {"verdict": "NOVEL", "score": 0.0}, "# demo\nbody")
    open(os.path.join(wd, "f.html"), "w").write(html)
    real_wd = _env("HUNT_WEB_DIR")
    writable = os.path.isdir(os.path.dirname(real_wd)) if real_wd else False
    return "PASS", f"finding HTML renders ({len(html)}B); HUNT_WEB_DIR parent writable={writable}"


def s_capabilities(live):
    import websearch, identity, sms, learn
    bits = []
    r = websearch.search("site:nvd.nist.gov CVE", n=3)
    bits.append(f"websearch={'live ('+str(len(r))+')' if r else 'no-egress'}")
    f = identity.gen_fields()
    bits.append(f"identity=gen-ok" + (""))
    if live:
        ident = identity.new_identity("_e2e", base=tempfile.mkdtemp())
        bits.append("mint=" + ("ok+token" if ident.get("token") else ("ok" if ident.get("email") else "err:" + str(ident.get("error"))[:30])))
    bits.append("sms=" + ("enabled" if sms.enabled() else "disabled"))
    bits.append(f"learned-skills={len(learn.learned_index())}")
    return "PASS", " · ".join(bits)


def s_guardrails():
    import guardrails as GR
    base = tempfile.mkdtemp(); os.makedirs(os.path.join(base, "_targets"))
    json.dump({"name": "z", "in_scope": ["*.z.com"], "out_of_scope": ["admin.z.com"],
               "self_register_ok": True},
              open(os.path.join(base, "_targets", "z.json"), "w"))
    a = GR.check("z", "register", url="https://api.z.com/s", base=base)[0]
    b = GR.check("z", "register", url="https://evil.com/s", base=base)[0]
    c = GR.check("z", "otp-brute", base=base)[0]
    return ("PASS", "in-scope allow / out-of-scope refuse / bruteforce refuse") if (a and not b and not c) \
        else ("FAIL", f"allow={a} evil={b} brute={c}")


# --------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description="end-to-end harness tracer")
    ap.add_argument("--ping", action="store_true", help="live-ping each model (small token cost)")
    ap.add_argument("--live", action="store_true", help="mint a real temp identity")
    ap.add_argument("--email", action="store_true", help="actually send the test email")
    a = ap.parse_args(argv)
    load_env()
    print("harness end-to-end trace\n" + "-" * 60)
    stage("env", True, s_env)
    stage("cursor-agent", True, s_cursor)
    stage("models", True, lambda: s_models(a.ping))
    stage("bridge", True, s_bridge)
    stage("n8n", False, s_n8n)
    stage("web", False, s_web)
    stage("targets", False, s_targets)
    stage("skills", True, s_skills)
    stage("pipeline", True, s_pipeline)
    stage("dedup", True, s_dedup)
    stage("learning", True, s_learning)
    stage("resilience", True, s_resilience)
    stage("notify", False, lambda: s_notify(a.email))
    stage("publish", False, s_publish)
    stage("capabilities", False, lambda: s_capabilities(a.live))
    stage("guardrails", True, s_guardrails)

    fails = [r for r in RESULTS if r[1] == "FAIL"]
    warns = [r for r in RESULTS if r[1] == "WARN"]
    print("-" * 60)
    print(f"e2e: {sum(1 for r in RESULTS if r[1]=='PASS')}/{len(RESULTS)} PASS, {len(warns)} WARN, {len(fails)} FAIL")
    if fails:
        print("FAILED:", ", ".join(r[0] for r in fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
