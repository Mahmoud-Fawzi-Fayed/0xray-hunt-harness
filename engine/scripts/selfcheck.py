#!/usr/bin/env python3
"""
selfcheck.py — crash/loop/edge-case gauntlet for the whole harness.

Goes beyond each module's happy-path selftest: it throws hostile input at every component and
asserts NOTHING crashes, hangs, or loops. Covers:
  - malformed / mixed-type / None / huge / binary input to every pure function
  - corrupt corpus + snapshot + journal + alert-feed files
  - junk entries in ingest lists
  - all module selftests (subprocess, timeout-bounded so a hang is caught, not waited on)
  - live bridge: bad JSON, oversized body, bad/missing token, unknown route, missing fields

Exit 0 = all green. Exit 1 = at least one crash. Stdlib only, offline (bridge calls are localhost).

    python3 scripts/selfcheck.py
"""
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ENGINE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine")
sys.path.insert(0, ENGINE)

import dedup       # noqa: E402
import novelty     # noqa: E402
import jsdiff      # noqa: E402
import yieldrank   # noqa: E402
import observe     # noqa: E402
import guardrails  # noqa: E402
import websearch   # noqa: E402
import identity    # noqa: E402
import sms         # noqa: E402
import learn       # noqa: E402
import agent       # noqa: E402
import authsession # noqa: E402
import targets     # noqa: E402
import state       # noqa: E402

RESULTS = []


def case(name, fn):
    try:
        fn()
        RESULTS.append((name, True, ""))
    except Exception as e:  # noqa: BLE001 — the whole point is to catch anything
        RESULTS.append((name, False, f"{type(e).__name__}: {e}"))


# --------------------------------------------------------------- dedup edge cases
case("dedup.norm_class none/empty/weird", lambda: [dedup.norm_class(x) for x in (None, "", "W e!!rd::x")])
case("dedup.title/path_tokens none+junk", lambda: (
    dedup.title_tokens(None), dedup.path_tokens(None),
    dedup.path_tokens("http://[::1]:8/x"), dedup.path_tokens("no scheme with spaces")))
case("dedup.similarity empty sigs", lambda: dedup.similarity(dedup.signature({}), dedup.signature({})))
case("dedup.record_id empty", lambda: dedup.record_id({}))
case("dedup.check empty candidate", lambda: dedup.Corpus("p", base=tempfile.mkdtemp()).check({}))


def _dedup_junk():
    b = tempfile.mkdtemp()
    c = dedup.Corpus("p", base=b)
    # mixed junk list: dicts, string, int, None
    c.ingest([{"title": "a", "vuln_class": "idor", "url": "/x", "link": "l1"}, "junk", 123, None, {"title": "b"}])
    open(c.path, "a", encoding="utf-8").write("this is not json\n")   # corrupt line
    c._records = None                                                 # force reload
    r = c.check({"vuln_class": "idor", "url": "/x", "title": "a"})
    assert r["verdict"] in ("NOVEL", "REVIEW", "LIKELY_DUP")
case("dedup.ingest junk+corrupt line, reload, check", _dedup_junk)
case("dedup.ingest a bare dict (not list)", lambda: dedup.Corpus("p2", base=tempfile.mkdtemp()).ingest({"title": "x", "vuln_class": "xss"}))


# --------------------------------------------------------------- novelty edge cases
def _novelty_junk():
    b = tempfile.mkdtemp()
    nv = novelty.Novelty("t", base=b)
    nv.watch({})                                                     # totally empty obs
    nv.watch({"subdomains": [None, 123, "a.com", "a.com"],
              "hosts": [{}, "stringhost", {"url": "https://a"}],
              "js": [{"url": None}, "x", {"url": "https://a/x.js", "hash": "h"}],
              "endpoints": ["/a", None], "params": [None, 1]})       # mixed types everywhere
    open(nv.latest_path, "w", encoding="utf-8").write("{ corrupt json")   # corrupt baseline
    d = nv.diff({"subdomains": ["b.com"]})
    assert "baseline" in d
case("novelty.watch empty+mixed-types+corrupt baseline", _novelty_junk)
case("novelty.summarize junk diff", lambda: novelty.summarize({"baseline": False}))


# --------------------------------------------------------------- jsdiff edge cases
case("jsdiff.extract none/empty", lambda: (jsdiff.extract(None), jsdiff.extract(""), jsdiff.diff(None, None)))
case("jsdiff huge input (no ReDoS/hang)", lambda: jsdiff.extract("var x='/api/a?p=1';" * 60000))
case("jsdiff binary-ish bytes", lambda: jsdiff.extract("\x00\x01\xff'/api/secret?t=1'\x00\x7f"))
case("jsdiff.scan via diff('',x)", lambda: jsdiff.diff("", "const u='/api/v9/admin?id=1';"))


# --------------------------------------------------------------- yieldrank edge cases
def _yr_junk():
    b = tempfile.mkdtemp()
    os.makedirs(os.path.join(b, "hunt-memory"))
    open(os.path.join(b, "hunt-memory", "journal.jsonl"), "w", encoding="utf-8").write(
        'not json\n{"vuln_class":"idor","result":"confirmed"}\n{}\n{"result":"duplicate"}\n')
    m = yieldrank.Model.load(b)
    assert m.bonus(None) == 0.0
    m.bonus("x"); m.score("idor", ["next.js"]); r = m.rank(["graphql"])
    assert any(row.get("class") == "idor" for row in r)
case("yieldrank corrupt journal + bonus(None) + rank", _yr_junk)


# --------------------------------------------------------------- observe edge cases (offline)
case("observe offline weird target", lambda: observe.observe("weird target name", base=tempfile.mkdtemp(), live=False))
case("observe helpers none/empty", lambda: (observe._host_of(""), observe._apex(""), observe._apex("x"),
                                            observe._host_of("https://a.b.c/x?y=1")))


# --------------------------------------------------------------- guardrails edge cases
def _guard_junk():
    b = tempfile.mkdtemp()
    for bad in (None, "", 123, {"x": 1}, ["a"]):
        guardrails.check("p", bad, url=bad, base=b)            # type: ignore
        guardrails._host_of(bad)                               # type: ignore
        guardrails.in_scope(bad, {"in_scope": [bad]})          # type: ignore
    # no scope loaded => writes refused, never crash
    assert guardrails.check("nope", "register", url="https://x.com/s", base=b)[0] is False
case("guardrails hostile input + no-scope refuse", _guard_junk)
case("guardrails bruteforce always refused", lambda: (
    None if not guardrails.check("p", "otp-brute", base=tempfile.mkdtemp())[0] else (_ for _ in ()).throw(AssertionError())))

# --------------------------------------------------------------- websearch edge cases (offline)
case("websearch parse junk/None/empty", lambda: (websearch.parse_serp(None), websearch.parse_serp(""),
                                                 websearch.parse_serp("<a class='x'>no results</a>")))
case("websearch search/fetch bad input no-raise", lambda: (websearch.search(None), websearch.search(""),
                                                           websearch.fetch(None), websearch.fetch("ftp://x")))
case("websearch strip huge html (no hang)", lambda: websearch._strip_tags("<p>x</p>" * 100000))

# --------------------------------------------------------------- identity edge cases (offline)
case("identity gen_fields strong", lambda: (identity.gen_fields(), identity.gen_fields()))
case("identity extract junk", lambda: [(identity.extract_code(x), identity.extract_link(x))
                                       for x in (None, "", 123, {"a": 1}, ["x"])])
case("identity offline-safe net calls", lambda: (identity.messages(None), identity.token_for(None, None),
                                                 identity.wait_for(None, timeout=5)))

# --------------------------------------------------------------- sms edge cases (offline)
def _sms_disabled():
    saved = {k: os.environ.pop(k, None) for k in ("SMS_PROVIDER", "SMS_API_KEY")}
    os.environ["HUNT_ENV_FILE"] = "/nonexistent-selftest-env"
    try:
        if sms.N is not None:
            sms.N._ENV_LOADED = False
        assert sms.enabled() is False
        assert sms.get_number("s", "p")["error"].startswith("SMS disabled")
        assert sms.wait_sms("x") == {}
        for bad in (None, "", 123):
            sms.extract_code(bad)                              # type: ignore
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
case("sms disabled-by-default + hostile input", _sms_disabled)

# --------------------------------------------------------------- learn edge cases (offline)
def _learn_junk():
    b = tempfile.mkdtemp()
    ld = os.path.join(tempfile.mkdtemp(), "learned")
    learn.LEARNED_DIR = ld
    r = learn.autolearn("tech", "Junk Stack 42", context="x", base=b, research=False)
    assert r.get("registered") and os.path.isfile(r["path"])
    for bad in (None, "", 123, {"x": 1}):
        learn.record_gap(bad, bad, bad, base=b)               # type: ignore
        learn._slug(bad)                                      # type: ignore
    # corrupt journal survives
    open(learn._journal(b), "a", encoding="utf-8").write("not json\n")
    learn.gaps(b)
case("learn autolearn offline + corrupt journal + hostile input", _learn_junk)


# --------------------------------------------------------------- model-pool enforcement (regression guard)
def _pool_guard():
    saved_oc = os.environ.get("OPENCODE_HUNT_MODELS")
    saved = os.environ.get("CURSOR_HUNT_MODELS")
    os.environ["OPENCODE_HUNT_MODELS"] = "opencode/a,openai/b,opencode/c"
    os.environ.pop("CURSOR_HUNT_MODELS", None)
    os.environ["HUNT_MOCK_AGENT"] = "1"           # observe model selection without calling any agent CLI
    try:
        # an off-pool pinned model (e.g. a stale default) must be forced back into the approved pool
        for _ in range(6):
            assert agent.run_agent("x", model="claude-sonnet-4-6")["model"] in ("opencode/a", "openai/b", "opencode/c")
        # model=None rotates the pool
        assert agent.run_agent("x", model=None)["model"] in ("opencode/a", "openai/b", "opencode/c")
        # opencode routing: opencode/* + openai/* -> opencode run, legacy -> cursor-agent
        assert agent._is_opencode_model("opencode/muse-spark-1.3-contributor-free")
        assert agent._is_opencode_model("openai/gpt-6-astra-fast")
        assert not agent._is_opencode_model("kimi-k3-max")
    finally:
        os.environ.pop("HUNT_MOCK_AGENT", None)
        if saved_oc is not None:
            os.environ["OPENCODE_HUNT_MODELS"] = saved_oc
        else:
            os.environ.pop("OPENCODE_HUNT_MODELS", None)
        if saved is not None:
            os.environ["CURSOR_HUNT_MODELS"] = saved
        else:
            os.environ.pop("CURSOR_HUNT_MODELS", None)
case("agent enforces approved model pool (no off-pool leak)", _pool_guard)


# --------------------------------------------------------------- session pool bounded + slot reuse
def _session_pool():
    _saved_base = os.environ.get("BUGHUNTER_BASE")
    os.environ["BUGHUNTER_BASE"] = tempfile.mkdtemp()
    agent._POOL.clear()
    try:
        s1, s2, s3 = agent._acquire("p"), agent._acquire("p"), agent._acquire("p")
        assert s1 is not s2 and s2 is not s3                      # distinct slots for parallel workers
        s4 = agent._acquire("p")
        assert s4.get("transient"), "pool must be bounded (overflow => transient)"
        assert len(agent._POOL["p"]) == agent.POOL_SIZE          # never grows past POOL_SIZE
        agent._release(s1)
        assert agent._acquire("p") is s1                         # a released slot is REUSED, not recreated
        s1["id"] = "sess-abc"; agent._release(s1)
        assert agent._acquire("p")["id"] == "sess-abc"          # slot remembers its session across leases
        # persistence: ids survive a process "restart" (pool cleared + reseeded from per-target file)
        # — but only sessions that are still ALIVE on disk (a dead id must be dropped, not resumed)
        _chats = tempfile.mkdtemp(); _proj = tempfile.mkdtemp()
        os.environ["HUNT_CHATS_DIR"] = _chats; os.environ["HUNT_PROJECTS_DIR"] = _proj
        os.makedirs(os.path.join(_proj, "ws", "agent-transcripts", "sess-abc"))   # alive
        agent._persist_pool("p")
        assert os.path.isfile(agent._pool_file("p")), "per-target session state file written"
        agent._POOL.clear()
        assert agent._acquire("p")["id"] == "sess-abc", "pool must persist across restarts"
        # dead persisted id -> skipped on reseed (resuming a dead id silently loses all context)
        import json as _json
        _json.dump({"ids": ["sess-dead"]}, open(agent._pool_file("p"), "w"))
        agent._POOL.clear()
        assert agent._acquire("p")["id"] is None, "dead pooled id must not be reseeded"
        os.environ.pop("HUNT_CHATS_DIR", None); os.environ.pop("HUNT_PROJECTS_DIR", None)
    finally:
        agent._POOL.clear()
        if _saved_base is not None:
            os.environ["BUGHUNTER_BASE"] = _saved_base
        else:
            os.environ.pop("BUGHUNTER_BASE", None)
case("agent session pool bounded + reused + persists across restarts", _session_pool)


# --------------------------------------------------------------- slug consistency (dir-resolution guard)
def _slug_consistency():
    # targets/state/agent/guardrails MUST agree, or logs/activity/sessions/engagement resolve to diff dirs
    for n in ("paddle", "DrAnsay", "Acme Corp", "API.v2", "ExpressVPN", "", "  weird__ name  ", None, 123):
        a, b, c, d = targets._slug(n), state._slug(n), agent._slug(n), guardrails._slug(n)
        assert a == b == c == d, f"slug mismatch for {n!r}: {a} / {b} / {c} / {d}"
case("slug consistent across targets/state/agent/guardrails", _slug_consistency)


# --------------------------------------------------------------- authsession edge cases (offline)
def _authsession_junk():
    for bad in (None, "", 123, {"x": 1}, ["a"]):
        authsession.pick_auth_host(bad); authsession.valid(bad)      # type: ignore
        authsession.auth_block(bad, bad); authsession.recent_attempt(bad)  # type: ignore
    # per-target session file isolation: two contexts -> two files
    import tempfile
    b = tempfile.mkdtemp()
    _sb = os.environ.get("BUGHUNTER_BASE")
    os.environ["BUGHUNTER_BASE"] = b
    try:
        agent._POOL.clear()
        s1 = agent._acquire("tgtA"); s1["id"] = "A1"; agent._persist_pool("tgtA")
        s2 = agent._acquire("tgtB"); s2["id"] = "B1"; agent._persist_pool("tgtB")
        assert agent._load_pool_ids("tgtA") == ["A1"] and agent._load_pool_ids("tgtB") == ["B1"]
        assert os.path.isfile(agent._pool_file("tgtA")) and os.path.isfile(agent._pool_file("tgtB"))
    finally:
        agent._POOL.clear()
        if _sb is not None:
            os.environ["BUGHUNTER_BASE"] = _sb
        else:
            os.environ.pop("BUGHUNTER_BASE", None)
case("authsession hostile input + per-target session isolation", _authsession_junk)

# --------------------------------------------------------------- authsession edge cases
case("authsession pick/valid/auth_block hostile input", lambda: (
    authsession.pick_auth_host(None), authsession.pick_auth_host(123), authsession.pick_auth_host({"x": 1}),
    authsession.valid(None), authsession.valid(123), authsession.auth_block(None, None),
    authsession.auth_block({"success": True, "host": "a.com", "cookies": {"s": "1"}}, "https://b.org/x")))


# --------------------------------------------------------------- module selftests (timeout-bounded)
def _run_selftest(mod, arg=True):
    args = [sys.executable, os.path.join(ENGINE, f"{mod}.py")] + (["selftest"] if arg else [])
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stdout[-400:] + r.stderr[-400:])
for _m in ("dedup", "novelty", "jsdiff", "yieldrank", "orchestrator", "notify", "scopefetch", "targets",
           "guardrails", "websearch", "identity", "sms", "learn", "authsession",
           "authn", "authz", "coverage", "apkmap", "scopeparse", "verify", "disposition", "sessions",
           "fixchat"):
    case(f"selftest: {_m}", lambda m=_m: _run_selftest(m, True))
for _m in ("agent", "state"):
    case(f"selftest: {_m}", lambda m=_m: _run_selftest(m, False))


# --------------------------------------------------------------- live bridge robustness
def _token():
    for p in ("/root/BugHunting_0xRay/harness/.env",):
        if os.path.isfile(p):
            for line in open(p):
                if line.startswith("HUNT_BRIDGE_TOKEN="):
                    return line.split("=", 1)[1].strip()
    return os.environ.get("HUNT_BRIDGE_TOKEN", "")


def _req(method, path, headers=None, data=None, timeout=12):
    req = urllib.request.Request("http://127.0.0.1:8899" + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


_bridge_up = False
try:
    _bridge_up = _req("GET", "/health")[0] == 200
except Exception:
    _bridge_up = False

if _bridge_up:
    tok = _token()
    H = {"X-Hunt-Token": tok, "Content-Type": "application/json"}

    def _c(name, method, path, headers, data, expect):
        def fn():
            code, _ = _req(method, path, headers, data)
            assert code in expect, f"got {code}, expected {expect}"
        case("bridge " + name, fn)

    _c("health no-token 200", "GET", "/health", {}, None, (200,))
    _c("bad token -> 401", "POST", "/dedup/check", {"X-Hunt-Token": "wrong", "Content-Type": "application/json"}, b"{}", (401,))
    _c("missing token -> 401", "POST", "/dedup/check", {"Content-Type": "application/json"}, b"{}", (401,))
    _c("malformed JSON body -> handled", "POST", "/dedup/check", H, b"{not valid json", (200, 400))

    def _oversized():
        # The bridge rejects on Content-Length BEFORE buffering the body, so the client may see a
        # clean 413 OR an early connection close (broken pipe). Both mean "rejected, no memory blowup".
        try:
            code, _ = _req("POST", "/dedup/check", H, b"x" * (2 * 1024 * 1024 + 50))
            assert code == 413, f"got {code}, expected 413"
        except (urllib.error.URLError, BrokenPipeError, ConnectionError, OSError):
            pass
    case("bridge oversized body rejected (413 or early-close)", _oversized)

    _c("unknown route -> 404", "POST", "/nope", H, b"{}", (404,))
    _c("watch missing target -> 400", "POST", "/novelty/watch", H, b"{}", (400,))
    _c("feed huge n -> clamped 200", "GET", "/novelty/feed?n=999999999", H, None, (200,))
    _c("feed junk n -> 200", "GET", "/novelty/feed?n=abc", H, None, (200,))
    _c("dedup/check inline ok", "POST", "/dedup/check", H,
       json.dumps({"program": "sc", "class": "idor", "url": "/x", "title": "t"}).encode(), (200,))
    _c("capabilities 200 (+sessions)", "GET", "/capabilities", H, None, (200,))
    _c("learn/journal 200", "GET", "/learn/journal?n=5", H, None, (200,))
    _c("accounts 200", "GET", "/accounts", H, None, (200,))
    _c("activity 200", "GET", "/activity?n=5", H, None, (200,))
    _c("hunt/log slug-safe 200", "GET", "/hunt/log?program=../etc&n=3", H, None, (200,))
else:
    RESULTS.append(("bridge live tests", True, "SKIPPED (bridge not running on :8899)"))


# --------------------------------------------------------------- report
def main():
    fails = [r for r in RESULTS if not r[1]]
    for name, ok, msg in RESULTS:
        tag = "PASS" if ok else "FAIL"
        extra = f"  ({msg})" if msg else ""
        print(f"[{tag}] {name}{extra}")
    print(f"\nselfcheck: {len(RESULTS) - len(fails)}/{len(RESULTS)} passed, {len(fails)} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
