#!/usr/bin/env python3
"""
engine.py — autonomous engagement orchestrator.

Deterministic control flow (scope, state, dispatch, ranking, dedup, reporting);
LLM only for recon/hunt/validate. Phases:

  scope -> recon -> rank -> hunt -> validate -> report

Scope is enforced in code at every boundary: recon discoveries are filtered to
in-scope hosts, and no hunt agent is ever dispatched at an out-of-scope target.
State is persisted after every step, so a run is auditable and resumable.

  python3 engine/engine.py --scope engine/engagement.example.json --mock        # dry-run the flow (no agents)
  python3 engine/engine.py --scope my-engagement.json --max-hunts 8             # live (needs Burp + claude budget)
  python3 engine/engine.py --scope my-engagement.json --phases hunt,validate,report   # resume later phases
"""
import argparse
import collections
import json
import os
import re
import sys
import threading as _threading
import time

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)

# Ensure ~/go/bin is in PATH so recon tools (subfinder, httpx, gau, katana, etc.) are found
_gobin = os.path.expanduser("~/go/bin")
if os.path.isdir(_gobin) and _gobin not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = _gobin + os.pathsep + os.environ.get("PATH", "")

from scope import Scope            # noqa: E402
from state import Engagement, PHASE_RUNNING, PHASE_PASS, PHASE_BLOCKED, PHASE_FAILED  # noqa: E402
import agent as A                  # noqa: E402
import modelroute as MR            # noqa: E402

# OSINT (subdomain/asset enum) is a SEPARATE concern (Claude-OSINT) — not in the engine flow.


class _HealthTracker:
    """Sliding-window circuit breaker shared by hunt workers."""

    def __init__(self, window=20, trip_rate=0.8, max_cooldown=300):
        self._window = collections.deque(maxlen=window)
        self._lock = _threading.Lock()
        self._trip_rate = trip_rate
        self._cooldown_until = 0.0
        self._cooldown_step = 30
        self._max_cooldown = max_cooldown
        self._retry_after = 0.0

    def record(self, outcome):
        with self._lock:
            self._window.append(outcome)
            if outcome == "success":
                self._cooldown_step = 30

    def note_retry_after(self, seconds):
        with self._lock:
            self._retry_after = max(self._retry_after, time.time() + float(seconds))

    def is_healthy(self):
        with self._lock:
            now = time.time()
            if now < self._cooldown_until or now < self._retry_after:
                return False
            if len(self._window) < 5:
                return True
            failures = sum(1 for o in self._window if o != "success")
            if failures / len(self._window) >= self._trip_rate:
                self._cooldown_until = now + self._cooldown_step
                self._cooldown_step = min(self._cooldown_step * 2, self._max_cooldown)
                return False
            return True

    def summary(self):
        with self._lock:
            total = len(self._window)
            failures = sum(1 for o in self._window if o != "success") if total else 0
            return {"total": total, "failures": failures,
                    "cooldown_until": self._cooldown_until,
                    "retry_after": self._retry_after}


def _deepen(items):
    """HUNT_DEEP: collapse surface items to ONE analysis-driven agent per endpoint (secrets keep their class).
    Applied at every add_surface call site so no path (gql/platform/feedback/scope) re-introduces per-class
    spray. Idempotent. Preserves metadata fields for rich knowledge-driven guidance."""
    if os.environ.get("HUNT_DEEP", "1") != "1" or os.environ.get("HUNT_MOCK_AGENT") == "1":
        return items   # mock pipeline is keyed by real vuln_class; never collapse under test
    out, seen = [], set()
    for it in (items or []):
        if it.get("source") == "secret":
            out.append(it)
            continue
        d = dict(it)
        d["vuln_class"] = "deep"
        d.pop("vuln_classes", None)
        k = (d.get("method", "GET"), d.get("url", ""), d.get("param", ""))
        if k not in seen:
            seen.add(k)
            # Enrich: ensure params list is available for signal detection
            if d.get("param") and not d.get("params"):
                d["params"] = [p.strip() for p in d["param"].split(",") if p.strip()]
            out.append(d)
        else:
            # Merge metadata from duplicate endpoints (different sources may carry different info)
            existing = next((o for o in out if (o.get("method", "GET"), o.get("url", ""), o.get("param", "")) == k), None)
            if existing:
                for field in ("auth_required", "body_params", "tags", "confidence", "tech", "category"):
                    if it.get(field) and not existing.get(field):
                        existing[field] = it[field]
                # Merge params lists
                new_params = it.get("params") or []
                old_params = existing.get("params") or []
                if new_params:
                    merged = list(dict.fromkeys(old_params + new_params))
                    existing["params"] = merged
    return out


# Static assets are excluded by transport type, never by vulnerability or URL naming.
_Q_STATIC = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|pdf|mp4|webm|avif|"
                       r"xml)(\?|$)", re.I)
_Q_CDN_HOST = re.compile(r"(^|\.)cdn[\d.-]", re.I)


def _skip_static_url(url):
    """Static/CDN bytes are not a hunt. Shape-based, not a host catalog."""
    u = url or ""
    if _Q_STATIC.search(u):
        return True
    try:
        from urllib.parse import urlparse
        host = (urlparse(u).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return False
    return bool(host.startswith("cdn.") or ".cdn." in host or _Q_CDN_HOST.search(host))


def _logged_out_result(analysis):
    """The agent stopped at a login wall instead of using the session."""
    t = (analysis or "").lower()
    if not any(x in t for x in ("401", "unauthorized", "authentication required", "invalid credentials")):
        return False
    if not any(x in t for x in ("unauthenticated", "session-gated", "auth enforced", "without the session",
                                "no session", "logged out", "login wall")):
        return False
    # A real look with the session names a 200 and the account it used.
    if re.search(r"\b200\b", t) and any(x in t for x in ("with the session", "logged in", "as identity", " as a")):
        return False
    return True


def _endpoint_quality(s):
    """Score observed business impact and trust dimensions, never URL or vulnerability names."""
    import function_profile as FP
    return FP.impact_score(FP.from_endpoint(s))
# DEFAULT = recon -> rank -> map (deterministic, ~free): map the surface to the skill arsenal and
# SHOW it. The operator focuses their effort from there. hunt/validate/report are OPT-IN (--hunt).
ALL_PHASES = ["recon", "discover", "explore", "rank", "map", "plan", "hunt", "validate", "chain", "report"]
DEFAULT_PHASES = ["recon", "discover", "explore", "rank", "map", "plan"]

# generic infra/hosting/CDN fingerprints that are NOT worth auto-drafting a skill for (too generic)
INFRA_TECH = {"nginx", "apache", "cloudflare", "akamai", "fastly", "varnish", "iis", "openresty",
              "envoy", "haproxy", "ubuntu", "debian", "aws", "gcp", "azure", "cloudfront", "tomcat",
              "netlify", "vercel", "heroku", "github-pages", "gitbook", "readme", "squarespace", "wix"}


def _lrn(fn, *a, **k):
    """Call engine/learn.py best-effort — the learning loop must NEVER crash or slow a hunt into failure."""
    try:
        import learn as _L
        return getattr(_L, fn)(*a, **k)
    except Exception:  # noqa: BLE001
        return None


def _authmod():
    try:
        import authsession as _AS
        return _AS
    except Exception:  # noqa: BLE001
        return None


class Engine:
    def __init__(self, scope_path, base, model, max_hunts, max_turns, timeout, mock=False,
                 allow_intrusive=False, parallel=3, expand=False):
        self.scope = Scope.load(scope_path)
        self.eng = Engagement(base, self.scope.name)
        self.base = base
        if getattr(self.scope, "user_agent", "") and not os.environ.get("HUNT_USER_AGENT"):
            os.environ["HUNT_USER_AGENT"] = self.scope.user_agent   # per-target SOC tag for recon + agent
        if getattr(self.scope, "proxy", "") and not os.environ.get("HUNT_PROXY"):
            os.environ["HUNT_PROXY"] = self.scope.proxy             # per-target egress proxy (edge-gated hosts)
        if getattr(self.scope, "impersonate", "") and not os.environ.get("HUNT_IMPERSONATE"):
            os.environ["HUNT_IMPERSONATE"] = self.scope.impersonate  # curl_cffi TLS profile (e.g. safari_ios)
        try:                                                        # authenticated recon when a session exists
            import authn as _AN
            if _AN.configured(self.scope.name, self.base):
                os.environ.setdefault("HUNT_TARGET_SLUG", _AN._slug(self.scope.name))
                os.environ.setdefault("HUNT_AUTH_FILE", _AN.path_for(self.scope.name, self.base))
                os.environ.setdefault("HUNT_RECON_IDENT", "A")      # recon + agent reach behind-login surface
        except Exception:  # noqa: BLE001
            pass
        self.model, self.max_hunts = model, max_hunts
        self.max_turns, self.timeout, self.mock = max_turns, timeout, mock
        if self.mock:
            os.environ["HUNT_MOCK_AGENT"] = "1"   # module-level _deepen keeps real classes under mock
        # HUNT_INTRUSIVE=1 unlocks ACTIVE testing (account creation + state-changing PoC to PROVE impact).
        self.allow_intrusive = bool(allow_intrusive) or os.environ.get("HUNT_INTRUSIVE") == "1"
        self.expand = expand
        self.parallel = max(1, parallel)
        # Defense-in-depth: arm netget scope guard so no HTTP request can escape scope
        try:
            import netget
            netget.set_scope_guard(self.scope, allow_intrusive=self.allow_intrusive)
        except Exception:
            pass
        # Wire evidence pipeline so every HTTP exchange is auto-recorded
        try:
            import netget as _ng
            edir = self.eng.evidence_path("")
            os.makedirs(edir, exist_ok=True)
            _ng.set_evidence_dir(edir)
        except Exception:
            pass
        # Ensure _targets/slug.json exists so guardrails can load scope for this program
        tgt_dir = os.path.join(os.path.expanduser(base), "_targets")
        os.makedirs(tgt_dir, exist_ok=True)
        tgt_path = os.path.join(tgt_dir, self.scope.name + ".json")
        if not os.path.exists(tgt_path):
            import json as _j
            scope_data = {"name": self.scope.name, "in_scope": self.scope.in_scope,
                          "out_of_scope": self.scope.out_of_scope}
            if self.scope.path_restrictions:
                scope_data["path_restrictions"] = self.scope.path_restrictions
            if getattr(self.scope, "out_path_restrictions", None):
                scope_data["out_path_restrictions"] = self.scope.out_path_restrictions
            with open(tgt_path, "w") as _f:
                _j.dump(scope_data, _f, indent=2)
        try:
            from scheduler import Scheduler
            self.scheduler = Scheduler(os.path.join(os.path.expanduser(base), self.scope.name))
        except Exception:
            self.scheduler = None
        self.eng.log(f"engine start | scope={self.scope.name} in={self.scope.in_scope} "
                     f"out={self.scope.out_of_scope} seeds={self.scope.seeds} mock={mock} "
                     f"intrusive={'ALLOWED' if self.allow_intrusive else 'READ-ONLY (default)'}"
                     f" scheduler={'ON' if self.scheduler else 'OFF'}")
        self._health = _HealthTracker()

    # ---------------- rules of engagement (injected into every agent) ----------------
    def _roe(self):
        hosts = ", ".join(self.scope.in_scope)
        roe = ("RULES OF ENGAGEMENT (mandatory — authorized SOW):\n"
               f"- SCOPE: ONLY these hosts are in scope: {hosts}. NEVER send a request to ANY other host "
               "(no third-party APIs / CDNs / SaaS such as emailjs, salesforce, google, etc.), even to 'prove' a "
               "finding. If proof would require touching an out-of-scope host/service, DO NOT do it — report the "
               "finding but set proof_note='would require out-of-scope action (NOT performed)'.\n")
        if getattr(self.scope, "user_agent", ""):
            roe += (f"- MANDATORY USER-AGENT: EVERY HTTP request (curl and any tool) MUST send "
                    f"'User-Agent: {self.scope.user_agent}' (e.g. curl -A '<UA>'). It tags traffic for the "
                    "client SOC; an untagged request violates the program rules.\n")
        roe += (f"- CONTROLLED TRANSPORT: send every target request through `python3 {ENGINE_DIR}/netget.py` "
                "with `--slug` or `--scope-file`; never use raw curl/wget/httpx. Prompt rules are guidance, "
                "not a substitute for the transport's scope checks.\n")
        if getattr(self.scope, "proxy", "") or getattr(self.scope, "impersonate", ""):
            roe += (f"- EDGE-GATED TARGET: plain curl/wget is RESET by the edge (source-IP / TLS gating). For "
                    f"EVERY request to this target use the harness fetch helper INSTEAD of curl:\n"
                    f"    python3 {ENGINE_DIR}/netget.py GET \"<url>\"      (POST: netget.py POST \"<url>\" '<body>')\n"
                    "  It carries the allowed egress proxy, the required TLS fingerprint, and the mandatory UA. "
                    "Raw curl will only return connection resets here.\n")
        if getattr(self.scope, "roe_extra", ""):
            roe += self.scope.roe_extra.rstrip() + "\n"
        try:
            import authn as _AN
            _ids = _AN.identities(self.scope.name, self.base)
        except Exception:  # noqa: BLE001
            _ids = []
        if _ids:
            roe += (f"- AUTHENTICATED SESSIONS available: {', '.join(_ids)}. Reach the behind-login surface with the "
                    f"fetch helper: `python3 {ENGINE_DIR}/netget.py GET \"<url>\" --as A`.\n")
            if "B" in _ids:
                roe += (f"  TWO actors → compare owned resources and effects across actor/tenant boundaries: "
                        f"observe an object as its owner, request the same operation as the accessor, and compare "
                        f"content and state. `python3 {ENGINE_DIR}/authz.py diff --slug {_AN._slug(self.scope.name)} "
                        f"--url \"<owner-observed url>\"` — require ownership-marker proof before drafting.\n")
            roe += "  Prefer authenticated observation whenever the target exposes actor-dependent behavior.\n"
        if not self.allow_intrusive:
            roe += ("- READ-ONLY / NON-DESTRUCTIVE: do NOT perform any state-changing or intrusive action — no sending "
                    "emails, no writes/updates/deletes, no cache purge/revalidate, no account creation, no spam, no "
                    "flooding/DoS, and do NOT exercise exposed credentials. Demonstrate a finding with the minimum safe, "
                    "read-only evidence (SHOW that something is exposed; do NOT use it). A finding you cannot demonstrate "
                    "safely read-only -> report it with proof_note='requires intrusive validation (NOT performed)'.\n")
        else:
            roe += ("- ACTIVE / INTRUSIVE TESTING AUTHORIZED: to PROVE a bug you MAY create test accounts, log in, "
                    "and perform STATE-CHANGING actions (writes/updates, email/password change on your OWN test "
                    "accounts, exercise an exposed credential just enough to show access) — do what it takes to "
                    "DEMONSTRATE real impact, don't stop at read-only. HARD LIMITS still apply: IN-SCOPE hosts only; "
                    "NO brute-force/cracking; NO destructive, DoS, or mass-exploitation (prove the primitive on ONE "
                    "object/account, then STOP); minimise touching real victims' data; and STOP at draft. Log what you did.\n")
        return roe

    def _scope_audit(self, f):
        """Deterministic safety net: which out-of-scope hosts did the agent's PoC touch?

        Dummy RFC 2606 / RFC 6761 names (example.invalid, *.test, etc.) are callback placeholders
        in OAuth DCR JSON, not hosts the PoC contacted. Flagging them was a false SCOPE warning
        on Superhuman/Coda advertised MCP DCR.
        """
        blob = " ".join([str(f.get("request", "")), str(f.get("evidence", "")),
                         " ".join(f.get("hosts_contacted") or [])])
        hosts = set(re.findall(r'https?://([A-Za-z0-9.\-]+)', blob)) | set(f.get("hosts_contacted") or [])
        return sorted({h for h in hosts if h and not self.scope.in_scope_host(h)
                       and not self._dummy_callback_host(h)})

    @staticmethod
    def _dummy_callback_host(host):
        h = (host or "").lower().rstrip(".")
        if h in ("example.com", "example.net", "example.org", "example.invalid"):
            return True
        # RFC 2606 / 6761 reserved: .invalid .test .example .localhost
        return bool(re.search(r"(^|\.)(invalid|test|example|localhost)$", h))

    # ---------------- osint (deterministic scope expansion) ----------------
    def osint(self):
        self.eng.set_phase("osint")
        if self.mock:
            self.eng.state["targets"] = [{"host": "localhost", "url": s, "status": 200, "tech": []}
                                         for s in self.scope.seeds]
            self.eng.save(); self.eng.log(f"osint(mock): {len(self.eng.state['targets'])} target(s)")
            return
        import osint as O  # subdomain/asset enum -> live-host + tech map (subfinder/assetfinder/crt.sh + curl)
        targets = O.osint(self.scope, log=self.eng.log)
        self.eng.state["targets"] = targets
        self.eng.save()
        self.eng.log(f"osint: {len(targets)} live in-scope target(s) -> recon")

    # ---------------- OSINT->recon bridge (opt-in --expand) ----------------
    def _expand_scope(self):
        """OPT-IN bridge: enumerate subdomains via the (separate) osint module, probe liveness,
        and set seeds to every LIVE in-scope host so recon runs on each. Off by default — OSINT is
        a separate concern (Claude-OSINT); this just ingests its result when you want one tool to do
        it. The apex alone is usually a marketing page; the real surface is on subdomains."""
        import osint as O
        from urllib.parse import urlparse
        apexes = {".".join((urlparse(s).hostname or "").split(".")[-2:]) for s in self.scope.seeds}
        subs = set()
        for apex in sorted(a for a in apexes if a):
            subs |= O.enumerate_subdomains(apex, log=self.eng.log)
        in_scope = [s for s in sorted(subs) if self.scope.in_scope_host(s)]
        self.eng.log(f"expand: {len(subs)} subdomain(s) -> {len(in_scope)} in scope; probing liveness...")
        live, _ = O.probe_hosts(in_scope, log=self.eng.log)
        new_seeds = sorted({t["url"] for t in live if t.get("url")})
        if new_seeds:
            self.scope.seeds = new_seeds
            self.eng.log(f"expand: recon will run on {len(new_seeds)} live host(s): "
                         + ", ".join(urlparse(u).hostname for u in new_seeds[:10]))

    # ---------------- recon (deterministic, SPA-aware, per target) ----------------
    def _gather_params_cached(self, R):
        """gau historical + katana live-crawl is slow (~15 min) AND hits the target (katana crawls it,
        which is what earns a 429). Cache the mined params per engagement so persist rounds reuse them
        instead of re-hammering the target every 30 min. Refresh after HUNT_PARAMS_TTL (default 6h)."""
        import time as _t
        import json as _j
        ttl = int(os.environ.get("HUNT_PARAMS_TTL", "21600"))
        cache = os.path.join(self.eng.dir, "params_cache.json")
        try:
            if os.path.isfile(cache):
                c = _j.load(open(cache))
                age = _t.time() - c.get("ts", 0)
                if age < ttl and isinstance(c.get("params"), list):
                    self.eng.log(f"recon: params from cache ({len(c['params'])} pair(s), {int(age)}s old) "
                                 f"— skipped gau+katana to avoid re-hammering the target (TTL {ttl}s)")
                    return c["params"]
        except Exception:  # noqa: BLE001
            pass
        params = R.gather_params(self.scope, log=self.eng.log)
        try:
            with open(cache, "w") as _f:
                _j.dump({"ts": _t.time(), "params": params}, _f)
        except Exception:  # noqa: BLE001
            pass
        return params

    def recon(self):
        self.eng.set_phase("recon")
        self._honor_heals()
        # Collapse /files/<uuid> duplicates before the "is the worklist empty?" decision,
        # so a pile of object ids is not treated as a reason to crawl again.
        if not self.mock:
            collapsed = self.eng.collapse_patterns()
            if collapsed:
                self.eng.log(f"recon: {collapsed} duplicate object-id URL(s) collapsed to one pattern each")
            d = self._review_directive()
            age = time.time() - float(d.get("ts_epoch") or 0)
            if d.get("skip_crawl") and age < 6 * 3600 and self._authn_ready():
                self.eng.log("recon: 2h review — skip crawl, mine the session if the worklist is empty")
                if not self.eng.worklist():
                    self._mine_session()
                return
        if self.mock:
            items = []
            for seed in self.scope.seeds:
                items += [it for it in MOCK_RECON.get(seed, []) if self.scope.in_scope_host(it.get("url", ""))]
            self.eng.add_surface(_deepen(items))
            self.eng.log(f"recon(mock): {len(items)} item(s)")
            return
        import recon as R, osint as O  # deterministic recon: service/tech + endpoints + secrets + params
        from urllib.parse import urlparse
        # CPU REBALANCE (vuln-first): don't re-run heavy recon (service probe + platform + openapi + SPA/JS
        # mining) EVERY round — on a small box that starves the hunt. Skip it while the last recon is fresh
        # AND there's still plenty queued to test; spend the cores on HUNTING. Heavy recon re-runs when the
        # worklist drains below one hunt-batch (needs fresh surface) or the TTL lapses (catch new surface).
        ttl = int(os.environ.get("HUNT_RECON_TTL", "10800"))         # 3h default
        last = self.eng.state.get("recon_ts") or 0
        queued = len(self.eng.worklist())
        # Skip heavy recon when queue is large enough AND cache is fresh — but always allow discovery
        # when queue is small, even if items remain, so new surface is found continuously.
        if last and (time.time() - last) < ttl and queued >= self.max_hunts:
            self.eng.log(f"recon: cached ({int((time.time()-last)/60)}m old) + {queued} item(s) queued "
                         f">= {self.max_hunts} — SKIPPING heavy recon, straight to HUNT (cores -> vuln-finding)")
            return
        # RECON CAP (a .recon_capped flag file dropped by the workflow-reviewer's auto-apply on a starved
        # huge-surface target). A flag FILE (not state) so it can't race the running hunt's own state saves.
        # There's already a worklist, so stop crawling toward full enumeration and HUNT the ranked slice now.
        _capf = os.path.join(self.eng.dir, ".recon_capped")
        try:
            _capfresh = os.path.exists(_capf) and (time.time() - os.path.getmtime(_capf)) < ttl
        except OSError:
            _capfresh = False
        if queued >= self.max_hunts and _capfresh:       # self-expires after the TTL so new surface is still caught
            self.eng.log(f"recon: CAPPED by reviewer + {queued} item(s) queued — straight to HUNT "
                         "(stop crawling the long tail, hunt the ranked slice)")
            return
        # Covered worklist: do not spend the round on gau/katana. With a session, pull new object
        # ids out of that session and test those. Without one, wait out the recon TTL.
        if queued == 0 and self._authn_ready():
            try:
                import authsession as _AS
                _sess = _AS.load(self.scope.name, self.base)
                if not (_AS.valid(_sess) and not _AS.site_rejects(_sess, program=self.scope.name, base=self.base)):
                    try:
                        _AS.relogin(self.scope.name, ident="A", base=self.base)
                        _sess = _AS.load(self.scope.name, self.base)
                    except Exception:  # noqa: BLE001
                        pass
                if not (_AS.valid(_sess) and not _AS.site_rejects(_sess, program=self.scope.name, base=self.base)):
                    self.eng.log("recon: no live session — not mining object ids")
                    return
            except Exception:  # noqa: BLE001
                pass
            js_n = self._jsdiff_surface()
            self.eng.log("recon: worklist covered and a session exists — mining logged-in object ids "
                         "instead of another crawl")
            self._profile()
            added = self._mine_session()
            if not added:
                added = self._hypothesize()
            added = (added or 0) + (js_n or 0)
            self.eng.state["recon_ts"] = time.time()
            self.eng.save()
            if not added:
                self.eng.log("recon: session mine found no new object urls — not starting another crawl")
            return
        elif queued == 0 and last and (time.time() - last) < ttl:
            self.eng.log("recon: worklist covered, no session, last crawl still fresh — not recrawling. "
                         "A logged-in session is required before another round pays.")
            return
        if self.expand:
            self._expand_scope()
        # AUTHENTICATED recon: when a session exists for this target, run the WHOLE recon as the logged-in
        # user (recon routes _get through netget when HUNT_RECON_IDENT is set) so JS mining + endpoint
        # discovery see the BEHIND-LOGIN app — where the paid bugs live. The session is mirrored into
        # authn 'A' by authsession.save(); here we just flip recon into authed mode for this target.
        if self._authn_ready():
            os.environ["HUNT_RECON_IDENT"] = "A"
            os.environ["HUNT_TARGET_SLUG"] = self.scope.name
            self.eng.log("recon: AUTHENTICATED (identity A) — mining the behind-login surface")
        else:
            os.environ.pop("HUNT_RECON_IDENT", None)
        # service / tech fingerprint of the seed target(s) — per-target (NOT subdomain enum)
        seed_hosts = sorted({urlparse(s).hostname for s in self.scope.seeds if urlparse(s).hostname})
        tech, _ = O.probe_hosts(seed_hosts, log=self.eng.log)
        self.eng.state["targets"] = tech
        self.eng.save()
        for t in tech:
            self.eng.log(f"recon: service {t.get('host')} [{t.get('status')}] · {', '.join(t.get('tech', [])) or 'tech?'}")
        plat = R.platform_recon(self.scope, log=self.eng.log)        # .well-known / Firebase / OAuth / robots
        api = R.openapi_recon(self.scope, log=self.eng.log)          # OpenAPI schema -> categorized + auth-sweep
        endpoints, oos = R.spa_recon(self.scope, log=self.eng.log)   # current API endpoints + JS secrets
        params = ([] if getattr(self.scope, "skip_param_mining", False)
                  else self._gather_params_cached(R))                 # gau+katana, cached (skipped if scanner-forbidden)
        # categorize every (endpoint | param) into its applicable attack classes, expand to work units
        expanded = list(api) + list(plat)                            # api + platform items are already categorized
        for it in endpoints:
            for cls in R.classify_all(it):
                e = dict(it); e["vuln_class"] = cls; e.pop("vuln_classes", None); expanded.append(e)
        for it in params:
            for cls in R.classes_for_param(it.get("param", ""), it.get("url", "")):
                e = dict(it); e["vuln_class"] = cls; expanded.append(e)
        # documented API routes from the scope (path-scoped programs where recon can't crawl the surface)
        for u in (getattr(self.scope, "endpoints", None) or []):
            if u and self.scope.in_scope_host(u):
                for cls in R.classify_all({"url": u, "method": "GET", "source": "scope-endpoint"}):
                    expanded.append({"url": u, "vuln_class": cls, "source": "scope-endpoint"})
        # Belt-and-suspenders: never let a non-curlable target (robots/scope glob with '*', or a
        # static asset) reach the worklist — those always waste a hunt step and yield 'nothing'.
        # A leaked-secret item keeps its own .js URL (the bundle IS the finding), so it's exempt.
        before = len(expanded)
        expanded = [e for e in expanded
                    if e.get("source") == "secret" or R.is_concrete_target(e.get("url", ""))]
        dropped = before - len(expanded)
        if os.environ.get("HUNT_DEEP", "1") == "1":   # ONE analysis-driven pentest agent per endpoint
            seen, deep = set(), []                    # (not N mechanical per-class hunts) — the agent views
            for e in expanded:                       # source, reasons about the endpoint, then exploits what fits
                if e.get("source") == "secret":
                    deep.append(e)                    # a leaked-secret item IS the finding — keep as-is
                    continue
                u = e.get("url", "")
                mk = f"{e.get('method','GET')}:{u}"
                if u and mk not in seen:
                    seen.add(mk)
                    d = dict(e)
                    d["vuln_class"] = "deep"
                    d.pop("vuln_classes", None)
                    deep.append(d)
            expanded = deep
        # SURFACE QUALITY: stop any ONE host from flooding the worklist (e.g. a staging host enumerated into
        # thousands of URLs). Keep the top slice per host by priority — generous + env-tunable, so it trims junk
        # domination without capping the AI's reach on real hosts. (Dead endpoints are also skipped at hunt time.)
        cap = int(os.environ.get("HUNT_MAX_PER_HOST", "500"))
        if cap > 0 and expanded:
            from urllib.parse import urlparse as _up
            byh = {}
            for e in expanded:
                byh.setdefault(_up(e.get("url", "")).netloc, []).append(e)
            capped = []
            for h, items in byh.items():
                if len(items) > cap:
                    self.eng.log(f"recon: per-host cap — {h} had {len(items)} endpoints, kept top {cap} by priority")
                    items = sorted(items, key=lambda x: -((x.get("priority") or 0) + _endpoint_quality(x)))[:cap]
                capped += items
            expanded = capped
        added = self.eng.add_surface(expanded)
        if dropped:
            self.eng.log(f"recon: dropped {dropped} non-curlable target(s) (glob/static) before worklist")
        if oos:
            self.eng.log(f"recon: {len(oos)} out-of-scope host(s) seen, NOT tested: {', '.join(oos[:8])}")
        self.eng.log(f"recon: {len(api)} api + {len(plat)} platform + {len(endpoints)} endpoint + "
                     f"{len(params)} param -> {added} categorized (target,class) work unit(s)")
        self._deep_recon(R)                    # authed GraphQL introspection + headless SPA API capture
        self.eng.state["recon_ts"] = time.time()   # mark heavy recon done -> next rounds hunt the cache
        self.eng.save()

    def _harvest_urls(self, urls):
        """Turn authenticated response bodies into concrete object URLs. No agent."""
        import authz
        import netget
        found = []
        for u in urls:
            try:
                status, body, hdrs = netget.get(u, method="GET", ident="A", slug=self.scope.name)
            except Exception:  # noqa: BLE001
                continue
            if not (200 <= (status or 0) < 300) or not body:
                continue
            # A marketing HTML page is not an object list. Ids have to come from JSON.
            ctype = (hdrs.get("content-type") or "") if isinstance(hdrs, dict) else ""
            is_json = body.lstrip()[:1] in "{[" or "json" in ctype.lower()
            if not is_json:
                # From an HTML page, keep only API links the session was shown. Not every href.
                for m in re.findall(r"https://[^\s\"'<>\\]{8,180}", body):
                    m = m.rstrip(").,]}>")
                    if "{" in m or "}" in m:
                        continue
                    if re.search(r"/api/|/gw/|/v[0-9]+/", m) and self.scope.in_scope_host(m):
                        found.append(m)
                continue
            for ou in authz._object_urls(u, authz._extract_ids(body)):
                if "{" not in ou and self.scope.in_scope_host(ou):
                    found.append(ou)
            for m in re.findall(r"https://[^\s\"'<>\\]{8,180}", body):
                m = m.rstrip(").,]}>")
                if "{" in m or "}" in m:
                    continue
                if self.scope.in_scope_host(m) and _endpoint_quality({"url": m}) > 0:
                    found.append(m)
        items, seen = [], set()
        for u in found:
            if u in seen:
                continue
            seen.add(u)
            items.append({"url": u, "vuln_class": "deep", "source": "session-mine", "priority": 90})
            if len(items) >= 15:
                break
        return items

    def _mine_session(self):
        """Pull object ids out of the logged-in session. Deterministic fetches first; an agent only
        if those fetches saw nothing, and at most once per recon TTL."""
        seeds = []
        for s in self.eng.state.get("surface") or []:
            u = s.get("url") or ""
            if not u or not self.scope.in_scope_host(u):
                continue
            if _endpoint_quality(s) < 20:
                continue
            if re.search(r"/files?/[0-9a-f-]{16,}", u, re.I):
                continue
            seeds.append(u)
        seeds.sort(key=lambda u: (0 if re.search(r"/api/|/gw/|/v[0-9]+/|https://api[.-]", u) else 1,
                                  -_endpoint_quality({"url": u})))
        seeds = seeds[:8]
        items = self._harvest_urls(seeds) if seeds else []
        who = "A"
        err = ""
        if not items:
            import agent as A
            ttl = int(os.environ.get("HUNT_RECON_TTL", "10800"))
            last_agent = self.eng.state.get("mine_agent_ts") or 0
            # A mine that added nothing should try again in 30 minutes, not sit out the
            # full recon TTL while the worklist stays empty.
            if self.eng.state.get("mine_agent_added") == 0:
                ttl = min(ttl, 1800)
            if last_agent and (time.time() - last_agent) < ttl:
                self.eng.log("session-mine: deterministic harvest empty; agent mine still inside its TTL")
                return 0
            try:
                import authn
                idents = authn.identities(self.scope.name, self.base)
            except Exception:  # noqa: BLE001
                idents = ["A"]
            who = ", ".join(idents) or "A"
            b = " and `--as B`" if "B" in idents else ""
            task = (
                f"You are mining a logged-in session for NEW object URLs on program {self.scope.name}. "
                "Do not crawl the public site and do not run gau or katana.\n"
                f"Identities: {who}. Fetch with `python3 {ENGINE_DIR}/netget.py GET \"<url>\" --as A`{b}.\n"
                "Follow the operations and object relationships this session actually exposes. Collect concrete "
                "operation URLs and resource identifiers observed in responses; do not infer them from product names.\n"
                "Return ONLY a fenced json object: {\"discovered\": [\"https://host/path/with-real-id\", ...]}.\n"
                "Every URL must be one you saw in an authenticated response. Do not invent URLs. "
                "At most 15 URLs, in-scope hosts only."
            )
            r = A.run_agent(task, context=self.scope.name, max_turns=30,
                            timeout=int(os.environ.get("HUNT_MINE_TIMEOUT", "700")),
                            model=MR.model_for("recon"))
            self.eng.state["mine_agent_ts"] = time.time()
            self.eng.save()
            err = r.get("error") or ""
            f = A.extract_json(r.get("result") or "") or {}
            for u in (f.get("discovered") or [])[:15]:
                if isinstance(u, str) and self.scope.in_scope_host(u) and not _Q_STATIC.search(u):
                    items.append({"url": u, "vuln_class": "deep", "source": "session-mine", "priority": 90})
        # Images and video are not a successful mine. Counting them kept the
        # worklist empty and blocked the next mine for the full recon TTL.
        items = [it for it in items if not _Q_STATIC.search(it.get("url") or "")]
        added = self.eng.add_surface(_deepen(items)) if items else 0
        self.eng.state["mine_agent_added"] = added
        self.eng.save()
        self.eng.log(f"session-mine: {added} new object url(s) from identity {who}"
                     + (f" ERR={err}" if err else ""))
        return added

    def _remember(self, it, analysis, classes, result="nothing", finding=None):
        """Write this look into the live hunt graph so the next agent does not repeat it."""
        try:
            import brain as BR
        except Exception:  # noqa: BLE001
            return
        f = finding if isinstance(finding, dict) else {}
        hyps = f.get("hypotheses") or []
        signals = f.get("signals_missed") or []
        BR.record_edge(self.scope.name, it.get("url") or "", analysis=analysis,
                       classes=classes, signals=signals, result=result,
                       hypotheses=hyps, base=self.base)
        if signals:
            BR.mark_reactive(self.scope.name, signals, self.base)
        if result != "auth_wall":
            try:
                import authsession as _AS
                _AS.note_live(self.scope.name, it.get("url") or "", self.base)
            except Exception:  # noqa: BLE001
                pass

    def _profile(self):
        """One look at what the product is, before another mine. Stolen from BugHunter AI's
        AppReviewAgent — without their XSSAgent/SQLiAgent dispatch table."""
        if self.mock:
            return
        try:
            import brain as BR
        except Exception:  # noqa: BLE001
            return
        prev = (BR.load(self.scope.name, self.base).get("profile") or {})
        if prev.get("narrative") and (time.time() - float(prev.get("ts") or 0)) < 6 * 3600:
            return
        import agent as A
        seeds = [s for s in (self.scope.seeds or []) if self.scope.in_scope_host(s)][:4]
        host = ""
        try:
            import authsession as _AS
            sess = _AS.load(self.scope.name, self.base)
            host = str((sess or {}).get("host") or "")
        except Exception:  # noqa: BLE001
            host = ""
        e = ENGINE_DIR
        surface_urls = [s.get("url", "") for s in (self.eng.state.get("surface") or [])
                        if s.get("url") and self.scope.in_scope_host(s["url"])][:20]
        surface_hint = "\n".join(f"  {u}" for u in surface_urls[:15]) if surface_urls else "(none discovered yet)"
        task = (
            f"You are doing DEEP RECON on program {self.scope.name}. Your job: understand EVERYTHING "
            "this app does — every feature, every API, every user role, every data flow — so the "
            "next phase can attack intelligently, not blindly.\n\n"
            f"Session host: {host or '?'}. Seeds: {', '.join(seeds) or '(none)'}.\n"
            f"Known surface so far:\n{surface_hint}\n\n"
            "PHASE 1 — OBSERVE AND EXPAND:\n"
            f"  `python3 {e}/netget.py GET \"<url>\" --as A` — fetch observed operations as the current actor\n"
            f"  `python3 {e}/browser.py capture --url <seed> --slug {self.scope.name} --as A "
            f"--scope {host or '<host>'}` — capture actual runtime calls and forms\n"
            "  Follow links, forms, scripts, schemas, calls, objects, and state transitions disclosed by responses. "
            "Use a protocol parser only when its schema or negotiation is actually present. Do not suggest paths "
            "from a conventional checklist or assume any API style.\n\n"
            "PHASE 2 — MODEL BEHAVIOR:\n"
            "  For each observed operation record its action, resource, actors, inputs, outputs, effects, "
            "preconditions, relationships, state changes, and invariants. Keep unparsed or inaccessible behavior "
            "as unknown; never infer completeness from URL count.\n\n"
            "PHASE 3 — RETURN a fenced ```json``` object:\n"
            '{"narrative":"<observed product behavior and actors>",'
            '"tech_stack":["technologies evidenced by responses"],'
            '"roles":["roles actually observed"],'
            '"auth_mechanism":"<observed mechanism or unknown>",'
            '"crown_jewels":["resources whose observed sensitivity or effects justify priority"],'
            '"api_surface":[{"method":"GET|POST|...","url":"https://...","function":"observed action",'
            '"params":["observed inputs"],"auth_required":true}],'
            '"flows":[{"what":"<observed transition>","url":"https://in-scope/...",'
            '"why":"<observed precondition, effect, or invariant>"}],'
            '"hidden_endpoints":["real operations found outside navigation"],'
            '"deprioritized":["content shown by transport and behavior to be static"]}\n'
            "List only real in-scope operations supported by observations. Do not guess endpoints or behavior."
        )
        r = A.run_agent(task, context=self.scope.name, max_turns=20,
                        timeout=int(os.environ.get("HUNT_PROFILE_TIMEOUT", "400")),
                        model=MR.model_for("profile"))
        f = A.extract_json(r.get("result") or "") or {}
        if not isinstance(f, dict) or not (f.get("narrative") or f.get("flows")):
            self.eng.log("profile: no narrative from the session — continuing without one"
                         + (f" ERR={r.get('error')}" if r.get("error") else ""))
            return
        BR.set_profile(self.scope.name, f, self.base)
        n_flows = len(f.get("flows") or [])
        n_api = len(f.get("api_surface") or [])
        n_hidden = len(f.get("hidden_endpoints") or [])
        self.eng.log(f"profile: {n_flows} flow(s), {n_api} API endpoint(s), {n_hidden} hidden — "
                     f"{(f.get('narrative') or '')[:140]}")
        items = []
        for fl in (f.get("flows") or [])[:12]:
            if not isinstance(fl, dict):
                continue
            u = fl.get("url") or fl.get("endpoint") or ""
            if isinstance(u, str) and self.scope.in_scope_host(u) and not _Q_STATIC.search(u):
                items.append({"url": u, "vuln_class": "deep", "source": "profile-flow", "priority": 110})
        for ep in (f.get("api_surface") or [])[:30]:
            if not isinstance(ep, dict):
                continue
            u = ep.get("url") or ""
            if isinstance(u, str) and self.scope.in_scope_host(u) and not _Q_STATIC.search(u):
                items.append({"url": u, "method": ep.get("method", "GET"),
                              "param": ",".join(ep.get("params") or [])[:200],
                              "vuln_class": "deep", "source": "profile-api", "priority": 105,
                              "note": ep.get("function", "")[:200]})
        for u in (f.get("hidden_endpoints") or [])[:10]:
            if isinstance(u, str) and self.scope.in_scope_host(u) and not _Q_STATIC.search(u):
                items.append({"url": u, "vuln_class": "deep", "source": "profile-hidden", "priority": 115})
        if items:
            added = self.eng.add_surface(_deepen(items))
            self.eng.log(f"profile: queued {added} endpoint(s) from flows+api+hidden")
        # write feature map artifacts
        try:
            import featuremap as FM
            FM.write_artifacts(self.scope.name, f, self.eng.dir, self.base)
        except Exception:  # noqa: BLE001
            pass

    def _jsdiff_surface(self):
        """Turn novelty's new/changed JS bundles into hunt worklist items (SOP: attack the delta)."""
        diff = self.eng.state.get("last_novelty") if isinstance(self.eng.state.get("last_novelty"), dict) else {}
        urls = [u for u in (diff.get("new_js") or []) if isinstance(u, str)]
        for c in diff.get("changed_js") or []:
            if isinstance(c, dict) and c.get("url"):
                urls.append(c["url"])
            elif isinstance(c, str):
                urls.append(c)
        seen_u, urls = set(), [u for u in urls if u not in seen_u and not seen_u.add(u)]
        if not urls:
            return 0
        last = float(self.eng.state.get("jsdiff_ts") or 0)
        if last and (time.time() - last) < 1800:
            return 0
        try:
            import jsdiff as JD
        except Exception:  # noqa: BLE001
            return 0
        from urllib.parse import urljoin, urlparse
        seed = (self.scope.seeds or [""])[0]
        origin = ""
        if seed:
            p = urlparse(seed)
            origin = f"{p.scheme}://{p.hostname}" if p.hostname else ""
        items = []
        for u in urls[:6]:
            if u.startswith("http") and not self.scope.in_scope_host(u):
                continue
            text = JD._curl(u) if u.startswith("http") else ""
            if not text:
                continue
            extracted = JD.extract(text)
            for ep in list(extracted.get("endpoints") or [])[:15]:
                if ep.startswith("/") and origin:
                    ep = urljoin(origin + "/", ep.lstrip("/"))
                if isinstance(ep, str) and ep.startswith("http") and self.scope.in_scope_host(ep):
                    items.append({"url": ep, "vuln_class": "deep", "source": "jsdiff", "priority": 90})
        self.eng.state["jsdiff_ts"] = time.time()
        added = self.eng.add_surface(_deepen(items)) if items else 0
        self.eng.log(f"jsdiff: {added} new endpoint(s) from {len(urls)} bundle(s)")
        self.eng.save()
        return added

    def _hypothesize(self):
        """When the worklist and the mine are empty, invent the next tests from the live session.

        Same idea as Reaper's later-round hypotheses / bountyhunter's loop mode: do not recrawl
        marketing pages and do not replay a class catalog. Ask one agent to name new in-scope
        URLs the session can actually see.
        """
        if self.mock:
            return 0
        ttl = min(int(os.environ.get("HUNT_RECON_TTL", "10800")), 1800)
        last = float(self.eng.state.get("hypo_ts") or 0)
        if last and (time.time() - last) < ttl:
            self.eng.log("hypothesize: still inside its TTL")
            return 0
        try:
            import brain as BR
            import agent as A
        except Exception:  # noqa: BLE001
            return 0
        notes = self.eng.state.get("hunt_notes") or {}
        prior = []
        if isinstance(notes, dict):
            for k, n in list(notes.items())[-12:]:
                url = k.split("|")[0]
                a = (n or {}).get("analysis") if isinstance(n, dict) else ""
                if url and a:
                    prior.append(f"- {url}: {str(a)[:160]}")
        memory = BR.prompt_block(self.scope.name, "", self.base)
        open_u = BR.open_urls(self.scope.name, self.base)
        items = []
        for u in open_u:
            if self.scope.in_scope_host(u) and not _Q_STATIC.search(u):
                items.append({"url": u, "vuln_class": "deep", "source": "hypothesis", "priority": 100})
        who = "A"
        err = ""
        if not items:
            try:
                import authn
                idents = authn.identities(self.scope.name, self.base)
            except Exception:  # noqa: BLE001
                idents = ["A"]
            who = ", ".join(idents) or "A"
            b = " and `--as B`" if "B" in idents else ""
            task = (
                f"You are inventing the NEXT tests for program {self.scope.name}. "
                "The worklist is empty. Do not recrawl the public site. Do not pick from a vuln class list.\n"
                f"Identities: {who}. Fetch with `python3 {ENGINE_DIR}/netget.py GET \"<url>\" --as A`{b}.\n"
                "Follow the operations, resources, and relationships visible to this session. From actual response "
                "data, name concrete in-scope operation URLs and observed resource IDs, plus one hypothesis per "
                "unresolved behavior that was NOT already tried below. Do not infer paths from product conventions.\n"
                + (memory or "")
                + ("Already looked:\n" + "\n".join(prior[:10]) + "\n" if prior else "")
                + "Return ONLY a fenced json object: "
                '{"discovered":["https://host/path/with-real-id"],'
                '"hypotheses":["<one-sentence tests>"]}. '
                "At most 10 URLs, in-scope hosts only, no static images or marketing pages."
            )
            r = A.run_agent(task, context=self.scope.name, max_turns=25,
                            timeout=int(os.environ.get("HUNT_HYPO_TIMEOUT", "400")),
                            model=MR.model_for("explore"))
            self.eng.state["hypo_ts"] = time.time()
            self.eng.save()
            err = r.get("error") or ""
            f = A.extract_json(r.get("result") or "") or {}
            for u in (f.get("discovered") or [])[:10]:
                if isinstance(u, str) and self.scope.in_scope_host(u) and not _Q_STATIC.search(u):
                    items.append({"url": u, "vuln_class": "deep", "source": "hypothesis", "priority": 100})
            brain = BR.load(self.scope.name, self.base)
            for h in f.get("hypotheses") or []:
                BR.add_hypothesis(brain, h, url=(items[0]["url"] if items else ""),
                                  source="hypothesize")
            BR.save(self.scope.name, brain, self.base)
        added = self.eng.add_surface(_deepen(items)) if items else 0
        self.eng.log(f"hypothesize: {added} new url(s) from identity {who}"
                     + (f" ERR={err}" if err else ""))
        return added

    def _unmark_tested(self, item):
        """Drop a just-written tested mark so a refused nothing is retried, not closed."""
        t = self.eng.state.get("tested")
        if isinstance(t, dict) and item:
            legacy = f"{item.get('url')}|{item.get('param','')}|{item.get('vuln_class','')}"
            modern = f"{item.get('method','GET')}|{legacy}"
            t.pop(legacy, None)
            t.pop(modern, None)
            self.eng.save()

    def _record_evidence_attempt(self, it, outcome="TESTED"):
        """Link transport-recorded observations to the test case. Returns True if evidence validates.
        Uses method, URL, and identity for precise matching — no URL-path fallback."""
        try:
            import evidence as EV
            edir = self.eng.evidence_path("")
            case_key = self.eng._key(it)
            method = (it.get("method") or "GET").upper()
            url = it.get("url", "")
            obs = EV.get_observations(edir, case_id=case_key)
            if obs:
                EV.record_attempt(edir, case_id=case_key,
                                  observation_ids=[o["id"] for o in obs[-10:]],
                                  outcome=outcome, method=method, url=url,
                                  identity=it.get("accessor") or it.get("role"),
                                  owner=it.get("owner"), accessor=it.get("accessor"),
                                  confidence="candidate" if outcome == "CONFIRMED" else "validated_by_rule")
                valid, _reason = EV.validate_evidence(
                    edir, case_key, method=method, url=url)
                return valid
            return False
        except Exception:  # noqa: BLE001
            return False

    def _needs_authz_gate(self, url, item=None):
        """Require actor-boundary proof only when the observed profile has that boundary."""
        if self.mock or not url or not str(url).startswith("http"):
            return False
        if not self.scope.in_scope_host(url):
            return False
        if item is not None:
            import testplan as TP
            profile = TP.analyze_endpoint(item).get("function_profile") or {}
            dimensions = set(profile.get("trust_dimensions") or [])
            if not dimensions & {"actor_variation", "ownership_boundary", "tenant_boundary", "role_transition"}:
                return False
        try:
            import authn
            ids = authn.identities(self.scope.name, self.base)
        except Exception:  # noqa: BLE001
            return False
        return "A" in ids and "B" in ids

    def _authz_closeout(self, url, method="GET", body=None, owner="A", accessor="B"):
        """Deterministic authz diff: request as owner (positive control), then as accessor (negative control).
        Logs `authz:` line. Returns the log line, or '' if not run (caller must refuse nothing)."""
        try:
            import authn
            import authz
            import netget
            slug = authn._slug(self.scope.name)
            d = authz.diff_one(method, url, body, self.scope.name, owner=owner, accessor=accessor)
            sb, _tb, _h = netget.get(url, method=method, data=body, ident=accessor, slug=slug)
        except Exception:  # noqa: BLE001
            return ""
        line = (f"authz: diff {owner}={d.get('A_status')} {accessor}={d.get('B_status')} "
                f"sim={d.get('similarity')} bola={bool(d.get('bola_suspect'))} "
                f"netget_{accessor}={sb} method={method} {str(url)[:120]}")
        self.eng.log(line)
        return line

    def _ab_same_host(self):
        """True when A and B log into the same host. Cross-tenant B (other subdomain) 401s on
        A's APIs by design — that is not IDOR and must not drive the hunt."""
        try:
            import authn
            d = authn.load(self.scope.name, self.base)
            ha = ((d.get("A") or {}).get("host") or "")
            hb = ((d.get("B") or {}).get("host") or "")
            if ha and hb:
                from urllib.parse import urlparse
                def _h(x):
                    x = str(x or "")
                    return (urlparse("https://" + x).hostname or x).lower()
                return _h(ha) == _h(hb)
        except Exception:  # noqa: BLE001
            pass
        try:
            import authsession as AS
            creds = AS.load_creds(self.scope.name, self.base) or {}
            ha = (creds.get("A") or {}).get("host") or ""
            hb = (creds.get("B") or {}).get("host") or ""
            if ha and hb:
                import guardrails as G
                return G._host_of(ha) == G._host_of(hb)
        except Exception:  # noqa: BLE001
            pass
        return True

    def _authz_lead(self, url):
        """Two live accounts: the first action on an object or API URL is A's id read as B.
        A similarity hit is a lead, not a finding, until B's body contains A's marker."""
        try:
            import authn
            ids = authn.identities(self.scope.name, self.base)
        except Exception:  # noqa: BLE001
            return ""
        if "A" not in ids or "B" not in ids:
            return ""
        if not self._ab_same_host():
            return ("\nAUTHZ PRE-CHECK: account B is a live login on a different host than A "
                    "(other tenant / other site). A 401 from B on this URL is tenant isolation, "
                    "not IDOR. Do not spend the look proving B=401. Invent the next test from "
                    "A's live bytes on THIS host.\n")
        if _endpoint_quality({"url": url}) < 25:
            return ""
        if re.search(r"/(logout|health|ready|live|robots\.txt|\.well-known)(/|$)", url or "", re.I):
            return ""
        try:
            import authz
            suspects = authz.id_oracle(url, self.scope.name) or []
        except Exception:  # noqa: BLE001
            suspects = []
        if not suspects:
            return ("\nAUTHZ PRE-CHECK: accounts A and B are both live. When testing ownership boundaries, "
                    "GET this URL as A, take one object id from the JSON, and GET that object as B. "
                    "vulnerable:true only if B's body contains a marker that belongs to A.\n")
        s = suspects[0]
        return (f"\nAUTHZ PRE-CHECK already compared A and B. B requested {s.get('url')} and got "
                f"HTTP {s.get('B_status')} ({float(s.get('similarity') or 0):.0%} similar to A). "
                "That similarity is not a finding. Quote a string that is in A's object and also in "
                "B's response, or return vulnerable:false.\n")

    def _authn_ready(self):
        """True iff an authn A/B session exists for this target (operator-provided or provisioned, mirrored
        by authsession.save()). Gates authenticated recon, headless browser capture, and the IDOR sweep."""
        try:
            import authn
            return bool(authn.configured(self.scope.name, self.base))
        except Exception:  # noqa: BLE001
            return False

    def _deep_recon(self, R):
        """Expand the surface with the DEEP authed API that curl recon misses: GraphQL introspection
        (cheap -> every round) + headless-browser XHR/fetch capture (expensive -> only on first recon,
        when the worklist is idle, or stale). This is what turns shallow public surface + 'testing 0
        items' into real authed endpoints to hunt. Never raises into the round."""
        if self.mock:
            return
        ident = "A" if self._authn_ready() else None
        try:
            gql = R.graphql_recon(self.scope, slug=self.scope.name, ident=ident, log=self.eng.log)
            if gql:
                self.eng.add_surface(_deepen(gql))
        except Exception as e:  # noqa: BLE001
            self.eng.log(f"deep-recon: graphql skipped ({type(e).__name__}: {e})")
        if os.environ.get("HUNT_BROWSER_RECON", "1") != "1":
            return
        last = self.eng.state.get("browser_recon_ts") or 0
        hrs = float(os.environ.get("HUNT_BROWSER_RECON_HOURS", "24") or 24)
        trigger = ("first" if not last
                   else "idle" if not self.eng.worklist()
                   else "refresh" if (time.time() - last) > hrs * 3600 else None)
        if not trigger:
            return
        try:
            caps = R.browser_recon(self.scope, base=self.base, slug=self.scope.name,
                                   ident=ident, log=self.eng.log)
            exp = []
            for it in (caps or []):
                for cls in R.classify_all(it):
                    e = dict(it); e["vuln_class"] = cls; e.setdefault("priority", 55)
                    exp.append(e)
            exp = [e for e in exp if R.is_concrete_target(e.get("url", ""))]
            added = self.eng.add_surface(_deepen(exp)) if exp else 0
            # Store rich browser capture data for featuremap consumption
            self.eng.state.setdefault("browser_capture", [])
            for it in (caps or []):
                if it.get("inputs") or it.get("source") in ("form", "button", "fetch", "xhr"):
                    self.eng.state["browser_capture"].append(it)
            self.eng.state["browser_recon_ts"] = time.time()
            self.eng.save()
            self.eng.log(f"deep-recon: browser capture ({trigger}) -> {added} new authed work unit(s)")
        except Exception as e:  # noqa: BLE001
            self.eng.log(f"deep-recon: browser skipped ({type(e).__name__}: {e})")

    # ---------------- discover (exhaustive function inventory) ----------------
    def discover(self):
        """Run exhaustive discovery before any testing — map ALL functions, endpoints, roles, boundaries."""
        self.eng.set_phase("discover")
        if self.mock:
            self.eng.state["discovery"] = {"discovery_ready": True, "coverage_pct": 100.0,
                                           "validated_endpoints": len(self.eng.state.get("surface") or [])}
            self.eng.save()
            self.eng.log("discover(mock): fixture surface ready")
            return
        total_added = 0
        try:
            import discovery as DISC
            result = DISC.discover(self.scope.name, self.scope, base=self.base, log=self.eng.log,
                                   allow_intrusive=self.allow_intrusive)
            surface_items = DISC.inventory_to_surface(result)
            if surface_items:
                total_added += self.eng.add_surface(_deepen(surface_items))
                self.eng.log(f"discover: queued {total_added} endpoint(s) from HTTP discovery")
            self.eng.state["discovery"] = result.get("coverage", {}).get("_summary", {})
            self.eng.save()
        except Exception as e:
            import traceback
            self.eng.log(f"discover: ERROR — HTTP discovery failed ({type(e).__name__}: {e})")
            self.eng.log(f"discover: traceback: {traceback.format_exc()[-500:]}")
            self.eng.state["discovery"] = {"error": f"{type(e).__name__}: {e}"}
            self.eng.save()
            raise

        # Browser capture — SPA apps expose their real API surface at runtime via JS
        try:
            import browser
            from urllib.parse import urlparse
            for seed in self.scope.seeds[:3]:
                host = seed.rstrip("/")
                if "://" not in host:
                    host = "https://" + host
                caps = browser.capture(host, slug=self.scope.name,
                                       scope_hosts=[urlparse(self.scope.seeds[0]).hostname],
                                       ident="A", scope=self.scope)
                browser_items = []
                for it in (caps or []):
                    url = it.get("url") or ""
                    if not url or not self.scope.in_scope_host(url):
                        continue
                    param_names = [p.get("name", "") for p in (it.get("params") or []) if p.get("name")]
                    browser_items.append({
                        "url": url, "method": it.get("method", "GET"),
                        "vuln_class": "deep", "source": "discovery/browser",
                        "priority": 65 + (10 if it.get("method", "GET") != "GET" else 0),
                        "param": ",".join(param_names[:5]),
                        "params": param_names[:10],
                        "auth_required": it.get("auth_required", bool(it.get("headers", {}).get("authorization")
                                                                       or it.get("headers", {}).get("cookie"))),
                        "confidence": "observed",
                        "body_params": [p.get("name", "") for p in (it.get("body_params") or []) if p.get("name")],
                        "note": it.get("label", "")[:200],
                    })
                if browser_items:
                    added = self.eng.add_surface(_deepen(browser_items))
                    total_added += added
                    self.eng.log(f"discover: browser capture on {host} → {added} new endpoint(s)")
        except Exception as e:
            self.eng.log(f"discover: browser capture unavailable ({type(e).__name__}: {e})")

        # GraphQL introspection — catches full query/mutation surface
        try:
            import recon as R
            gql = R.graphql_recon(self.scope, slug=self.scope.name, log=self.eng.log)
            gql_items = []
            for ep in (gql or []):
                url = ep.get("url") or ""
                if not url:
                    continue
                args = [a.get("name", "") for a in (ep.get("args") or []) if a.get("name")]
                gql_items.append({
                    "url": url, "method": "POST",
                    "vuln_class": "deep", "source": "discovery/graphql",
                    "priority": 70,
                    "param": ep.get("name", ""),
                    "params": args[:10] if args else [ep.get("name", "")],
                    "auth_required": True,
                    "confidence": "observed",
                    "tech": ["graphql"],
                    "tags": [ep.get("type", "query")],
                    "note": f"GraphQL {ep.get('type', 'query')}: {ep.get('name', '')}",
                })
            if gql_items:
                added = self.eng.add_surface(_deepen(gql_items))
                total_added += added
                self.eng.log(f"discover: GraphQL introspection → {added} operation(s)")
        except Exception as e:
            self.eng.log(f"discover: GraphQL introspection unavailable ({type(e).__name__}: {e})")

        # Coverage gate — loud warning if discovery found nothing
        if total_added == 0:
            self.eng.log("discover: ⚠ WARNING — discovered ZERO endpoints! "
                         "Check: (1) are seeds correct? (2) is auth configured? "
                         "(3) does the target require browser capture? "
                         "Hunting on an empty surface will find nothing.")
            _lrn("record_gap", "bypass", f"empty-discovery-{self.scope.name}",
                 f"discovery found 0 endpoints for {self.scope.name} — seeds: {self.scope.seeds[:3]}. "
                 "Target may need auth, browser capture, or different discovery approach.",
                 self.base)
        else:
            self.eng.log(f"discover: TOTAL {total_added} endpoint(s) queued from all discovery methods")
        self.eng.save()

    # ---------------- explore (functional discovery) ----------------
    def explore(self):
        self.eng.set_phase("explore")
        try:
            import explorer as EX
            result = EX.analyze(self.eng.state, scope={"in_scope": self.scope.in_scope})
            self.eng.state["app_model"] = result
            self.eng.state.setdefault("surface", [])
            for ep in result.get("api_surface", []):
                url = ep.get("path") or ep.get("url") or ""
                if not url:
                    continue
                if not url.startswith(("http://", "https://")):
                    continue
                if not self.scope.in_scope_host(url):
                    continue
                method = ep.get("method", "GET")
                if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                    continue
                self.eng.state["surface"].append({
                    "url": url, "method": method,
                    "params": ep.get("params", []), "confidence": "inferred",
                    "source": "explorer/" + ep.get("source", "unknown"),
                })
            self.eng.save()
            self.eng.log(f"explore: {result['stats']}")
        except Exception as e:
            import traceback
            self.eng.log(f"explore: ERROR — functional discovery failed ({type(e).__name__}: {e})")
            self.eng.log(f"explore: traceback: {traceback.format_exc()[-500:]}")
            raise

    # ---------------- rank ----------------
    def rank(self):
        self.eng.set_phase("rank")
        session_host = ""
        from urllib.parse import urlparse
        try:
            import authsession as _AS
            sess = _AS.load(self.scope.name, self.base)
            if _AS.valid(sess):
                session_host = str((sess or {}).get("host") or "").split("/")[0].split(":")[0].lower()
        except Exception:
            session_host = ""
        for s in self.eng.state["surface"]:
            s["priority"] = _endpoint_quality(s)
            if s.get("source") == "novelty":
                s["priority"] += 140
            if session_host and (urlparse(s.get("url") or "").hostname or "") == session_host:
                s["priority"] += 120
        self._dedup_downrank()   # known-issue surface sinks below novel surface (no-op w/o corpus)
        self.eng.save()
        wl = self.eng.worklist()
        self.eng.log(f"rank: {len(wl)} item(s) prioritized; top: "
                     + ", ".join(f"{s['vuln_class']}@{s['url']}" for s in wl[:3]))

    def _dedup_downrank(self):
        """Sink surface that maps onto a KNOWN issue (public disclosure or own past report) below
        novel surface, so hunt budget goes where dups are least likely. No-op without a corpus."""
        try:
            import dedup as D
        except Exception:
            return
        cp = D.Corpus(self.scope.name, base=self.base)
        if not cp.records:
            return
        dup = review = 0
        for s in self.eng.state["surface"]:
            v = cp.check({"vuln_class": s.get("vuln_class", ""), "url": s.get("url", ""),
                          "title": s.get("note", "")})
            s["dedup_verdict"] = v["verdict"]
            if v["verdict"] == "LIKELY_DUP":
                s["priority"] = s.get("priority", 20) - 80
                dup += 1
            elif v["verdict"] == "REVIEW":
                s["priority"] = s.get("priority", 20) - 25
                review += 1
        if dup or review:
            self.eng.log(f"rank: dedup down-ranked {dup} likely-dup + {review} review item(s) "
                         f"(corpus={len(cp.records)}) — novel surface floats to top")

    # ---------------- map (arsenal categorization — the default deliverable) ----------------
    def map(self):
        """Analyze the surface dynamically — per target, show what it does, what
        signals it carries, and a first probe curl. No static vuln-class menu."""
        self.eng.set_phase("map")
        import skill_map as SM
        import testplan as TP
        from collections import OrderedDict
        tech = sorted({t for tg in self.eng.state.get("targets", []) for t in tg.get("tech", [])})
        groups = OrderedDict()
        for s in sorted(self.eng.state["surface"], key=lambda z: -z.get("priority", 0)):
            url = s.get("url") or ""
            if not url:
                continue
            profile = TP.analyze_endpoint(s)
            key = (url, s.get("param", ""))
            g = groups.setdefault(key, {"signals": [], "src": s.get("source", ""),
                                        "priority": profile["priority"],
                                        "method": s.get("method", "GET")})
            for sig in profile["signals"]:
                if sig not in g["signals"]:
                    g["signals"].append(sig)
        learned_now = 0
        for t in ([] if self.mock else tech):
            tl = (t or "").lower()
            if not tl or tl in INFRA_TECH or SM.tech_skills([tl]):
                continue
            if learned_now >= 5:                     # bound per-run latency
                _lrn("record_gap", "tech", tl, f"{self.scope.name}: detected {tl}, no skill (deferred)", self.base)
                continue
            r = _lrn("autolearn", "tech", t, context=f"{self.scope.name}: detected {t}, no existing skill",
                     base=self.base)
            if isinstance(r, dict) and r.get("registered"):
                learned_now += 1
                self.eng.log(f"learn: no skill for '{t}' -> drafted {os.path.basename(os.path.dirname(r['path']))} "
                             f"(self-authored, review before relying on it)")
        lines = [f"# Attack surface — {self.scope.name}", "",
                 f"**Service / tech:** {', '.join(tech) or '?'}  ",
                 f"**Endpoints:** {len(groups)} target(s). Dynamic analysis — hunt agent reasons per-endpoint.",
                 "", "> Baseline observations come first; vulnerability references are selected only after "
                 "a concrete, case-linked hypothesis. No static vuln matching.", ""]
        self.eng.log(f"map: SURFACE — tech: {', '.join(tech) or 'none'} | {len(groups)} endpoint(s):")
        for (url, param), g in groups.items():
            label = param if param else "(endpoint)"
            sigs = ", ".join(g["signals"]) if g["signals"] else "general"
            self.eng.log(f"map:   {g['priority']:8s} {g['method']:6s} {url[:50]:50s}  [{sigs}]")
            lines.append(f"## `{label}`  —  {g['method']}  [{g['priority']}]")
            lines.append(f"- **URL:** `{url}`" + (f"  ·  source: {g['src']}" if g["src"] else ""))
            lines.append(f"- **Signals:** {sigs}")
            lines.append(f"- **Probe:** `{SM.probe_for('deep', url, param)}`")
            lines.append("")
        path = os.path.join(self.eng.dir, "arsenal.md")
        with open(path, "w") as _f:
            _f.write("\n".join(lines))
        self.eng.log(f"map: wrote arsenal map -> {path}  ← focus your 20% here (or run --hunt to auto-test)")

    # ---------------- parallel runner ----------------
    def _run_parallel(self, fn, items):
        """Run fn(item) across self.parallel workers; yield (item, result) as each finishes.
        Workers do only the slow agent call (NO state mutation); the caller serializes all
        state writes, so there's no race on state.json."""
        if self.parallel <= 1 or len(items) <= 1:
            for it in items:
                yield it, fn(it)
            return
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=self.parallel) as ex:
            futs = {ex.submit(fn, it): it for it in items}
            for fut in as_completed(futs):
                it = futs[fut]
                try:
                    yield it, fut.result()
                except Exception as e:
                    self.eng.log(f"  worker error on {it.get('url')}: {e}")
                    yield it, {}

    def _burp_preamble(self, engine_dir):
        try:
            from burp import agent_burp_preamble
            text = agent_burp_preamble()
            if text:
                return text
        except Exception:
            pass
        return ""

    def _session_preamble(self):
        """Build the session-static preamble once. Cached on self._preamble for reuse across endpoints."""
        if hasattr(self, "_preamble") and self._preamble:
            return self._preamble
        e = ENGINE_DIR
        p = self.scope.name
        parts = [self._roe()]
        parts.append(
            "HUNT METHOD — fully dynamic, no vuln catalog:\n"
            "1. FETCH the endpoint as the session. Read every byte: status, headers, body, "
            "object IDs, roles, links, error shapes, auth tokens, timing.\n"
            "2. UNDERSTAND what the endpoint does — what resource, what action, what auth model, "
            "what boundaries exist between users/orgs/roles.\n"
            "3. HYPOTHESIZE what could go wrong based on what you SEE, not a checklist. "
            "Ask: what would the developer NOT want another user to do here? What assumption "
            "does this response rely on? What happens if I change the identity, the object, "
            "the method, the content-type, the timing, the sequence?\n"
            "4. TEST your hypothesis. One precise request that either proves or disproves it.\n"
            "5. If negative, form a DIFFERENT hypothesis from what you learned and test again.\n"
            "6. Prove impact with in-scope actions only. No theoretical claims.\n")
        parts.append(
            "AUTHZ GATE (hard): when identities A and B are both live, do NOT return vulnerable:false "
            "until you have executed both: "
            f"`python3 {e}/authz.py diff --slug {p} --url \"<URL>\"` and "
            f"`python3 {e}/netget.py GET \"<URL>\" --as B`. "
            "analysis must contain `authz:` plus both HTTP statuses and whether B saw A's marker.\n")
        parts.append(
            "PROOF STANDARD: claim a vulnerability only with demonstrated, exploitable impact—not reflection, "
            "an error, or a permissive header. For actor/resource boundaries, require a positive owner control, "
            "an accessor control, and an owner-specific marker or state effect; similar responses are only leads. "
            "Do not nominate behavior without attacker-relevant impact. HOLD_RTFS/HOLD_INFORMATIVE still apply.\n")
        parts.append(
            f"OOB TESTING: `python3 {e}/oob.py payload --tag <tag>` → inject → "
            f"`python3 {e}/oob.py poll --tag <tag> --timeout 30`.\n")
        parts.append(self._burp_preamble(e))
        parts.append(self._capabilities_note())
        parts.append(
            "OUTPUT: End with a fenced ```json``` object: "
            '{"vulnerable":true|false,"vuln_class":"<class>","severity":"low|medium|high|critical",'
            '"analysis":"<observed action, resources, actors, and effects>","dimensions_considered":["<dimension>"],'
            '"baseline_observation_ids":["<observation id>"],"skill_references":["<selected after hypothesis>"],'
            '"hypotheses":["<next tests>"],"signals_missed":["<seen not proved>"],'
            '"hypothesis_results":[{"hypothesis":"<tested assumption>","dimension":"<trust dimension>",'
            '"status":"tested|confirmed|disproved|inconclusive|blocked","observation_ids":["<observation id>"],'
            '"evidence":"<result or blocked reason>"}],'
            '"evidence":"<proof>","request":"<winning request>","response":"<winning response>",'
            '"owner_marker":"<A-owned unique value for authz proof>","control_url":"<negative control URL>",'
            '"hosts_contacted":["<hosts>"],"attacker_holds":"nothing|own_session|'
            'link_issued_by_product|foreign_id_shown","id_source":"not_required|enumerated|product_link|'
            'archive|in_scope_oracle|own_only|asserted_leak",'
            '"discovered":["<new endpoints/params/secrets>"],'
            '"proof_note":"<empty or why limited>"}')
        self._preamble = "\n".join(p for p in parts if p)
        return self._preamble

    # ---------------- plan ----------------
    def plan(self):
        """Generate security test plan from feature map and state."""
        self.eng.set_phase("plan")
        import testplan as TP
        fmap_path = os.path.join(self.eng.dir, "feature-map.json")
        fmap = {}
        if os.path.isfile(fmap_path):
            try:
                fmap = json.load(open(fmap_path))
            except (json.JSONDecodeError, OSError):
                pass
        if not fmap.get("endpoints"):
            import featuremap as FM
            fmap = FM.build_feature_map(self.scope.name, eng_dir=self.eng.dir, state=self.eng.state)
        result = TP.build_test_plan(fmap, state=self.eng.state,
                                    scope={"in_scope": self.scope.in_scope,
                                           "out_of_scope": self.scope.out_of_scope})
        existing_plan = self.eng.state.get("test_plan") or []
        if existing_plan:
            existing_statuses = {}
            for c in existing_plan:
                if isinstance(c, dict) and c.get("status") not in ("pending", None):
                    sk = TP.case_id(c)
                    existing_statuses[sk] = {"status": c["status"], "evidence": c.get("evidence")}
            for c in result["plan"]:
                sk = TP.case_id(c)
                if sk in existing_statuses:
                    c["status"] = existing_statuses[sk]["status"]
                    if existing_statuses[sk].get("evidence"):
                        c["evidence"] = existing_statuses[sk]["evidence"]
        self.eng.state["test_plan"] = result["plan"]
        self.eng.state["test_plan_summary"] = result["summary"]
        plan_path = os.path.join(self.eng.dir, "test-plan.md")
        with open(plan_path, "w") as f:
            f.write(result["markdown"])
        self.eng.log(f"test plan: {result['summary']['total_cases']} cases "
                     f"({result['summary']['pending']} pending, "
                     f"{result['summary']['coverage_pct']}% covered)")
        # --- auth bootstrap: analyze what accounts are needed BEFORE hunting ---
        try:
            import authbootstrap as AB
            auth_plan = AB.analyze_auth_needs(self.eng.state.get("surface", []))
            if auth_plan["auth_walled_endpoints"] > 0:
                plan_path = os.path.join(self.eng.dir, "auth-plan.md")
                with open(plan_path, "w") as f:
                    f.write(AB.format_plan(auth_plan))
                self.eng.log(f"auth: {auth_plan['auth_walled_endpoints']}/{auth_plan['total_endpoints']} "
                             f"endpoints need auth ({auth_plan['auth_coverage_pct']}%) — "
                             f"{len(auth_plan['accounts_needed'])} accounts needed — "
                             f"plan at {plan_path}")
                if auth_plan["auth_coverage_pct"] > 50:
                    self.eng.log(f"auth: CRITICAL — {auth_plan['auth_coverage_pct']}% of surface needs auth. "
                                 "Hunt phase will BLOCK unless a session is provisioned. "
                                 "Run: python3 engine/engine/authsession.py provision --program "
                                 f"{self.scope.name}")
        except Exception as exc:
            self.eng.log(f"auth: bootstrap analysis failed ({exc})")
        self.eng.save()

    # ---------------- hunt ----------------
    def hunt(self):
        self.eng.set_phase("hunt")
        # --- GATE: coverage check — refuse to hunt on empty or thin surface ---
        surface = self.eng.state.get("surface") or []
        disc = self.eng.state.get("discovery") or {}
        if not surface:
            self.eng.log("hunt: BLOCKED — surface is empty. Run discovery first.")
            self.eng.state["hunt_blocked"] = "empty_surface"
            self.eng.save()
            return
        ready = disc.get("discovery_ready",
                         disc.get("validated_endpoints", disc.get("total_endpoints", 0)) > 0)
        failed_required = disc.get("failed_required_methods") or []
        if (not ready or failed_required) and not os.environ.get("HUNT_SKIP_COVERAGE_GATE"):
            reason = ("required discovery methods failed: " + ", ".join(failed_required) if failed_required
                      else "no validated endpoints; guessed paths are leads only")
            self.eng.log(f"hunt: BLOCKED — discovery not ready ({reason}).")
            self.eng.state["hunt_blocked"] = "coverage_gate"
            self.eng.save()
            return
        if disc.get("uncovered_categories"):
            self.eng.log(f"hunt: discovery PARTIAL — {len(disc['uncovered_categories'])} categories remain "
                         "missing/unknown; they are not counted as covered")
        # --- GATE: auth check — refuse to hunt when majority needs auth and no session exists ---
        auth_walled = sum(1 for s in surface if s.get("auth_required"))
        auth_pct = (auth_walled / len(surface) * 100) if surface else 0
        if auth_pct > 50 and not os.environ.get("HUNT_SKIP_AUTH_GATE"):
            _AS = _authmod()
            has_session = False
            if _AS:
                sess = _AS.load(self.scope.name, self.base)
                has_session = bool(sess and _AS.valid(sess))
            if not has_session:
                self.eng.log(f"hunt: BLOCKED — {auth_walled}/{len(surface)} endpoints ({auth_pct:.0f}%) "
                             "need auth but no session exists. Provision accounts first "
                             "(set HUNT_SKIP_AUTH_GATE=1 to override).")
                self.eng.state["hunt_blocked"] = "auth_gate"
                self.eng.save()
                return
        self._honor_heals()
        self.eng.state.pop("hunt_blocked", None)
        # start OOB callback server for blind vuln testing (best-effort)
        self._oob = None
        try:
            from oob import OOBServer
            existing = OOBServer.load()
            if existing:
                self._oob = existing
                self.eng.log(f"hunt: OOB server reused — {existing.domain}")
            else:
                self._oob = OOBServer.start()
                self.eng.log(f"hunt: OOB server started — {self._oob.domain}")
        except Exception as exc:  # noqa: BLE001
            self.eng.log(f"hunt: OOB server unavailable ({exc}), blind testing degraded")
        # load an authenticated session (if HUNT_AUTH=1 + one was provisioned) to reach behind-login surface
        self._auth_session = None
        self._auth_dead = False
        self._auth_dead_host = ""
        if os.environ.get("HUNT_AUTH") == "1":
            _AS = _authmod()
            if _AS:
                self._auth_session = _AS.load(self.scope.name, self.base)
                if _AS.valid(self._auth_session) and _AS.site_rejects(
                        self._auth_session, program=self.scope.name, base=self.base):
                    rel = {}
                    try:
                        rel = _AS.relogin(self.scope.name, ident="A", base=self.base)
                    except Exception:  # noqa: BLE001
                        rel = {}
                    if rel.get("ok"):
                        self._auth_session = _AS.load(self.scope.name, self.base)
                        self._auth_dead = False
                        self.eng.log(f"hunt: auto-relogin — AUTHENTICATED on {self._auth_session.get('host')} "
                                     f"(user {self._auth_session.get('user')})")
                        try:
                            _AS.relogin(self.scope.name, ident="B", base=self.base)
                        except Exception:  # noqa: BLE001
                            pass
                    else:
                        self.eng.log("hunt: session file was rejected by the site (logged out) — "
                                     "not using it, and not marking auth-walled URLs tested")
                        self._auth_dead = True
                        self._auth_dead_host = str((self._auth_session or {}).get("host") or "")
                        self._auth_session = None
                elif _AS.valid(self._auth_session):
                    self._auth_dead = False
                    self.eng.log(f"hunt: AUTHENTICATED — using test session on {self._auth_session.get('host')} "
                                 f"(user {self._auth_session.get('user')})")
                else:
                    rel = {}
                    try:
                        rel = _AS.relogin(self.scope.name, ident="A", base=self.base)
                    except Exception:  # noqa: BLE001
                        rel = {}
                    if rel.get("ok"):
                        self._auth_session = _AS.load(self.scope.name, self.base)
                        self._auth_dead = False
                        self.eng.log(f"hunt: auto-relogin — AUTHENTICATED on {self._auth_session.get('host')} "
                                     f"(user {self._auth_session.get('user')})")
                        try:
                            _AS.relogin(self.scope.name, ident="B", base=self.base)
                        except Exception:  # noqa: BLE001
                            pass
                    else:
                        self._auth_dead_host = str((self._auth_session or {}).get("host") or "")
                        self._auth_dead = bool(self._auth_dead_host)
                        self._auth_session = None
                        self.eng.log("hunt: HUNT_AUTH=1 but no valid session yet — hunting unauthenticated this round"
                                     + (f"; holding {self._auth_dead_host} until a live paste" if self._auth_dead_host else ""))
        collapsed = self.eng.collapse_patterns()
        if collapsed:
            self.eng.log(f"hunt: {collapsed} duplicate object-id URL(s) collapsed to one pattern each")
        self._honor_review_skips()
        # --- test-plan-driven hunting: expand each pending plan case into its own worklist item ---
        import testplan as TP
        plan_cases = self.eng.state.get("test_plan") or []
        pending = TP.pending_cases(plan_cases) if plan_cases else []
        _plan_index = {}  # state_key -> case, for post-hunt status update
        if pending:
            prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            pending.sort(key=lambda c: prio_order.get(c.get("priority", "low"), 3))
            plan_items = []
            plan_keys = set()
            for c in pending:
                sk = TP.case_id(c)
                _plan_index[sk] = c
                params = c.get("params") or []
                item = {
                    "url": c.get("endpoint", ""),
                    "method": c.get("method", "GET"),
                    "param": params[0] if params else "",
                    "params": params,
                    "role": c.get("role", ""),
                    "owner": c.get("owner", ""),
                    "accessor": c.get("accessor", ""),
                    "vuln_class": c.get("category", "deep"),
                    "function_profile": c.get("function_profile") or {},
                    "trust_dimensions": c.get("trust_dimensions") or [],
                    "source": "test-plan",
                    "priority": prio_order.get(c.get("priority", "low"), 3),
                    "_plan_key": sk,
                }
                if sk not in plan_keys and item["url"]:
                    plan_keys.add(sk)
                    plan_items.append(item)
            raw_wl = self.eng.worklist()
            plan_operations = {(it.get("method", "GET"), it.get("url", "")) for it in plan_items}
            other_items = (list(raw_wl) if self.mock or os.environ.get("HUNT_DEEP", "1") != "1"
                           else [it for it in raw_wl
                                 if (it.get("method", "GET"), it.get("url", "")) not in plan_operations])
            wl = (plan_items + other_items)[: self.max_hunts]
            self.eng.log(f"hunt: {len(plan_items)} cases from test plan, {len(other_items)} extra from worklist")
        else:
            wl = self.eng.worklist()[: self.max_hunts]
        self._plan_index = _plan_index
        todo = []
        skipped_static = 0
        for it in wl:
            if "{" in (it.get("url") or ""):
                self.eng.log(f"hunt: skipping template url {it['url']}")
                self.eng.mark_skipped(it, "unresolved_template")
            elif _skip_static_url(it.get("url") or ""):
                self.eng.mark_skipped(it, "static_or_cdn")
                skipped_static += 1
            elif not self.scope.in_scope_host(it["url"]):     # belt-and-suspenders scope gate
                self.eng.log(f"hunt: REFUSING out-of-scope {it['url']} ({self.scope.reject_reason(it['url'])})")
                self.eng.mark_skipped(it, "out_of_scope")
            elif self._auth_dead:
                from urllib.parse import urlparse as _up
                dead = (self._auth_dead_host or "").split("/")[0].split(":")[0].lower()
                host = (_up(it.get("url") or "").hostname or "").lower()
                if dead and host == dead:
                    self.eng.log(f"hunt: holding {it['url']} until a live session is pasted")
                    continue
                todo.append(it)
            else:
                todo.append(it)
        if skipped_static:
            self.eng.log(f"hunt: skipped {skipped_static} static/CDN url(s) — the round stays on APIs")
        # --- scheduler integration: recover crashed work, filter already-completed ---
        _sched = self.scheduler
        if _sched:
            expired = _sched.recover_expired()
            if expired:
                self.eng.log(f"hunt: scheduler recovered {len(expired)} expired lease(s)")
            _pre = len(todo)
            _filtered = []
            for it in todo:
                case_id = self.eng._key(it)
                cs = _sched.status(case_id)
                if cs and cs.get("status") == "completed":
                    continue
                if cs and cs.get("status") == "failed":
                    attempt = cs.get("attempt", 0)
                    max_r = cs.get("max_retries", 3)
                    if attempt >= max_r:
                        self.eng.mark_skipped(it, "scheduler_retries_exhausted")
                        continue
                    if not cs.get("idempotent", True):
                        continue
                _filtered.append(it)
            if _pre != len(_filtered):
                self.eng.log(f"hunt: scheduler filtered {_pre - len(_filtered)} already-completed/exhausted item(s)")
            todo = _filtered
        self.eng.log(f"hunt: testing {len(todo)} item(s), {self.parallel} at a time")
        self.eng.record_hunt_start()
        self._round_learnings = []
        for it, f in self._run_parallel(self._scheduled_hunt, todo):
            # Circuit breaker — stop dispatching if runtime is unhealthy
            if not self._health.is_healthy():
                self.eng.state["hunt_blocked"] = "circuit_breaker"
                self.eng.log("hunt: circuit breaker tripped — too many consecutive failures, stopping")
                break
            # Budget gate — stop if model call/token budget exhausted
            _budget_reason = MR.budget_exceeded()
            if _budget_reason:
                self.eng.state["hunt_blocked"] = "budget_exceeded"
                self.eng.log(f"hunt: {_budget_reason} — stopping")
                break
            # Record health outcome from this dispatch
            if f and f.get("error") == "timeout":
                self._health.record("timeout")
            elif f and f.get("error") and ("429" in str(f["error"]) or "rate" in str(f["error"]).lower()):
                self._health.record("rate_limit")
            elif f and f.get("error"):
                self._health.record("error")
            else:
                self._health.record("success")
            if f and f.get("error") == "timeout":
                if not self._timeout_retry_allowed(it):
                    self.eng.mark_skipped(it, "uncertain_non_idempotent_timeout")
                    self.eng.log(f"hunt: INCONCLUSIVE non-idempotent timeout on {it['url']} — NOT replaying")
                    continue
                alt = self._alt_model(f.get("model"))
                fbt = int(os.environ.get("HUNT_FAILOVER_TIMEOUT", "900"))
                self.eng.log(f"hunt: timeout on {it.get('vuln_class')}@{it['url']} (model {f.get('model')}) "
                             f"— failover to {alt} ({fbt}s)")
                f = self._scheduled_hunt(it, model=alt, timeout=fbt)
                if f and f.get("error") == "timeout":
                    self.eng.mark_skipped(it, "double_timeout")
                    self.eng.log(f"hunt: INCONCLUSIVE (double-timeout) {it.get('vuln_class')}@{it['url']} "
                                 "— marked skipped, moving on (too heavy for the budget)")
                    _lrn("record_gap", "bypass", f"timeout-{it.get('vuln_class', 'deep')}",
                         f"double-timeout on {it['url']} — endpoint too complex or defended for current approach",
                         self.base)
                    continue
            if f and f.get("error"):
                err = f["error"]
                # rate-limit (429): back off and retry once
                if "429" in str(err) or "rate" in str(err).lower():
                    backoff = int(os.environ.get("HUNT_RATE_LIMIT_BACKOFF", "60"))
                    self.eng.log(f"hunt: rate-limited on {it.get('vuln_class')}@{it['url']} "
                                 f"— backing off {backoff}s then retrying")
                    time.sleep(backoff)
                    f = self._scheduled_hunt(it)
                    if f and f.get("error"):
                        self.eng.log(f"hunt: still failing after backoff ({f['error']}) — skipping")
                        continue
                # auth expired (401/403): try session refresh once
                elif ("401" in str(err) or "403" in str(err)) and self._auth_session:
                    self.eng.log(f"hunt: auth error on {it['url']} — attempting session refresh")
                    _AS = _authmod()
                    if _AS:
                        try:
                            rel = _AS.relogin(self.scope.name, ident="A", base=self.base)
                            if rel.get("ok"):
                                self._auth_session = _AS.load(self.scope.name, self.base)
                                self.eng.log("hunt: session refreshed, retrying")
                                f = self._scheduled_hunt(it)
                                if f and not f.get("error"):
                                    pass  # fall through to normal processing
                                else:
                                    self.eng.log(f"hunt: retry after refresh failed — skipping")
                                    continue
                            else:
                                self.eng.log("hunt: session refresh failed — skipping endpoint")
                                continue
                        except Exception:
                            self.eng.log("hunt: session refresh exception — skipping endpoint")
                            continue
                    else:
                        continue
                else:
                    self.eng.log(f"hunt: error on {it.get('vuln_class')}@{it['url']} ({err}) "
                                 f"— not marking tested, will retry next round")
                    retry_key = self.eng._key(it)
                    retries = self.eng.state.setdefault("_retry_counts", {})
                    retries[retry_key] = retries.get(retry_key, 0) + 1
                    if retries[retry_key] >= 3:
                        self.eng.mark_skipped(it, f"max_retries_exceeded: {err}")
                        self.eng.log(f"hunt: max retries (3) reached for {it['url']} — marking skipped")
                        _lrn("record_gap", "bypass", f"retry-fail-{it.get('vuln_class', 'deep')}",
                             f"3x failure on {it['url']}: {err} — need different approach",
                             self.base)
                    self.eng.save()
                    continue
            # --- classify result BEFORE marking tested ---
            self._feedback_surface(f)                 # endpoints the agent found mid-hunt -> back into the worklist
            if f and f.get("rate_limited"):
                self.eng.log("hunt: ⚠ model usage limit hit — remaining results may be partial")
            _plan_status = None  # determined by result quality, applied after
            if f and f.get("vulnerable"):
                oos = self._scope_audit(f)
                cand = {"url": it["url"], "param": it.get("param", ""),
                        "params": list(it.get("params") or []),
                        "method": it.get("method", "GET"), "body": it.get("body"),
                        "role": it.get("role", ""), "owner": it.get("owner", ""),
                        "accessor": it.get("accessor", ""), "case_id": self.eng._key(it),
                        "vuln_class": f.get("vuln_class") or it.get("vuln_class"),
                        "severity": f.get("severity", "unknown"), "evidence": f.get("evidence", ""),
                        "response": f.get("response", ""),
                        "owner_marker": f.get("owner_marker") or it.get("owner_marker", ""),
                        "control_url": f.get("control_url") or it.get("control_url", ""),
                        "request": f.get("request", ""), "proof_note": f.get("proof_note", ""),
                        "attacker_holds": f.get("attacker_holds", ""),
                        "id_source": f.get("id_source", ""),
                        "trust_dimensions": list(it.get("trust_dimensions") or
                                                   (it.get("function_profile") or {}).get("trust_dimensions") or
                                                   TP.analyze_endpoint(it)["function_profile"]["trust_dimensions"]),
                        "disposition": f.get("disposition") or {},
                        "scope_warning": oos or None}
                import disposition as _D
                if _D.own_session_oauth(cand):
                    self.eng.mark_rejected(cand, "own-session oauth")
                    self.eng.log(f"hunt: dropped own-session oauth @ {it['url']} — "
                                 "the token belongs to the account that registered the client")
                else:
                    self.eng.add_candidate(cand)
                    self.eng.record_hypothesis(confirmed=True)
                    self._remember(it, cand.get("evidence") or "", [cand.get("vuln_class")],
                                   result="candidate", finding=f)
                    self.eng.log((f"hunt: ⚠ CANDIDATE {cand['vuln_class']} @ {it['url']} — PoC touched OUT-OF-SCOPE "
                                  f"host(s): {', '.join(oos)} (flagged)") if oos
                                 else f"hunt: CANDIDATE {cand['vuln_class']} @ {it['url']}")
                # Candidate awaits validate phase — mark tested ONLY with transport-verified evidence
                if f.get("request"):
                    ev_valid = self._record_evidence_attempt(it, outcome="CONFIRMED")
                    if ev_valid or self.mock:
                        self.eng.mark_tested(it)
                        self.eng.record_endpoint_tested()
                        _plan_status = ("tested", f.get("evidence") or f.get("proof_note") or "candidate — awaiting validation")
                    else:
                        self.eng.log(f"hunt: candidate at {it['url']} has request text but no transport-verified observation — NOT marking tested")
                        _plan_status = ("inconclusive", "candidate found, request text present but no transport evidence")
                else:
                    self.eng.log(f"hunt: candidate at {it['url']} lacks request evidence — not marking tested")
                    _plan_status = ("blocked", "candidate found but no execution evidence recorded")
            elif f and f.get("skipped"):
                self.eng.log(f"hunt: skipped {it.get('vuln_class')}@{it['url']} — {f['skipped']}")
                _plan_status = ("blocked", f.get("skipped") or "skipped by hunt agent")
            else:
                analysis = ""
                classes = []
                if isinstance(f, dict):
                    analysis = f.get("analysis") or ""
                    classes = f.get("hypothesis_results") or f.get("dimensions_considered") or []
                if isinstance(f, dict) and f.get("_inconclusive"):
                    self.eng.log(f"hunt: inconclusive result for {it.get('vuln_class')}@{it['url']} — "
                                 "no structured output, will retry")
                    self.eng.note_hunt(it, "inconclusive — no structured agent output", [])
                    _plan_status = ("inconclusive", "agent returned no structured output")
                    continue
                if _logged_out_result(analysis):
                    self.eng.note_hunt(it, analysis, classes)
                    self._remember(it, analysis, classes, result="auth_wall", finding=f)
                    self.eng.log(f"hunt: auth wall on {it.get('vuln_class')}@{it['url']} — left untested "
                                 "so a live session can retry")
                    continue
                # Deep + two live accounts: hunt:nothing is refused until authz.py diff and
                # netget --as B have actually run. The log line is the proof authz_logged reads.
                if ((it.get("vuln_class") or "").lower() == "deep"
                        and self._needs_authz_gate(it.get("url"), it)):
                    line = self._authz_closeout(
                        it.get("url"), method=it.get("method", "GET"),
                        body=it.get("body"), owner=it.get("owner", "A"),
                        accessor=it.get("accessor", "B"))
                    if not line:
                        self.eng.log(f"hunt: refused nothing on {it.get('vuln_class')}@{it['url']} "
                                     "— authz.py diff and netget --as B were not run")
                        continue
                    analysis = (str(analysis) + "\n" + line).strip()
                has_execution_evidence = bool(
                    isinstance(f, dict) and f.get("request")
                )
                self.eng.record_hypothesis(confirmed=False)
                if analysis and has_execution_evidence:
                    ev_valid = self._record_evidence_attempt(it, outcome="TESTED")
                    if ev_valid or self.mock:
                        self.eng.mark_tested(it)
                        self.eng.record_endpoint_tested()
                        _plan_status = ("tested", analysis[:300])
                    else:
                        self.eng.log(f"hunt: {it.get('vuln_class')}@{it['url']} has request text but no transport evidence — NOT marking tested")
                        _plan_status = ("inconclusive", "agent ran but no transport-verified observation recorded")
                else:
                    self.eng.log(f"hunt: insufficient execution evidence for {it.get('vuln_class')}@{it['url']} — left untested")
                self.eng.note_hunt(it, analysis, classes)
                self._remember(it, analysis, classes, result="nothing", finding=f)
                tail = f" — {str(analysis)[:160]}" if analysis else ""
                self.eng.log(f"hunt: nothing on {it.get('vuln_class')}@{it['url']}{tail}")
            # --- accumulate round learnings for cross-endpoint context ---
            _learning = {"url": it["url"], "method": it.get("method", "GET")}
            if f and f.get("vulnerable"):
                _learning["result"] = "vulnerable"
                _learning["vuln_class"] = f.get("vuln_class", "")
                _learning["note"] = (f.get("evidence") or f.get("proof_note") or "")[:200]
            elif isinstance(f, dict) and f.get("analysis"):
                _learning["result"] = "nothing"
                _learning["note"] = str(f["analysis"])[:200]
            if _learning.get("note"):
                self._round_learnings.append(_learning)
            if _sched and f and not f.get("error") and not f.get("skipped"):
                self._finalize_scheduled(
                    it,
                    self.mock or bool(_plan_status and _plan_status[0] in ("tested", "confirmed")),
                    (_plan_status[1] if _plan_status else "no execution evidence"),
                )
            # --- update test plan case status ---
            if _plan_status and self._plan_index:
                _sk = it.get("_plan_key") or TP.case_id({
                    "endpoint": it.get("url", ""), "method": it.get("method", "GET"),
                    "params": it.get("params") or ([it["param"]] if it.get("param") else []),
                    "category": it.get("vuln_class", ""), "role": it.get("role", ""),
                    "owner": it.get("owner", ""), "accessor": it.get("accessor", "")})
                _pc = self._plan_index.get(_sk)
                if _pc:
                    if isinstance(f, dict):
                        TP.apply_hypothesis_results(
                            _pc, f.get("hypothesis_results") or [],
                            evidence_dir=self.eng.evidence_path(""), case_key=self.eng._key(it))
                        _pc.setdefault("hypothesis_ledger", []).append({
                            "status": _plan_status[0], "evidence": _plan_status[1],
                            "dimensions_considered": list(f.get("dimensions_considered") or []),
                            "hypotheses": list(f.get("hypotheses") or []),
                            "signals_missed": list(f.get("signals_missed") or []),
                            "baseline_observation_ids": list(f.get("baseline_observation_ids") or []),
                            "skill_references": list(f.get("skill_references") or []),
                            "case_id": self.eng._key(it), "ts": time.time(),
                        })
                    try:
                        TP.mark_case(_pc, _plan_status[0], evidence=_plan_status[1])
                    except (ValueError, TypeError):
                        pass
        # --- persist updated test plan statuses ---
        if plan_cases and self._plan_index:
            cov = TP.plan_coverage(plan_cases)
            self.eng.state["test_plan"] = plan_cases
            self.eng.log(f"hunt: test plan updated — {cov.get('executed',0)}/{cov.get('total',0)} executed, "
                         f"{cov.get('confirmed',0)} confirmed, {cov.get('disproved',0)} disproved")
        # --- record hunt metrics ---
        self.eng.record_hunt_end()
        m = self.eng.metrics()
        self.eng.log(f"hunt: METRICS — {m['endpoints_tested']} endpoints tested, "
                     f"{m['hypotheses_formed']} hypotheses ({m['hypotheses_confirmed']} confirmed), "
                     f"{m['findings_verified']} verified, {m['time_on_target_sec']}s on target")
        if _sched:
            sm = _sched.metrics()
            retryable = _sched.retryable()
            self.eng.log(f"hunt: SCHEDULER — {sm['total']} claims: {sm['by_status']}, "
                         f"{len(retryable)} retryable")
        self.eng.save()

    def _related_endpoints(self, url, method, max_results=6):
        """Find sibling endpoints from the surface — same resource path or related operations."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.strip("/").split("/") if p]
        if not path_parts:
            return []
        base_resource = "/".join(path_parts[:-1]) if len(path_parts) > 1 else path_parts[0]
        siblings = []
        for s in self.eng.state.get("surface", []):
            s_url = s.get("url", "")
            if s_url == url and s.get("method", "GET") == method:
                continue
            s_parsed = urlparse(s_url)
            if s_parsed.hostname != parsed.hostname:
                continue
            s_path = s_parsed.path.strip("/")
            if base_resource and base_resource in s_path:
                siblings.append(s)
        siblings.sort(key=lambda s: s.get("method", "GET") != method)
        return siblings[:max_results]

    def _round_context_block(self, url):
        """Build a context block from learnings accumulated during this round."""
        learnings = getattr(self, "_round_learnings", [])
        if not learnings:
            return ""
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        relevant = [l for l in learnings if host in l.get("url", "")][-5:]
        if not relevant:
            return ""
        lines = ["ROUND CONTEXT — what other endpoints on this host revealed so far:"]
        for l in relevant:
            status = "VULNERABLE" if l.get("result") == "vulnerable" else "tested-clean"
            note = l.get("note", "")
            lines.append(f"  {l.get('method','?')} {l['url'][:80]} → {status}"
                         + (f": {note[:120]}" if note else ""))
        lines.append("Use this to avoid redundant work and to spot patterns across endpoints.\n")
        return "\n".join(lines) + "\n"

    def _hunt_deep(self, it, model=None, timeout=None):
        """Analyze one observed function and test target-specific trust hypotheses with bounded evidence."""
        import agent as A
        import testplan as TP
        it = dict(it)
        it["params"] = TP._params(it)
        it["body_params"] = TP._params({"params": it.get("body_params")})
        # Set case context so transport-level observations are tagged with this case
        case_key = self.eng._key(it)
        edir = self.eng.evidence_path("")
        try:
            import netget as _ng
            _ng.set_current_case(case_key)
        except Exception:
            pass
        # Per-task env for subprocess agents — never mutate os.environ (concurrent race)
        # Include scope slug so netget.py subprocess can load the egress policy
        _task_env = {
            "HUNT_EVIDENCE_DIR": edir,
            "HUNT_CASE_ID": case_key,
            "HUNT_TARGET_SLUG": self.scope.name,
        }
        url = it["url"]
        tech = sorted({t for tg in self.eng.state.get("targets", []) for t in tg.get("tech", [])})
        p, e = self.scope.name, ENGINE_DIR
        lead = self._authz_lead(url)
        try:
            import brain as BR
            memory = BR.prompt_block(p, url, self.base)
        except Exception:  # noqa: BLE001
            memory = ""
        import testplan as TP
        endpoint_profile = TP.analyze_endpoint(it)
        skill_hint = ("Fetch a baseline first and retain its observation IDs. Form a concrete hypothesis from those "
                      "bytes, then call `skill_map.for_hypothesis(hypothesis, function_profile, "
                      "evidence_dir=os.environ['HUNT_EVIDENCE_DIR'], case_id=os.environ['HUNT_CASE_ID'], "
                      "observation_ids=[...])`. Without matching live observations only methodology is returned. "
                      "Skills are optional references, never a worklist or coverage target. Return one "
                      "hypothesis_results entry per tested dimension; unreported dimensions remain untested.")
        knowledge_block = ("\nOBSERVED FUNCTION PROFILE (target-specific, not a vulnerability catalog):\n"
                           + json.dumps(endpoint_profile.get("function_profile") or {}, default=str)[:5000] + "\n")
        # Rich endpoint metadata from discovery
        meta_parts = []
        if it.get("auth_required"):
            meta_parts.append("auth: REQUIRED")
        if it.get("confidence"):
            meta_parts.append(f"confidence: {it['confidence']}")
        if it.get("body_params"):
            meta_parts.append(f"body_params: {', '.join(it['body_params'][:10])}")
        if it.get("tags"):
            meta_parts.append(f"tags: {', '.join(it['tags'][:6])}")
        metadata_line = f"  {' | '.join(meta_parts)}\n" if meta_parts else ""
        # Planned identities from test plan (owner/accessor/role)
        identity_block = ""
        if it.get("owner") or it.get("accessor") or it.get("role"):
            id_parts = []
            if it.get("owner"):
                id_parts.append(f"OWNER identity: {it['owner']} (create/own the resource with `--as {it['owner']}`)")
            if it.get("accessor"):
                id_parts.append(f"ACCESSOR identity: {it['accessor']} (attempt unauthorized access with `--as {it['accessor']}`)")
            if it.get("role"):
                id_parts.append(f"TEST ROLE: {it['role']}")
            identity_block = "PLANNED IDENTITIES:\n  " + "\n  ".join(id_parts) + "\n"
        # Available identities and tools for boundary testing — the AI decides the approach
        test_spec = ""
        if it.get("owner") and it.get("accessor"):
            _m = it.get("method", "GET")
            test_spec = (
                f"AVAILABLE IDENTITIES for boundary testing:\n"
                f"  Owner: {it['owner']}  Accessor: {it['accessor']}  Method: {_m}\n"
                f"  Tool: `python3 {ENGINE_DIR}/netget.py {_m} \"<url>\" --as <ident> --slug $SLUG`\n"
                f"  Compare response bodies, not just status codes, to demonstrate actual impact.\n")
            if it.get("body"):
                import json as _json
                test_spec += f"  Body: '{_json.dumps(it['body'])[:200]}'\n"
            test_spec += "\n"
        # Related endpoints — sibling operations on the same resource
        siblings = self._related_endpoints(url, it.get("method", "GET"))
        related_block = ""
        if siblings:
            lines = ["RELATED ENDPOINTS on the same resource (test cross-endpoint interactions):"]
            for s in siblings[:5]:
                s_params = ", ".join(s.get("params", [])[:5]) or "none"
                lines.append(f"  {s.get('method','GET')} {s['url'][:80]}  params: {s_params}"
                             + (f"  [auth_required]" if s.get("auth_required") else ""))
            lines.append("Related operations on the same resource — consider interactions if observations suggest them.\n")
            related_block = "\n".join(lines) + "\n"
        # Round context — what previous hunts in this round found
        round_block = self._round_context_block(url)
        task = (self._session_preamble() + "\n"
                f"INVESTIGATE THIS ENDPOINT — form and test hypotheses from observed behavior.\n"
                + lead + memory +
                f"URL: {url}   method: {it.get('method','GET')}   known param(s): {', '.join(it.get('params') or []) or it.get('param','')}   "
                f"tech: {', '.join(tech) or 'unknown'}\n"
                + metadata_line + identity_block + test_spec
                + f"Signals: {', '.join(endpoint_profile.get('signals', [])) or 'general'}   "
                f"Priority: {endpoint_profile.get('priority', 'medium')}\n"
                + knowledge_block + related_block + round_block
                + "Use the session's Cookie/headers on EVERY request. "
                + skill_hint + "\n"
                f"  authed fetch: `python3 {e}/netget.py GET \"<url>\" --as A` (second: `--as B`).  "
                f"No playbook? `python3 {e}/learn.py auto --kind <tech|vuln|bypass|program> --name \"<thing>\" --context \"<why>\"` — drafts a skill for the next hunt.\n")
        task += self._prior_note(it)
        sess = getattr(self, "_auth_session", None)
        if sess:
            _AS = _authmod()
            if _AS:
                task += _AS.auth_block(sess, url)
        # Give the AI real room to THINK + work an endpoint end-to-end (analyse source -> reason -> exploit ->
        # chain): a generous time budget and plenty of turns, both env-tunable. Not capped to the quick per-class
        # budget — a deep pentest legitimately takes many minutes.
        dt = timeout or int(os.environ.get("HUNT_DEEP_TIMEOUT", "600"))
        mt = int(os.environ.get("HUNT_DEEP_TURNS", "40"))
        self.eng.log(f"hunt: deep-pentest {url} (analysis-driven) model={model or 'pool'} budget={dt}s/{mt}turns")
        r = A.run_agent(task, context=self.scope.name, max_turns=mt, timeout=dt, model=model, env_extra=_task_env)
        if r.get("error"):
            return {"error": r["error"], "model": r.get("model")}
        f = A.extract_json(r.get("result", ""))
        if f is None:
            f = {"vulnerable": False, "_inconclusive": True}
        if isinstance(f, dict):
            if f.get("vulnerable") and not (f.get("evidence") and f.get("request")):
                f["_inconclusive"] = True
            if r.get("_parse_fallback"):
                f["_parse_fallback"] = True
                f["_inconclusive"] = True
        f["_model"] = r.get("model")
        return f

    def _capabilities_note(self):
        """Tell the agent about the harness tools it may drive mid-hunt (all guardrail-gated)."""
        try:
            import sms as _SMS
            sms_state = "ENABLED" if _SMS.enabled() else "DISABLED (skip phone-gated signups)"
        except Exception:  # noqa: BLE001
            sms_state = "DISABLED"
        p, e = self.scope.name, ENGINE_DIR
        return (
            "\nHARNESS CAPABILITIES — use these when the finding needs them. Stay IN-SCOPE and read-only, "
            "except account creation which is guardrail-gated. NO bruteforce/cracking (refused by policy).\n"
            f"- Research: `python3 {e}/websearch.py search \"<query>\"`  (read a page: `... fetch <url>`). "
            "Use it to confirm a CVE, a framework's known bugs, or a disclosed report before claiming impact.\n"
            f"- Actor-dependent testing: when observed boundaries require another identity, mint a disposable, "
            f"capped, in-scope-only test identity with a live inbox:\n"
            f"    `python3 {e}/identity.py new  --program {p}`   then read the verify mail: "
            f"`python3 {e}/identity.py poll --program {p} --email <addr>`\n"
            f"  (phone-gated signups: SMS is {sms_state}.)\n"
            f"- No playbook for a stack/vuln/bypass? Teach the harness: "
            f"`python3 {e}/learn.py auto --kind <tech|vuln|bypass|program> --name \"<thing>\" --context \"<why>\"` — reads it after drafting.\n"
            f"- Headless-browser capture (observe runtime calls, forms, and relationships): "
            f"`python3 {e}/browser.py capture --url <seed> --slug {p} [--as A] --scope <in-scope-host>`.\n"
            f"- Authenticated fetch (carries your session, bypasses edge TLS/IP gating): "
            f"`python3 {e}/netget.py GET \"<url>\" --as A` (second actor: `--as B`).\n"
            f"- Actor/resource boundary diff: `python3 {e}/authz.py diff --slug {p} --url \"<owner-observed url>\"` "
            f"-> leads only; confirm with ownership markers and positive/negative controls.\n"
            f"- App-backed program (esp. geo/IP-gated API)? Pull the API surface from the APK: "
            f"`python3 {e}/apkmap.py extract --apk <file>` -> hosts + endpoints + secrets.\n"
            "- All account/login/SMS actions pass engine/guardrails.py (scope + per-program cap) and are audited.\n")

    @staticmethod
    def _timeout_retry_allowed(item):
        return (item.get("method") or "GET").upper() in ("GET", "HEAD", "OPTIONS")

    @staticmethod
    def _alt_model(current):
        """A pool model different from `current` — for timeout failover (a stuck model/endpoint often
        clears on another model)."""
        import agent
        return agent._next_model(current)

    def _scheduled_hunt(self, it, model=None, timeout=None):
        """Claim and execute work; completion is finalized only after evidence validation."""
        _sched = self.scheduler
        if not _sched:
            return self._hunt_agent(it, model, timeout)
        case_id = self.eng._key(it)
        worker_id = f"pid-{os.getpid()}"
        method = it.get("method") or "GET"
        is_read = method.upper() in ("GET", "HEAD", "OPTIONS")
        lease_sec = int(os.environ.get("HUNT_LEASE_SEC", "600"))
        claim = _sched.claim_work(
            case_id, worker_id, lease_sec=lease_sec,
            method=method, url=it.get("url"),
            owner_identity=it.get("owner"), accessor_identity=it.get("accessor"),
            idempotent=is_read)
        if claim is None:
            cs = _sched.status(case_id)
            self.eng.log(f"hunt: scheduler skip {it.get('url','?')[:60]} (status={cs.get('status') if cs else '?'})")
            return {"skipped": "scheduler: already claimed or exhausted"}
        import threading as _th
        _hb_stop = _th.Event()
        hb_interval = max(lease_sec // 3, 10)
        def _heartbeat_loop():
            while not _hb_stop.wait(hb_interval):
                _sched.heartbeat(case_id, worker_id)
        _hb_thread = _th.Thread(target=_heartbeat_loop, daemon=True)
        _hb_thread.start()
        try:
            f = self._hunt_agent(it, model, timeout)
            if f and f.get("error"):
                _sched.fail(case_id, worker_id, error=f["error"])
            elif f and f.get("skipped"):
                _sched.fail(case_id, worker_id, error=f"skipped: {f['skipped']}")
            return f
        except Exception as exc:
            _sched.fail(case_id, worker_id, error=str(exc))
            raise
        finally:
            _hb_stop.set()
            _hb_thread.join(timeout=2)

    def _finalize_scheduled(self, it, evidence_valid, reason=""):
        if not self.scheduler:
            return
        case_id = self.eng._key(it)
        worker_id = f"pid-{os.getpid()}"
        if evidence_valid:
            self.scheduler.complete(case_id, worker_id)
        else:
            self.scheduler.fail(case_id, worker_id, error=reason or "no transport evidence")

    def _hunt_agent(self, it, model=None, timeout=None):
        if self.mock:
            return MOCK_HUNT.get((it["url"], it.get("vuln_class")), {"vulnerable": False})
        try:
            import netget as _ng
            _ng.set_current_case(self.eng._key(it))
        except Exception:
            pass
        # DEAD-SURFACE PRE-PROBE: don't burn a ~2-min LLM hunt on an endpoint whose host is WAF/staging-walled.
        # A staging host that 403s every path wastes the whole budget if we hunt each URL.
        # Probe once with the authed session; a 403 or 5xx means walled/dead -> skip + mark tested (won't requeue).
        if os.environ.get("HUNT_SKIP_WALLED", "1") == "1" and str(it.get("url", "")).startswith("http"):
            try:
                import netget as _ng
                from urllib.parse import urlparse as _up
                _st, _, _ = _ng.get(it["url"], ident="A", slug=self.scope.name)
                # A 500 on one route is an application result, not a dead host.
                # Skip only when the host root is also 403, which is a WAF wall.
                if _st == 403:
                    _p = _up(it["url"])
                    _root = f"{_p.scheme}://{_p.netloc}/"
                    if _root.rstrip("/") != it["url"].split("?")[0].rstrip("/"):
                        _rst, _, _ = _ng.get(_root, ident="A", slug=self.scope.name)
                    else:
                        _rst = _st
                    if _rst == 403:
                        return {"vulnerable": False, "skipped": f"host walled (HTTP {_st})"}
            except Exception:  # noqa: BLE001
                pass
        # Similarity is only a lead. Deterministic confirmation requires an explicit A-owned marker.
        if str(it.get("url", "")).startswith("http") and it.get("owner_marker"):
            try:
                import authn as _AN
                import authz as _AZ
                _owner = it.get("owner") or "A"
                _accessor = it.get("accessor") or "B"
                _method = it.get("method") or "GET"
                ids = _AN.identities(self.scope.name, self.base)
                if _owner in ids and _accessor in ids:
                    proof = _AZ.prove_ownership(
                        _method, it["url"], it.get("body"), self.scope.name,
                        it["owner_marker"], control_url=it.get("control_url"),
                        owner=_owner, accessor=_accessor)
                    if proof.get("confirmed"):
                        return {"vulnerable": True, "severity": "high", "vuln_class": "idor",
                                "evidence": (f"Cross-account {_method}: {_accessor} received {_owner}'s unique marker "
                                             f"from {it['url']} (A={proof['A_status']}, B={proof['B_status']})."),
                                "request": f"{_method} {it['url']} — as {_owner} vs {_accessor}",
                                "response": f"A-owned marker present in B response: {it['owner_marker']}",
                                "owner_marker": it["owner_marker"], "control_url": it.get("control_url"),
                                "attacker_holds": "own_session", "id_source": "in_scope_oracle",
                                "_model": "authz-ownership-proof", "_skills": ["hunt-idor"]}
            except Exception:  # noqa: BLE001
                pass
        if not model:
            ctx = {"params": len(it.get("params") or []),
                   "auth_required": it.get("auth_required", False),
                   "sensitivity": (it.get("function_profile") or {}).get("sensitivity", {}).get("level", 0),
                   "boundaries": len((it.get("function_profile") or {}).get("trust_dimensions") or []),
                   "previous_result": it.get("_previous_result")}
            model, _eff, _budget = MR.route("hunt", ctx)
            self.eng.log(f"hunt: model={model} effort={_eff} (budget={_budget['max_tokens']}) for {it.get('vuln_class')}@{it.get('url','?')[:60]}")
        return self._hunt_deep(it, model, timeout)

    def _feedback_surface(self, f):
        """Hunt->recon feedback: in-scope endpoints the agent discovered WHILE testing get added back to the
        surface. GUARDED so it can't rabbit-hole: a per-host CAP stops one subdomain (e.g. a 401-walled
        help-desk / Zendesk API) from exploding the surface into hundreds of dead-ends, and agent-found items
        get LOWER priority than the core recon surface so the high-value, session-applicable hosts hunt FIRST."""
        if not isinstance(f, dict):
            return
        import recon as _R
        from urllib.parse import urlparse
        from collections import Counter
        cap = int(os.environ.get("HUNT_FEEDBACK_HOST_CAP", "40"))
        per_host = Counter(urlparse(s.get("url", "")).hostname for s in self.eng.state.get("surface", []))
        added = 0
        for u in (f.get("discovered") or [])[:25]:
            if not isinstance(u, str) or "://" not in u:
                continue
            h = urlparse(u).hostname
            if per_host.get(h, 0) >= cap:                 # host already well-covered -> don't amplify a dead-end
                continue
            if self.scope.in_scope_host(u) and _R.is_concrete_target(u):
                for it in _deepen([{"url": u, "vuln_class": c, "source": "agent-found", "priority": 30}
                                   for c in _R.classify_all({"url": u})]):
                    if self.eng.add_surface([it]):
                        added += 1
                        per_host[h] += 1
        if added:
            self.eng.log(f"feedback: +{added} work unit(s) from endpoints the agent found mid-hunt (host cap {cap})")

    # ---------------- chain ----------------
    def chain(self):
        """Compose observed effects and preconditions into an evidence-backed sequence.
        Runs only when multiple primitives exist; never selects a chain from class names."""
        if self.mock:
            return
        pool = (self.eng.state.get("confirmed") or []) + (self.eng.state.get("candidates") or [])
        rejected = self.eng.rejected_keys()
        seen, prims = set(), []
        for c in pool:
            k = (c.get("vuln_class"), c.get("url"))
            fk = f"{c.get('url','')}|{c.get('vuln_class','')}"
            if fk in rejected or f"{c.get('url','')}|" in rejected:
                continue
            if c.get("url") and not self.scope.in_scope_host(c["url"]):
                continue
            if c.get("url") and k not in seen:
                seen.add(k)
                prims.append(c)
        if len(prims) < 2:
            return                                   # single primitive can't chain -> no agent call
        if not any(p.get("severity", "").lower() in ("medium", "high", "critical") for p in prims):
            return                                   # all low-severity -> unlikely to compose into high-impact
        self.eng.set_phase("chain")
        classes = ", ".join(sorted({p.get("vuln_class") for p in prims}))
        plist = "\n".join(f"  - {p.get('vuln_class')} @ {p.get('url')} | {str(p.get('evidence', ''))[:150]}"
                          for p in prims[:8])
        self.eng.log(f"chain: composing from {len(prims)} primitive(s) — {classes}")
        task = (self._roe() + "\n"
                "TASK: You have these evidence-backed primitives on this target. Analyze their actual resources, "
                "actors, inputs, effects, and preconditions. Try to compose only relationships supported by those "
                "observations into one higher-impact sequence. Do not select a chain pattern by vulnerability name. "
                "Prove every transition END-TO-END with real in-scope, read-only requests. If no real chain "
                "composes, return chained:false — never speculate.\n"
                f"PRIMITIVES:\n{plist}\n"
                "End with a fenced ```json``` object: "
                '{"chained":true|false,"severity":"low|medium|high|critical","chain":"<A -> B -> impact>",'
                '"evidence":"<requests/responses proving the FULL chain>","request":"<key request(s)>",'
                '"hosts_contacted":["every host contacted"],"proof_note":"<empty or why limited>"}.'
                + self._capabilities_note())
        sess = getattr(self, "_auth_session", None)
        if sess:
            _AS = _authmod()
            if _AS:
                task += _AS.auth_block(sess, prims[0].get("url", ""))
        r = A.run_agent(task, context=self.scope.name, max_turns=self.max_turns,
                        timeout=int(os.environ.get("HUNT_CHAIN_TIMEOUT", "300")),
                        model=MR.model_for("exploit"))
        if r.get("error"):
            self.eng.log(f"chain: agent error ({r['error']}) — will retry next round")
            return
        f = A.extract_json(r["result"]) or {}
        if isinstance(f, dict) and f.get("chained"):
            oos = self._scope_audit(f)
            self.eng.add_candidate({
                "url": prims[0].get("url", ""), "vuln_class": "chain",
                "severity": f.get("severity", "high"), "evidence": f.get("evidence", ""),
                "request": f.get("request", ""), "proof_note": f.get("proof_note", ""),
                "chain": f.get("chain", ""), "components": sorted({p.get("vuln_class") for p in prims[:8]}),
                "scope_warning": oos or None})
            self.eng.log(f"chain: ⚠ CHAINED {str(f.get('chain', ''))[:120]} (severity {f.get('severity')})")
        else:
            self.eng.log("chain: no end-to-end chain composed from current primitives")

    # ---------------- validate ----------------
    def _honor_heals(self):
        """Apply a workflow-review heal written to disk. State lives in this process, so the
        reviewer cannot edit tested URLs or the mine timer directly."""
        path = os.path.join(os.path.expanduser(self.base), "_review", "heals",
                            self.scope.name + ".json")
        try:
            heal = json.load(open(path))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(heal, dict):
            return
        if heal.get("reset_mine"):
            self.eng.state["mine_agent_ts"] = 0
            self.eng.state.pop("mine_agent_added", None)
            self.eng.state["hypo_ts"] = 0
            self.eng.log("review: mine timer reset — empty worklist, live session, last mine added nothing")
        if heal.get("coerce_deep") and os.environ.get("HUNT_DEEP", "1") == "1":
            n_c = 0
            for s in self.eng.state.get("surface") or []:
                if not isinstance(s, dict) or s.get("source") == "secret":
                    continue
                cls = (s.get("vuln_class") or "").lower()
                if cls and cls not in ("deep",):
                    s["vuln_class"] = "deep"
                    s.pop("vuln_classes", None)
                    n_c += 1
            if n_c:
                self.eng.log(f"review: coerced {n_c} leftover class slot(s) to deep")
        n = 0
        if heal.get("reopen_auth_wall"):
            tested = self.eng.state.get("tested") or {}
            notes = self.eng.state.get("hunt_notes") or {}
            if isinstance(tested, dict) and isinstance(notes, dict):
                for key, note in list(notes.items()):
                    analysis = (note or {}).get("analysis") if isinstance(note, dict) else ""
                    if key in tested and _logged_out_result(analysis):
                        tested.pop(key, None)
                        notes.pop(key, None)
                        n += 1
                self.eng.state["tested"] = tested
                self.eng.state["hunt_notes"] = notes
        try:
            os.remove(path)
        except OSError:
            pass
        self.eng.save()
        if n:
            self.eng.log(f"review: reopened {n} url(s) closed on a login wall")
        if heal.get("hypothesize"):
            added = self._hypothesize()
            self.eng.log(f"review: hypothesis pass queued {added} url(s)")

    def _honor_review_skips(self):
        """The workflow review marks brochure pages as not worth a deep agent. Applied at hunt start
        so a running process picks the decision up from disk."""
        d = self._review_directive()
        skip_junk = bool(d.get("skip_junk"))
        tested = self.eng.state.get("tested")
        if not isinstance(tested, dict):
            tested = {}
        n = 0
        collapsed = self.eng.state.setdefault("collapsed", {})
        now = time.time()
        for it in list(self.eng.state.get("surface") or []):
            url = it.get("url") or ""
            if not _skip_static_url(url):
                continue
            key = self.eng._key(it)
            if key in tested or key in collapsed:
                continue
            collapsed[key] = now
            n += 1
        if n:
            self.eng.save()
            self.eng.log(f"review: collapsed {n} marketing/static url(s) — not counted as tested coverage")
        return n

    def _review_directive(self):
        path = os.path.join(os.path.expanduser(self.base), "_review", "directives",
                            self.scope.name + ".json")
        try:
            d = json.load(open(path))
            return d if isinstance(d, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _apply_review_directives(self):
        """Close candidates the 2h workflow check already judged. Read from disk each pass so a
        running hunt picks the decision up without a restart."""
        d = self._review_directive()
        closed = 0
        for item in d.get("close") or []:
            if not isinstance(item, dict) or not item.get("url"):
                continue
            reason = item.get("reason") or "2h workflow review"
            targets = [item]
            if not item.get("vuln_class"):
                targets = [c for c in self.eng.state.get("candidates") or []
                           if c.get("url") == item.get("url")] or [item]
            for t in targets:
                fk = f"{t.get('url','')}|{t.get('vuln_class','')}"
                if fk in self.eng.rejected_keys():
                    continue
                self.eng.mark_rejected({"url": t.get("url"), "vuln_class": t.get("vuln_class", "")}, reason)
                closed += 1
        if closed:
                self.eng.log(f"review: closed {closed} candidate(s) from the workflow review")

    def _candidate_key(self, c):
        return (c.get("url"), c.get("vuln_class"))

    def _close_candidate(self, c, reason):
        self.eng.mark_rejected(c, reason)
        self.eng.log(f"validate: closed {c.get('vuln_class')} @ {c.get('url')} — {reason}")

    def validate(self):
        real_todo = [it for it in self.eng.worklist()
                     if not _skip_static_url(it.get("url") or "")]
        has_candidates = bool(self.eng.state.get("candidates"))
        if len(real_todo) > 20 and not has_candidates:
            self.eng.log(f"validate: {len(real_todo)} real url(s) still untested and no candidates — staying on hunt")
            return
        if len(real_todo) > 20:
            self.eng.log(f"validate: {len(real_todo)} url(s) still untested but {len(self.eng.state['candidates'])} candidate(s) pending — validating candidates")
        self.eng.set_phase("validate")
        self._apply_review_directives()
        def outcome(candidate, cls, result, note="", **_kwargs):
            dimensions = candidate.get("trust_dimensions") or []
            return _lrn("record_outcome", self.scope.name, cls, result, note, base=self.base,
                        trust_dimension=dimensions[0] if dimensions else "")
        import disposition as D
        held_keys = {(h.get("url"), h.get("vuln_class"))
                     for h in (self.eng.state.get("disposition_held") or [])}
        rejected = self.eng.rejected_keys()
        confirmed = {(cf.get("url"), cf.get("vuln_class")) for cf in self.eng.state["confirmed"]}
        pending = []
        for c in self.eng.state["candidates"]:
            key = self._candidate_key(c)
            fk = f"{c.get('url','')}|{c.get('vuln_class','')}"
            if key in held_keys or key in confirmed or fk in rejected:
                continue
            if not self.scope.in_scope_host(c.get("url") or ""):
                self._close_candidate(c, "out of scope — not re-checked")
                continue
            if D.own_session_oauth(c):
                self._close_candidate(c, "own-session oauth — token belongs to the registering account")
                continue
            pending.append(c)
        survivors = []
        for c in pending:
            cls, url = c.get("vuln_class"), c.get("url")
            pre = self._reproduce(c, None)
            if pre["status"] == "disproved":
                c["reproduction"] = pre
                self.eng.mark_rejected(c, f"disproved via {pre['method']}")
                outcome(c, cls, "false-positive",
                     f"disproved by {pre['method']}: {pre['signal']}", base=self.base)
                self.eng.log(f"validate: ✗ PRE-CHECK disproved {cls} @ {url} — {pre['signal']} (LLM skipped)")
            else:
                survivors.append(c)
        self.eng.log(f"validate: {len(survivors)} candidate(s) to verify "
                     f"({len(pending) - len(survivors)} pre-disproved, {len(rejected)} already closed), "
                     f"{self.parallel} at a time")
        for c, v in self._run_parallel(self._validate_agent, survivors):
            cls, url = c.get("vuln_class"), c.get("url")
            repro = self._reproduce(c, v)
            c["reproduction"] = repro
            llm_real = bool(v and v.get("real"))
            # 1) deterministic DISPROOF overrides an LLM 'real' -> NOT a real bug (kills false positives)
            if repro["status"] == "disproved":
                self.eng.mark_rejected(c, f"disproved via {repro['method']}")
                outcome(c, cls, "false-positive",
                     f"disproved by {repro['method']}: {repro['signal']}", base=self.base)
                self.eng.log(f"validate: ✗ NOT REAL (disproved via {repro['method']}) {cls} @ {url} — {repro['signal']}")
                continue
            # 2) the skeptical validator says it's not real -> drop it, and do not verify it again
            if not llm_real:
                self.eng.mark_rejected(c, (v or {}).get("reason", "") or "false positive")
                outcome(c, cls, "false-positive",
                     (v or {}).get("reason", ""), base=self.base)
                self.eng.log(f"validate: ✗ rejected (false positive) {cls} @ {url} — "
                             f"{(v or {}).get('reason', 'no verdict')}")
                continue
            # 3) RTFS / Informative disposition hold (advisory text-gate) -> held, not reported
            disp = self._disposition(c, v)
            if disp["verdict"] != "PASS":
                self.eng.mark_rejected(c, disp.get("reason", "") or disp["verdict"])
                self.eng.state.setdefault("disposition_held", []).append({
                    "url": url, "vuln_class": cls, "verdict": disp["verdict"], "reason": disp.get("reason", "")})
                self.eng.save()
                outcome(c, cls,
                     "held-" + disp["verdict"].lower().replace("_", "-"), disp.get("reason", ""), base=self.base)
                self.eng.log(f"validate: HELD {disp['verdict']} {cls} @ {url} — {disp.get('reason','')}")
                continue
            reproduced = repro["status"] == "reproduced" or self.mock
            if not reproduced:
                c["reproduction"] = repro
                self.eng.state.setdefault("disposition_held", []).append({
                    "url": url, "vuln_class": cls, "verdict": "NEEDS_MANUAL_REPRODUCTION",
                    "reason": repro.get("signal", "independent reproduction required")})
                self.eng.state.setdefault("manual_review", []).append(c)
                self.eng.save()
                outcome(c, cls, "manual-review", repro["signal"], base=self.base)
                self.eng.log(f"validate: HELD — independent reproduction required [{repro['method']}] {cls} @ {url}")
                continue
            if v.get("severity"):
                c["severity"] = v["severity"]
            c["reproduction"] = ({**repro, "status": "reproduced",
                                  "tools": ["mock-transport", "mock-oracle"]} if self.mock else repro)
            self.eng.confirm(c, v, reproduction_status="reproduced")
            self.eng.record_finding_verified()
            outcome(c, cls, "confirmed", repro["signal"], base=self.base)
            self.eng.log(f"validate: CONFIRMED REAL (reproduced) [{repro['method']}] {cls} @ {url} "
                         f"({v.get('severity','')})")
        # post-validate: evolve learned skills with accumulated outcomes
        try:
            evolved = _lrn("evolve_all", base=self.base)
            if evolved:
                for slug, info in (evolved or {}).items():
                    self.eng.log(f"learn: evolved skill '{slug}' — {info.get('confirmed',0)} confirmed, "
                                 f"{info.get('fp',0)} FP, {info.get('dup',0)} dup")
        except Exception:  # noqa: BLE001
            pass
        # post-validate: auto-learn from gaps recorded during this engagement
        try:
            all_gaps = _lrn("gaps", base=self.base) or []
            fresh_gaps = [g for g in all_gaps
                          if g.get("kind") == "bypass" and self.scope.name in (g.get("context") or "")]
            if fresh_gaps:
                self.eng.log(f"learn: {len(fresh_gaps)} gap(s) recorded this engagement — attempting auto-learn")
                learned_count = 0
                for gap in fresh_gaps[:3]:
                    r = _lrn("autolearn", gap.get("kind", "bypass"), gap.get("name", ""),
                             context=gap.get("context", ""), base=self.base)
                    if isinstance(r, dict) and r.get("registered"):
                        learned_count += 1
                        self.eng.log(f"learn: drafted skill for gap '{gap.get('name')}' "
                                     f"-> {os.path.basename(os.path.dirname(r['path']))}")
                if learned_count:
                    self.eng.log(f"learn: {learned_count} new skill(s) drafted from engagement gaps")
        except Exception:  # noqa: BLE001
            pass

    def _disposition(self, c, v):
        """Score the candidate the way a program triager scores RTFS / Informative. Never raises."""
        import disposition as DP
        reason = (v or {}).get("reason") or ""
        finding = {
            "vuln_class": c.get("vuln_class"), "url": c.get("url"),
            "title": c.get("note") or "",
            "evidence": c.get("evidence") or "",
            "request": c.get("request") or "",
            "impact": reason, "steps": reason,
            "proof_note": c.get("proof_note") or "",
            "attacker_holds": (v or {}).get("attacker_holds") or c.get("attacker_holds") or "",
            "id_source": (v or {}).get("id_source") or c.get("id_source") or "",
            "disposition": (v or {}).get("disposition") or c.get("disposition") or {},
        }
        return DP.check(finding)

    def _reproduce(self, c, v):
        """INDEPENDENT, deterministic real-vs-not separator — grounds 'real' in actual re-execution, not an
        LLM's word. (1) replays the proof read-only (verify.live_check: scope-guarded, GET-only, few probes),
        (2) for IDOR/BOLA with a second identity, runs an authz cross-account diff, (3) else detects concrete
        demonstrated impact already present in the write-up. Returns {status: reproduced|disproved|inconclusive,
        method, signal}. Never raises into the round."""
        cls = (c.get("vuln_class") or "").lower()
        finding = {"vuln_class": cls, "url": c.get("url"), "param": c.get("param"),
                   "program": self.scope.name, "evidence": c.get("evidence", ""),
                   "request": c.get("request", "")}
        note = ""
        try:                                           # 1) deterministic live re-test (read-only, in-scope)
            import verify as _V
            lv = _V.live_check(finding, program=self.scope.name, base=self.base)
            note = lv.get("note", "")
            if lv.get("confirmed") is True:
                return {"status": "reproduced", "method": "live-retest", "signal": note}
            if lv.get("confirmed") is False:
                return {"status": "disproved", "method": "live-retest", "signal": note}
        except Exception as e:  # noqa: BLE001
            note = f"live unavailable: {e}"
        if cls in ("idor", "bola") and str(c.get("url") or "").startswith("http"):
            try:
                import authz as _AZ
                import authn as _AN
                _owner = c.get("owner") or "A"
                _accessor = c.get("accessor") or "B"
                if _accessor in _AN.identities(self.scope.name, self.base) and c.get("owner_marker"):
                    proof = _AZ.prove_ownership(
                        c.get("method") or "GET", c["url"], c.get("body"), self.scope.name,
                        c["owner_marker"], control_url=c.get("control_url"),
                        owner=_owner, accessor=_accessor)
                    if proof.get("confirmed"):
                        return {"status": "reproduced", "method": "ownership-marker-replay",
                                "signal": f"{_accessor} received {_owner}'s unique marker in an independent replay"}
                    return {"status": "inconclusive", "method": "ownership-marker-replay",
                            "signal": proof.get("reason", "ownership proof did not reproduce")}
            except Exception:  # noqa: BLE001
                pass
        try:
            import evidence as _EV
            edir = self.eng.evidence_path("")
            case_key = c.get("case_id") or self.eng._key(c)
            valid, _reason = _EV.validate_evidence(edir, case_key)
            if valid:
                return {"status": "plausible", "method": "transport-evidence-present",
                        "signal": "transport observations exist but independent replay did not confirm — needs manual verification"}
        except Exception:  # noqa: BLE001
            pass
        return {"status": "inconclusive", "method": "none",
                "signal": note or "could not auto-reproduce read-only — needs manual verification"}

    def _validate_agent(self, c):
        if self.mock:
            return MOCK_VALIDATE.get((c["url"], c["vuln_class"]), {"real": False, "reason": "mock-default"})
        import skill_map as SM
        paths = SM.skill_paths(c.get("vuln_class", ""))
        tv = os.path.join(SM.SKILLS_DIR, "triage-validation", "SKILL.md")
        dg = os.path.join(SM.SKILLS_DIR, "disposition-gate", "SKILL.md")
        front = [p for p in (dg, tv) if os.path.isfile(p)]
        if front:
            paths = front + [p for p in paths if p not in front]
        task = (self._roe() + "\n"
                f"VALIDATE: Adversarially verify a claimed finding (be skeptical — default to false positive). "
                f"Claim: {c['vuln_class']} at {c['url']} (param `{c.get('param','')}`). "
                f"Reported evidence: {c.get('evidence','')[:400]}.\n"
                f"FIRST read and FOLLOW these gates/methodology (`cat` each):\n  " + "\n  ".join(paths) + "\n"
                f"Independently re-test it WITHIN the rules of engagement above (in-scope + read-only only). If the only "
                f"proof would require an out-of-scope host or an intrusive action, treat the impact as UNPROVEN and lower "
                f"the severity. Is it a REAL, exploitable vulnerability or a false positive? "
                f"Run `python3 {os.path.dirname(os.path.abspath(__file__))}/disposition.py check` on the evidence "
                f"before you confirm. HOLD_RTFS and HOLD_INFORMATIVE are not real bounty findings.\n"
                f"End with a fenced ```json``` object: "
                f'{{"real":true|false,"severity":"low|medium|high|critical","reason":"<why, incl. any scope/intrusive caveat>",'
                f'"attacker_holds":"nothing|own_session|link_issued_by_product|foreign_id_shown",'
                f'"id_source":"not_required|enumerated|product_link|archive|in_scope_oracle|own_only|asserted_leak"}}.')
        r = A.run_agent(task, context=self.scope.name, max_turns=self.max_turns, timeout=self.timeout,
                        model=MR.model_for("validate"))
        self.eng.log(f"validate: {c['vuln_class']}@{c['url']} model={r.get('model', '?')}"
                     + (f" ERR={r['error']}" if r.get("error") else ""))
        if r.get("error"):
            return {"real": False, "reason": f"verify error: {r['error']}"}
        return A.extract_json(r["result"]) or {"real": False, "reason": "no verdict"}

    # ---------------- report ----------------
    def report(self):
        self.eng.set_phase("report")
        c = self.eng.state["confirmed"]
        try:
            import dedup as D
            D.annotate(self.scope.name, c, base=self.base)
        except Exception as e:
            self.eng.log(f"report: dedup annotate skipped ({e})")
        def eligible(f):
            dd = f.get("dedup") or {}
            verdict = dd.get("verdict")
            reproduced = ((f.get("reproduction") or {}).get("status") or f.get("reproduction_status")) == "reproduced"
            dedup_ok = verdict == "NOVEL" or (verdict == "REVIEW" and bool(f.get("differentiator")))
            return reproduced and dedup_ok and not f.get("scope_warning")
        dropped = [f for f in c if not eligible(f)]
        if dropped:
            self.eng.log(f"report: report-ready gate held {len(dropped)} finding(s) "
                         "(reproduction, scope, or dedup unresolved)")
        c = [f for f in c if eligible(f)]
        s = self.eng.summary()
        try:
            import report as RPT
            paths = RPT.write_report(c, self.eng.dir, scope_name=self.scope.name,
                                     in_scope=self.scope.in_scope, summary=s)
            self.eng.log(f"report: wrote {len(c)} confirmed finding(s) -> {paths['markdown']} + {paths['json']}")
            return paths["markdown"]
        except Exception as e:
            self.eng.log(f"report: report.py failed ({e}), falling back to inline markdown")
        # Fallback: inline markdown (kept for resilience)
        lines = [f"# Engagement report — {self.scope.name}", "",
                 f"In scope: `{'`, `'.join(self.scope.in_scope)}`  ",
                 f"Surface mapped: {s['surface']} · tested: {s['tested']} · "
                 f"candidates: {s['candidates']} · **confirmed: {s['confirmed']}**", ""]
        if not c:
            lines += ["No confirmed findings.", ""]
        flagged = [f for f in c if f.get("scope_warning")]
        if flagged:
            lines += [f"> ⚠️ **{len(flagged)} finding(s) flagged: PoC referenced an out-of-scope host — "
                      f"review before reporting to the client.**", ""]
        for i, f in enumerate(c, 1):
            block = [f"## {i}. {f.get('vuln_class','?').upper()} — {f.get('severity','?')}",
                     f"- **URL:** `{f['url']}`" + (f" (param `{f['param']}`)" if f.get("param") else "")]
            rp = f.get("reproduction") or {}
            if rp.get("status"):
                label = {"reproduced": "✅ independently reproduced",
                         "inconclusive": "⚠ NOT independently reproduced — verify manually before submit"
                         }.get(rp["status"], rp["status"])
                block.append(f"- **Real-vs-not:** {label} ({rp.get('method','')}) — {rp.get('signal','')}")
            dd = f.get("dedup")
            if dd and dd.get("corpus_size"):
                line = f"- **Dedup:** {dd['verdict']} (score {dd['score']}, corpus {dd['corpus_size']})"
                near = dd["matches"][0] if dd.get("matches") else None
                if near:
                    line += f" — nearest: {near.get('title', '')[:60]} {near.get('link', '')}".rstrip()
                block.append(line)
            if f.get("scope_warning"):
                block.append(f"- ⚠️ **SCOPE WARNING:** PoC referenced out-of-scope host(s): "
                             f"`{'`, `'.join(f['scope_warning'])}` — verify the in-scope finding holds without them.")
            if f.get("proof_note"):
                block.append(f"- **Proof note:** {f['proof_note']}")
            block += [f"- **Evidence:** {f.get('evidence','')}",
                      f"- **Request:** `{f.get('request','')}`",
                      f"- **Verifier:** {f.get('verdict',{}).get('reason','')}", ""]
            lines += block
        path = os.path.join(self.eng.dir, "report.md")
        with open(path, "w") as _f:
            _f.write("\n".join(lines))
        self.eng.log(f"report: wrote {len(c)} confirmed finding(s) -> {path}")
        return path

    def _prior_note(self, it):
        prior = self.eng.hunt_note(it)
        if not prior.get("analysis"):
            return ""
        return ("\nPRIOR LOOK on this exact URL — do not repeat this dead end; try a different input "
                f"or object id: {prior['analysis'][:400]} classes={prior.get('classes')}\n")

    def _drop_own_session_oauth(self):
        """A confirmed OAuth whose only token belongs to the registering account is not a finding."""
        import disposition as D
        held = {(h.get("url"), h.get("vuln_class"))
                for h in (self.eng.state.get("disposition_held") or [])}
        kept, dropped = [], 0
        for c in list(self.eng.state.get("confirmed") or []):
            if not D.own_session_oauth(c):
                kept.append(c)
                continue
            dropped += 1
            key = (c.get("url"), c.get("vuln_class"))
            if key not in held:
                self.eng.state.setdefault("disposition_held", []).append({
                    "url": c.get("url"), "vuln_class": c.get("vuln_class"),
                    "verdict": "HOLD_RTFS",
                    "reason": "Own-session OAuth: the token belongs to the account that registered the client.",
                })
                held.add(key)
            self.eng.log(f"validate: unconfirm own-session oauth {c.get('vuln_class')} @ {c.get('url')}")
        if dropped:
            self.eng.state["confirmed"] = kept
            self.eng.save()

    def run(self, phases):
        self._drop_own_session_oauth()
        self.eng.reconcile_stale_running()
        # AI preflight — verify runtime before spending time on phases that need it
        _ai_phases = {"hunt", "validate", "report"}
        if _ai_phases & set(phases) and not self.mock:
            _pf = A.preflight()
            if not _pf["ok"]:
                self.eng.log(f"preflight: {_pf['error']}")
                for _ap in _ai_phases & set(phases):
                    self.eng.set_phase_status(_ap, PHASE_BLOCKED, cause=f"preflight: {_pf['error']}")
                phases = [p for p in phases if p not in _ai_phases]
                if not phases:
                    return {"status": "blocked", "blocked_by": "preflight",
                            "failed_phases": [{"phase": p, "error": _pf["error"]}
                                              for p in _ai_phases],
                            "phase_timings": {}}
        failed_phases = []
        phase_timings = {}
        _eng_timeout = int(os.environ.get("HUNT_ENGAGEMENT_TIMEOUT", "3600") or 3600)
        _eng_start = time.time()
        _stop_requested = False
        import signal
        def _handle_stop(signum, _frame):
            nonlocal _stop_requested
            _stop_requested = True
            self.eng.log(f"received signal {signum} — will stop after current phase")
        _prev_int = signal.signal(signal.SIGINT, _handle_stop)
        _prev_term = signal.signal(signal.SIGTERM, _handle_stop)
        try:
            for ph in ALL_PHASES:
                if ph in phases:
                    if _stop_requested or time.time() - _eng_start > _eng_timeout:
                        reason = "signal" if _stop_requested else f"timeout ({_eng_timeout}s)"
                        self.eng.log(f"engagement {reason} — stopping before {ph}")
                        failed_phases.extend(p for p in ALL_PHASES if p in phases and p not in failed_phases
                                             and ALL_PHASES.index(p) >= ALL_PHASES.index(ph))
                        break
                    blocked = [b for b in self.eng.blocked_dependencies(ph)
                               if b[0] in phases]
                    if blocked:
                        cause = f"blocked by: {', '.join(b[0] for b in blocked)}"
                        self.eng.set_phase_status(ph, PHASE_BLOCKED, cause=cause)
                        self.eng.log(f"phase {ph}: BLOCKED — {cause}")
                        failed_phases.append({"phase": ph, "error": cause})
                        continue
                    self.eng.set_phase_status(ph, PHASE_RUNNING)
                    _ph_start = time.time()
                    try:
                        getattr(self, ph)()
                        # Check if the phase set an internal block (e.g. hunt_blocked)
                        internal_block = self.eng.state.get("hunt_blocked") if ph == "hunt" else None
                        if internal_block:
                            self.eng.set_phase_status(ph, PHASE_BLOCKED, cause=f"gate: {internal_block}")
                            failed_phases.append({"phase": ph, "error": f"gate: {internal_block}"})
                            self.eng.log(f"phase {ph}: BLOCKED by internal gate ({internal_block})")
                        else:
                            self.eng.set_phase_status(ph, PHASE_PASS)
                    except Exception as e:
                        self.eng.set_phase_status(ph, PHASE_FAILED, cause=f"{type(e).__name__}: {e}")
                        failed_phases.append({"phase": ph, "error": f"{type(e).__name__}: {e}"})
                        self.eng.log(f"phase {ph} error (continuing with partial state): {type(e).__name__}: {e}")
                    phase_timings[ph] = round(time.time() - _ph_start, 1)
                    self.eng.record_phase_time(ph, phase_timings[ph])
                    self.eng.save()
        finally:
            signal.signal(signal.SIGINT, _prev_int)
            signal.signal(signal.SIGTERM, _prev_term)
        blocked = self.eng.state.get("hunt_blocked")
        if blocked:
            self.eng.set_phase("blocked")
            self.eng.save()
            self.eng.log(f"engine BLOCKED — hunt gate '{blocked}' prevented testing | {self.eng.summary()}")
            return {"status": "blocked", "blocked_by": blocked, "failed_phases": failed_phases,
                    "phase_timings": phase_timings}
        if failed_phases:
            self.eng.set_phase("partial")
            self.eng.state["failed_phases"] = failed_phases
            self.eng.save()
            self.eng.log(f"engine partial | failed: {failed_phases} | {self.eng.summary()}")
        else:
            self.eng.set_phase("done")
            self.eng.log(f"engine done | {self.eng.summary()}")
        return {"status": "partial" if failed_phases else "done", "failed_phases": failed_phases,
                "phase_timings": phase_timings}


# ---- mock fixtures for --mock flow validation (no agents) ----
MOCK_RECON = {
    "http://localhost:3002": [
        {"url": "http://localhost:3002/api/account?id=5", "param": "id", "vuln_class": "idor", "note": "id param"},
        {"url": "http://localhost:3002/redirect?next=x", "param": "next", "vuln_class": "open-redirect", "note": "redirect"},
        {"url": "http://localhost:3002/search?q=x", "param": "q", "vuln_class": "xss", "note": "reflected"},
        {"url": "http://evil.example/x", "param": "", "vuln_class": "sqli", "note": "OUT OF SCOPE — should be dropped"},
    ]
}
MOCK_HUNT = {
    ("http://localhost:3002/api/account?id=5", "idor"): {"vulnerable": True, "severity": "high", "evidence": "id=N returns other users' PII", "request": "GET /api/account?id=6"},
    ("http://localhost:3002/redirect?next=x", "open-redirect"): {"vulnerable": True, "severity": "medium", "evidence": "302 to external", "request": "GET /redirect?next=//evil.com"},
    ("http://localhost:3002/search?q=x", "xss"): {"vulnerable": False},
}
MOCK_VALIDATE = {
    ("http://localhost:3002/api/account?id=5", "idor"): {"real": True, "severity": "high", "reason": "confirmed PII exposure for arbitrary id"},
    ("http://localhost:3002/redirect?next=x", "open-redirect"): {"real": False, "reason": "only redirects to relative paths on re-test (false positive)"},
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True, help="engagement/scope JSON (name, in_scope, out_of_scope, seeds)")
    ap.add_argument("--base", default="~/.bughunter-engagements")
    ap.add_argument("--phases", default=None,
                    help="explicit phase list; default is recon,rank,map (add --hunt to test)")
    ap.add_argument("--hunt", action="store_true",
                    help="OPT-IN: after mapping, auto-test with agents (recon,rank,map,hunt,validate,report)")
    ap.add_argument("--model", default="claude-sonnet-4-6")
    ap.add_argument("--max-hunts", type=int, default=10)
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--mock", action="store_true", help="dry-run the orchestration with canned agent output")
    ap.add_argument("--allow-intrusive", action="store_true",
                    help="permit state-changing PoCs (emails/writes/purges). DEFAULT OFF = read-only, non-destructive.")
    ap.add_argument("--parallel", type=int, default=3, help="concurrent hunt/validate agents (default 3)")
    ap.add_argument("--expand", action="store_true",
                    help="OSINT bridge: enumerate subdomains, probe, and recon every live in-scope host "
                         "(the apex is usually just marketing; the real surface is on subdomains)")
    a = ap.parse_args()
    if a.phases:
        phases = [p.strip() for p in a.phases.split(",") if p.strip()]
    elif a.hunt:
        phases = ALL_PHASES                       # full: map then auto-test
    else:
        phases = DEFAULT_PHASES                   # default: recon -> rank -> map, then STOP for the operator
    eng = Engine(a.scope, a.base, a.model, a.max_hunts, a.max_turns, a.timeout, a.mock,
                 a.allow_intrusive, a.parallel, a.expand)
    result = eng.run(phases)
    print("\n" + json.dumps(eng.eng.summary(), indent=2))
    print("engagement dir:", eng.eng.dir)
    if result.get("status") == "blocked":
        sys.exit(3)
    if result.get("failed_phases"):
        sys.exit(1)


if __name__ == "__main__":
    main()
