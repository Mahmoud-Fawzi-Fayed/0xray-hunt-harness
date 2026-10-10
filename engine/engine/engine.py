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
import json
import os
import re
import sys
import time

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE_DIR)
from scope import Scope            # noqa: E402
from state import Engagement       # noqa: E402
import agent as A                  # noqa: E402

# OSINT (subdomain/asset enum) is a SEPARATE concern (Claude-OSINT) — not in the engine flow.


def _deepen(items):
    """HUNT_DEEP: collapse surface items to ONE analysis-driven agent per endpoint (secrets keep their class).
    Applied at every add_surface call site so no path (gql/platform/feedback/scope) re-introduces per-class
    spray. Idempotent."""
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
        k = (d.get("url", ""), d.get("param", ""))
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


# ---- endpoint quality (signal-based, target-agnostic) ----------------------------------------
# Rank by URL shape (API vs brochure), never by a vuln-class menu and never by hostname.
_Q_API_PATH = re.compile(r"/(api|graphql|gql|rest|v[0-9]+|internal|admin|oauth|auth|authorize|token|"
                         r"session|logout|sso|account|users?|me|profile|orders?|payments?|invoices?|"
                         r"transactions?|wallet|cards?|transfers?|balance|upload|files?|export|import|"
                         r"webhooks?|callback|redirect|search|query|filter|settings|billing|"
                         r"subscriptions?|teams?|projects?|reports?|integrations?|keys?|tokens?)\b", re.I)
_Q_API_HOST = re.compile(r"^(api|apis|gateway|rest|gql|graphql|admin|account|accounts|my|portal|merchant|"
                         r"customer|app|apps|dashboard|secure|auth|login|sso|id|oauth|connect|rest)[.-]", re.I)
_Q_STATIC = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|pdf|mp4|webm|avif|"
                       r"xml)(\?|$)", re.I)
_Q_MARKETING = re.compile(r"/(pricing|blog|about|contact|careers?|press|news(room)?|legal|terms|privacy|"
                          r"cookies?|faq|features?|resources?|case-stud\w*|customers?|partners?|events?|"
                          r"webinars?|ebooks?|guides?|academy|community|company|jsi18n|sitemap\w*|robots|"
                          r"favicon|solutions?|testimonial\w*|reviews?)\b", re.I)
# Pages the workflow review tells a hunt to skip. Narrower than _Q_MARKETING so /api/customers/123 stays huntable.
_REVIEW_JUNK = re.compile(
    r"/(blog|legal|careers?|customer-stories|events|pricing|whats-new|about|press|news(room)?|"
    r"terms|privacy|cookies|faq|features|resources|solutions|webinars?|ebooks?|academy|community|"
    r"company|docs|integrations|team|jobs|compare|compliance|switch|support|enterprise)"
    r"(/|$|\?)|robots\.txt|security\.txt|/\.well-known/|/healthz?\b|manifest\.json|favicon|[?&]_rsc=",
    re.I)
_Q_OBJID = re.compile(r"/(\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}|[0-9a-f]{16,})(/|\?|$)", re.I)
_Q_DISCOVERED = {"graphql-op", "graphql", "graphql-recon", "browser", "browser-capture",
                 "agent-found", "authed", "deep-recon"}


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
    """Bug-likelihood delta for ranking (roughly -85..+175). Pure function of the item's URL + metadata."""
    from urllib.parse import urlparse
    url = s.get("url", "") or ""
    try:
        p = urlparse(url)
        host, path, query = (p.hostname or ""), (p.path or ""), (p.query or "")
    except Exception:  # noqa: BLE001
        return 0
    q = 0
    if _Q_API_PATH.search(path):
        q += 45
    if _Q_API_HOST.search(host):
        q += 35
    if query:
        q += 25                                    # injectable params = live input
    if _Q_OBJID.search(path):
        q += 30                                    # object id in path = IDOR/BOLA surface
    if s.get("param"):
        q += 10
    if (s.get("source") or "").lower() in _Q_DISCOVERED:
        q += 30                                    # a discovered real endpoint, not a static crawl hit
    if s.get("authed") or "authenticated" in (s.get("note", "") or "").lower():
        q += 25
    if _Q_STATIC.search(path):
        q -= 70                                    # static asset: nothing to pentest
    # /files/<uuid> is a capability URL the product already handed out, not an IDOR job.
    if re.search(r"/files?/[0-9a-f-]{16,}(?:/|$)", path, re.I) and s.get("source") != "session-mine":
        q -= 60
    if _Q_MARKETING.search(path):
        q -= 40                                    # brochure page
    if path in ("", "/"):
        q -= 15                                    # bare homepage shell
    # Logout, health, and discovery docs are not where a paid bug lives.
    if re.search(r"/(logout|health|ready|live|robots\.txt|security\.txt|\.well-known)(/|$)", path, re.I):
        q -= 80
    return q
# DEFAULT = recon -> rank -> map (deterministic, ~free): map the surface to the skill arsenal and
# SHOW it. The operator focuses their effort from there. hunt/validate/report are OPT-IN (--hunt).
ALL_PHASES = ["recon", "rank", "map", "hunt", "validate", "chain", "report"]
DEFAULT_PHASES = ["recon", "rank", "map"]

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
        self.eng.log(f"engine start | scope={self.scope.name} in={self.scope.in_scope} "
                     f"out={self.scope.out_of_scope} seeds={self.scope.seeds} mock={mock} "
                     f"intrusive={'ALLOWED' if self.allow_intrusive else 'READ-ONLY (default)'}")

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
                roe += (f"  TWO accounts → hunt IDOR/BOLA (OWASP #1): get an object id as A, request it as B, diff. "
                        f"Automate the sweep: `python3 {ENGINE_DIR}/authz.py diff --slug {_AN._slug(self.scope.name)} "
                        f"--url \"<A-owned url>\"` — confirm any bola_suspect with a real two-account PoC before drafting.\n")
            roe += "  Prefer authenticated testing — the paid bugs (IDOR/BOLA, business logic, GraphQL authz) are behind login.\n"
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
            _j.dump({"ts": _t.time(), "params": params}, open(cache, "w"))
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
        # Anything still untested is hunted now. A fresh crawl happens only when the queue is empty.
        if queued > 0:
            self.eng.log(f"recon: {queued} item(s) still untested — skipping the crawl, straight to HUNT")
            return
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
                    self.eng.log("recon: no live session — not mining object ids")
                    return
            except Exception:  # noqa: BLE001
                pass
            self.eng.log("recon: worklist covered and a session exists — mining logged-in object ids "
                         "instead of another crawl")
            self._profile()
            added = self._mine_session()
            if not added:
                added = self._hypothesize()
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
                if u and u not in seen:
                    seen.add(u)
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
                "Open the APIs this session can actually see (profile, bookings, orders, trips, payments, "
                "seats, documents). Collect concrete object URLs the responses returned, with the real id.\n"
                "Return ONLY a fenced json object: {\"discovered\": [\"https://host/path/with-real-id\", ...]}.\n"
                "Every URL must be one you saw in an authenticated response. Do not invent URLs. "
                "At most 15 URLs, in-scope hosts only."
            )
            r = A.run_agent(task, context=self.scope.name, max_turns=30,
                            timeout=int(os.environ.get("HUNT_MINE_TIMEOUT", "700")))
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
        task = (
            f"You are profiling program {self.scope.name} so the next hunt attacks the product, "
            "not a vulnerability catalog. Do not name SQLi/XSS/IDOR unless you saw that sink.\n"
            f"Session host: {host or '?'}. Seeds: {', '.join(seeds) or '(none)'}.\n"
            f"Fetch with `python3 {ENGINE_DIR}/netget.py GET \"<url>\" --as A` "
            "and read what the logged-in app actually is.\n"
            "Return ONLY a fenced json object: "
            '{"narrative":"<one sentence: this product lets who do what>",'
            '"roles":["..."],"crown_jewels":["the data/actions that pay if stolen"],'
            '"flows":[{"what":"<user flow>","url":"https://in-scope/...","why":"<why this flow is dangerous>"}],'
            '"deprioritized":["marketing/static things to skip"]}. '
            "URLs must be in-scope and real. No class-agent names."
        )
        r = A.run_agent(task, context=self.scope.name, max_turns=20,
                        timeout=int(os.environ.get("HUNT_MINE_TIMEOUT", "700")))
        f = A.extract_json(r.get("result") or "") or {}
        if not isinstance(f, dict) or not (f.get("narrative") or f.get("flows")):
            self.eng.log("profile: no narrative from the session — continuing without one"
                         + (f" ERR={r.get('error')}" if r.get("error") else ""))
            return
        BR.set_profile(self.scope.name, f, self.base)
        n = len(f.get("flows") or [])
        self.eng.log(f"profile: {n} flow(s) — {(f.get('narrative') or '')[:140]}")
        items = []
        for fl in (f.get("flows") or [])[:8]:
            if not isinstance(fl, dict):
                continue
            u = fl.get("url") or fl.get("endpoint") or ""
            if isinstance(u, str) and self.scope.in_scope_host(u) and not _Q_STATIC.search(u):
                items.append({"url": u, "vuln_class": "deep", "source": "profile", "priority": 110})
        if items:
            added = self.eng.add_surface(_deepen(items))
            self.eng.log(f"profile: queued {added} flow url(s)")

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
                "Open what this session can actually see (whatever the product calls it — profile, docs, "
                "files, orgs, bookings, payments, admin). From the JSON/HTML, name concrete in-scope URLs "
                "with real ids, plus one sentence each of what to try that was NOT already tried below.\n"
                + (memory or "")
                + ("Already looked:\n" + "\n".join(prior[:10]) + "\n" if prior else "")
                + "Return ONLY a fenced json object: "
                '{"discovered":["https://host/path/with-real-id"],'
                '"hypotheses":["<one-sentence tests>"]}. '
                "At most 10 URLs, in-scope hosts only, no static images or marketing pages."
            )
            r = A.run_agent(task, context=self.scope.name, max_turns=25,
                            timeout=int(os.environ.get("HUNT_MINE_TIMEOUT", "700")))
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
            t.pop(f"{item.get('url')}|{item.get('param','')}|{item.get('vuln_class','')}", None)
            self.eng.save()

    def _needs_authz_gate(self, url):
        """True when a deep nothing on this URL would be a guess: A and B are live and the URL
        is an in-scope endpoint worth an object-level diff. Health/logout checks are not."""
        if self.mock or not url or not str(url).startswith("http"):
            return False
        if not self.scope.in_scope_host(url):
            return False
        if re.search(r"/(logout|health|ready|live|robots\.txt|\.well-known)(/|$)", url, re.I):
            return False
        try:
            import authn
            ids = authn.identities(self.scope.name, self.base)
        except Exception:  # noqa: BLE001
            return False
        return "A" in ids and "B" in ids

    def _authz_closeout(self, url):
        """Read-only authz.py diff plus netget as B. Logs `authz:` only from that run.
        Returns the log line, or '' if the commands were not run (caller must refuse nothing)."""
        try:
            import authn
            import authz
            import netget
            slug = authn._slug(self.scope.name)
            d = authz.diff_one("GET", url, None, self.scope.name)
            sb, _tb, _h = netget.get(url, method="GET", ident="B", slug=slug)
        except Exception:  # noqa: BLE001
            return ""
        line = (f"authz: diff A={d.get('A_status')} B={d.get('B_status')} "
                f"sim={d.get('similarity')} bola={bool(d.get('bola_suspect'))} "
                f"netget_B={sb} {str(url)[:120]}")
        self.eng.log(line)
        return line

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
            return ("\nAUTHZ PRE-CHECK: accounts A and B are both live. Before any other class, "
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
            self.eng.state["browser_recon_ts"] = time.time()
            self.eng.save()
            self.eng.log(f"deep-recon: browser capture ({trigger}) -> {added} new authed work unit(s)")
        except Exception as e:  # noqa: BLE001
            self.eng.log(f"deep-recon: browser skipped ({type(e).__name__}: {e})")

    # ---------------- rank ----------------
    def rank(self):
        self.eng.set_phase("rank")
        ym = None
        try:
            import yieldrank as Y
            ym = Y.Model.load(self.base)     # yield priors + learned (your confirms up, your dups down)
        except Exception:
            ym = None
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
            s["priority"] = 50 + (5 if s.get("param") else 0) + (55 if s.get("source") == "secret" else 0)
            s["priority"] += _endpoint_quality(s)    # float REAL attack surface above brochure/asset pages
            # The logged-in host is the one the operator can actually test. Do not
            # let a shared marketing apex outrank it.
            if session_host and (urlparse(s.get("url") or "").hostname or "") == session_host:
                s["priority"] += 120
            if ym:
                s["priority"] += ym.bonus(s.get("vuln_class", ""))
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
        """Categorize the surface against the skill arsenal and SHOW it: per target ->
        applicable hunt-* skill(s) + first curl. This is where the operator focuses; the
        engine does NOT auto-test by default (run with --hunt to spend agents)."""
        self.eng.set_phase("map")
        import skill_map as SM
        from collections import OrderedDict
        tech = sorted({t for tg in self.eng.state.get("targets", []) for t in tg.get("tech", [])})
        groups = OrderedDict()
        for s in sorted(self.eng.state["surface"], key=lambda z: -z.get("priority", 0)):
            key = (s["url"], s.get("param", ""))
            g = groups.setdefault(key, {"classes": [], "src": s.get("source", "")})
            if s["vuln_class"] not in g["classes"]:
                g["classes"].append(s["vuln_class"])
        tech_sk = SM.tech_skills(tech)
        # self-learning: a detected app/framework with NO playbook is a capability gap -> research +
        # auto-draft a skill so the NEXT hunt already knows it. Infra fingerprints are skipped (too generic).
        learned_now = 0
        for t in ([] if self.mock else tech):        # skip network research during mock/self-test runs
            tl = (t or "").lower()
            if not tl or tl in INFRA_TECH or SM.tech_skills([tl]):
                continue
            if learned_now >= 3:                     # bound per-run latency
                _lrn("record_gap", "tech", tl, f"{self.scope.name}: detected {tl}, no skill (deferred)", self.base)
                continue
            r = _lrn("autolearn", "tech", t, context=f"{self.scope.name}: detected {t}, no existing skill",
                     base=self.base)
            if isinstance(r, dict) and r.get("registered"):
                learned_now += 1
                self.eng.log(f"learn: no skill for '{t}' -> drafted {os.path.basename(os.path.dirname(r['path']))} "
                             f"(self-authored, review before relying on it)")
        lines = [f"# Arsenal map — {self.scope.name}", "",
                 f"**Service / tech:** {', '.join(tech) or '?'}  ",
                 f"**Tech-wide skills:** {', '.join('`'+s+'`' for s in tech_sk) or 'none'}  ",
                 f"**Attack surface:** {len(groups)} target(s). For each: applicable skill(s) + the first curl.",
                 "", "> Active testing is curl-first; Burp MCP only for OOB/blind/fuzzing. "
                 "Run the engine with `--hunt` to auto-test these with agents (skills-off, parallel).", ""]
        self.eng.log(f"map: ARSENAL — tech-skills: {', '.join(tech_sk) or 'none'} | {len(groups)} target(s):")
        for (url, param), g in groups.items():
            label = param if param else "(endpoint)"
            per = "  ".join(f"{c}→{','.join(SM.skills_for(c, url=url))}" for c in g["classes"])
            self.eng.log(f"map:   {label:16.16s} {url[:42]:42.42s}  {per}")
            lines.append(f"## `{label}`  —  {', '.join(g['classes'])}")
            lines.append(f"- **URL:** `{url}`" + (f"  ·  source: {g['src']}" if g["src"] else ""))
            for c in g["classes"]:
                lines.append(f"- **{c}** → {', '.join('`'+s+'`' for s in SM.skills_for(c, url=url))}  ·  "
                             f"`{SM.probe_for(c, url, param)}`")
            lines.append("")
        path = os.path.join(self.eng.dir, "arsenal.md")
        open(path, "w").write("\n".join(lines))
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

    # ---------------- hunt ----------------
    def hunt(self):
        self.eng.set_phase("hunt")
        self._honor_heals()
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
        wl = self.eng.worklist()[: self.max_hunts]
        todo = []
        for it in wl:
            if "{" in (it.get("url") or ""):
                self.eng.log(f"hunt: skipping template url {it['url']}")
                self.eng.mark_tested(it)
            elif not self.scope.in_scope_host(it["url"]):     # belt-and-suspenders scope gate
                self.eng.log(f"hunt: REFUSING out-of-scope {it['url']} ({self.scope.reject_reason(it['url'])})")
                self.eng.mark_tested(it)
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
        self.eng.log(f"hunt: testing {len(todo)} item(s), {self.parallel} at a time")
        for it, f in self._run_parallel(self._hunt_agent, todo):
            if f and f.get("error") == "timeout":
                # MODEL-FAILOVER: a timeout usually clears on a DIFFERENT model — try ONCE more with a generous
                # budget. If it times out AGAIN, the endpoint is too heavy: mark it tested (INCONCLUSIVE) and move
                # on, so it can't starve the queue by re-timing-out every round forever.
                alt = self._alt_model(f.get("model"))
                fbt = int(os.environ.get("HUNT_FAILOVER_TIMEOUT", "900"))
                self.eng.log(f"hunt: timeout on {it.get('vuln_class')}@{it['url']} (model {f.get('model')}) "
                             f"— failover to {alt} ({fbt}s)")
                f = self._hunt_agent(it, model=alt, timeout=fbt)
                if f and f.get("error") == "timeout":
                    self.eng.mark_tested(it)
                    self.eng.log(f"hunt: INCONCLUSIVE (double-timeout) {it.get('vuln_class')}@{it['url']} "
                                 "— marked tested, moving on (too heavy for the budget)")
                    continue
            if f and f.get("error"):
                # a transient agent error (parse/rate-limit/timeout) must NOT permanently mark the
                # endpoint tested — leave it so the next round retries it (with a fresh pool model).
                self.eng.log(f"hunt: error on {it.get('vuln_class')}@{it['url']} ({f['error']}) "
                             f"— not marking tested, will retry next round")
                continue
            self.eng.mark_tested(it)
            self._feedback_surface(f)                 # endpoints the agent found mid-hunt -> back into the worklist
            if f and f.get("rate_limited"):
                self.eng.log("hunt: ⚠ model usage limit hit — remaining results may be partial")
            if f and f.get("vulnerable"):
                oos = self._scope_audit(f)
                cand = {"url": it["url"], "param": it.get("param", ""),
                        "vuln_class": f.get("vuln_class") or it.get("vuln_class"),
                        "severity": f.get("severity", "unknown"), "evidence": f.get("evidence", ""),
                        "request": f.get("request", ""), "proof_note": f.get("proof_note", ""),
                        "attacker_holds": f.get("attacker_holds", ""),
                        "id_source": f.get("id_source", ""),
                        "disposition": f.get("disposition") or {},
                        "scope_warning": oos or None}
                import disposition as _D
                if _D.own_session_oauth(cand):
                    self.eng.mark_rejected(cand, "own-session oauth")
                    self.eng.log(f"hunt: dropped own-session oauth @ {it['url']} — "
                                 "the token belongs to the account that registered the client")
                else:
                    self.eng.add_candidate(cand)
                    self._remember(it, cand.get("evidence") or "", [cand.get("vuln_class")],
                                   result="candidate", finding=f)
                    self.eng.log((f"hunt: ⚠ CANDIDATE {cand['vuln_class']} @ {it['url']} — PoC touched OUT-OF-SCOPE "
                                  f"host(s): {', '.join(oos)} (flagged)") if oos
                                 else f"hunt: CANDIDATE {cand['vuln_class']} @ {it['url']}")
            elif f and f.get("skipped"):
                self.eng.log(f"hunt: skipped {it.get('vuln_class')}@{it['url']} — {f['skipped']}")
            else:
                analysis = ""
                classes = []
                if isinstance(f, dict):
                    analysis = f.get("analysis") or ""
                    classes = f.get("classes_considered") or []
                if _logged_out_result(analysis):
                    self._unmark_tested(it)
                    self.eng.note_hunt(it, analysis, classes)
                    self._remember(it, analysis, classes, result="auth_wall", finding=f)
                    self.eng.log(f"hunt: auth wall on {it.get('vuln_class')}@{it['url']} — left untested "
                                 "so a live session can retry")
                    continue
                # Deep + two live accounts: hunt:nothing is refused until authz.py diff and
                # netget --as B have actually run. The log line is the proof authz_logged reads.
                if ((it.get("vuln_class") or "").lower() == "deep"
                        and self._needs_authz_gate(it.get("url"))):
                    line = self._authz_closeout(it.get("url"))
                    if not line:
                        self._unmark_tested(it)
                        self.eng.log(f"hunt: refused nothing on {it.get('vuln_class')}@{it['url']} "
                                     "— authz.py diff and netget --as B were not run")
                        continue
                    analysis = (str(analysis) + "\n" + line).strip()
                self.eng.note_hunt(it, analysis, classes)
                self._remember(it, analysis, classes, result="nothing", finding=f)
                tail = f" — {str(analysis)[:160]}" if analysis else ""
                self.eng.log(f"hunt: nothing on {it.get('vuln_class')}@{it['url']}{tail}")

    def _hunt_deep(self, it, model=None, timeout=None):
        """ANALYSIS-DRIVEN per-endpoint pentest: the agent reads the endpoint's source/JS, reasons about what
        it actually is, decides which vuln classes are PLAUSIBLE, then exploits only those — a thinking
        pentester, not a payload-sprayer. One smart agent per endpoint (not N mechanical per-class hunts)."""
        import agent as A
        import skill_map as SM
        url = it["url"]
        tech = sorted({t for tg in self.eng.state.get("targets", []) for t in tg.get("tech", [])})
        p, e = self.scope.name, ENGINE_DIR
        lead = self._authz_lead(url)
        # Do not log "authz:" here. A queued sentence is not a run; authz_logged stays false
        # until _authz_closeout (or a real diff) writes the line.
        try:
            import brain as BR
            memory = BR.prompt_block(p, url, self.base)
        except Exception:  # noqa: BLE001
            memory = ""
        hinted = SM.matching(url, tech, extra=str(it.get("note") or ""))
        hinted_paths = []
        for n in hinted[:6]:
            sp = os.path.join(SM.SKILLS_DIR, n, "SKILL.md")
            if os.path.isfile(sp):
                hinted_paths.append(sp)
        hypo = os.path.join(SM.SKILLS_DIR, "hunt-hypothesis", "SKILL.md")
        if os.path.isfile(hypo) and hypo not in hinted_paths:
            hinted_paths.insert(0, hypo)
        skill_hint = ("Read these ONLY if they match what the live response is: "
                      + ", ".join(f"`{x}`" for x in hinted_paths[:6])
                      + f". Any other hunt-* in {SM.SKILLS_DIR} may be Read. "
                      "They are references, not a menu. Invent the test from the bytes on the wire.")
        task = (self._roe() + "\n"
                f"PENTEST THIS ONE ENDPOINT. Think from the live response. Do NOT walk a vulnerability catalog.\n"
                + lead + memory +
                f"URL: {url}   method: {it.get('method','GET')}   known param(s): {it.get('param','')}   "
                f"tech: {', '.join(tech) or 'unknown'}\n\n"
                "If an AUTHENTICATED SESSION block is attached below, send its Cookie and headers on EVERY "
                "request. A 401 from a request that omitted them is not a result. Do not return "
                "vulnerable:false just because the logged-out call was rejected. Use the session, list the "
                "objects it can see, then test those.\n"
                "AUTHZ GATE (hard): when identities A and B are both live, do NOT return vulnerable:false "
                "on this endpoint until you have actually executed both read-only commands (running them, "
                "not describing them): "
                f"`python3 {e}/authz.py diff --slug {p} --url \"<this URL or an A-owned object URL>\"` and "
                f"`python3 {e}/netget.py GET \"<that same URL>\" --as B`. "
                "analysis must contain a line that starts with `authz:` plus both HTTP statuses and whether "
                "B's body contained a marker that belongs only to A. vulnerable:true only with that marker — "
                "a similarity score is not a finding. The harness refuses hunt:nothing and leaves the "
                "endpoint untested if those two commands did not run. No brute force, no id guessing past "
                "ids account A already returned, in-scope GET only.\n"
                "STEP 1 — SEE: fetch this URL (and linked JS / maps) as the session. Write what the product "
                "is doing, every input, every object id, every other host or role the response implies.\n"
                "STEP 2 — INVENT: from those bytes, name one trust boundary and one test that would be "
                "false if the developer had been careful. Do not start from SQLi/XSS/IDOR because those "
                "words exist in a list. If a previous look is in HUNT MEMORY, do something else.\n"
                "STEP 3 — RUN that test with curl / netget. Then a second different test if the first is "
                "negative. "
                + skill_hint + "\n"
                f"  authed fetch: `python3 {e}/netget.py GET \"<url>\" --as A`. Before any negative on an "
                f"authed endpoint also run `python3 {e}/netget.py GET \"<A-object-url>\" --as B` and "
                f"`python3 {e}/authz.py diff --slug {p} --url \"<A-object-url>\"`.  "
                f"Unknown stack? `python3 {e}/learn.py auto --kind tech --name \"<thing>\" --context \"<why>\"` "
                "then Read the drafted skill.\n"
                "STEP 4 — PROVE: claim a vuln ONLY with demonstrated, exploitable impact (never reflection, an "
                "error, or a permissive header) using in-scope, read-only actions. "
                "IDOR/BOLA: vulnerable:true ONLY with an A-vs-B body-diff showing B received A's unique "
                "marker on an attacker-enumerated or product-issued (in-scope list/oracle) id — not a "
                "holder-only capability URL. Do NOT nominate as candidates: public CDN/UUID marketing/"
                "static files (PNG/JPG/WebP/SVG, UUID v7 unguessable, DELETE 401) or unauthenticated "
                "WordPress field-title leaks (/wp-json titles/schema without field values/secrets). "
                "Disposition HOLD_RTFS/HOLD_INFORMATIVE still apply — do not weaken those gates.\n"
                "End with a fenced ```json``` object: "
                '{"vulnerable":true|false,"vuln_class":"<class you PROVED or invented>",'
                '"severity":"low|medium|high|critical",'
                '"analysis":"<what the source/responses told you this endpoint is + does>",'
                '"classes_considered":["<what you actually tested, including invented names>"],'
                '"hypotheses":["<next tests this target still deserves>"],'
                '"signals_missed":["<things you saw and did not prove>"],'
                '"evidence":"<what proves it>","request":"<the winning request>",'
                '"hosts_contacted":["every host you hit"],"attacker_holds":"nothing|own_session|'
                'link_issued_by_product|foreign_id_shown","id_source":"not_required|enumerated|product_link|'
                'archive|in_scope_oracle|own_only|asserted_leak",'
                '"discovered":["<new in-scope endpoints/params/secrets you saw in the source>"],'
                '"proof_note":"<empty, or why proof was limited>"}'
                + self._capabilities_note())
        task += self._prior_note(it)
        sess = getattr(self, "_auth_session", None)
        if sess:
            _AS = _authmod()
            if _AS:
                task += _AS.auth_block(sess, url)
        # Give the AI real room to THINK + work an endpoint end-to-end (analyse source -> reason -> exploit ->
        # chain): a generous time budget and plenty of turns, both env-tunable. Not capped to the quick per-class
        # budget — a deep pentest legitimately takes many minutes.
        dt = timeout or int(os.environ.get("HUNT_DEEP_TIMEOUT", "1200"))
        mt = int(os.environ.get("HUNT_DEEP_TURNS", "80"))
        self.eng.log(f"hunt: deep-pentest {url} (analysis-driven) model={model or 'pool'} budget={dt}s/{mt}turns")
        r = A.run_agent(task, context=self.scope.name, max_turns=mt, timeout=dt, model=model)
        if r.get("error"):
            return {"error": r["error"], "model": r.get("model")}
        f = A.extract_json(r.get("result", "")) or {"vulnerable": False}
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
            f"- Authenticated testing (IDOR/auth need real accounts): mint a disposable, capped, in-scope-only "
            f"test identity with a live inbox:\n"
            f"    `python3 {e}/identity.py new  --program {p}`   then read the verify mail: "
            f"`python3 {e}/identity.py poll --program {p} --email <addr>`\n"
            f"  (phone-gated signups: SMS is {sms_state}.)\n"
            f"- Unknown stack/class with no skill? Teach the harness, then read what it drafted: "
            f"`python3 {e}/learn.py auto --kind tech --name \"<thing>\" --context \"<why>\"`.\n"
            f"- Headless-browser capture (find the REAL API behind a SPA — biggest discovery win): "
            f"`python3 {e}/browser.py capture --url <seed> --slug {p} [--as A] --scope <in-scope-host>` -> "
            f"XHR/fetch/GraphQL endpoints, then test those.\n"
            f"- Authenticated fetch (carries your session, bypasses edge TLS/IP gating): "
            f"`python3 {e}/netget.py GET \"<url>\" --as A` (second account: `--as B`).\n"
            f"- IDOR/BOLA sweep (OWASP #1, best-paying): `python3 {e}/authz.py diff --slug {p} --url \"<A-owned url>\"` "
            f"-> bola_suspect leads; confirm each with a real two-account PoC.\n"
            f"- App-backed program (esp. geo/IP-gated API)? Pull the API surface from the APK: "
            f"`python3 {e}/apkmap.py extract --apk <file>` -> hosts + endpoints + secrets.\n"
            "- All account/login/SMS actions pass engine/guardrails.py (scope + per-program cap) and are audited.\n")

    @staticmethod
    def _alt_model(current):
        """A pool model different from `current` — for timeout failover (a stuck model/endpoint often
        clears on another model)."""
        import random
        pool = [m.strip() for m in os.environ.get("CURSOR_HUNT_MODELS", "").split(",") if m.strip()]
        alts = [m for m in pool if m and m != current] or pool
        return random.choice(alts) if alts else None

    def _hunt_agent(self, it, model=None, timeout=None):
        if self.mock:
            return MOCK_HUNT.get((it["url"], it.get("vuln_class")), {"vulnerable": False})
        cls = (it.get("vuln_class") or "").lower()
        if os.environ.get("HUNT_DEEP", "1") == "1" and cls not in ("deep",):
            it = dict(it)
            it["vuln_class"] = "deep"
            cls = "deep"
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
        if cls == "deep":                          # analysis-driven per-endpoint pentest (think, then exploit)
            return self._hunt_deep(it, model, timeout)
        # DETERMINISTIC 2-account IDOR/BOLA — the #1 missing paying class. 2025 IDOR attempts produced 0
        # candidates because the LLM alone rarely runs the cross-account diff. When TWO identities exist and
        # the URL bears an object id, run authz.diff ourselves: if B reaches A's id-bearing object (2xx,
        # >=90% identical), that's a real BOLA/IDOR candidate the validate phase then confirms.
        if cls in ("idor", "bola") and str(it.get("url", "")).startswith("http"):
            try:
                import authn as _AN
                import authz as _AZ
                ids = _AN.identities(self.scope.name, self.base)
                if "A" in ids and "B" in ids:
                    d = _AZ.diff_one("GET", it["url"], None, self.scope.name)
                    # direct diff catches an already-id-bearing url; else the ID-ORACLE harvests A's object
                    # ids from this (list/self) endpoint and tries to read A's objects AS B.
                    s = d if d.get("bola_suspect") else (_AZ.id_oracle(it["url"], self.scope.name) or [None])[0]
                    if s and s.get("bola_suspect"):
                        return {"vulnerable": True, "severity": "high", "vuln_class": "idor",
                                "evidence": (f"Cross-account read (authz 2-account): identity B requested A's object "
                                             f"{s['url']} and received HTTP {s['B_status']} with {s['similarity']:.0%}-"
                                             f"identical id-bearing content (A={s['A_status']}/{s['A_len']}B, "
                                             f"B={s['B_status']}/{s['B_len']}B) — object-level authorization missing."),
                                "request": f"GET {s['url']}  — as A vs as B (two-account diff)",
                                "attacker_holds": "own_session", "id_source": "in_scope_oracle",
                                "_model": "authz-idor", "_skills": ["hunt-idor"]}
            except Exception:  # noqa: BLE001
                pass
        import skill_map as SM
        tech = sorted({t for tg in self.eng.state.get("targets", []) for t in tg.get("tech", [])})
        paths = SM.skill_paths(it.get("vuln_class", ""), tech)
        names = [os.path.basename(os.path.dirname(p)) for p in paths]
        probe = SM.probe_for(it.get("vuln_class", ""), it["url"], it.get("param"))
        task = (self._roe() + "\n"
                f"TASK: Test {it['url']} (parameter `{it.get('param','')}`) for {it.get('vuln_class')}, strictly "
                f"within the rules of engagement above.\n"
                f"FIRST, read and FOLLOW these skill files — they hold the exact methodology, payloads, and "
                f"discipline/validation gates for this class. `cat` each one before you test:\n  "
                + "\n  ".join(paths) + "\n"
                f"curl-FIRST: use curl for your requests. Starter probe: {probe} . "
                f"Only claim a vulnerability if you can DEMONSTRATE real, exploitable impact (not mere reflection, "
                f"an error, or a permissive header) using ONLY in-scope, read-only actions. "
                f"End with a fenced ```json``` object: "
                f'{{"vulnerable":true|false,"severity":"low|medium|high|critical","evidence":"<what proves it>",'
                f'"request":"<the winning request>","hosts_contacted":["every host you sent a request to"],'
                f'"attacker_holds":"nothing|own_session|link_issued_by_product|foreign_id_shown",'
                f'"id_source":"not_required|enumerated|product_link|archive|in_scope_oracle|own_only|asserted_leak",'
                f'"discovered":["<any NEW in-scope endpoint/URL you saw while testing — from JS, redirects, '
                f'API responses or links; helps the next round go deeper>"],'
                f'"proof_note":"<empty, or why proof was limited by scope/read-only>"}}.'
                + self._capabilities_note())
        task += self._prior_note(it)
        sess = getattr(self, "_auth_session", None)             # inject the logged-in session if it fits this host
        if sess:
            _AS = _authmod()
            if _AS:
                task += _AS.auth_block(sess, it["url"])
        if cls in ("idor", "bola"):                             # two accounts present -> demand the cross-account proof
            try:
                import authn as _AN2
                if "B" in _AN2.identities(self.scope.name, self.base):
                    e, sl = ENGINE_DIR, _AN2._slug(self.scope.name)
                    task += (f"\nTWO ACCOUNTS AVAILABLE (A and B) — do NOT conclude from one session. Prove cross-account "
                             f"access:\n  1) As A, GET the endpoint and note an object id it returns: "
                             f"`python3 {e}/netget.py GET \"{it['url']}\" --as A`.\n"
                             f"  2) As B, request A's object id: `python3 {e}/netget.py GET \"<A-object-url>\" --as B`. "
                             "If B receives A's data, that is IDOR/BOLA.\n"
                             f"  3) Confirm deterministically: `python3 {e}/authz.py diff --slug {sl} "
                             "--url \"<A-object-url>\"` (bola_suspect=true -> report). vulnerable:true ONLY if B read A's data.\n")
            except Exception:  # noqa: BLE001
                pass
        try:                                                    # LEARN from the operator's past dispositions
            import findings as _FS
            les = _FS.lessons_for(self.base, self.scope.name, it.get("vuln_class"))
            if les["invalid"] or les["valid"]:
                tl = "\nOPERATOR DISPOSITION LESSONS — learn from how past findings here were judged:\n"
                for l in les["invalid"][:4]:
                    tl += (f"  - AVOID: a '{l['vuln_class']}' finding was marked {l['status']} — "
                           f"{l['reason'] or 'not a valid/impactful bug'}. Do NOT submit this again unless you "
                           "now have the exact missing proof/impact.\n")
                for l in les["valid"][:3]:
                    tl += (f"  - WORKS: a '{l['vuln_class']}' finding was {l['status']} — "
                           f"{l['reason'] or 'accepted as a real bug'}. Prioritise this kind of proven impact.\n")
                task += tl
        except Exception:  # noqa: BLE001
            pass
        r = A.run_agent(task, context=self.scope.name, max_turns=self.max_turns,
                        timeout=timeout or self.timeout, model=model)   # model/timeout override => failover path
        self.eng.log(f"hunt: {it.get('vuln_class')}@{it['url']} model={r.get('model', '?')} "
                     f"skills=[{','.join(names)}]" + (f" ERR={r['error']}" if r.get("error") else ""))
        if r.get("error"):
            # learn from the failure: a model/class that keeps erroring is visible in the journal + panel
            _lrn("record_outcome", self.scope.name, it.get("vuln_class"), "error", r["error"], base=self.base)
            return {"vulnerable": False, "error": r["error"], "rate_limited": r["error"] == "rate-limited"}
        f = A.extract_json(r["result"]) or {"vulnerable": False}
        if isinstance(f, dict):
            f["_model"], f["_skills"] = r.get("model"), names
        return f

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
        """Chain composer (vuln-first): take confirmed + candidate PRIMITIVES and actively try to COMBINE them
        into ONE higher-severity chain (open-redirect->OAuth token theft->ATO, IDOR->privesc, SSRF->cloud
        metadata->cred, XSS->session/ATO, subdomain-takeover->cookie/OAuth). Spends an agent call ONLY when
        chainable primitives exist -> free on targets that found nothing. In-scope, read-only, end-to-end."""
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
        if not prims:
            return                                   # nothing chainable -> no agent call, no cost
        self.eng.set_phase("chain")
        classes = ", ".join(sorted({p.get("vuln_class") for p in prims}))
        plist = "\n".join(f"  - {p.get('vuln_class')} @ {p.get('url')} | {str(p.get('evidence', ''))[:150]}"
                          for p in prims[:8])
        self.eng.log(f"chain: composing from {len(prims)} primitive(s) — {classes}")
        task = (self._roe() + "\n"
                "TASK: You have these CONFIRMED/suspected primitives on this target. Actively try to COMPOSE "
                "them (with each other, or with a documented pattern) into ONE higher-severity CHAIN — e.g. "
                "open-redirect -> OAuth code/token theft -> account takeover; IDOR -> privilege escalation; "
                "SSRF -> cloud metadata -> credential; XSS -> session/ATO; subdomain-takeover -> cookie/OAuth "
                "theft. Prove the chain END-TO-END with real in-scope, read-only requests. If no real chain "
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
        r = A.run_agent(task, context=self.scope.name, max_turns=self.max_turns, timeout=self.timeout)
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
        if not d.get("skip_junk"):
            return 0
        tested = self.eng.state.get("tested")
        if not isinstance(tested, dict):
            tested = {}
        n = 0
        for it in list(self.eng.state.get("surface") or []):
            url = it.get("url") or ""
            if not (_REVIEW_JUNK.search(url) or _Q_STATIC.search(url)):
                continue
            key = f"{url}|{it.get('param','')}|{it.get('vuln_class','')}"
            if key in tested:
                continue
            self.eng.mark_tested(it)
            tested = self.eng.state.get("tested") or tested
            n += 1
        if n:
            self.eng.log(f"review: skipped {n} marketing/static url(s) — the round stays on APIs")
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
        self.eng.set_phase("validate")
        self._apply_review_directives()
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
        self.eng.log(f"validate: {len(pending)} new candidate(s) to verify "
                     f"({len(rejected)} already closed), {self.parallel} at a time")
        for c, v in self._run_parallel(self._validate_agent, pending):
            cls, url = c.get("vuln_class"), c.get("url")
            repro = self._reproduce(c, v)              # INDEPENDENT, deterministic real-vs-not separator
            c["reproduction"] = repro
            llm_real = bool(v and v.get("real"))
            # 1) deterministic DISPROOF overrides an LLM 'real' -> NOT a real bug (kills false positives)
            if repro["status"] == "disproved":
                self.eng.mark_rejected(c, f"disproved via {repro['method']}")
                _lrn("record_outcome", self.scope.name, cls, "false-positive",
                     f"disproved by {repro['method']}: {repro['signal']}", base=self.base)
                self.eng.log(f"validate: ✗ NOT REAL (disproved via {repro['method']}) {cls} @ {url} — {repro['signal']}")
                continue
            # 2) the skeptical validator says it's not real -> drop it, and do not verify it again
            if not llm_real:
                self.eng.mark_rejected(c, (v or {}).get("reason", "") or "false positive")
                _lrn("record_outcome", self.scope.name, cls, "false-positive",
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
                _lrn("record_outcome", self.scope.name, cls,
                     "held-" + disp["verdict"].lower().replace("_", "-"), disp.get("reason", ""), base=self.base)
                self.eng.log(f"validate: HELD {disp['verdict']} {cls} @ {url} — {disp.get('reason','')}")
                continue
            # 4) REAL -> confirm, LABELLED by how we know it's real (reproduced vs LLM-only-needs-manual-check)
            if v.get("severity"):
                c["severity"] = v["severity"]     # use the validator's CALIBRATED severity, not the hunt's
            self.eng.confirm(c, v)
            reproduced = repro["status"] == "reproduced"
            tag = ("✅ CONFIRMED REAL (reproduced)" if reproduced
                   else "⚠ CONFIRMED — LLM-validated but NOT independently reproduced; verify before submit")
            _lrn("record_outcome", self.scope.name, cls,
                 "confirmed" if reproduced else "confirmed-unreproduced", repro["signal"], base=self.base)
            self.eng.log(f"validate: {tag} [{repro['method']}] {cls} @ {url} ({v.get('severity','')})"
                         + (f" ⚠ scope-flagged: {', '.join(c['scope_warning'])}" if c.get('scope_warning') else ''))

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
            try:                                       # 2) two-account cross-account diff (needs identity B)
                import authz as _AZ
                import authn as _AN
                if "B" in _AN.identities(self.scope.name, self.base):
                    d = _AZ.diff_one("GET", c["url"], None, self.scope.name)
                    if d.get("bola_suspect"):
                        return {"status": "reproduced", "method": "two-account-diff",
                                "signal": f"B's request to A's object returned matching data (sim={d.get('similarity')})"}
                    return {"status": "disproved", "method": "two-account-diff",
                            "signal": "two-account diff shows proper isolation — B cannot read A's object"}
            except Exception:  # noqa: BLE001
                pass
        try:                                           # 3) concrete demonstrated impact already in the evidence
            import disposition as _DP
            blob = (str(c.get("evidence", "")) + " " + str((v or {}).get("reason", ""))).lower()
            if _DP._PROOF_SHOWN.search(blob):
                return {"status": "reproduced", "method": "proof-in-evidence",
                        "signal": "concrete demonstrated impact shown in the evidence"}
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
                f"Adversarially verify a claimed finding (be skeptical — default to false positive if unproven). "
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
        r = A.run_agent(task, context=self.scope.name, max_turns=self.max_turns, timeout=self.timeout)  # same pool as hunt
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
            D.annotate(self.scope.name, c, base=self.base)   # tag each finding with dup-risk + nearest match
        except Exception as e:
            self.eng.log(f"report: dedup annotate skipped ({e})")
        s = self.eng.summary()
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
            if rp.get("status"):                        # REAL-vs-not: how we know it's a real bug
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
        open(path, "w").write("\n".join(lines))
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
        for ph in ALL_PHASES:
            if ph in phases:
                try:
                    getattr(self, ph)()
                except Exception as e:                    # one phase failing must not abort the rest
                    self.eng.log(f"phase {ph} error (continuing with partial state): {type(e).__name__}: {e}")
        self.eng.set_phase("done")
        self.eng.log(f"engine done | {self.eng.summary()}")


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
    eng.run(phases)
    print("\n" + json.dumps(eng.eng.summary(), indent=2))
    print("engagement dir:", eng.eng.dir)


if __name__ == "__main__":
    main()
