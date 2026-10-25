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

# Ensure ~/go/bin is in PATH so recon tools (subfinder, httpx, gau, katana, etc.) are found
_gobin = os.path.expanduser("~/go/bin")
if os.path.isdir(_gobin) and _gobin not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = _gobin + os.pathsep + os.environ.get("PATH", "")

from scope import Scope            # noqa: E402
from state import Engagement       # noqa: E402
import agent as A                  # noqa: E402
import modelroute as MR            # noqa: E402

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
        k = (d.get("method", "GET"), d.get("url", ""), d.get("param", ""))
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
_Q_CDN_HOST = re.compile(r"(^|\.)cdn[\d.-]", re.I)
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
ALL_PHASES = ["recon", "explore", "rank", "map", "plan", "hunt", "validate", "chain", "report"]
DEFAULT_PHASES = ["recon", "explore", "rank", "map", "plan"]

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
            netget.set_scope_guard(self.scope)
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
            _j.dump(scope_data, open(tgt_path, "w"), indent=2)
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
                "Open the APIs this session can actually see (profile, bookings, orders, trips, payments, "
                "seats, documents). Collect concrete object URLs the responses returned, with the real id.\n"
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
            "PHASE 1 — DISCOVER (use all of these):\n"
            f"  `python3 {e}/netget.py GET \"<url>\" --as A` — fetch any page/API as logged-in user\n"
            f"  `python3 {e}/browser.py capture --url <seed> --slug {self.scope.name} --as A "
            f"--scope {host or '<host>'}` — capture SPA XHR/fetch/GraphQL calls\n"
            f"  `python3 {e}/recon.py graphql --scope <scope-file>` — GraphQL introspection\n"
            "  Read robots.txt, sitemap.xml, .well-known/*, /api/docs, /swagger*, /openapi*\n"
            "  Check for: /admin, /dashboard, /settings, /internal, /debug, /graphql, /api/v*/\n"
            "  Read JS bundles for API routes: grep for '/api/', 'fetch(', 'axios.', endpoint patterns\n\n"
            "PHASE 2 — MAP (build a complete picture):\n"
            "  For each feature/endpoint found, note: what it does, what data it touches, "
            "what role can access it, what parameters it takes.\n\n"
            "PHASE 3 — RETURN a fenced ```json``` object:\n"
            '{"narrative":"<2-3 sentences: what this product is and who uses it>",'
            '"tech_stack":["detected technologies"],'
            '"roles":["every user role found (admin, user, guest, api-consumer, ...)"],'
            '"auth_mechanism":"cookie|jwt|oauth|apikey|saml|...",'
            '"crown_jewels":["highest-value data/actions — PII, payments, admin, exports"],'
            '"api_surface":[{"method":"GET|POST|...","url":"https://...","function":"what it does",'
            '"params":["param names"],"auth_required":true}],'
            '"flows":[{"what":"<user flow>","url":"https://in-scope/...","why":"<why this flow is dangerous>"}],'
            '"hidden_endpoints":["admin/debug/internal URLs found"],'
            '"deprioritized":["static/marketing/CDN things to skip"]}\n'
            "List EVERY endpoint you find in api_surface — the more complete, the better the hunt. "
            "URLs must be in-scope and real. Do not guess endpoints you didn't verify exist."
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
            self.eng.log(f"explore: skipped ({type(e).__name__}: {e})")

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
            url = s.get("url") or ""
            cls = s.get("vuln_class") or "deep"
            if not url:
                continue
            key = (url, s.get("param", ""))
            g = groups.setdefault(key, {"classes": [], "src": s.get("source", "")})
            if cls not in g["classes"]:
                g["classes"].append(cls)
        tech_sk = SM.tech_skills(tech)
        # self-learning: a detected app/framework with NO playbook is a capability gap -> research +
        # auto-draft a skill so the NEXT hunt already knows it. Infra fingerprints are skipped (too generic).
        learned_now = 0
        for t in ([] if self.mock else tech):        # skip network research during mock/self-test runs
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
            "HUNT METHOD: Fetch the endpoint as the session. Read what it does, every input, object id, "
            "host, and role the response implies. From those bytes, invent a test the developer should have "
            "refused — do NOT start from a vulnerability catalog. Run it. If negative, try a second different "
            "test. Prove impact with in-scope, read-only actions only.\n")
        parts.append(
            "AUTHZ GATE (hard): when identities A and B are both live, do NOT return vulnerable:false "
            "until you have executed both: "
            f"`python3 {e}/authz.py diff --slug {p} --url \"<URL>\"` and "
            f"`python3 {e}/netget.py GET \"<URL>\" --as B`. "
            "analysis must contain `authz:` plus both HTTP statuses and whether B saw A's marker.\n")
        parts.append(
            "PROOF STANDARD: claim a vuln ONLY with demonstrated, exploitable impact (not reflection, "
            "error, or permissive header). IDOR/BOLA: vulnerable:true ONLY with A-vs-B body-diff showing "
            "B received A's unique marker on an attacker-enumerated id. Do NOT nominate: public CDN/UUID "
            "static files, unauthenticated WordPress field-title leaks. "
            "HOLD_RTFS/HOLD_INFORMATIVE still apply.\n")
        parts.append(
            f"OOB TESTING: `python3 {e}/oob.py payload --tag <tag>` → inject → "
            f"`python3 {e}/oob.py poll --tag <tag> --timeout 30`.\n")
        parts.append(self._burp_preamble(e))
        parts.append(self._capabilities_note())
        parts.append(
            "OUTPUT: End with a fenced ```json``` object: "
            '{"vulnerable":true|false,"vuln_class":"<class>","severity":"low|medium|high|critical",'
            '"analysis":"<what endpoint does>","classes_considered":["<tested>"],'
            '"hypotheses":["<next tests>"],"signals_missed":["<seen not proved>"],'
            '"evidence":"<proof>","request":"<winning request>",'
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
            fmap = FM.build_feature_map(self.eng.scope.name, eng_dir=self.eng.dir, state=self.eng.state)
        result = TP.build_test_plan(fmap, state=self.eng.state,
                                    scope={"in_scope": self.eng.scope.in_scope,
                                           "out_of_scope": self.eng.scope.out_of_scope})
        self.eng.state["test_plan"] = result["plan"]
        self.eng.state["test_plan_summary"] = result["summary"]
        plan_path = os.path.join(self.eng.dir, "test-plan.md")
        with open(plan_path, "w") as f:
            f.write(result["markdown"])
        self.eng.log(f"test plan: {result['summary']['total_cases']} cases "
                     f"({result['summary']['pending']} pending, "
                     f"{result['summary']['coverage_pct']}% covered)")

    # ---------------- hunt ----------------
    def hunt(self):
        self.eng.set_phase("hunt")
        self._honor_heals()
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
            prio_order = {"high": 0, "medium": 1, "low": 2}
            pending.sort(key=lambda c: prio_order.get(c.get("priority", "low"), 3))
            plan_items = []
            plan_keys = set()
            for c in pending:
                sk = TP.state_key(c)
                _plan_index[sk] = c
                params = c.get("params") or []
                item = {
                    "url": c.get("endpoint", ""),
                    "method": c.get("method", "GET"),
                    "param": params[0] if params else "",
                    "params": params,
                    "role": c.get("role", ""),
                    "vuln_class": c.get("category", "deep"),
                    "source": "test-plan",
                    "priority": prio_order.get(c.get("priority", "low"), 3),
                    "_plan_key": sk,
                }
                if sk not in plan_keys and item["url"]:
                    plan_keys.add(sk)
                    plan_items.append(item)
            raw_wl = self.eng.worklist()
            other_items = [it for it in raw_wl
                           if TP.state_key({"endpoint": it.get("url", ""), "method": it.get("method", "GET"),
                                            "params": it.get("params") or ([it["param"]] if it.get("param") else []),
                                            "category": it.get("vuln_class", ""), "role": it.get("role", "")})
                           not in plan_keys]
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
                    self.eng.mark_skipped(it, "double_timeout")
                    self.eng.log(f"hunt: INCONCLUSIVE (double-timeout) {it.get('vuln_class')}@{it['url']} "
                                 "— marked skipped, moving on (too heavy for the budget)")
                    continue
            if f and f.get("error"):
                err = f["error"]
                # rate-limit (429): back off and retry once
                if "429" in str(err) or "rate" in str(err).lower():
                    backoff = int(os.environ.get("HUNT_RATE_LIMIT_BACKOFF", "60"))
                    self.eng.log(f"hunt: rate-limited on {it.get('vuln_class')}@{it['url']} "
                                 f"— backing off {backoff}s then retrying")
                    time.sleep(backoff)
                    f = self._hunt_agent(it)
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
                                f = self._hunt_agent(it)
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
                    continue
            # --- classify result BEFORE marking tested ---
            self._feedback_surface(f)                 # endpoints the agent found mid-hunt -> back into the worklist
            if f and f.get("rate_limited"):
                self.eng.log("hunt: ⚠ model usage limit hit — remaining results may be partial")
            _plan_status = None  # determined by result quality, applied after
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
                # Candidate awaits validate phase — mark tested but plan stays "tested" not "confirmed"
                self.eng.mark_tested(it)
                _plan_status = ("tested", f.get("evidence") or f.get("proof_note") or "candidate — awaiting validation")
            elif f and f.get("skipped"):
                self.eng.log(f"hunt: skipped {it.get('vuln_class')}@{it['url']} — {f['skipped']}")
                _plan_status = ("blocked", f.get("skipped") or "skipped by hunt agent")
            else:
                analysis = ""
                classes = []
                if isinstance(f, dict):
                    analysis = f.get("analysis") or ""
                    classes = f.get("classes_considered") or []
                if _logged_out_result(analysis):
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
                        self.eng.log(f"hunt: refused nothing on {it.get('vuln_class')}@{it['url']} "
                                     "— authz.py diff and netget --as B were not run")
                        continue
                    analysis = (str(analysis) + "\n" + line).strip()
                if analysis:
                    self.eng.mark_tested(it)
                    _plan_status = ("tested", analysis[:300])
                else:
                    self.eng.log(f"hunt: no analysis returned for {it.get('vuln_class')}@{it['url']} — left untested")
                self.eng.note_hunt(it, analysis, classes)
                self._remember(it, analysis, classes, result="nothing", finding=f)
                tail = f" — {str(analysis)[:160]}" if analysis else ""
                self.eng.log(f"hunt: nothing on {it.get('vuln_class')}@{it['url']}{tail}")
            # --- update test plan case status ---
            if _plan_status and self._plan_index:
                _sk = it.get("_plan_key") or TP.state_key({
                    "endpoint": it.get("url", ""), "method": it.get("method", "GET"),
                    "params": it.get("params") or ([it["param"]] if it.get("param") else []),
                    "category": it.get("vuln_class", ""), "role": it.get("role", "")})
                _pc = self._plan_index.get(_sk)
                if _pc:
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
        skill_hint = ("Read these ONLY if they match what the live response is: "
                      + ", ".join(f"`{x}`" for x in hinted_paths[:6])
                      + f". Any other hunt-* in {SM.SKILLS_DIR} may be Read. "
                      "They are references, not a menu.")
        task = (self._session_preamble() + "\n"
                f"PENTEST THIS ONE ENDPOINT.\n"
                + lead + memory +
                f"URL: {url}   method: {it.get('method','GET')}   known param(s): {it.get('param','')}   "
                f"tech: {', '.join(tech) or 'unknown'}\n"
                "Use the session's Cookie/headers on EVERY request. "
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
            f"- No playbook for a stack/vuln/bypass? Teach the harness: "
            f"`python3 {e}/learn.py auto --kind <tech|vuln|bypass|program> --name \"<thing>\" --context \"<why>\"` — reads it after drafting.\n"
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
        pool = []
        for key in ("OPENCODE_HUNT_MODELS", "CURSOR_HUNT_MODELS", "HUNT_MODELS"):
            pool = [m.strip() for m in os.environ.get(key, "").split(",") if m.strip()]
            if pool:
                break
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
        # DETERMINISTIC 2-account IDOR/BOLA shortcut — runs before the LLM call.
        # If B can read A's object, that's a confirmed IDOR without burning an agent.
        if str(it.get("url", "")).startswith("http"):
            try:
                import authn as _AN
                import authz as _AZ
                ids = _AN.identities(self.scope.name, self.base)
                if "A" in ids and "B" in ids:
                    d = _AZ.diff_one("GET", it["url"], None, self.scope.name)
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
        if not model:
            ctx = {"vuln_class": it.get("vuln_class"), "params": len(it.get("params") or []),
                   "auth_required": it.get("auth_required", False),
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
        for it in list(self.eng.state.get("surface") or []):
            url = it.get("url") or ""
            if not (_skip_static_url(url) or (skip_junk and _REVIEW_JUNK.search(url))):
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
        real_todo = [it for it in self.eng.worklist()
                     if not _skip_static_url(it.get("url") or "")
                     and not _REVIEW_JUNK.search(it.get("url") or "")]
        has_candidates = bool(self.eng.state.get("candidates"))
        if len(real_todo) > 20 and not has_candidates:
            self.eng.log(f"validate: {len(real_todo)} real url(s) still untested and no candidates — staying on hunt")
            return
        if len(real_todo) > 20:
            self.eng.log(f"validate: {len(real_todo)} url(s) still untested but {len(self.eng.state['candidates'])} candidate(s) pending — validating candidates")
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
        survivors = []
        for c in pending:
            cls, url = c.get("vuln_class"), c.get("url")
            pre = self._reproduce(c, None)
            if pre["status"] == "disproved":
                c["reproduction"] = pre
                self.eng.mark_rejected(c, f"disproved via {pre['method']}")
                _lrn("record_outcome", self.scope.name, cls, "false-positive",
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
        # post-validate: evolve learned skills with accumulated outcomes
        try:
            evolved = _lrn("evolve_all", base=self.base)
            if evolved:
                for slug, info in (evolved or {}).items():
                    self.eng.log(f"learn: evolved skill '{slug}' — {info.get('confirmed',0)} confirmed, "
                                 f"{info.get('fp',0)} FP, {info.get('dup',0)} dup")
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
                    _ph_start = time.time()
                    try:
                        getattr(self, ph)()
                    except Exception as e:
                        failed_phases.append({"phase": ph, "error": f"{type(e).__name__}: {e}"})
                        self.eng.log(f"phase {ph} error (continuing with partial state): {type(e).__name__}: {e}")
                    phase_timings[ph] = round(time.time() - _ph_start, 1)
                    self.eng.save()
        finally:
            signal.signal(signal.SIGINT, _prev_int)
            signal.signal(signal.SIGTERM, _prev_term)
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
    eng.run(phases)
    print("\n" + json.dumps(eng.eng.summary(), indent=2))
    print("engagement dir:", eng.eng.dir)


if __name__ == "__main__":
    main()
