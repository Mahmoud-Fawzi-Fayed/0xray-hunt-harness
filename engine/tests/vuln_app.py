#!/usr/bin/env python3
"""
vuln_app.py — intentionally-vulnerable test application for e2e harness validation.

Multi-tenant, multi-role, with known vulns AND correctly protected controls.

Tenants:
  Tenant 1: Alice (admin, id=1), Bob (user, id=2)
  Tenant 2: Carol (admin, id=3), Dave (user, id=4)

Known vulnerabilities:
  - IDOR: GET /api/users/:id returns any user's full data without ownership check
  - IDOR: PATCH /api/users/:id updates any user without ownership check
  - Authz: DELETE /api/users/:id requires admin but no tenant/ownership check
  - XSS: GET /api/search?q= reflects query param unescaped
  - Info disclosure: GET /api/debug returns server env info
  - Missing auth: GET /api/admin/users accessible without admin role
  - CSRF: POST /api/transfer has no CSRF token
  - Open redirect: GET /redirect?url= redirects without validation

Correctly protected (must NOT be flagged):
  - GET /api/users/:id?fields=public returns only public data
  - POST /api/admin/config requires admin role + CSRF token
  - GET /api/v1/notifications requires auth (401 without)

Special behaviors:
  - session-expired token returns 401 with expired message
  - 429 rate limit after 50 requests/60s per session
  - POST /api/async-transfer returns 202 + job_id; GET /api/jobs/:id tracks status
  - /app serves SPA with hidden fetch endpoint
  - /api/research/* allowed; /api/internal/* excluded in scope policy

OOS sink:
  Runs on APP_PORT+1. Records all requests. Use get_oos_requests() to inspect.

Run:
  python3 engine/tests/vuln_app.py                    # start on port 9999
  python3 engine/tests/vuln_app.py --port 9999        # custom port
"""
import argparse
import json
import os
import sys
import time
import threading
import uuid
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

OOS_SINK_PORT_OFFSET = 1

# --- Data ---

USERS = {
    "1": {"id": "1", "email": "alice@test.local", "name": "Alice", "role": "admin",
          "tenant": "t1", "secret": "alice-secret-data", "public_name": "Alice A."},
    "2": {"id": "2", "email": "bob@test.local", "name": "Bob", "role": "user",
          "tenant": "t1", "secret": "bob-secret-data", "public_name": "Bob B."},
    "3": {"id": "3", "email": "carol@test.local", "name": "Carol", "role": "admin",
          "tenant": "t2", "secret": "carol-secret-data", "public_name": "Carol C."},
    "4": {"id": "4", "email": "dave@test.local", "name": "Dave", "role": "user",
          "tenant": "t2", "secret": "dave-secret-data", "public_name": "Dave D."},
}

SESSIONS = {
    "session-alice": "1",
    "session-bob": "2",
    "session-carol": "3",
    "session-dave": "4",
}

CSRF_TOKENS = {
    "1": "csrf-token-alice-abc123",
    "3": "csrf-token-carol-def456",
}

# Mutable state for async jobs and rate limiting
_jobs = {}
_rate_counts = defaultdict(list)  # session -> [timestamps]
_RATE_LIMIT = 50
_RATE_WINDOW = 60

# --- OOS Sink ---

_oos_requests = []
_oos_lock = threading.Lock()


def get_oos_requests():
    with _oos_lock:
        return list(_oos_requests)


def clear_oos_requests():
    with _oos_lock:
        _oos_requests.clear()


class OOSSinkHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self, method):
        with _oos_lock:
            _oos_requests.append({
                "method": method,
                "path": self.path,
                "headers": dict(self.headers),
                "time": time.time(),
            })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"sink": true}')

    def do_GET(self):
        self._record("GET")

    def do_POST(self):
        self._record("POST")

    def do_PUT(self):
        self._record("PUT")

    def do_PATCH(self):
        self._record("PATCH")

    def do_DELETE(self):
        self._record("DELETE")

    def do_HEAD(self):
        self._record("HEAD")

    def do_OPTIONS(self):
        self._record("OPTIONS")


# --- Main App ---

class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_id(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def _current_user(self):
        sid = self._session_id()
        if not sid:
            return None
        if sid == "session-expired":
            return "EXPIRED"
        if sid in SESSIONS:
            return USERS.get(SESSIONS[sid])
        return None

    def _check_rate_limit(self):
        sid = self._session_id()
        if not sid:
            return False
        now = time.time()
        times = _rate_counts[sid]
        _rate_counts[sid] = [t for t in times if now - t < _RATE_WINDOW]
        if len(_rate_counts[sid]) >= _RATE_LIMIT:
            return True
        _rate_counts[sid].append(now)
        return False

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _parse_body(self, raw):
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return dict(p.split("=", 1) for p in raw.decode().split("&") if "=" in p)

    def do_GET(self):
        if self._check_rate_limit():
            self._json(429, {"error": "rate limit exceeded", "retry_after": _RATE_WINDOW})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        # --- Home ---
        if path == "/":
            self._html(200, """<!DOCTYPE html>
<html><head><title>VulnApp</title></head><body>
<h1>VulnApp Test Target</h1>
<nav><a href="/login">Login</a> <a href="/dashboard">Dashboard</a> <a href="/admin">Admin</a> <a href="/app">App</a></nav>
<form action="/api/search" method="GET"><input name="q" placeholder="Search"><button>Go</button></form>
<script>fetch("/api/v1/notifications");const role="user";path:"/api/internal/debug"</script>
</body></html>""")
            return

        # --- Login page ---
        if path == "/login":
            self._html(200, """<!DOCTYPE html><html><body>
<form action="/api/login" method="POST">
<input name="email" type="email"><input name="password" type="password">
<button type="submit">Login</button></form></body></html>""")
            return

        # --- SPA page (hidden endpoint discoverable only via JS execution) ---
        if path == "/app":
            self._html(200, """<!DOCTYPE html><html><head><title>VulnApp SPA</title></head><body>
<div id="root">Loading...</div>
<script>
fetch("/api/v1/hidden-endpoint").then(r=>r.json()).then(d=>{
  document.getElementById("root").innerHTML = "<h1>App Loaded</h1>";
});
function loadSettings() { fetch("/api/v1/user-settings"); }
</script>
<button onclick="loadSettings()">Settings</button>
<a href="/app/profile">My Profile</a>
<a href="/app/transfers">Transfers</a>
</body></html>""")
            return

        if path == "/app/profile":
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "authentication required"})
                return
            uid = user['id']
            self._html(200, f"<html><body><h1>{user['name']}'s Profile</h1>"
                       f"<form action='/api/users/{uid}' method='POST'>"
                       f"<input name='_method' value='PATCH'><input name='name'>"
                       f"<button>Update</button></form></body></html>")
            return

        if path == "/app/transfers":
            user = self._current_user()
            if not user or user == "EXPIRED":
                self._json(401, {"error": "authentication required"})
                return
            self._html(200, f"<html><body><h1>Transfers</h1>"
                       f"<form action='/api/async-transfer' method='POST'>"
                       f"<input name='to'><input name='amount'>"
                       f"<button>Transfer</button></form></body></html>")
            return

        # --- Dashboard (auth required) ---
        if path == "/dashboard":
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "authentication required"})
                return
            self._html(200, f"<html><body><h1>Welcome {user['name']}</h1>"
                       f"<a href='/api/users/{user['id']}'>My Profile</a>"
                       f"<form action='/api/transfer' method='POST'>"
                       f"<input name='to'><input name='amount'><button>Transfer</button></form>"
                       f"</body></html>")
            return

        # --- Admin panel (missing role check - vuln!) ---
        if path == "/admin":
            self._html(200, "<html><body><h1>Admin Panel</h1>"
                       "<a href='/api/admin/users'>Manage Users</a>"
                       "<a href='/api/admin/config'>Config</a>"
                       "<a href='/api/debug'>Debug Info</a></body></html>")
            return

        # --- IDOR: any user's data without ownership check ---
        if path.startswith("/api/users/"):
            uid = path.split("/")[-1]
            user = USERS.get(uid)
            if not user:
                self._json(404, {"error": "user not found"})
                return
            fields = qs.get("fields", [""])[0]
            if fields == "public":
                self._json(200, {"id": user["id"], "public_name": user["public_name"], "role": user["role"]})
                return
            self._json(200, user)
            return

        # --- XSS: reflected search ---
        if path == "/api/search":
            q = qs.get("q", [""])[0]
            self._html(200, f"<html><body><h2>Results for: {q}</h2><p>No results</p></body></html>")
            return

        # --- Info disclosure: debug endpoint ---
        if path == "/api/debug":
            self._json(200, {"server": "vuln-app/1.0", "python": sys.version,
                             "env": dict(os.environ), "users_count": len(USERS)})
            return

        # --- Missing auth on admin endpoint ---
        if path == "/api/admin/users":
            self._json(200, {"users": list(USERS.values())})
            return

        # --- Open redirect ---
        if path == "/redirect":
            url = qs.get("url", [""])[0]
            if url:
                self.send_response(302)
                self.send_header("Location", url)
                self.end_headers()
                return
            self._json(400, {"error": "missing url param"})
            return

        # --- Notifications (auth required — correctly protected) ---
        if path == "/api/v1/notifications":
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "auth required"})
                return
            self._json(200, {"notifications": [], "tenant": user["tenant"]})
            return

        # --- Hidden endpoints (discoverable via SPA JS) ---
        if path == "/api/v1/hidden-endpoint":
            self._json(200, {"features": ["transfers", "settings", "admin-tools"],
                             "version": "2.1.0"})
            return

        if path == "/api/v1/user-settings":
            user = self._current_user()
            if not user or user == "EXPIRED":
                self._json(401, {"error": "auth required"})
                return
            self._json(200, {"theme": "dark", "locale": "en", "tenant": user["tenant"]})
            return

        # --- Hidden internal endpoint (should be excluded by scope policy) ---
        if path.startswith("/api/internal/"):
            self._json(200, {"internal": True, "build": "dev-2024",
                             "flags": ["beta-ui", "new-billing"],
                             "path": path})
            return

        # --- Research endpoint (allowed path) ---
        if path.startswith("/api/research/"):
            topic = path.split("/")[-1]
            self._json(200, {"topic": topic, "results": [f"paper-{topic}-1", f"paper-{topic}-2"]})
            return

        # --- Async job status ---
        if path.startswith("/api/jobs/"):
            job_id = path.split("/")[-1]
            job = _jobs.get(job_id)
            if not job:
                self._json(404, {"error": "job not found"})
                return
            elapsed = time.time() - job["created"]
            status = "completed" if elapsed > 2 else "pending"
            self._json(200, {"job_id": job_id, "status": status,
                             "from": job["from"], "to": job["to"],
                             "amount": job["amount"]})
            return

        # --- OpenAPI spec (documented discovery source) ---
        if path in ("/openapi.json", "/api-docs"):
            spec = {
                "openapi": "3.0.3",
                "info": {"title": "VulnApp API", "version": "1.0.0"},
                "paths": {
                    "/api/users/{id}": {
                        "get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}]},
                        "patch": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}],
                                  "requestBody": {"content": {"application/json": {"schema": {
                                      "properties": {"name": {"type": "string"}, "email": {"type": "string"}}}}}}},
                        "delete": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}]},
                    },
                    "/api/search": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}},
                    "/api/transfer": {"post": {}},
                    "/api/admin/users": {"get": {}},
                    "/api/admin/config": {"post": {}},
                    "/api/v1/notifications": {"get": {}},
                    "/api/roles/promote": {"post": {"description": "Promote user role"}},
                },
            }
            self._json(200, spec)
            return

        # --- GraphQL endpoint ---
        if path == "/graphql" and self.command == "GET":
            q = qs.get("query", [""])[0]
            if "IntrospectionQuery" in q or "__schema" in q:
                schema = {"data": {"__schema": {"types": [
                    {"name": "Query", "fields": [
                        {"name": "user", "args": [{"name": "id"}]},
                        {"name": "users", "args": []},
                        {"name": "me", "args": []},
                    ]},
                    {"name": "Mutation", "fields": [
                        {"name": "updateUser", "args": [{"name": "id"}, {"name": "name"}]},
                        {"name": "deleteUser", "args": [{"name": "id"}]},
                        {"name": "transferFunds", "args": [{"name": "to"}, {"name": "amount"}]},
                    ]},
                ]}}}
                self._json(200, schema)
                return
            self._json(200, {"data": {"message": "GraphQL query processed"}})
            return

        # --- Role escalation: promote endpoint (VULN: no admin check) ---
        if path == "/api/roles/promote":
            user = self._current_user()
            if not user:
                self._json(401, {"error": "auth required"})
                return
            self._json(200, {"status": "promoted", "user": user["id"], "new_role": "admin"})
            return

        # --- Redirect to OOS sink (tests redirect scope enforcement) ---
        if path == "/api/redirect-oos":
            oos_port = int(self.server.server_address[1]) + OOS_SINK_PORT_OFFSET
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{oos_port}/redirected-oos")
            self.end_headers()
            return

        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self._check_rate_limit():
            self._json(429, {"error": "rate limit exceeded", "retry_after": _RATE_WINDOW})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        raw = self._read_body()

        # --- Login ---
        if path == "/api/login":
            data = self._parse_body(raw)
            email = data.get("email", "")
            for uid, user in USERS.items():
                if user["email"] == email:
                    sid = f"session-{user['name'].lower()}"
                    self._json(200, {"success": True, "user": user["name"],
                                     "session": sid, "tenant": user["tenant"]})
                    return
            self._json(401, {"error": "invalid credentials"})
            return

        # --- CSRF-vulnerable transfer (no token check) ---
        if path == "/api/transfer":
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "auth required"})
                return
            self._json(200, {"status": "transferred", "from": user["id"],
                             "tenant": user["tenant"]})
            return

        # --- Async transfer (returns 202) ---
        if path == "/api/async-transfer":
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "auth required"})
                return
            data = self._parse_body(raw)
            job_id = str(uuid.uuid4())[:8]
            _jobs[job_id] = {
                "from": user["id"],
                "to": data.get("to", ""),
                "amount": data.get("amount", "0"),
                "created": time.time(),
                "tenant": user["tenant"],
            }
            self._json(202, {"status": "accepted", "job_id": job_id,
                             "poll": f"/api/jobs/{job_id}"})
            return

        # --- Admin config (correctly protected: admin + CSRF token) ---
        if path == "/api/admin/config":
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "auth required"})
                return
            if user["role"] != "admin":
                self._json(403, {"error": "admin role required"})
                return
            data = self._parse_body(raw)
            expected_token = CSRF_TOKENS.get(user["id"])
            if not expected_token or data.get("csrf_token") != expected_token:
                self._json(403, {"error": "invalid or missing CSRF token"})
                return
            self._json(200, {"status": "config updated", "by": user["id"]})
            return

        # --- GraphQL POST ---
        if path == "/graphql":
            data = self._parse_body(raw)
            query = data.get("query", "")
            if "__schema" in query or "IntrospectionQuery" in query:
                self._json(200, {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "Mutation"}]}}})
                return
            user = self._current_user()
            if "user(" in query and user:
                self._json(200, {"data": {"user": USERS.get(user["id"], {})}})
                return
            self._json(200, {"data": None, "errors": [{"message": "auth required"}]})
            return

        # --- Role escalation POST (VULN: any user can promote themselves) ---
        if path == "/api/roles/promote":
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired"})
                return
            if not user:
                self._json(401, {"error": "auth required"})
                return
            data = self._parse_body(raw)
            target_role = data.get("role", "admin")
            self._json(200, {"status": "promoted", "user_id": user["id"],
                             "old_role": user["role"], "new_role": target_role})
            return

        self._json(404, {"error": "not found"})

    def do_PATCH(self):
        if self._check_rate_limit():
            self._json(429, {"error": "rate limit exceeded", "retry_after": _RATE_WINDOW})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        raw = self._read_body()

        # --- IDOR: PATCH any user without ownership check ---
        if path.startswith("/api/users/"):
            uid = path.split("/")[-1]
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "auth required"})
                return
            target = USERS.get(uid)
            if not target:
                self._json(404, {"error": "user not found"})
                return
            # VULN: no ownership check — any authed user can update any user
            data = self._parse_body(raw)
            for k in ("name", "email"):
                if k in data:
                    target[k] = data[k]
            self._json(200, {"status": "updated", "user": target})
            return

        self._json(404, {"error": "not found"})

    def do_DELETE(self):
        if self._check_rate_limit():
            self._json(429, {"error": "rate limit exceeded", "retry_after": _RATE_WINDOW})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # --- Authz vuln: DELETE requires admin but no tenant/ownership check ---
        if path.startswith("/api/users/"):
            uid = path.split("/")[-1]
            user = self._current_user()
            if user == "EXPIRED":
                self._json(401, {"error": "session expired", "code": "SESSION_EXPIRED"})
                return
            if not user:
                self._json(401, {"error": "auth required"})
                return
            if user["role"] != "admin":
                self._json(403, {"error": "admin role required"})
                return
            target = USERS.get(uid)
            if not target:
                self._json(404, {"error": "user not found"})
                return
            # VULN: admin from tenant 1 can delete user from tenant 2
            self._json(200, {"status": "deleted", "user_id": uid, "by": user["id"]})
            return

        self._json(404, {"error": "not found"})


# --- Server management ---

def _start_oos_sink(port):
    server = HTTPServer(("127.0.0.1", port), OOSSinkHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def serve(port=9999, start_sink=True):
    clear_oos_requests()
    _jobs.clear()
    _rate_counts.clear()

    sink = None
    sink_port = port + OOS_SINK_PORT_OFFSET
    if start_sink:
        sink = _start_oos_sink(sink_port)
        print(f"vuln_app: OOS sink on http://127.0.0.1:{sink_port}")

    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"vuln_app: listening on http://127.0.0.1:{port}")
    print(f"  Tenant 1: alice@test.local (admin), bob@test.local (user)")
    print(f"  Tenant 2: carol@test.local (admin), dave@test.local (user)")
    print(f"  Sessions: Cookie: sid=session-alice / sid=session-bob / sid=session-carol / sid=session-dave")
    print(f"  Expired:  Cookie: sid=session-expired")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    if sink:
        sink.shutdown()
        sink.server_close()


def start_threaded(port=19876):
    """Start app + OOS sink in background threads. Returns (app_server, sink_server, sink_port)."""
    clear_oos_requests()
    _jobs.clear()
    _rate_counts.clear()

    sink_port = port + OOS_SINK_PORT_OFFSET
    sink = _start_oos_sink(sink_port)

    app = HTTPServer(("127.0.0.1", port), VulnHandler)
    t = threading.Thread(target=app.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    return app, sink, sink_port


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="intentionally vulnerable test app")
    ap.add_argument("--port", type=int, default=9999)
    serve(ap.parse_args().port)
