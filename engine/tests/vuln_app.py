#!/usr/bin/env python3
"""
vuln_app.py — minimal intentionally-vulnerable test application for e2e harness validation.

Has two users (A/B), multiple roles, REST APIs, hidden features, and known vulnerabilities:
  - IDOR: GET /api/users/:id returns any user's data without ownership check
  - XSS: GET /api/search?q= reflects query param unescaped in response
  - Info disclosure: GET /api/debug returns server env info
  - Missing auth: GET /api/admin/users accessible without admin role
  - CSRF: POST /api/transfer has no CSRF token
  - Open redirect: GET /redirect?url= redirects without validation

Run:
  python3 engine/tests/vuln_app.py                    # start on port 9999
  python3 engine/tests/vuln_app.py --port 9999        # custom port
"""
import argparse
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

USERS = {
    "1": {"id": "1", "email": "alice@test.local", "name": "Alice", "role": "admin", "secret": "alice-secret-data"},
    "2": {"id": "2", "email": "bob@test.local", "name": "Bob", "role": "user", "secret": "bob-secret-data"},
}
SESSIONS = {
    "session-alice": "1",
    "session-bob": "2",
}


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

    def _current_user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid" and v in SESSIONS:
                return USERS.get(SESSIONS[v])
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:] in SESSIONS:
            return USERS.get(SESSIONS[auth[7:]])
        return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        # --- Home ---
        if path == "/":
            self._html(200, """<!DOCTYPE html>
<html><head><title>VulnApp</title></head><body>
<h1>VulnApp Test Target</h1>
<nav><a href="/login">Login</a> <a href="/dashboard">Dashboard</a> <a href="/admin">Admin</a></nav>
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

        # --- Dashboard (auth required) ---
        if path == "/dashboard":
            user = self._current_user()
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
                       "<a href='/api/debug'>Debug Info</a></body></html>")
            return

        # --- IDOR: any user's data without ownership check ---
        if path.startswith("/api/users/"):
            uid = path.split("/")[-1]
            user = USERS.get(uid)
            if user:
                self._json(200, user)
            else:
                self._json(404, {"error": "user not found"})
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

        # --- Notifications (auth) ---
        if path == "/api/v1/notifications":
            user = self._current_user()
            if not user:
                self._json(401, {"error": "auth required"})
                return
            self._json(200, {"notifications": []})
            return

        # --- Hidden internal endpoint ---
        if path == "/api/internal/debug":
            self._json(200, {"internal": True, "build": "dev-2024", "flags": ["beta-ui", "new-billing"]})
            return

        self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        # --- Login ---
        if path == "/api/login":
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = dict(p.split("=", 1) for p in body.decode().split("&") if "=" in p)
            email = data.get("email", "")
            for uid, user in USERS.items():
                if user["email"] == email:
                    sid = f"session-{user['name'].lower()}"
                    self._json(200, {"success": True, "user": user["name"], "session": sid})
                    return
            self._json(401, {"error": "invalid credentials"})
            return

        # --- CSRF-vulnerable transfer (no token check) ---
        if path == "/api/transfer":
            user = self._current_user()
            if not user:
                self._json(401, {"error": "auth required"})
                return
            self._json(200, {"status": "transferred", "from": user["id"]})
            return

        self._json(404, {"error": "not found"})


def serve(port=9999):
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"vuln_app: listening on http://127.0.0.1:{port}")
    print(f"  Users: alice@test.local (admin), bob@test.local (user)")
    print(f"  Sessions: Cookie: sid=session-alice / sid=session-bob")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="intentionally vulnerable test app")
    ap.add_argument("--port", type=int, default=9999)
    serve(ap.parse_args().port)
