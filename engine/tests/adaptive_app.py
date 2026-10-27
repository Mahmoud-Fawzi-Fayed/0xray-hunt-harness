#!/usr/bin/env python3
"""Schema-less local target for response-driven discovery and workflow evaluation."""
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse


class AdaptiveHandler(BaseHTTPRequestHandler):
    transitions = {}

    def log_message(self, *_args):
        pass

    def _send(self, status, body, content_type, extra=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, value, status=200):
        self._send(status, json.dumps(value), "application/json")

    def do_OPTIONS(self):
        self._send(204, "", "text/plain", {"Allow": "GET, POST, OPTIONS"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._send(200, """<!doctype html><title>Unlabelled</title>
<a href='/catalog/alpha'>catalog</a>
<form action='/catalog/alpha' method='get'><input name='view'><input name='record'></form>
""", "text/html")
        elif path == "/catalog/alpha":
            query = parse_qs(parsed.query)
            self._json({"items": [{"id": "alpha", "selected": query.get("record", [""])[0]}],
                        "navigation": {"next": "/operations/dispatch"},
                        "delivery": {"events": "/streams/activity"},
                        "start": "/transitions/begin"})
        elif path == "/operations/dispatch":
            self._json({"operations": [{"method": "POST", "href": "/operations/dispatch",
                                       "protocol": "json-rpc", "function": "perform_operation",
                                       "input": {"operation": "string", "arguments": "object"},
                                       "owner": "account-alpha"}]})
        elif path == "/streams/activity":
            self._send(200, 'event: update\ndata: {"continuation": "/transitions/begin"}\n\n',
                       "text/event-stream")
        elif path == "/transitions/begin":
            self._send(200, """<form action='/transitions/begin' method='post'>
<input name='account'><input name='amount'><button>Begin</button></form>""", "text/html")
        elif path.startswith("/transitions/"):
            transition = self.transitions.get(path.rsplit("/", 1)[-1])
            self._json(transition or {"error": "unknown transition"}, 200 if transition else 404)
        else:
            self._json({"error": "unavailable"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json({"error": "invalid representation"}, 400)
            return
        if path == "/operations/dispatch":
            self._json({"accepted": data.get("operation"), "actor": "account-alpha",
                        "receipt": data.get("arguments", {})})
        elif path == "/transitions/begin":
            token = f"local-{len(self.transitions) + 1}"
            self.transitions[token] = {"state": "opened", "account": data.get("account")}
            self._json({"state": "opened", "next": f"/transitions/{token}"}, 201)
        elif path.startswith("/transitions/"):
            token = path.rsplit("/", 1)[-1]
            if token not in self.transitions:
                self._json({"error": "unknown transition"}, 404)
            elif self.transitions[token]["state"] != "opened":
                self._json({"error": "precondition failed", "state": self.transitions[token]["state"]}, 409)
            else:
                self.transitions[token]["state"] = "finished"
                self._json(self.transitions[token])
        else:
            self._json({"error": "unavailable"}, 404)


def start_threaded(port=19882):
    AdaptiveHandler.transitions = {}
    server = HTTPServer(("127.0.0.1", port), AdaptiveHandler, bind_and_activate=False)
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return server
