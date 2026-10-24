#!/usr/bin/env python3
"""
oob.py — out-of-band callback server for blind vulnerability confirmation.

Wraps interactsh-client to provide:
  - A unique OOB domain per session
  - Tagged payloads for correlating callbacks to specific tests
  - Polling for interactions with timeout
  - Automatic cleanup

Usage from hunt agents:
  python3 engine/engine/oob.py start          # prints the OOB domain
  python3 engine/engine/oob.py payload --tag ssrf-1
  python3 engine/engine/oob.py poll --tag ssrf-1 [--timeout 30]
  python3 engine/engine/oob.py stop

Programmatic:
  from oob import OOBServer
  srv = OOBServer.start()
  payload = srv.get_payload("ssrf-test-1")
  # ... send payload to target ...
  hits = srv.poll("ssrf-test-1", timeout=30)
  srv.stop()
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

_STATE_DIR = os.path.join(os.path.expanduser("~/.bughunter-engagements"), "oob")
_PID_FILE = os.path.join(_STATE_DIR, "interactsh.pid")
_DOMAIN_FILE = os.path.join(_STATE_DIR, "domain.txt")
_LOG_FILE = os.path.join(_STATE_DIR, "interactions.jsonl")


def _burp_collaborator_available():
    try:
        from burp import is_burp_available
        return is_burp_available()
    except ImportError:
        return False


def _interactsh_bin():
    for name in ("interactsh-client", os.path.expanduser("~/go/bin/interactsh-client")):
        if shutil.which(name) or os.path.isfile(name):
            return name if shutil.which(name) else name
    return None


class OOBServer:
    def __init__(self, domain, pid):
        self.domain = domain
        self.pid = pid

    @staticmethod
    def start(timeout=15):
        """Start interactsh-client in background, return OOBServer with the domain."""
        binary = _interactsh_bin()
        if not binary:
            raise RuntimeError("interactsh-client not found. Install: go install "
                               "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
        os.makedirs(_STATE_DIR, exist_ok=True)
        # Kill any existing instance
        OOBServer._kill_existing()
        proc = subprocess.Popen(
            [binary, "-json", "-o", _LOG_FILE, "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        # Wait for the domain line
        domain = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            # interactsh-client prints the domain in its banner
            m = re.search(r"([a-z0-9]+\.oast\.\w+)", line)
            if not m:
                m = re.search(r"([a-z0-9]+\.[a-z0-9]+\.interactsh\.\w+)", line)
            if not m:
                m = re.search(r"Using\s+(\S+)\s+as", line, re.IGNORECASE)
            if m:
                domain = m.group(1)
                break
        if not domain:
            proc.kill()
            raise RuntimeError("Failed to get OOB domain from interactsh-client")
        with open(_PID_FILE, "w") as f:
            f.write(str(proc.pid))
        with open(_DOMAIN_FILE, "w") as f:
            f.write(domain)
        return OOBServer(domain, proc.pid)

    def get_payload(self, tag):
        """Generate a tagged OOB payload URL."""
        return f"{tag}.{self.domain}"

    def poll(self, tag=None, timeout=30):
        """Poll for OOB interactions, optionally filtered by tag."""
        deadline = time.time() + timeout
        hits = []
        while time.time() < deadline:
            hits = self._read_interactions(tag)
            if hits:
                return hits
            time.sleep(2)
        return hits

    def _read_interactions(self, tag=None):
        hits = []
        if not os.path.isfile(_LOG_FILE):
            return hits
        try:
            with open(_LOG_FILE, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if tag and tag not in rec.get("full-id", "") and tag not in rec.get("unique-id", ""):
                        continue
                    hits.append({
                        "protocol": rec.get("protocol", "unknown"),
                        "full_id": rec.get("full-id", ""),
                        "remote_address": rec.get("remote-address", ""),
                        "timestamp": rec.get("timestamp", ""),
                        "raw_request": rec.get("raw-request", "")[:500],
                    })
        except OSError:
            pass
        return hits

    def stop(self):
        OOBServer._kill_existing()

    @staticmethod
    def _kill_existing():
        if os.path.isfile(_PID_FILE):
            try:
                pid = int(open(_PID_FILE).read().strip())
                os.kill(pid, 9)
            except (ValueError, OSError):
                pass
            try:
                os.remove(_PID_FILE)
            except OSError:
                pass

    @staticmethod
    def load():
        """Load an existing running server from state files."""
        if not os.path.isfile(_DOMAIN_FILE) or not os.path.isfile(_PID_FILE):
            return None
        try:
            domain = open(_DOMAIN_FILE).read().strip()
            pid = int(open(_PID_FILE).read().strip())
            os.kill(pid, 0)  # check alive
            return OOBServer(domain, pid)
        except (OSError, ValueError):
            return None


# --- CLI ---
def _cmd_start(_a):
    srv = OOBServer.start()
    print(f"OOB domain: {srv.domain}")
    print(f"PID: {srv.pid}")
    return 0

def _cmd_payload(a):
    srv = OOBServer.load()
    if not srv:
        print("No running OOB server. Run: python3 engine/engine/oob.py start", file=sys.stderr)
        return 1
    print(srv.get_payload(a.tag))
    return 0

def _cmd_poll(a):
    srv = OOBServer.load()
    if not srv:
        print("No running OOB server.", file=sys.stderr)
        return 1
    hits = srv.poll(tag=a.tag, timeout=a.timeout)
    if hits:
        print(json.dumps(hits, indent=2))
    else:
        print(f"No interactions for tag '{a.tag}' within {a.timeout}s")
    return 0 if hits else 1

def _cmd_stop(_a):
    OOBServer._kill_existing()
    print("OOB server stopped")
    return 0

def _cmd_selftest(_a):
    binary = _interactsh_bin()
    if not binary:
        print("SKIP: interactsh-client not installed")
        return 0
    print(f"interactsh-client found: {binary}")
    print("oob.py self-test: PASS (binary present, full test requires network)")
    return 0

def main(argv=None):
    ap = argparse.ArgumentParser(description="OOB callback server for blind vuln confirmation")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("start").set_defaults(fn=_cmd_start)
    pp = sub.add_parser("payload")
    pp.add_argument("--tag", required=True)
    pp.set_defaults(fn=_cmd_payload)
    po = sub.add_parser("poll")
    po.add_argument("--tag", default=None)
    po.add_argument("--timeout", type=int, default=30)
    po.set_defaults(fn=_cmd_poll)
    sub.add_parser("stop").set_defaults(fn=_cmd_stop)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)

if __name__ == "__main__":
    sys.exit(main())
