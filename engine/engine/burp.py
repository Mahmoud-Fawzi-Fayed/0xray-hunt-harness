#!/usr/bin/env python3
"""
burp.py — Burp Suite Professional MCP integration for the hunt harness.

When Burp Pro is running with the MCP BApp extension (port 9876), the harness
can use it for:
  - HTTP request sending (through Burp proxy → captured in history/sitemap)
  - Burp Collaborator (OOB callbacks — superior to interactsh for Burp users)
  - Passive/active scan results
  - Sitemap and proxy history querying

The Burp MCP server exposes these tools (official BApp, mid-2026):
  mcp__burp__send_http1_request     — send HTTP/1.1 request through Burp
  mcp__burp__send_http2_request     — send HTTP/2 request through Burp
  mcp__burp__generate_collaborator_payload — get a unique Collaborator subdomain
  mcp__burp__get_collaborator_interactions — poll for OOB interactions
  mcp__burp__get_sitemap            — get target sitemap entries
  mcp__burp__get_proxy_history      — get proxy history entries
  mcp__burp__get_scan_issues        — get scanner-reported issues
  mcp__burp__send_to_repeater       — send a request to Repeater tab
  mcp__burp__active_scan            — launch active scan on a URL

Setup:
  1. Burp Pro open with MCP BApp extension loaded (Extender → BApp Store → "MCP Server")
  2. MCP server listening on 127.0.0.1:9876
  3. Register with Claude Code:
     claude mcp add burp -s user -- java -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876

CLI:
  python3 engine/engine/burp.py status              # check Burp MCP connectivity
  python3 engine/engine/burp.py setup               # register Burp MCP in Claude Code + OpenCode
  python3 engine/engine/burp.py collaborator         # get a Collaborator payload (tests connectivity)
"""
import argparse
import json
import os
import subprocess
import sys
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))

# Default Burp MCP SSE endpoint
BURP_MCP_URL = os.environ.get("BURP_MCP_URL", "http://127.0.0.1:9876")

# Path to MCP proxy jar (Burp BApp extension)
BURP_MCP_JAR = os.environ.get("BURP_MCP_JAR",
               os.path.expanduser("~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar"))

# Burp proxy endpoint (for routing requests through Burp)
BURP_PROXY = os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")

# All known Burp MCP tool names — used by the engine to tell agents what's available
BURP_MCP_TOOLS = [
    "mcp__burp__send_http1_request",
    "mcp__burp__send_http2_request",
    "mcp__burp__generate_collaborator_payload",
    "mcp__burp__get_collaborator_interactions",
    "mcp__burp__get_sitemap",
    "mcp__burp__get_proxy_history",
    "mcp__burp__get_scan_issues",
    "mcp__burp__send_to_repeater",
    "mcp__burp__active_scan",
]

# Tools that hunt agents should know about in their preamble
HUNT_RELEVANT_TOOLS = {
    "mcp__burp__send_http1_request": "Send HTTP/1.1 request through Burp (captured in proxy history)",
    "mcp__burp__send_http2_request": "Send HTTP/2 request through Burp",
    "mcp__burp__generate_collaborator_payload": "Get unique Burp Collaborator subdomain for OOB testing",
    "mcp__burp__get_collaborator_interactions": "Poll for OOB callback interactions on a Collaborator payload",
    "mcp__burp__get_scan_issues": "Get Burp Scanner findings for a URL",
    "mcp__burp__send_to_repeater": "Send a request to Burp Repeater for manual analysis",
}


def is_burp_available():
    """Check if Burp MCP server is reachable."""
    try:
        import urllib.request, urllib.error
        req = urllib.request.Request(BURP_MCP_URL, method="GET")
        urllib.request.urlopen(req, timeout=3)
        return True
    except urllib.error.HTTPError as e:
        return e.code in (400, 403, 404, 405)
    except Exception:
        return False


def is_jar_available():
    """Check if the MCP proxy jar exists on disk."""
    return os.path.isfile(BURP_MCP_JAR)


def mcp_config_dict():
    """Return the MCP server config dict for Burp, suitable for JSON configs."""
    return {
        "command": "java",
        "args": ["-jar", BURP_MCP_JAR, "--sse-url", BURP_MCP_URL]
    }


def claude_code_config_path():
    """Path to Claude Code's MCP config."""
    return os.path.expanduser("~/.claude.json")


def is_registered_in_claude():
    """Check if Burp MCP is already registered in Claude Code."""
    path = claude_code_config_path()
    if not os.path.isfile(path):
        return False
    try:
        with open(path) as f:
            data = json.load(f)
        return "burp" in data.get("mcpServers", {})
    except (json.JSONDecodeError, OSError):
        return False


def register_in_claude(dry_run=False):
    """Register Burp MCP server in Claude Code's ~/.claude.json."""
    path = claude_code_config_path()
    data = {}
    if os.path.isfile(path):
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            data = {}

    servers = data.setdefault("mcpServers", {})
    if "burp" in servers:
        return {"status": "already_registered", "path": path}

    servers["burp"] = mcp_config_dict()

    if dry_run:
        return {"status": "dry_run", "would_write": path, "config": servers["burp"]}

    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return {"status": "registered", "path": path}


def register_in_opencode(dry_run=False):
    """Register Burp MCP server in OpenCode's config."""
    oc_config = os.path.expanduser("~/.config/opencode/opencode.json")
    data = {}
    if os.path.isfile(oc_config):
        try:
            with open(oc_config) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            data = {}

    mcp = data.setdefault("mcp", {})
    if "burp" in mcp:
        return {"status": "already_registered", "path": oc_config}

    mcp["burp"] = {
        "type": "local",
        "command": ["java", "-jar", BURP_MCP_JAR, "--sse-url", BURP_MCP_URL],
        "enabled": True
    }

    if dry_run:
        return {"status": "dry_run", "would_write": oc_config, "config": mcp["burp"]}

    os.makedirs(os.path.dirname(oc_config), exist_ok=True)
    with open(oc_config, "w") as f:
        json.dump(data, f, indent=2)
    return {"status": "registered", "path": oc_config}


def write_project_mcp_config(output_path=None):
    """Write a burp-mcp.json config file for use with --mcp-config flag."""
    if output_path is None:
        output_path = os.path.join(ENGINE, "burp-mcp.json")
    config = {"mcpServers": {"burp": mcp_config_dict()}}
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)
    return output_path


def _mcp_call(tool_name, arguments=None, timeout=15):
    """Call an MCP tool on the Burp SSE server directly via JSON-RPC over HTTP.

    The Burp MCP BApp exposes an SSE endpoint. Protocol:
      1. GET /sse → server sends  event: endpoint  data: /message?sessionId=...
      2. POST JSON-RPC to that endpoint
      3. Server replies with event: message  data: {jsonrpc response}
    """
    import urllib.request
    import urllib.error
    import threading
    import queue
    import uuid

    base = BURP_MCP_URL.rstrip("/")
    q = queue.Queue()

    def _sse_reader(conn, q):
        """Read SSE events from the connection, push parsed events to queue."""
        buf = b""
        try:
            while True:
                chunk = conn.read(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n\n" in buf:
                    raw, buf = buf.split(b"\n\n", 1)
                    event_type, data = "", ""
                    for line in raw.decode("utf-8", errors="replace").split("\n"):
                        if line.startswith("event:"):
                            event_type = line[6:].strip()
                        elif line.startswith("data:"):
                            data = line[5:].strip()
                    if event_type or data:
                        q.put((event_type, data))
        except Exception:
            pass
        finally:
            q.put(("_done", ""))

    try:
        req = urllib.request.Request(base + "/sse", headers={"Accept": "text/event-stream"})
        conn = urllib.request.urlopen(req, timeout=timeout)
    except Exception:
        return None

    reader = threading.Thread(target=_sse_reader, args=(conn, q), daemon=True)
    reader.start()

    # Wait for endpoint event
    endpoint_path = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            etype, edata = q.get(timeout=max(0.1, deadline - time.time()))
        except queue.Empty:
            break
        if etype == "endpoint":
            endpoint_path = edata
            break
        if etype == "_done":
            break

    if not endpoint_path:
        conn.close()
        return None

    # POST JSON-RPC call
    post_url = base + endpoint_path if endpoint_path.startswith("/") else endpoint_path
    rpc = json.dumps({
        "jsonrpc": "2.0", "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
    }).encode()
    try:
        post_req = urllib.request.Request(post_url, data=rpc,
                                          headers={"Content-Type": "application/json"})
        urllib.request.urlopen(post_req, timeout=timeout)
    except Exception:
        conn.close()
        return None

    # Read response from SSE stream
    while time.time() < deadline:
        try:
            etype, edata = q.get(timeout=max(0.1, deadline - time.time()))
        except queue.Empty:
            break
        if etype == "message" and edata:
            try:
                msg = json.loads(edata)
                conn.close()
                result = msg.get("result", {})
                # MCP tool results have content[].text
                content = result.get("content") or []
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        return json.loads(c["text"])
                return result
            except (json.JSONDecodeError, KeyError):
                conn.close()
                return None
        if etype == "_done":
            break

    conn.close()
    return None


def query_proxy_history(timeout=15):
    """Query Burp proxy history via direct MCP SSE call. Returns list of entries or []."""
    if not is_burp_available():
        return []
    try:
        data = _mcp_call("get_proxy_http_history", timeout=timeout)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def agent_burp_preamble():
    """Return the Burp MCP preamble text to inject into hunt agent prompts.
    Only returns content if Burp is available or registered."""
    if not is_registered_in_claude() and not is_burp_available():
        return ""
    lines = [
        "BURP SUITE MCP (available): you can send requests through Burp and use Collaborator for OOB testing.",
        "Prefer Burp MCP tools over raw curl when Burp is running — requests are captured in proxy history.",
    ]
    for tool, desc in HUNT_RELEVANT_TOOLS.items():
        lines.append(f"  - `{tool}`: {desc}")
    lines.append(
        "For blind/OOB testing: use `mcp__burp__generate_collaborator_payload` to get a unique domain, "
        "inject it, then `mcp__burp__get_collaborator_interactions` to check for callbacks. "
        "Collaborator is more reliable than interactsh for DNS/HTTP/SMTP interactions."
    )
    return "\n".join(lines) + "\n"


def status():
    """Full status check for Burp MCP integration."""
    info = {
        "jar_exists": is_jar_available(),
        "jar_path": BURP_MCP_JAR,
        "mcp_url": BURP_MCP_URL,
        "mcp_reachable": is_burp_available(),
        "proxy_url": BURP_PROXY,
        "registered_claude": is_registered_in_claude(),
        "registered_opencode": os.path.isfile(os.path.expanduser("~/.config/opencode/opencode.json")),
    }
    return info


# --- CLI ---
def _cmd_status(_a):
    s = status()
    print("Burp MCP Integration Status:")
    print(f"  MCP proxy jar: {'YES' if s['jar_exists'] else 'NO'} ({s['jar_path']})")
    print(f"  MCP server:    {'REACHABLE' if s['mcp_reachable'] else 'NOT REACHABLE'} ({s['mcp_url']})")
    print(f"  Burp proxy:    {s['proxy_url']}")
    print(f"  Claude Code:   {'REGISTERED' if s['registered_claude'] else 'NOT REGISTERED'}")
    print(f"  OpenCode:      {'CONFIG EXISTS' if s['registered_opencode'] else 'NO CONFIG'}")
    if not s['jar_exists']:
        print(f"\nTo install: open Burp Pro → Extender → BApp Store → 'MCP Server' → Install")
        print(f"Then copy mcp-proxy-all.jar to {s['jar_path']}")
    if not s['registered_claude']:
        print(f"\nTo register: python3 {__file__} setup")
    return 0


def _cmd_setup(a):
    if not is_jar_available():
        print(f"WARNING: MCP proxy jar not found at {BURP_MCP_JAR}")
        print("The registration will work but Burp MCP won't connect until the jar is installed.")
        print("Install: Burp Pro → Extender → BApp Store → 'MCP Server'")

    r1 = register_in_claude(dry_run=a.dry_run)
    print(f"Claude Code: {r1['status']} ({r1.get('path', '')})")

    r2 = register_in_opencode(dry_run=a.dry_run)
    print(f"OpenCode:    {r2['status']} ({r2.get('path', '')})")

    # Also ensure project-level config exists
    if not a.dry_run:
        p = write_project_mcp_config()
        print(f"Project MCP: written to {p}")

    if not a.dry_run:
        print("\nDone. Restart Claude Code / OpenCode for the MCP server to connect.")
        print("Make sure Burp Pro is running with the MCP BApp extension loaded.")
    return 0


def _cmd_collaborator(_a):
    if not is_burp_available():
        print("Burp MCP not reachable. Start Burp Pro with MCP extension.", file=sys.stderr)
        return 1
    print("Burp Collaborator test: use mcp__burp__generate_collaborator_payload in Claude Code")
    print("(Cannot call MCP tools directly from Python — they require the MCP client)")
    return 0


def _cmd_selftest(_a):
    s = status()
    print(f"jar_exists={s['jar_exists']}")
    print(f"mcp_reachable={s['mcp_reachable']}")
    print(f"registered_claude={s['registered_claude']}")
    print(f"agent_preamble={'YES' if agent_burp_preamble() else 'NO'}")
    print(f"mcp_config_dict={json.dumps(mcp_config_dict())}")
    print("burp.py self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Burp Suite MCP integration for the hunt harness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=_cmd_status)
    ps = sub.add_parser("setup")
    ps.add_argument("--dry-run", action="store_true")
    ps.set_defaults(fn=_cmd_setup)
    sub.add_parser("collaborator").set_defaults(fn=_cmd_collaborator)
    sub.add_parser("selftest").set_defaults(fn=_cmd_selftest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
