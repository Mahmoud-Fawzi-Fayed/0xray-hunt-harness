#!/usr/bin/env python3
"""
test_policy_egress.py — subprocess-level scope enforcement tests.

Proves that netget.py and browser.py CLIs, when invoked as child processes
(the way the agent dispatcher invokes them), enforce scope policy before
sending any traffic.

Run:
  python3 engine/tests/test_policy_egress.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(TESTS, "..", "engine")
sys.path.insert(0, ENGINE)
sys.path.insert(0, TESTS)

from vuln_app import start_threaded, get_oos_requests, clear_oos_requests, OOS_SINK_PORT_OFFSET

PASS = 0
FAIL = 0
BLOCKED = 0
RESULTS = []

NETGET = os.path.join(ENGINE, "netget.py")
BROWSER = os.path.join(ENGINE, "browser.py")


def _record(test_id, name, status, detail=""):
    global PASS, FAIL, BLOCKED
    if status == "PASS":
        PASS += 1
    elif status == "FAIL":
        FAIL += 1
    else:
        BLOCKED += 1
    RESULTS.append({"id": test_id, "name": name, "status": status, "detail": detail})
    mark = {"PASS": "✓", "FAIL": "✗", "BLOCKED": "⊘"}[status]
    print(f"  [{mark} {status:13s}] {test_id}: {name}" + (f" — {detail}" if detail else ""))


def _run(args, timeout=15):
    """Run a subprocess and return (exit_code, stdout, stderr)."""
    r = subprocess.run(
        [sys.executable] + args,
        capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def run_tests():
    import random
    port = random.randint(21000, 29000)
    oos_port = port + OOS_SINK_PORT_OFFSET
    app, sink, _ = start_threaded(port)
    base = tempfile.mkdtemp()
    BASE_URL = f"http://127.0.0.1:{port}"

    # Set up scope files
    scope_data = {
        "name": "vuln-local",
        "in_scope": [f"127.0.0.1:{port}", "localhost"],
        "out_of_scope": [],
        "seeds": [BASE_URL],
    }
    scope_file = os.path.join(base, "scope.json")
    with open(scope_file, "w") as f:
        json.dump(scope_data, f)

    # Set up _targets/ dir for slug resolution
    tgt_dir = os.path.join(base, "_targets")
    os.makedirs(tgt_dir, exist_ok=True)
    with open(os.path.join(tgt_dir, "vuln-local.json"), "w") as f:
        json.dump(scope_data, f)

    # Malformed scope file
    malformed_file = os.path.join(base, "malformed.json")
    with open(malformed_file, "w") as f:
        f.write("{{{not json")

    env = os.environ.copy()
    env["BUGHUNTER_BASE"] = base

    try:
        print("\n--- Policy egress tests (subprocess) ---")
        clear_oos_requests()

        # T-PE-1: Valid --scope-file, in-scope request → success
        rc, out, err = _run([NETGET, "GET", f"{BASE_URL}/api/users/1", "--scope-file", scope_file])
        if rc == 0 and "HTTP 200" in out:
            _record("T-PE-1", "netget --scope-file in-scope request succeeds", "PASS")
        else:
            _record("T-PE-1", "netget --scope-file in-scope request succeeds", "FAIL",
                    f"rc={rc} out={out[:120]} err={err[:120]}")

        # T-PE-2: No scope at all → must fail before connecting
        rc, out, err = _run([NETGET, "GET", "https://evil.com/test"])
        if rc != 0 and "no valid scope policy" in err:
            _record("T-PE-2", "netget no-scope blocks remote request", "PASS")
        else:
            _record("T-PE-2", "netget no-scope blocks remote request", "FAIL",
                    f"rc={rc} err={err[:200]}")

        # T-PE-3: Valid scope file but target not in scope → scope violation
        rc, out, err = _run([NETGET, "GET", "http://evil.com/test", "--scope-file", scope_file])
        if rc != 0 and ("scope violation" in out.lower() or "scope violation" in err.lower()
                        or "scope" in out.lower()):
            _record("T-PE-3", "netget scope-file blocks OOS target", "PASS")
        else:
            _record("T-PE-3", "netget scope-file blocks OOS target", "FAIL",
                    f"rc={rc} out={out[:200]} err={err[:200]}")

        # T-PE-4: Load from --slug via _targets/ dir
        rc, out, err = _run(
            [NETGET, "GET", f"{BASE_URL}/api/users/1", "--slug", "vuln-local"],
            timeout=15,
        )
        # Pass env with BUGHUNTER_BASE
        r = subprocess.run(
            [sys.executable, NETGET, "GET", f"{BASE_URL}/api/users/1", "--slug", "vuln-local"],
            capture_output=True, text=True, timeout=15, env=env,
        )
        if r.returncode == 0 and "HTTP 200" in r.stdout:
            _record("T-PE-4", "netget --slug resolves policy from _targets/", "PASS")
        else:
            _record("T-PE-4", "netget --slug resolves policy from _targets/", "FAIL",
                    f"rc={r.returncode} out={r.stdout[:120]} err={r.stderr[:120]}")

        # T-PE-5: --as A with --slug (identity loading)
        r = subprocess.run(
            [sys.executable, NETGET, "GET", f"{BASE_URL}/api/users/1",
             "--as", "A", "--slug", "vuln-local"],
            capture_output=True, text=True, timeout=15, env=env,
        )
        if r.returncode == 0 and "HTTP 200" in r.stdout:
            _record("T-PE-5", "netget --as A --slug loads identity", "PASS")
        else:
            _record("T-PE-5", "netget --as A --slug loads identity", "FAIL",
                    f"rc={r.returncode} out={r.stdout[:120]} err={r.stderr[:120]}")

        # T-PE-6: Malformed scope file → must fail
        rc, out, err = _run([NETGET, "GET", "https://example.com/", "--scope-file", malformed_file])
        if rc != 0 and ("invalid" in err.lower() or "error" in err.lower()):
            _record("T-PE-6", "netget rejects malformed scope file", "PASS")
        else:
            _record("T-PE-6", "netget rejects malformed scope file", "FAIL",
                    f"rc={rc} err={err[:200]}")

        # T-PE-7: Nonexistent slug → must fail
        r = subprocess.run(
            [sys.executable, NETGET, "GET", "https://example.com/", "--slug", "nonexistent"],
            capture_output=True, text=True, timeout=15, env=env,
        )
        if r.returncode != 0 and ("no scope file found" in r.stderr.lower()
                                   or "no valid scope" in r.stderr.lower()):
            _record("T-PE-7", "netget rejects nonexistent slug", "PASS")
        else:
            _record("T-PE-7", "netget rejects nonexistent slug", "FAIL",
                    f"rc={r.returncode} err={r.stderr[:200]}")

        # T-PE-8: Browser CLI without scope → must exit nonzero
        try:
            r = subprocess.run(
                [sys.executable, BROWSER, "capture", "--url", f"{BASE_URL}"],
                capture_output=True, text=True, timeout=20,
            )
            if r.returncode != 0 and ("error" in r.stderr.lower() or "requires" in r.stderr.lower()):
                _record("T-PE-8", "browser CLI exits nonzero without scope", "PASS")
            else:
                _record("T-PE-8", "browser CLI exits nonzero without scope", "FAIL",
                        f"rc={r.returncode} err={r.stderr[:200]}")
        except subprocess.TimeoutExpired:
            _record("T-PE-8", "browser CLI exits nonzero without scope", "BLOCKED", "timeout")

        # T-PE-9: Redirect to OOS — use follow_redirects or check _redirect_blocked
        # The vuln_app has /redirect?url=<dest> which redirects.
        # With netget (redirects disabled by default), we get a 302 with _redirect_blocked tag
        clear_oos_requests()
        r = subprocess.run(
            [sys.executable, NETGET, "GET",
             f"{BASE_URL}/redirect?url=http://127.0.0.1:{oos_port}/should-not-reach",
             "--scope-file", scope_file],
            capture_output=True, text=True, timeout=15,
        )
        oos_reqs = get_oos_requests()
        if len(oos_reqs) == 0:
            _record("T-PE-9", "Redirect to OOS sink produces zero sink hits", "PASS",
                    f"rc={r.returncode}, 302 returned safely")
        else:
            _record("T-PE-9", "Redirect to OOS sink produces zero sink hits", "FAIL",
                    f"{len(oos_reqs)} OOS requests leaked")

        # Final OOS check
        all_oos = get_oos_requests()
        _record("T-PE-F", "Total OOS requests across all policy tests",
                "PASS" if len(all_oos) == 0 else "FAIL",
                f"{len(all_oos)} prohibited requests")

    except Exception as e:
        import traceback
        _record("CRASH", f"Unexpected error: {type(e).__name__}", "FAIL", str(e))
        traceback.print_exc()
    finally:
        app.shutdown()
        if sink:
            sink.shutdown()

    print(f"\n{'='*70}")
    print(f"  POLICY EGRESS TEST RESULTS")
    print(f"  PASS={PASS}  FAIL={FAIL}  BLOCKED={BLOCKED}")
    print(f"  Total: {len(RESULTS)}")
    print(f"{'='*70}")

    if FAIL > 0:
        print("\n  FAILED tests:")
        for r in RESULTS:
            if r["status"] == "FAIL":
                print(f"    {r['id']}: {r['name']} — {r['detail']}")

    report_path = os.path.join(TESTS, "..", "..", "artifacts", "release-validation")
    os.makedirs(report_path, exist_ok=True)
    with open(os.path.join(report_path, "policy-egress-results.json"), "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pass": PASS, "fail": FAIL, "blocked": BLOCKED,
            "results": RESULTS,
        }, f, indent=2)

    return 1 if FAIL > 0 else 0


if __name__ == "__main__":
    print("Policy Egress Tests (subprocess scope enforcement)")
    print("=" * 70)
    sys.exit(run_tests())
