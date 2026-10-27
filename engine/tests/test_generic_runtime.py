#!/usr/bin/env python3
import json
import os
import shlex
import sys
import tempfile

TESTS = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(TESTS, "..", "engine")
sys.path.insert(0, ENGINE)

import agent as A
import modelroute as MR

FAKE = os.path.join(TESTS, "fake_agent.py")
PASS = 0


def check(name, condition, detail=""):
    global PASS
    if not condition:
        raise AssertionError(f"{name}: {detail}")
    PASS += 1
    print(f"  [PASS] {name}")


def command(mode="json", resume=False, record=None):
    parts = [sys.executable, FAKE, "--mode", mode, "--model={model}"]
    if resume:
        parts += ["--resume={resume}"]
    if record:
        parts += ["--record", record]
    return " ".join(shlex.quote(part) for part in parts) + " {task}"


def stdin_command(mode="json"):
    return " ".join(shlex.quote(part) for part in [sys.executable, FAKE, "--mode", mode,
                                                     "--model={model}"])


def main():
    global PASS
    saved = {key: os.environ.get(key) for key in
             ("HUNT_AGENT_CMD", "HUNT_MODELS", "HUNT_MOCK_AGENT", "BUGHUNTER_BASE")}
    work = tempfile.mkdtemp()
    os.environ["BUGHUNTER_BASE"] = work
    os.environ.pop("HUNT_MOCK_AGENT", None)
    os.environ["HUNT_MODELS"] = "arbitrary/model-a,unclassified-model-b"
    try:
        os.environ["HUNT_AGENT_CMD"] = command()
        result = A.run_agent("argv prompt", model="arbitrary/model-a", context=None)
        check("argv prompt and arbitrary label use active command",
              result["result"] == "argv prompt" and result["model"] == "arbitrary/model-a", result)

        os.environ["HUNT_AGENT_CMD"] = stdin_command()
        result = A.run_agent("stdin prompt", model="unclassified-model-b", context=None)
        check("stdin prompt works without runtime-specific flags", result["result"] == "stdin prompt", result)

        os.environ["HUNT_AGENT_CMD"] = command("jsonl")
        result = A.run_agent("stream prompt", model="arbitrary/model-a", context=None)
        check("JSONL events parsed by content", result["result"] == "stream prompt" and not result["error"], result)

        os.environ["HUNT_AGENT_CMD"] = command("plain")
        result = A.run_agent("plain prompt", context=None)
        check("plain text output accepted", result["result"] == "plain prompt", result)

        os.environ.pop("HUNT_AGENT_CMD", None)
        result = A.run_agent("must not execute", context=None)
        check("missing runtime fails closed", result["error"].startswith("runtime-not-configured"), result)

        record = os.path.join(work, "calls.jsonl")
        resume_command = command(resume=True, record=record)
        os.environ["HUNT_AGENT_CMD"] = resume_command
        A._POOL.clear()
        first = A.run_agent("first", model="arbitrary/model-a", context="runtime-binding")
        second = A.run_agent("second", context="runtime-binding")
        check("generic session resume supported", first["session_id"] == "generic-session" and second["reused"], second)
        runtime_one = A._runtime()
        os.environ["HUNT_AGENT_CMD"] = resume_command + " --delay 0.01"
        third = A.run_agent("third", context="runtime-binding")
        check("changed command cannot resume old runtime",
              runtime_one != A._runtime() and not third["reused"], third)
        with open(record) as fh:
            calls = [json.loads(line) for line in fh if line.strip()]
        check("recorded calls prove no cross-runtime resume",
              not calls[0]["resume"] and calls[1]["resume"] == "generic-session" and
              not calls[2]["resume"], calls)

        os.environ["HUNT_AGENT_CMD"] = command()
        result = A.run_agent("unsupported", resume_id="old-runtime", context=None)
        check("resume without placeholder rejected", result["error"] == "runtime-resume-unsupported", result)

        os.environ["HUNT_AGENT_CMD"] = command("sleep")
        cmd = A._cmd("sleep", None)
        result = A._run_once(cmd, None, 0.05)
        check("timeout returns partial output and terminates process",
              result["error"] == "timeout" and result["partial"], result)

        os.environ["HUNT_MODEL_OVERRIDE"] = "opaque-a"
        try:
            check("model router does not infer provider tiers", MR.model_for("hunt") == "opaque-a")
        finally:
            os.environ.pop("HUNT_MODEL_OVERRIDE", None)
    finally:
        A._POOL.clear()
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    print(f"\nGENERIC RUNTIME TESTS: {PASS} PASS, 0 FAIL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
