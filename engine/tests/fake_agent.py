#!/usr/bin/env python3
"""Local fake host for generic runtime contract tests."""
import argparse
import json
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task", nargs="?")
    parser.add_argument("--mode", default="json")
    parser.add_argument("--model", default="host-default")
    parser.add_argument("--resume")
    parser.add_argument("--record")
    parser.add_argument("--delay", type=float, default=0)
    args = parser.parse_args()
    task = args.task if args.task is not None else sys.stdin.read()
    if args.record:
        with open(args.record, "a") as fh:
            fh.write(json.dumps({"task": task, "model": args.model, "resume": args.resume}) + "\n")
    session = "generic-session"
    if args.mode == "sleep":
        print(json.dumps({"type": "text", "sessionID": session,
                          "part": {"type": "text", "text": "partial"}}), flush=True)
        time.sleep(args.delay or 2)
        return 0
    if args.delay:
        time.sleep(args.delay)
    if args.mode == "plain":
        print(task)
    elif args.mode == "jsonl":
        print(json.dumps({"type": "step_start", "sessionID": session}))
        print(json.dumps({"type": "text", "sessionID": session,
                          "part": {"type": "text", "text": task}}))
        print(json.dumps({"type": "step_finish", "sessionID": session,
                          "part": {"reason": "stop", "tokens": {"input": 2, "output": 1}}}))
    elif args.mode == "incomplete":
        print(json.dumps({"type": "text", "sessionID": session,
                          "part": {"type": "text", "text": task}}))
    elif args.mode == "rate":
        print("rate limit reached")
    elif args.mode == "error":
        print(json.dumps({"result": task, "session_id": session}))
        return 7
    else:
        print(json.dumps({"result": task, "model": args.model, "session_id": session,
                          "is_error": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
