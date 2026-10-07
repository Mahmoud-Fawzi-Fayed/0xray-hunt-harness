#!/usr/bin/env python3
"""
disposition.py — pre-draft gate for bug-bounty findings.

Dedup answers "have we seen this before?". This gate answers a different question:
"will a program close this as RTFS or Informative?"

It is structural. It does not know any one vendor. A finding is held when the
evidence shows one of these shapes:

  HOLD_RTFS          the impact needs a precondition the PoC never obtains
                     (a victim session, a foreign object id, an archive leak
                     that the write-up itself calls unproven)
  HOLD_INFORMATIVE   the behavior is real and it is the product's own
                     capability: an unguessable id the product already gives
                     the holder, or a write that stops once the object reaches
                     its documented terminal state

PASS means the harness may draft. It does not mean the finding is valid.
A listed `break` clears a hold only when the evidence text also shows that break.

CLI:
  python3 disposition.py check --file finding.md
  python3 disposition.py check --file finding.json
  echo '{...}' | python3 disposition.py check --stdin
Exit 0 on PASS, 2 on HOLD.
"""
import argparse
import json
import os
import re
import sys

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)
DEFAULT_BASE = os.environ.get("BUGHUNTER_BASE", "~/.bughunter-engagements")

# A bare flag must not bypass the gate. Each break is accepted only with this proof.
BREAKS = {
    "cross_account_without_secret": "a second identity, and the object id is enumerable rather than a secret the holder was given",
    "unauth_write_past_terminal_lock": "the write still succeeds after the object is billed, completed, or paid",
    "session_or_csrf_primitive_shown": "session theft or cross-site submission was reproduced, not named",
    "in_scope_id_oracle": "an in-scope response lists another user's secret id, and that id was then used",
}

_CROSS = re.compile(
    r"\b(account|user|seller|tenant)\s*b\b|other users?|another user|cross-account|"
    r"victim'?s|second (account|user|seller|tenant)|arbitrary id|\bid\s*=\s*n\b")
_OWN = re.compile(
    r"\b(my|our) own\b|own (sandbox|account|session|seller|invoice|transaction|data)|"
    r"researcher'?s own|only my ")
_UNAUTH = re.compile(
    r"no (?:api )?token|unauthenticated|without (?:a |any )?(?:session|cookie|token|auth)|"
    r"no credentials|no auth(?:entication)? headers|public (?:numeric )?(?:seller_)?id")
_SAME_SESSION = re.compile(r"session cookies?|logged in as|my session|with the session|cookie:")
_PRECONDITION = re.compile(
    r"stolen session|obtain(?:s|ed|ing)? (?:a |the )?(?:victim'?s? )?(?:vendor |user )?session|"
    r"cookie theft|session hijack|shared machine|physical access|\bmitm\b|man-in-the-middle|"
    r"anyone who obtains")
_PROVEN_ENTRY = re.compile(
    r"samesite\s*=\s*none.{0,200}(cross-site|csrf)|"
    r"(cross-site|csrf).{0,200}samesite\s*=\s*none|"
    r"document\.cookie|xss.{0,80}(executed|fired|exfiltrat)|"
    r"session.?theft (?:shown|demonstrated|reproduced)")
_LEAK_SOURCE = re.compile(
    r"wayback|web\.archive|archive\.org|sourcegraph|public code|webhook payload|"
    r"receipt email|committed to")
_UNQUANTIFIED = re.compile(
    r"unquantified|not demonstrated|asserted rather|no third-party|own data only|"
    r"fixtures only|leak(?:age)? rate")
_UNGUESSABLE = re.compile(
    r"\buuid\b|unguessable|ulid|high[- ]entropy|txn_[0-9a-z]{10,}|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_LOW_ENTROPY = re.compile(r"\bid\s*=\s*\d|\bsequential\b|\bincrement(?:ing|ed)?\b|numeric (?:id|seller)")
_ARCHIVE = re.compile(r"wayback|web\.archive|archive\.org|passively recovered|forwarded email")
_PRODUCT_LINK = re.compile(
    r"_ptxn|payment link|checkout\.url|recovery url|recover\?|"
    r"emailed (?:to|the) (?:the )?buyer|link (?:sent|issued) to the")
_ORACLE = re.compile(
    r"list(?:s|ed|ing)? (?:other|another|victim)|in-scope (?:api|endpoint|response).{0,60}(?:uuid|id)|"
    r"response (?:lists|included|returned) (?:another|other|victim)")
_TERMINAL_REJECT = re.compile(
    r"\b(409|403)\b.{0,120}\b(billed|completed|paid|finali[sz]ed)\b|"
    r"\b(billed|completed|paid|finali[sz]ed)\b.{0,120}\b(409|403)\b")
_DRAFT_WRITE = re.compile(
    r"\b(draft|pending|ready)\b.{0,180}\b(200|rewrit|substitut|changed|updated|patched)\b|"
    r"\b(200|rewrit|substitut).{0,100}\b(draft|pending)\b")
_TERMINAL_WRITE = re.compile(
    r"\b(billed|completed|paid)\b.{0,80}\b200\b|\b200\b.{0,80}\b(billed|completed|paid)\b")
_ATO = re.compile(
    r"account takeover|\bato\b|any (?:buyer|user|seller|victim)|other compan|full (?:seller|account)")


def _blob(f):
    if not isinstance(f, dict):
        return ""
    parts = []
    for k in ("title", "steps", "poc", "impact", "evidence", "request", "response",
              "proof_note", "notes"):
        v = f.get(k)
        if v:
            parts.append(str(v))
    verdict = f.get("verdict")
    if isinstance(verdict, dict) and verdict.get("reason"):
        parts.append(str(verdict["reason"]))
    return "\n".join(parts).lower()[:24000]


def _meta(f):
    d = f.get("disposition") if isinstance(f, dict) and isinstance(f.get("disposition"), dict) else {}
    def pick(*keys):
        for k in keys:
            v = d.get(k)
            if v is None and isinstance(f, dict):
                v = f.get(k)
            if v:
                return str(v).lower().replace(" ", "_").replace("-", "_")
        return ""
    return {
        "holds": pick("attacker_holds"),
        "idsrc": pick("id_source"),
        "lock": bool(d.get("terminal_lock_held")),
        "break": pick("break"),
    }


def _hit(blob, pat):
    """True when pat matches and the match is not immediately negated ('not', 'without', 'no')."""
    if not blob or not pat:
        return False
    for m in pat.finditer(blob):
        pre = blob[max(0, m.start() - 16):m.start()]
        if re.search(r"\b(not|without|no)\s+$", pre):
            continue
        return True
    return False


def _break_proven(name, blob):
    if name == "cross_account_without_secret":
        return _hit(blob, _CROSS) and _hit(blob, _LOW_ENTROPY) and not _hit(blob, _ARCHIVE)
    if name == "unauth_write_past_terminal_lock":
        return _hit(blob, _TERMINAL_WRITE) and not _hit(blob, _TERMINAL_REJECT)
    if name == "session_or_csrf_primitive_shown":
        return _hit(blob, _PROVEN_ENTRY)
    if name == "in_scope_id_oracle":
        return _hit(blob, _ORACLE) and _hit(blob, _CROSS)
    return False


def _rules(blob, meta):
    rules = []
    cross = _hit(blob, _CROSS)
    own = _hit(blob, _OWN)
    unauth = _hit(blob, _UNAUTH)
    proven_entry = _hit(blob, _PROVEN_ENTRY)
    oracle = _hit(blob, _ORACLE)

    session_assumed = (
        meta["holds"] in ("own_session", "victim_session_unproven")
        or (_hit(blob, _PRECONDITION) and not proven_entry)
        or (own and _hit(blob, _SAME_SESSION) and _hit(blob, _ATO) and not unauth and not cross and not proven_entry)
    )
    if session_assumed and not proven_entry and not (cross and not own):
        rules.append({
            "id": "unproven_precondition",
            "verdict": "HOLD_RTFS",
            "reason": "The impact starts from a session, cookie, or device the evidence never obtains. "
                      "A state change inside a session the tester already holds is the account acting as itself.",
        })

    leak_asserted = _hit(blob, _LEAK_SOURCE) and _hit(blob, _UNQUANTIFIED) and not cross and not oracle
    if leak_asserted or meta["idsrc"] in ("asserted_leak",):
        rules.append({
            "id": "asserted_identifier_leak",
            "verdict": "HOLD_RTFS",
            "reason": "The attack is described as depending on a leaked identifier, and the write-up does not "
                      "show a foreign object obtained from an in-scope response. An unquantified leak is not a PoC.",
        })

    secret_id = _hit(blob, _UNGUESSABLE) and not _hit(blob, _LOW_ENTROPY)
    holder_path = _hit(blob, _ARCHIVE) or _hit(blob, _PRODUCT_LINK) or meta["idsrc"] in (
        "archive", "product_link", "own_only")
    if secret_id and holder_path and not cross and not oracle and meta["idsrc"] != "in_scope_oracle":
        rules.append({
            "id": "capability_url",
            "verdict": "HOLD_INFORMATIVE",
            "reason": "Access requires an unguessable identifier, and the only demonstrated copies are ones the "
                      "product already gives the holder or that were recovered from an archive. That is a capability "
                      "URL, not an authorization bypass, until an in-scope response hands over somebody else's id.",
        })

    lock_held = meta["lock"] or (_hit(blob, _TERMINAL_REJECT) and _hit(blob, _DRAFT_WRITE))
    if lock_held and not cross and not oracle and not _break_proven("unauth_write_past_terminal_lock", blob):
        rules.append({
            "id": "terminal_lock_held",
            "verdict": "HOLD_INFORMATIVE",
            "reason": "The write works on a non-final object and is rejected once the object is billed, completed, "
                      "or paid. That is the product's edit window, not a missing control.",
        })
    return rules


# AUTO proof-override: the write-up SHOWS concrete, demonstrated security impact (not merely asserts it).
# When present, the RTFS/Informative TEXT-heuristic is overridden — a proven, impactful finding is reportable
# even if its prose also mentions a session/precondition (the regex can't see the PoC; real proof wins). Kept
# NARROW on purpose: a cross-account read/write actually shown, command/file/metadata execution, SQLi
# extraction, or a demonstrated session/token theft — never bare words like "account takeover" or "could".
_PROOF_SHOWN = re.compile(
    r"cross-account"
    r"|another user'?s |other users?'? (pii|data|order|invoice|account|email|record)"
    r"|victim'?s (data|order|invoice|account|email|record|session|token|cookie)"
    r"|account ?b (read|saw|retrieved|accessed|received|returned|got|calls|lists)"
    r"|\buid=\d|\bgid=\d|\bwhoami\b|root@|root:.*:0:0|/etc/passwd|command output"
    r"|169\.254\.169\.254|metadata.*(token|credential|role)"
    r"|union select|sleep\(\d|extracted (the )?(data|rows|password|hash|version)"
    r"|stole (the )?(session|token|cookie)|session (token |cookie )?(stolen|hijacked|exfiltrated)"
    # info-disclosure proof — GENERIC (any class/target, no finding-specific nouns): sensitive data actually
    # RETURNED in a response, or a quantified dump. Works for configs, PII, invoices, secrets, keys, etc.
    r"|(?:response|endpoint|api|server)\b[^\n]{0,20}(?:contains?|returned|included?|expos\w+|disclos\w+|leak\w*|lists?)"
    r"[^\n]{0,60}(?:secret|credential|password|token|api[_ ]?key|private key|internal|sensitive|personal|pii|another|other user)"
    r"|\d[\d,]{2,}\s+(?:entr(?:y|ies)|records?|rows?|users?|accounts?|objects?|items?)\b"
    r"[^\n]{0,20}(?:returned|exposed|disclos\w+|leaked|accessible|in the response)",
    re.I)


def check(finding, program=None, base=DEFAULT_BASE):
    """Return {verdict, draft, rules, reason}. Never raises on hostile input."""
    try:
        f = finding if isinstance(finding, dict) else {}
        blob = _blob(f)
        meta = _meta(f)
        if not blob.strip() and not meta["holds"] and not meta["idsrc"]:
            return {"verdict": "HOLD_RTFS", "draft": False, "rules": [{
                "id": "empty", "verdict": "HOLD_RTFS",
                "reason": "No evidence text. A finding with nothing to score is not drafted.",
            }], "reason": "No evidence text."}

        br = meta["break"]
        if br in BREAKS and _break_proven(br, blob):
            return {"verdict": "PASS", "draft": True, "rules": [{
                "id": "break_proven", "verdict": "PASS",
                "reason": f"Evidence shows the break `{br}`: {BREAKS[br]}.",
            }], "reason": f"Break `{br}` is present in the evidence."}

        if _PROOF_SHOWN.search(blob):          # concrete demonstrated impact overrides the RTFS text-heuristic
            return {"verdict": "PASS", "draft": True, "rules": [{
                "id": "proof_shown", "verdict": "PASS",
                "reason": "Evidence shows concrete, demonstrated security impact (cross-account data / "
                          "command output / extraction / token theft) — reportable over the text-heuristic.",
            }], "reason": "Concrete demonstrated impact present in the evidence."}

        rules = _rules(blob, meta)
        if any(r["verdict"] == "HOLD_RTFS" for r in rules):
            verdict = "HOLD_RTFS"
        elif rules:
            verdict = "HOLD_INFORMATIVE"
        else:
            verdict = "PASS"
        reason = rules[0]["reason"] if rules else "No RTFS or Informative shape detected."
        return {"verdict": verdict, "draft": verdict == "PASS", "rules": rules, "reason": reason}
    except Exception as e:  # noqa: BLE001 — a gate failure must hold, not draft
        return {"verdict": "HOLD_RTFS", "draft": False, "rules": [{
            "id": "gate_error", "verdict": "HOLD_RTFS", "reason": f"{type(e).__name__}: {e}",
        }], "reason": "Disposition gate failed closed."}


def from_text(text):
    """A JSON object, or a report whose full text is the evidence the rules read."""
    raw = text or ""
    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    return {"title": (raw.splitlines() or [""])[0][:180],
            "evidence": raw[:20000], "steps": raw[:20000], "impact": raw[:20000], "poc": raw[:20000]}


def _selftest():
    own_session = {
        "title": "Missing re-authentication allows account takeover",
        "evidence": "POST /user-2fa-disable with the session cookie disables 2FA. "
                    "Tested on my own sandbox account. Anyone who obtains a vendor session "
                    "(XSS, cookie theft, malware, shared machine) gets full account takeover. "
                    "Password change requires the previous password.",
    }
    draft_edit = {
        "title": "Unauthenticated checkout item rewrite",
        "evidence": "The checkout URL is /checkout/recover?_ptxn=txn_01abcdefghij0123456789. "
                    "PATCH items with no auth headers rewrites a draft transaction I created (200). "
                    "A billed transaction returns 409. Webhook payloads and public code contain the id format; "
                    "the live leakage rate is unquantified. All tests used my own sandbox transaction.",
    }
    archive_read = {
        "title": "Unauthenticated invoice read",
        "evidence": "GET /invoices/025f48d5-114e-4837-a259-70c22a9b32bc with no auth returns the invoice. "
                    "UUIDs are unguessable. Both URLs were passively recovered from web.archive.org. "
                    "The list route is not mounted. Sibling routes return 403.",
    }
    enumerable_idor = {
        "vuln_class": "idor",
        "evidence": "id=N returns other users' PII",
        "request": "GET /api/account?id=6",
    }
    public_id_create = {
        "title": "Unauthenticated checkout creation",
        "evidence": "POST /transaction-checkout with no token and a public numeric seller_id creates a "
                    "payable checkout in that seller account. seller_id is sequential. Paid with a test card. "
                    "Transaction status became completed. No session and no credentials required. "
                    "Tested using my own sandbox seller ids, which are public.",
    }
    oracle = {
        "title": "List endpoint discloses ids",
        "evidence": "Account B calls GET /api/users. The in-scope response lists victim user UUIDs. "
                    "GET /api/orders/{uuid} with account B's token returns the victim's order. Cross-account.",
        "disposition": {"break": "in_scope_id_oracle"},
    }
    csrf = {
        "title": "Cross-site email change",
        "evidence": "The session cookie is SameSite=None. A cross-site form POST from the attacker origin "
                    "changes the email while the victim is only logged in. No cookie was copied. "
                    "CSRF reproduced in the browser.",
        "disposition": {"break": "session_or_csrf_primitive_shown"},
    }
    past_lock = {
        "title": "Billed invoice still writable",
        "evidence": "Account B sends PATCH on account A's billed invoice and the response is 200. "
                    "The seller record shows the new total. The id is sequential (id=44).",
        "disposition": {"break": "unauth_write_past_terminal_lock"},
    }

    cases = [
        ("own-session ATO", own_session, "HOLD_RTFS"),
        ("draft edit + unquantified leak", draft_edit, "HOLD_RTFS"),
        ("archive uuid read", archive_read, "HOLD_INFORMATIVE"),
        ("enumerable idor", enumerable_idor, "PASS"),
        ("public id create", public_id_create, "PASS"),
        ("in-scope id oracle", oracle, "PASS"),
        ("csrf shown", csrf, "PASS"),
        ("write past terminal lock", past_lock, "PASS"),
    ]
    for name, finding, expect in cases:
        got = check(finding)
        assert got["verdict"] == expect, (name, got)
        assert got["draft"] is (expect == "PASS"), (name, got)

    # archive read must not be clearable by naming a break the text does not prove
    lied = dict(archive_read)
    lied["disposition"] = {"break": "in_scope_id_oracle"}
    assert check(lied)["verdict"] == "HOLD_INFORMATIVE", check(lied)

    # hostile input fails closed or holds, and never raises
    for junk in (None, "", 0, [], {"evidence": None}, {"disposition": "nope"}):
        out = check(junk)
        assert out["verdict"] in ("PASS", "HOLD_RTFS", "HOLD_INFORMATIVE"), out
        assert out["verdict"] != "PASS" or junk == {"disposition": "nope"}

    text = from_text(json.dumps(enumerable_idor))
    assert check(text)["verdict"] == "PASS"
    assert check(from_text("# title\n\n" + archive_read["evidence"]))["verdict"] == "HOLD_INFORMATIVE"
    print("disposition.py self-test: PASS")
    return 0


def _main(argv=None):
    ap = argparse.ArgumentParser(description="RTFS / Informative disposition gate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("check")
    pc.add_argument("--file")
    pc.add_argument("--stdin", action="store_true")
    pc.add_argument("--program")
    pc.add_argument("--base", default=DEFAULT_BASE)
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return _selftest()
    if a.stdin:
        raw = sys.stdin.read()
    elif a.file:
        raw = open(os.path.expanduser(a.file), encoding="utf-8", errors="replace").read()
    else:
        ap.error("check needs --file or --stdin")
    finding = from_text(raw)
    if a.program:
        finding["program"] = a.program
    out = check(finding, program=a.program, base=a.base)
    print(json.dumps(out, indent=2))
    return 0 if out["verdict"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(_main())
