#!/usr/bin/env python3
"""
scheduler.py — durable, crash-safe work scheduler for hunt execution.

Manages work claims with leases, heartbeats, checkpoints, retry budgets,
and duplicate prevention. Ensures interrupted work resumes without inflated
coverage or replayed non-idempotent requests.

Storage: <engagement_dir>/scheduler/
  claims.json   — active work claims (one per case)
  history.jsonl — append-only log of all claim state transitions
"""
import json
import os
import sys
import threading
import time
import uuid

ENGINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ENGINE)

DEFAULT_LEASE_SEC = 600
DEFAULT_MAX_RETRIES = 3
DEFAULT_HEARTBEAT_SEC = 30
BACKOFF_BASE = 5.0
BACKOFF_MAX = 300.0
JITTER_FACTOR = 0.25

CLAIM_PENDING = "pending"
CLAIM_ACTIVE = "active"
CLAIM_COMPLETED = "completed"
CLAIM_FAILED = "failed"
CLAIM_EXPIRED = "expired"
CLAIM_CANCELLED = "cancelled"
CLAIM_AWAITING_APPROVAL = "awaiting_approval"

_LOCK = threading.Lock()


def _scheduler_dir(engagement_dir):
    d = os.path.join(engagement_dir, "scheduler")
    os.makedirs(d, exist_ok=True)
    return d


def _claims_path(engagement_dir):
    return os.path.join(_scheduler_dir(engagement_dir), "claims.json")


def _history_path(engagement_dir):
    return os.path.join(_scheduler_dir(engagement_dir), "history.jsonl")


def _load_claims(engagement_dir):
    path = _claims_path(engagement_dir)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_claims(engagement_dir, claims):
    path = _claims_path(engagement_dir)
    tmp = path + f".tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(claims, f, indent=2, default=str)
    os.replace(tmp, path)


def _append_history(engagement_dir, event):
    path = _history_path(engagement_dir)
    event["timestamp"] = time.time()
    line = json.dumps(event, default=str) + "\n"
    with open(path, "a") as f:
        f.write(line)


def _backoff(attempt):
    """Exponential backoff with jitter."""
    import random
    delay = min(BACKOFF_BASE * (2 ** attempt), BACKOFF_MAX)
    jitter = delay * JITTER_FACTOR * random.random()
    return delay + jitter


class WorkClaim:
    """Represents a claim on a work item with lease-based ownership."""

    def __init__(self, case_id, worker_id, engagement_dir,
                 lease_sec=DEFAULT_LEASE_SEC, method=None, url=None,
                 owner_identity=None, accessor_identity=None,
                 idempotent=True):
        self.case_id = case_id
        self.worker_id = worker_id
        self.engagement_dir = engagement_dir
        self.lease_sec = lease_sec
        self.method = method
        self.url = url
        self.owner_identity = owner_identity
        self.accessor_identity = accessor_identity
        self.idempotent = idempotent
        self.claim_id = uuid.uuid4().hex[:12]
        self.status = CLAIM_PENDING
        self.attempt = 0
        self.max_retries = DEFAULT_MAX_RETRIES
        self.created_at = time.time()
        self.lease_expires = 0.0
        self.last_heartbeat = 0.0
        self.checkpoint = None
        self.error = None

    def to_dict(self):
        return {
            "claim_id": self.claim_id,
            "case_id": self.case_id,
            "worker_id": self.worker_id,
            "status": self.status,
            "attempt": self.attempt,
            "max_retries": self.max_retries,
            "lease_sec": self.lease_sec,
            "lease_expires": self.lease_expires,
            "last_heartbeat": self.last_heartbeat,
            "created_at": self.created_at,
            "method": self.method,
            "url": self.url,
            "owner_identity": self.owner_identity,
            "accessor_identity": self.accessor_identity,
            "idempotent": self.idempotent,
            "checkpoint": self.checkpoint,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d, engagement_dir):
        c = cls.__new__(cls)
        c.engagement_dir = engagement_dir
        for k, v in d.items():
            setattr(c, k, v)
        return c


class Scheduler:
    """Durable work scheduler with lease-based claim management."""

    def __init__(self, engagement_dir):
        self.engagement_dir = engagement_dir

    def claim_work(self, case_id, worker_id, lease_sec=DEFAULT_LEASE_SEC,
                   method=None, url=None, owner_identity=None,
                   accessor_identity=None, idempotent=True):
        """Attempt to claim a work item. Returns WorkClaim or None if already claimed."""
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            existing = claims.get(case_id)
            if existing:
                if existing["status"] == CLAIM_ACTIVE:
                    if time.time() < existing.get("lease_expires", 0):
                        return None
                    existing["status"] = CLAIM_EXPIRED
                    _append_history(self.engagement_dir, {
                        "event": "lease_expired", "case_id": case_id,
                        "claim_id": existing["claim_id"],
                        "worker_id": existing["worker_id"]})
                if existing["status"] in (CLAIM_COMPLETED, CLAIM_CANCELLED):
                    return None
                if existing["status"] == CLAIM_FAILED:
                    attempt = existing.get("attempt", 0)
                    if attempt >= existing.get("max_retries", DEFAULT_MAX_RETRIES):
                        return None
                    if not existing.get("idempotent", True):
                        return None

            wc = WorkClaim(case_id, worker_id, self.engagement_dir,
                           lease_sec=lease_sec, method=method, url=url,
                           owner_identity=owner_identity,
                           accessor_identity=accessor_identity,
                           idempotent=idempotent)
            if existing and existing["status"] in (CLAIM_FAILED, CLAIM_EXPIRED):
                wc.attempt = existing.get("attempt", 0)
                wc.checkpoint = existing.get("checkpoint")
            wc.status = CLAIM_ACTIVE
            wc.lease_expires = time.time() + lease_sec
            wc.last_heartbeat = time.time()
            claims[case_id] = wc.to_dict()
            _save_claims(self.engagement_dir, claims)
            _append_history(self.engagement_dir, {
                "event": "claimed", "case_id": case_id,
                "claim_id": wc.claim_id, "worker_id": worker_id,
                "attempt": wc.attempt})
            return wc

    def heartbeat(self, case_id, worker_id, checkpoint=None):
        """Renew the lease on a work claim. Returns True if still valid."""
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            c = claims.get(case_id)
            if not c or c.get("worker_id") != worker_id:
                return False
            if c["status"] != CLAIM_ACTIVE:
                return False
            c["lease_expires"] = time.time() + c.get("lease_sec", DEFAULT_LEASE_SEC)
            c["last_heartbeat"] = time.time()
            if checkpoint is not None:
                c["checkpoint"] = checkpoint
            _save_claims(self.engagement_dir, claims)
            return True

    def complete(self, case_id, worker_id):
        """Mark a work claim as completed."""
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            c = claims.get(case_id)
            if not c or c.get("worker_id") != worker_id:
                return False
            c["status"] = CLAIM_COMPLETED
            _save_claims(self.engagement_dir, claims)
            _append_history(self.engagement_dir, {
                "event": "completed", "case_id": case_id,
                "claim_id": c["claim_id"], "worker_id": worker_id})
            return True

    def fail(self, case_id, worker_id, error=None):
        """Mark a work claim as failed (eligible for retry if idempotent and under budget).
        Increments the attempt counter so retry budget is correctly tracked."""
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            c = claims.get(case_id)
            if not c or c.get("worker_id") != worker_id:
                return False
            c["status"] = CLAIM_FAILED
            c["attempt"] = c.get("attempt", 0) + 1
            c["error"] = str(error or "")[:500]
            _save_claims(self.engagement_dir, claims)
            _append_history(self.engagement_dir, {
                "event": "failed", "case_id": case_id,
                "claim_id": c["claim_id"], "worker_id": worker_id,
                "error": c["error"], "attempt": c["attempt"]})
            return True

    def cancel(self, case_id, worker_id):
        """Cancel a work claim (no retry)."""
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            c = claims.get(case_id)
            if not c or c.get("worker_id") != worker_id:
                return False
            c["status"] = CLAIM_CANCELLED
            _save_claims(self.engagement_dir, claims)
            _append_history(self.engagement_dir, {
                "event": "cancelled", "case_id": case_id,
                "claim_id": c["claim_id"], "worker_id": worker_id})
            return True

    def set_awaiting_approval(self, case_id, worker_id):
        """Mark that human approval is needed (pauses safely, doesn't count as failure)."""
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            c = claims.get(case_id)
            if not c or c.get("worker_id") != worker_id:
                return False
            c["status"] = CLAIM_AWAITING_APPROVAL
            _save_claims(self.engagement_dir, claims)
            _append_history(self.engagement_dir, {
                "event": "awaiting_approval", "case_id": case_id,
                "claim_id": c["claim_id"], "worker_id": worker_id})
            return True

    def recover_expired(self):
        """Find and mark expired leases. Returns list of expired case_ids."""
        now = time.time()
        expired = []
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            for case_id, c in claims.items():
                if c["status"] == CLAIM_ACTIVE and now >= c.get("lease_expires", 0):
                    c["status"] = CLAIM_EXPIRED
                    expired.append(case_id)
                    _append_history(self.engagement_dir, {
                        "event": "lease_expired", "case_id": case_id,
                        "claim_id": c["claim_id"],
                        "worker_id": c.get("worker_id")})
            if expired:
                _save_claims(self.engagement_dir, claims)
        return expired

    def retryable(self):
        """Return case_ids eligible for retry (failed + under budget + idempotent)."""
        with _LOCK:
            claims = _load_claims(self.engagement_dir)
            result = []
            for case_id, c in claims.items():
                if c["status"] in (CLAIM_FAILED, CLAIM_EXPIRED):
                    if c.get("idempotent", True):
                        if c.get("attempt", 0) < c.get("max_retries", DEFAULT_MAX_RETRIES):
                            result.append(case_id)
            return result

    def status(self, case_id=None):
        """Get claim status for one or all cases."""
        claims = _load_claims(self.engagement_dir)
        if case_id:
            return claims.get(case_id)
        return claims

    def metrics(self):
        """Summary metrics for the scheduler."""
        claims = _load_claims(self.engagement_dir)
        counts = {}
        for c in claims.values():
            s = c.get("status", "unknown")
            counts[s] = counts.get(s, 0) + 1
        return {
            "total": len(claims),
            "by_status": counts,
            "retryable": len(self.retryable()),
        }


def _selftest():
    import tempfile
    d = tempfile.mkdtemp()
    s = Scheduler(d)

    # Claim work
    c1 = s.claim_work("case-1", "worker-A", lease_sec=2)
    assert c1 is not None, "first claim should succeed"
    assert c1.status == CLAIM_ACTIVE

    # Duplicate claim should fail (active lease)
    c2 = s.claim_work("case-1", "worker-B")
    assert c2 is None, "duplicate claim should fail"

    # Heartbeat
    assert s.heartbeat("case-1", "worker-A", checkpoint={"step": 1})

    # Complete
    assert s.complete("case-1", "worker-A")
    assert s.status("case-1")["status"] == CLAIM_COMPLETED

    # Completed work can't be reclaimed
    assert s.claim_work("case-1", "worker-C") is None

    # Claim + fail + retry
    c3 = s.claim_work("case-2", "worker-A", lease_sec=2)
    assert c3 is not None
    s.fail("case-2", "worker-A", error="timeout")
    assert "case-2" in s.retryable()

    # Retry succeeds
    c4 = s.claim_work("case-2", "worker-B")
    assert c4 is not None
    assert c4.attempt == 1
    s.complete("case-2", "worker-B")

    # Non-idempotent work doesn't retry
    c5 = s.claim_work("case-3", "worker-A", idempotent=False)
    s.fail("case-3", "worker-A", error="uncertain outcome")
    assert "case-3" not in s.retryable()

    # Lease expiry
    c6 = s.claim_work("case-4", "worker-A", lease_sec=0)
    time.sleep(0.1)
    expired = s.recover_expired()
    assert "case-4" in expired

    # Expired work is retryable
    assert "case-4" in s.retryable()

    # Awaiting approval
    c7 = s.claim_work("case-5", "worker-A")
    s.set_awaiting_approval("case-5", "worker-A")
    assert s.status("case-5")["status"] == CLAIM_AWAITING_APPROVAL

    # Max retries exhausted
    c8 = s.claim_work("case-6", "worker-A", lease_sec=1)
    s.fail("case-6", "worker-A", error="fail-0")
    for i in range(1, DEFAULT_MAX_RETRIES):
        cn = s.claim_work("case-6", "worker-A")
        assert cn is not None, f"retry {i} should succeed"
        s.fail("case-6", "worker-A", error=f"fail-{i}")
    assert "case-6" not in s.retryable(), "exhausted retries should not be retryable"

    # Metrics
    m = s.metrics()
    assert m["total"] > 0

    # History file exists and has entries
    hist = _history_path(d)
    assert os.path.isfile(hist)
    with open(hist) as f:
        lines = [l for l in f if l.strip()]
    assert len(lines) >= 6

    # Concurrent claims (thread safety)
    import concurrent.futures
    results = []
    def _try_claim(wid):
        return s.claim_work("case-race", wid, lease_sec=60)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_try_claim, f"w-{i}") for i in range(10)]
        results = [f.result() for f in futs]
    winners = [r for r in results if r is not None]
    assert len(winners) == 1, f"exactly one claim should win, got {len(winners)}"

    import shutil
    shutil.rmtree(d, ignore_errors=True)
    print("scheduler.py self-test: PASS")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        _selftest()
    else:
        _selftest()
