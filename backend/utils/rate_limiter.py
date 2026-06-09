"""
Rate limiting and free-tier quota enforcement for Jester.

Design notes (fixes the "counter resets / unlimited scans" bug):
  * Daily quota is persisted in SQLite, so it SURVIVES container restarts,
    redeploys and the host sleeping. The old version kept counts in an
    in-memory dict that was wiped on every restart -> effectively unlimited.
  * Quota is keyed on a stable per-install client id (sent by the extension
    as the X-Client-Id header), NOT on request.remote_addr. Behind a proxy
    (Railway, etc.) remote_addr is the proxy's IP and is shared by every
    user, so it could never enforce a real per-user limit.
  * Premium tokens are loaded from the PREMIUM_TOKENS env var (comma
    separated) plus a built-in demo token, so Premium can actually be
    activated and demonstrated.
"""

import os
import time
import sqlite3
import threading
from datetime import datetime, timezone

FREE_DAILY_LIMIT     = int(os.environ.get("FREE_DAILY_LIMIT", "5"))
RATE_WINDOW_SECONDS  = 60
RATE_MAX_PER_MINUTE  = 10

# Where the quota database lives. Override with QUOTA_DB_PATH in production
# (point it at a mounted/persistent volume so it is not lost on redeploy).
DB_PATH = os.environ.get("QUOTA_DB_PATH", os.path.join(os.path.dirname(__file__), "quota.db"))

# ---------------------------------------------------------------------------
# Premium tokens
# ---------------------------------------------------------------------------
# A built-in demo token so the team can show the Premium experience to the
# professor without provisioning anything. In real production you would issue
# per-user tokens and store only their hashes.
_DEMO_TOKEN = "JESTER-PREMIUM-DEMO-2026"


def _load_premium_tokens() -> set:
    tokens = {_DEMO_TOKEN}
    env = os.environ.get("PREMIUM_TOKENS", "")
    for t in env.split(","):
        t = t.strip()
        if t:
            tokens.add(t)
    return tokens


PREMIUM_TOKENS = _load_premium_tokens()


def is_premium(token: str) -> bool:
    return bool(token) and token in PREMIUM_TOKENS


# ---------------------------------------------------------------------------
# Per-minute burst limiter (in-memory is fine: it only protects against
# bursts within a 60s window, where a restart simply resets the window).
# ---------------------------------------------------------------------------
from collections import defaultdict

_request_log: dict = defaultdict(list)
_lock = threading.Lock()


def is_rate_limited(key: str) -> bool:
    now = time.time()
    window_start = now - RATE_WINDOW_SECONDS
    with _lock:
        _request_log[key] = [t for t in _request_log[key] if t > window_start]
        if len(_request_log[key]) >= RATE_MAX_PER_MINUTE:
            return True
        _request_log[key].append(now)
    return False


# ---------------------------------------------------------------------------
# Persistent daily quota (SQLite)
# ---------------------------------------------------------------------------
def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_usage (
                client_id TEXT NOT NULL,
                day       TEXT NOT NULL,
                count     INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (client_id, day)
            )
            """
        )
        conn.commit()


_init_db()


def _today() -> str:
    """UTC calendar day, e.g. '2026-06-09'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def get_used(client_id: str) -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT count FROM daily_usage WHERE client_id=? AND day=?",
            (client_id, _today()),
        ).fetchone()
    return row[0] if row else 0


def get_scans_remaining(client_id: str, token: str = None) -> int:
    if is_premium(token):
        return -1  # unlimited
    return max(0, FREE_DAILY_LIMIT - get_used(client_id))


def is_daily_limit_reached(client_id: str, token: str = None) -> bool:
    """Read-only check. Does NOT consume a scan."""
    if is_premium(token):
        return False
    return get_used(client_id) >= FREE_DAILY_LIMIT


def consume_scan(client_id: str, token: str = None) -> bool:
    """
    Atomically record one successful scan against today's quota.
    Returns True if the scan was allowed and counted, False if the free
    limit was already reached. Premium clients are never counted.
    """
    if is_premium(token):
        return True

    day = _today()
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT count FROM daily_usage WHERE client_id=? AND day=?",
            (client_id, day),
        ).fetchone()
        used = row[0] if row else 0
        if used >= FREE_DAILY_LIMIT:
            return False
        conn.execute(
            """
            INSERT INTO daily_usage (client_id, day, count) VALUES (?, ?, 1)
            ON CONFLICT(client_id, day) DO UPDATE SET count = count + 1
            """,
            (client_id, day),
        )
        conn.commit()
    return True
