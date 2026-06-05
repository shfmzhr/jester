import time
from collections import defaultdict

# Simple in-memory rate limiter: max 10 requests per minute per IP
_request_log: dict = defaultdict(list)
MAX_REQUESTS = 10
WINDOW_SECONDS = 60

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window_start = now - WINDOW_SECONDS

    # Remove old entries outside the window
    _request_log[ip] = [t for t in _request_log[ip] if t > window_start]

    if len(_request_log[ip]) >= MAX_REQUESTS:
        return True

    _request_log[ip].append(now)
    return False
