import time
from collections import defaultdict

_request_log: dict = defaultdict(list)
_daily_log: dict = defaultdict(list)

FREE_DAILY_LIMIT = 5
RATE_WINDOW_SECONDS = 60
RATE_MAX_PER_MINUTE = 10

PREMIUM_TOKENS = set()

def is_premium(token: str) -> bool:
    return token and token in PREMIUM_TOKENS

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window_start = now - RATE_WINDOW_SECONDS
    _request_log[ip] = [t for t in _request_log[ip] if t > window_start]
    if len(_request_log[ip]) >= RATE_MAX_PER_MINUTE:
        return True
    _request_log[ip].append(now)
    return False

def is_daily_limit_reached(ip: str, token: str = None) -> bool:
    if is_premium(token):
        return False
    today_start = time.time() - (time.time() % 86400)
    _daily_log[ip] = [t for t in _daily_log[ip] if t > today_start]
    if len(_daily_log[ip]) >= FREE_DAILY_LIMIT:
        return True
    _daily_log[ip].append(time.time())
    return False

def get_scans_remaining(ip: str, token: str = None) -> int:
    if is_premium(token):
        return -1
    today_start = time.time() - (time.time() % 86400)
    used = len([t for t in _daily_log[ip] if t > today_start])
    return max(0, FREE_DAILY_LIMIT - used)
