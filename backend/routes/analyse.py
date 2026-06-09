from flask import Blueprint, request, jsonify

from email_parser import parse_email
from utils.rate_limiter import (
    is_rate_limited,
    is_daily_limit_reached,
    consume_scan,
    get_scans_remaining,
    is_premium,
    FREE_DAILY_LIMIT,
)
from utils.url_checker import check_urls
from llm.llm_engine import analyse_email

analyse_bp = Blueprint("analyse", __name__)

MAX_EMAIL_CHARS = 50_000


def _client_id() -> str:
    """
    Stable per-install identifier sent by the extension. Falls back to the
    forwarded client IP so the endpoint still works for ad-hoc curl/testing.
    """
    cid = (request.headers.get("X-Client-Id") or "").strip()
    if cid:
        return cid[:128]
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return "ip:" + fwd.split(",")[0].strip()
    return "ip:" + (request.remote_addr or "unknown")


@analyse_bp.route("/status", methods=["GET"])
def status():
    """Lightweight endpoint so the popup can sync the quota badge on open."""
    cid = _client_id()
    token = request.headers.get("X-Premium-Token")
    return jsonify({
        "premium": is_premium(token),
        "scans_remaining": get_scans_remaining(cid, token),
        "daily_limit": FREE_DAILY_LIMIT,
    }), 200


@analyse_bp.route("/analyse", methods=["POST"])
def analyse():
    cid = _client_id()
    token = request.headers.get("X-Premium-Token")

    if is_rate_limited(cid):
        return jsonify({"error": "Too many requests. Slow down."}), 429

    # Read-only check (does NOT consume a scan).
    if is_daily_limit_reached(cid, token):
        return jsonify({
            "error": f"Free tier limit reached ({FREE_DAILY_LIMIT} scans/day). "
                     "Upgrade to Jester Premium for unlimited scans.",
            "upgrade": True,
            "scans_remaining": 0,
        }), 403

    data = request.get_json(silent=True)
    if not data or "email_text" not in data:
        return jsonify({"error": "Missing email_text field"}), 400

    email_text = str(data["email_text"]).strip()
    if not email_text:
        return jsonify({"error": "email_text cannot be empty"}), 400
    if len(email_text) > MAX_EMAIL_CHARS:
        return jsonify({"error": "email_text too large"}), 413

    parsed = parse_email(email_text)
    url_report = check_urls(parsed.get("urls", []))
    if url_report.get("flagged"):
        parsed["flagged_urls"] = url_report["flagged"]
        parsed.setdefault("deterministic_signals", []).append(
            "One or more links were flagged by Google Safe Browsing"
        )

    result = analyse_email(parsed, premium=is_premium(token))

    # Only consume a free scan if the analysis actually succeeded.
    if result.get("verdict") != "UNKNOWN":
        consume_scan(cid, token)

    scans_left = get_scans_remaining(cid, token)

    # Do not echo the full raw body back to the client.
    parsed_public = {
        "subject": parsed.get("subject", ""),
        "sender": parsed.get("sender", ""),
        "reply_to": parsed.get("reply_to", ""),
        "urls": parsed.get("urls", []),
        "has_attachments": parsed.get("has_attachments", False),
    }

    return jsonify({
        "verdict":             result["verdict"],
        "risk_level":          result["risk_level"],
        "explanation":         result["explanation"],
        "signals":             result.get("signals", []),
        "recommended_action":  result.get("recommended_action", ""),
        "premium":             result.get("premium", False),
        "url_check":           url_report,
        "scans_remaining":     scans_left,
        "parsed_email":        parsed_public,
    }), 200
