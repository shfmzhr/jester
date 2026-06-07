from flask import Blueprint, request, jsonify
from email_parser import parse_email
from utils.rate_limiter import is_rate_limited, is_daily_limit_reached, get_scans_remaining
from utils.url_checker import check_urls
from llm.llm_engine import analyse_email

analyse_bp = Blueprint("analyse", __name__)

@analyse_bp.route("/analyse", methods=["POST"])
def analyse():
    client_ip = request.remote_addr
    token = request.headers.get("X-Premium-Token", None)

    if is_rate_limited(client_ip):
        return jsonify({"error": "Too many requests. Slow down."}), 429

    if is_daily_limit_reached(client_ip, token):
        return jsonify({
            "error": "Free tier limit reached (5 scans/day). Upgrade to Jester Premium for unlimited scans.",
            "upgrade": True,
            "scans_remaining": 0
        }), 403

    data = request.get_json()
    if not data or "email_text" not in data:
        return jsonify({"error": "Missing email_text field"}), 400

    email_text = data["email_text"].strip()
    if not email_text:
        return jsonify({"error": "email_text cannot be empty"}), 400

    # Parse email
    parsed = parse_email(email_text)

    # Check URLs against Google Safe Browsing
    url_report = check_urls(parsed.get("urls", []))

    # If URLs are flagged, add them as signals to parsed email
    if url_report["flagged"]:
        parsed["flagged_urls"] = url_report["flagged"]

    # Call Claude for verdict
    result = analyse_email(parsed, premium=bool(token))
    scans_left = get_scans_remaining(client_ip, token)

    return jsonify({
        "verdict":              result["verdict"],
        "risk_level":           result["risk_level"],
        "explanation":          result["explanation"],
        "signals":              result["signals"],
        "url_check":            url_report,
        "scans_remaining":      scans_left,
        "parsed_email":         parsed
    }), 200
