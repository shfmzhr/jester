from flask import Blueprint, request, jsonify
from email_parser import parse_email
from utils.rate_limiter import is_rate_limited

analyse_bp = Blueprint("analyse", __name__)

@analyse_bp.route("/analyse", methods=["POST"])
def analyse():
    client_ip = request.remote_addr

    if is_rate_limited(client_ip):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    data = request.get_json()
    if not data or "email_text" not in data:
        return jsonify({"error": "Missing email_text field"}), 400

    email_text = data["email_text"].strip()
    if not email_text:
        return jsonify({"error": "email_text cannot be empty"}), 400

    parsed = parse_email(email_text)

    # llm_engine will be plugged in by Sanwal — stub response for now
    stub_result = {
        "verdict": "PENDING",
        "risk_level": "unknown",
        "explanation": "LLM module not yet connected.",
        "signals": [],
        "parsed_email": parsed
    }

    return jsonify(stub_result), 200
