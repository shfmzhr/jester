import os
import json
import anthropic

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are Jester, an expert email security analyst specializing in phishing detection.

Your job is to analyse emails and determine if they are phishing attempts or legitimate.

You must respond with ONLY a valid JSON object — no explanation, no markdown, no code fences.

The JSON must have exactly these fields:
{
  "verdict": "PHISHING" or "LEGITIMATE",
  "risk_level": "high", "medium", or "low",
  "explanation": "2-3 sentence plain English explanation of your verdict",
  "signals": ["list", "of", "specific", "phishing", "signals", "detected"]
}

Phishing signals to look for:
- Sender domain mismatch or spoofing (e.g. paypa1.com, secure-bank.net)
- Reply-To address different from From address
- Urgency language (act now, account suspended, verify immediately)
- Suspicious URLs (IP addresses, URL shorteners, misspelled domains)
- Requests for credentials, OTPs, or personal information
- Generic greetings (Dear Customer, Dear User)
- Threats of account suspension or legal action
- Mismatched or suspicious links
- Poor grammar or spelling
- Unexpected attachments

If the email is clearly legitimate, say so. Do not over-classify.
"""

def analyse_email(parsed_email: dict, premium: bool = False) -> dict:
    email_text = f"""
FROM: {parsed_email.get('sender', 'Unknown')}
REPLY-TO: {parsed_email.get('reply_to', 'None')}
SUBJECT: {parsed_email.get('subject', 'None')}
URLS FOUND: {', '.join(parsed_email.get('urls', [])) or 'None'}
HAS ATTACHMENTS: {parsed_email.get('has_attachments', False)}

BODY:
{parsed_email.get('body', '')[:3000]}
""".strip()

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Analyse this email and return your verdict as JSON:\n\n{email_text}"
                }
            ]
        )

        raw = response.content[0].text.strip()

        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        result = json.loads(raw)

        required = {"verdict", "risk_level", "explanation", "signals"}
        if not required.issubset(result.keys()):
            raise ValueError("Missing required fields in LLM response")

        result["verdict"]    = result["verdict"].upper()
        result["risk_level"] = result["risk_level"].lower()

        # Free tier: hide signals, truncate explanation
        if not premium:
            result["signals"] = []
            result["explanation"] = result["explanation"][:200]

        return result

    except json.JSONDecodeError:
        return _fallback("Could not parse AI response.")
    except Exception as e:
        return _fallback(str(e))


def _fallback(reason: str) -> dict:
    return {
        "verdict": "UNKNOWN",
        "risk_level": "unknown",
        "explanation": f"Analysis could not be completed: {reason}",
        "signals": []
    }
