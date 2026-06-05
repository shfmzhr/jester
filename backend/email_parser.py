import email
import re
from email import policy

def parse_email(raw_text: str) -> dict:
    """
    Parse raw email text and extract structured fields.
    Handles both full RFC 2822 emails and plain body-only text.
    """
    result = {
        "subject": "",
        "sender": "",
        "reply_to": "",
        "body": "",
        "urls": [],
        "has_attachments": False
    }

    try:
        msg = email.message_from_string(raw_text, policy=policy.default)

        result["subject"]   = str(msg.get("Subject", "")).strip()
        result["sender"]    = str(msg.get("From", "")).strip()
        result["reply_to"]  = str(msg.get("Reply-To", "")).strip()

        # Extract body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    result["body"] += part.get_content()
                elif content_type not in ("text/plain", "text/html", "multipart/alternative", "multipart/mixed"):
                    result["has_attachments"] = True
        else:
            result["body"] = msg.get_content()

        # If nothing parsed as email headers, treat entire input as plain body
        if not result["subject"] and not result["sender"]:
            result["body"] = raw_text

    except Exception:
        result["body"] = raw_text

    # Extract URLs from body
    result["urls"] = extract_urls(result["body"])

    return result


def extract_urls(text: str) -> list:
    pattern = r'https?://[^\s\'"<>]+'
    return list(set(re.findall(pattern, text)))
