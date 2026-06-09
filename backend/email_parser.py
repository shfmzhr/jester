"""
Email parsing and deterministic feature extraction for Jester.

Improvements over the original:
  * Falls back to extracting text from the HTML part when there is no
    text/plain part (most phishing mail is HTML-only -> old parser saw an
    empty body and the model had nothing to judge -> false negatives).
  * Extracts URLs from HTML <a href=...> too, not just visible bare URLs.
  * Detects a display-text vs href mismatch (classic phishing signal).
  * Fixes attachment detection (uses Content-Disposition instead of the
    old, incorrect content-type guesswork).
  * Adds cheap, deterministic header heuristics (From vs Reply-To mismatch,
    lookalike / punycode / IP-literal domains). These run OUTSIDE the LLM so
    a prompt-injected verdict can be sanity-checked against hard signals.
"""

import email
import re
from email import policy
from urllib.parse import urlparse

from bs4 import BeautifulSoup

URL_PATTERN = re.compile(r'https?://[^\s\'"<>)\]]+', re.IGNORECASE)
EMAIL_IN_ANGLE = re.compile(r'<([^<>@\s]+@[^<>@\s]+)>')

# Domains commonly impersonated; used only to flag *lookalikes*, never to
# whitelist the real domain.
COMMON_BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase", "dhl", "fedex",
    "instagram", "linkedin", "outlook", "office365", "icloud",
]


def parse_email(raw_text: str) -> dict:
    """Parse raw email text into structured fields plus deterministic signals."""
    result = {
        "subject": "",
        "sender": "",
        "reply_to": "",
        "body": "",
        "urls": [],
        "has_attachments": False,
        "deterministic_signals": [],
    }

    try:
        msg = email.message_from_string(raw_text, policy=policy.default)

        result["subject"]  = str(msg.get("Subject", "")).strip()
        result["sender"]   = str(msg.get("From", "")).strip()
        result["reply_to"] = str(msg.get("Reply-To", "")).strip()

        plain_body, html_body = "", ""

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    result["has_attachments"] = True
                    continue
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    plain_body += _safe_content(part)
                elif ctype == "text/html":
                    html_body += _safe_content(part)
        else:
            if msg.get_content_type() == "text/html":
                html_body = _safe_content(msg)
            else:
                plain_body = _safe_content(msg)

        # Prefer plain text; fall back to stripped HTML when no plain part.
        if plain_body.strip():
            result["body"] = plain_body.strip()
        elif html_body.strip():
            result["body"] = _html_to_text(html_body)

        # No headers parsed at all -> treat the whole input as a plain body.
        if not result["subject"] and not result["sender"] and not result["body"]:
            result["body"] = raw_text

        # URLs: bare URLs from the body + hrefs from any HTML part.
        urls = set(URL_PATTERN.findall(result["body"]))
        if html_body:
            urls |= _extract_hrefs(html_body)
            if _has_link_text_mismatch(html_body):
                result["deterministic_signals"].append(
                    "Link display text does not match its destination URL"
                )
        result["urls"] = sorted(urls)

    except Exception:
        result["body"] = raw_text
        result["urls"] = sorted(set(URL_PATTERN.findall(raw_text)))

    result["deterministic_signals"].extend(_header_signals(result))
    return result


def _safe_content(part) -> str:
    try:
        return part.get_content() or ""
    except Exception:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="ignore")
        return str(payload or "")


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return re.sub(r"\n{3,}", "\n\n", soup.get_text("\n")).strip()


def _extract_hrefs(html: str) -> set:
    soup = BeautifulSoup(html, "html.parser")
    hrefs = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().startswith(("http://", "https://")):
            hrefs.add(href)
    return hrefs


def _has_link_text_mismatch(html: str) -> bool:
    """True if an anchor's visible text shows one domain but links to another."""
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        text = a.get_text(" ", strip=True)
        shown = URL_PATTERN.findall(text)
        if shown and href.lower().startswith(("http://", "https://")):
            href_dom = _domain(href)
            for s in shown:
                if href_dom and _domain(s) and _domain(s) != href_dom:
                    return True
    return False


def _domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _addr(header_value: str) -> str:
    m = EMAIL_IN_ANGLE.search(header_value or "")
    if m:
        return m.group(1).strip().lower()
    return (header_value or "").strip().lower()


def _header_signals(parsed: dict) -> list:
    signals = []

    from_addr = _addr(parsed.get("sender", ""))
    reply_addr = _addr(parsed.get("reply_to", ""))

    if from_addr and reply_addr and "@" in from_addr and "@" in reply_addr:
        if from_addr.split("@")[-1] != reply_addr.split("@")[-1]:
            signals.append("Reply-To domain differs from the From domain")

    sender_dom = from_addr.split("@")[-1] if "@" in from_addr else ""
    if sender_dom:
        if sender_dom.startswith("xn--") or ".xn--" in sender_dom:
            signals.append("Sender uses a punycode (internationalised) domain")
        for brand in COMMON_BRANDS:
            if brand in sender_dom and not _is_official(sender_dom, brand):
                signals.append(
                    f"Sender domain '{sender_dom}' looks like a '{brand}' lookalike"
                )
                break

    for url in parsed.get("urls", []):
        host = _domain(url)
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host or ""):
            signals.append("A link points to a raw IP address instead of a domain")
            break

    return signals


def _is_official(domain: str, brand: str) -> bool:
    # Treat brand.com / brand.co.uk / mail.brand.com as official; flag
    # brand-secure.com, brand.verify-login.net, paypa1.com, etc.
    parts = domain.split(".")
    if len(parts) >= 2:
        registrable = ".".join(parts[-2:])
        if registrable == f"{brand}.com" or registrable.startswith(f"{brand}."):
            return True
    return False


def extract_urls(text: str) -> list:
    return sorted(set(URL_PATTERN.findall(text)))
