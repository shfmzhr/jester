import os
import requests

SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_urls(urls: list) -> dict:
    """
    Check a list of URLs against Google Safe Browsing API.
    Returns a dict with flagged URLs and overall verdict.
    """
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")

    if not urls:
        return {"flagged": [], "safe_browsing_checked": False, "reason": "No URLs found"}

    if not api_key:
        return {"flagged": [], "safe_browsing_checked": False, "reason": "API key not configured"}

    payload = {
        "client": {
            "clientId": "jester-phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls[:10]]  # max 10 URLs
        }
    }

    try:
        response = requests.post(
            f"{SAFE_BROWSING_API}?key={api_key}",
            json=payload,
            timeout=5
        )
        data = response.json()

        flagged = []
        if "matches" in data:
            for match in data["matches"]:
                flagged.append({
                    "url": match["threat"]["url"],
                    "threat_type": match["threatType"]
                })

        return {
            "flagged": flagged,
            "safe_browsing_checked": True,
            "urls_checked": len(urls[:10])
        }

    except Exception as e:
        return {
            "flagged": [],
            "safe_browsing_checked": False,
            "reason": str(e)
        }
