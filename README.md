# JESTER — LLM-based Phishing Email Detector & Explainer

Jester analyses emails (pasted or auto-extracted from Gmail), returns a
phishing verdict with a plain-English explanation, and runs deterministic
header/URL checks alongside an LLM (Anthropic Claude) for defence in depth.

Built with **Flask + Anthropic Claude + Google Safe Browsing + a Chrome MV3 extension.**

## Team
- **Shifa Mazhar** — Backend Developer
- **Sanwal Fareed** — AI / ML Engineer
- **Hifsa Iftikhar** — Frontend / Extension Developer
- (PM / Report Writer)

## Architecture
```
Chrome Extension (popup + Gmail content script)
        │  POST /analyse   { email_text }   headers: X-Client-Id, X-Premium-Token
        ▼
Flask API (Railway)
   ├─ rate_limiter   persistent per-client daily quota (SQLite)
   ├─ email_parser   headers + HTML→text + URL/href + deterministic signals
   ├─ url_checker    Google Safe Browsing
   └─ llm_engine     Claude verdict (prompt-injection hardened) + signal merge
        ▼
   JSON verdict → rendered in popup
```

## Setup (local)
```bash
cd backend
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."          # REQUIRED
export GOOGLE_SAFE_BROWSING_KEY="..."          # optional (URL reputation)
export PREMIUM_TOKENS="my-token-1,my-token-2"  # optional (extra premium codes)
python app.py
```
API runs at http://localhost:5000

### Environment variables
| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key (required) |
| `GOOGLE_SAFE_BROWSING_KEY` | URL reputation (optional) |
| `PREMIUM_TOKENS` | Comma-separated premium codes (optional) |
| `FREE_DAILY_LIMIT` | Free scans/day (default 5) |
| `QUOTA_DB_PATH` | SQLite quota DB path — point at a persistent volume in prod |
| `ALLOWED_ORIGINS` | Comma-separated CORS allow-list (default `*`) |

## Endpoints
- `POST /analyse` — body `{ "email_text": "..." }`; headers `X-Client-Id`, optional `X-Premium-Token`. Returns verdict JSON.
- `GET /status` — returns `{ premium, scans_remaining, daily_limit }` so the popup can sync its quota badge.

## Premium (demo)
Open the extension → **Activate Premium** → enter `JESTER-PREMIUM-DEMO-2026`.
Premium = unlimited scans + detailed signals + recommended action.

## Tests
```bash
cd backend
python test_fixes.py       # 24 offline unit checks (LLM mocked, no key needed)
python test_endpoints.py   # end-to-end HTTP checks via Flask test client
```

## Extension
Load `extension/` as an unpacked extension in Chrome (`chrome://extensions` →
Developer mode → Load unpacked).
