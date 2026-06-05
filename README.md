# PhishGuard

LLM-based phishing email detector and explainer.  
Built with Flask + Anthropic Claude API + Chrome Extension.

## Team
- Shifa Mazhar — Backend Developer
- Sanwal Fareed — AI / LLM Engineer

## Setup (local)

```bash
cd backend
pip install -r requirements.txt
python app.py
```

API runs at http://localhost:5000

## Endpoints

`POST /analyse` — Accepts `{ "email_text": "..." }`, returns verdict JSON.
