import os, json, tempfile
tmp = tempfile.mkdtemp()
os.environ["QUOTA_DB_PATH"] = os.path.join(tmp, "ep.db")
os.environ["ANTHROPIC_API_KEY"] = "test-key"
os.environ["FREE_DAILY_LIMIT"] = "3"

import anthropic
class _R:
    def __init__(s,t): s.content=[type("B",(),{"text":t})]
class M:
    def create(s,**k): return _R(json.dumps({"verdict":"PHISHING","risk_level":"high",
        "explanation":"Test phish.","signals":["urgency"],"recommended_action":"Delete it."}))
class C:
    def __init__(s,**k): s.messages=M()
anthropic.Anthropic = C

from app import create_app
app = create_app(); c = app.test_client()
H = {"X-Client-Id":"e2e-user-1"}
ok = True

r = c.get("/status", headers=H); d=r.get_json()
print("status:", d); ok &= (d["scans_remaining"]==3 and d["premium"] is False)

for i in range(3):
    r = c.post("/analyse", json={"email_text":"From: a@b.com\n\nClick now"}, headers=H)
    print(f"scan {i+1}: {r.status_code} remaining={r.get_json().get('scans_remaining')}")
    ok &= (r.status_code==200)

r = c.post("/analyse", json={"email_text":"x"}, headers=H)
print("4th scan (over limit):", r.status_code, r.get_json().get("upgrade"))
ok &= (r.status_code==403 and r.get_json().get("upgrade") is True)

# premium header -> unlimited
HP = {"X-Client-Id":"e2e-user-1","X-Premium-Token":"JESTER-PREMIUM-DEMO-2026"}
r = c.post("/analyse", json={"email_text":"From: a@b.com\n\nhi"}, headers=HP); d=r.get_json()
print("premium scan:", r.status_code, "remaining=", d.get("scans_remaining"), "signals=", d.get("signals"))
ok &= (r.status_code==200 and d["scans_remaining"]==-1 and d["premium"] is True and len(d["signals"])>=1)

# different client still has full quota (not shared via proxy IP)
r = c.get("/status", headers={"X-Client-Id":"e2e-user-2"}); 
print("other client status:", r.get_json())
ok &= (r.get_json()["scans_remaining"]==3)

# oversized body rejected
r = c.post("/analyse", json={"email_text":"x"*60000}, headers={"X-Client-Id":"big"})
print("oversized:", r.status_code); ok &= r.status_code in (413,400)

print("\nENDPOINT TESTS:", "ALL PASS" if ok else "FAILURE")
import sys; sys.exit(0 if ok else 1)
