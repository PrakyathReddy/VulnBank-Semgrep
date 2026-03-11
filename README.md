# VulnBank — Semgrep CI/CD Security Demo

A deliberately vulnerable Flask banking app demonstrating
how Semgrep catches security issues automatically in Jenkins.

## Vulnerabilities Demonstrated
- SQL Injection (login bypass) — app.py:112-116 <br>
  query = (
      f"SELECT * FROM users WHERE username = '{username}' "
      f"AND password = '{hashed}'"
  ) <br>
  user = db.execute(query).fetchone() <br>
  Username is concatenated directly into the SQL query. Payload like ' OR '1'='1' -- in the username field bypasses authentication. <br>
  
- IDOR (unauthorized account access) — app.py:141-143 <br>
  account = db.execute(
      "SELECT * FROM accounts WHERE id = ?", (account_id,)
  ).fetchone() <br>
  No ownership check. Any logged-in user can visit /account/1, /account/2, etc. and see any account. <br>

- Command Injection (file upload) — app.py:226-231 <br>
  result = subprocess.run(f"file {save_path}", shell=True, capture_output=True, text=True,) <br>
  The uploaded filename is embedded unsanitized into a shell command. A filename like foo; cat /etc/passwd executes arbitrary commands. <br>

- Hardcoded Secrets (admin credentials) — app.py:10-12                                                                                             
  app.secret_key = "supersecretkey123"                                                                                               
  ADMIN_USERNAME = "admin"                                                                                                            
  ADMIN_PASSWORD = "admin123"
  AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
  AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"                                                                                              
  Admin credentials and Flask session secret hardcoded in source.
  
- Weak Cryptography (MD5 password reset tokens) — app.py:249 <br>
  token = hashlib.md5(username.encode()).hexdigest() <br>
  MD5 is cryptographically broken and deterministic — the token for alice is always the same and trivially reversible via rainbow
  tables. <br>
  
- Vulnerable Dependencies (CVE-XXXX-XXXX in requests) — requirements.txt:2 <br>
  requests==2.18.0 <br>
  Pinned to an old version with known CVEs (e.g. CVE-2018-18074 — credential exposure via redirect). <br>

## App Screenshots

![Login Page](static/images/login%20page.png)

![Dashboard](static/images/post-login.png)

---
### Jenkins setup
1. Start docker engine through Docker Desktop
2. pull container for jenkins: $ docker pull jenkins/jenkins
3. run container for jenkins: $ docker run -d --name jenkins -p 8080:8080 -p 50000:50000 -v jenkins_home:/var/jenkins jenkins/jenkins:latest
---
## What Semgrep Catches

Semgrep ran 128 rules on 17 files and flagged **4 blocking findings**:

| Rule | File | Line | Description |
|---|---|---|---|
| `python.django.security.injection.tainted-sql-string` | app.py | 113 | User input concatenated into raw SQL query (SQL Injection) |
| `python.flask.security.injection.tainted-sql-string` | app.py | 113 | User input concatenated into raw SQL query (SQL Injection, Flask-specific) |
| `python.flask.security.injection.nan-injection` | app.py | 175 | User input passed directly into `float()` typecast (NaN injection) |
| `python.lang.security.audit.subprocess-shell-true` | app.py | 228 | `subprocess.run` called with `shell=True` (Command Injection) |

```
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings:        4 (4 blocking)
 • Rules run:       128
 • Targets scanned: 17
 • Parsed lines:    ~100.0%
```
---
### Secrets Scan (`p/secrets`)

Semgrep ran 94 rules on 17 files and flagged **0 findings** — despite hardcoded credentials in `app.py` (Flask secret key, admin password, dummy AWS keys). This demonstrates a key limitation of pattern-based secret detection: the `p/secrets` ruleset focuses on recognizable secret formats (API keys, tokens with specific patterns) and may miss generic variable assignments like `ADMIN_PASSWORD = "admin123"`.

```
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings:        0 (0 blocking)
 • Rules run:       94
 • Targets scanned: 17
 • Parsed lines:    ~100.0%
```
Despite injecting secrets, they didn't show up in the scan. There's limited number of rules in the free tier. I probably need to upgrade to a paid one or make custom rules.
---
## The Pipeline
[diagram of Jenkins stages]

## Running Locally
