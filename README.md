# VulnBank — Semgrep CI/CD Security Demo

A deliberately vulnerable Flask banking app demonstrating
how Semgrep catches security issues automatically in Jenkins.

## Vulnerabilities Demonstrated
- SQL Injection (login bypass)
- IDOR (unauthorized account access)
- Command Injection (file upload)
- Hardcoded Secrets (admin credentials)
- Weak Cryptography (MD5 password reset tokens)
- Vulnerable Dependencies (CVE-XXXX-XXXX in requests)

## What Semgrep Catches
[screenshot of Jenkins pipeline failure]
[screenshot of inline finding with exact line]

## The Pipeline
[diagram of Jenkins stages]

## Running Locally
