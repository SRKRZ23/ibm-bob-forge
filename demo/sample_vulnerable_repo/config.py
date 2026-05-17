"""
FORGE DEMO FILE — INTENTIONALLY VULNERABLE
==========================================
All credentials below are INVALID PLACEHOLDERS used to test FORGE's
ability to detect OWASP LLM06 (Sensitive Information Disclosure).

NONE of these tokens are real or functional. If your secrets scanner
flags this file, that is the demonstration working as intended —
FORGE detects the SAME patterns and generates policies to prevent
real secrets from being committed.

DO NOT use these strings anywhere. They are pedagogical examples only.
"""

# ❌ LLM06: Hardcoded credentials — all values are PLACEHOLDERS
API_KEYS = {
    "openai": "sk-FORGE_DEMO_PLACEHOLDER_NOT_A_REAL_TOKEN",
    "anthropic": "sk-FORGE_DEMO_PLACEHOLDER_NOT_A_REAL_TOKEN",
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",  # AWS-documented sample
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS-documented sample
}

# ❌ LLM06: Database credentials — placeholder
DATABASE_URL = "postgresql://admin:FORGE_DEMO_FAKE_PASSWORD@localhost:5432/demo"

# ❌ LLM06: API tokens — placeholder
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/FORGE_DEMO_FAKE"
GITHUB_TOKEN = "ghp_FORGE_DEMO_PLACEHOLDER_NOT_A_REAL_GITHUB_PAT"

# ❌ LLM06: Encryption keys — placeholder
SECRET_KEY = "FORGE_DEMO_FAKE_SECRET_KEY_DO_NOT_USE"
JWT_SECRET = "FORGE_DEMO_FAKE_JWT_SECRET_DO_NOT_USE"

# Debug mode
DEBUG = True  # ❌ Should be False in production
