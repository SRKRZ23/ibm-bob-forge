"""
Configuration file with security issues
"""

# ❌ LLM06: Hardcoded credentials
API_KEYS = {
    "openai": "sk-proj-CONFIG789xyz123abc",
    "anthropic": "sk-ant-api03-DEMO123456789",
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ❌ LLM06: Database credentials
DATABASE_URL = "postgresql://admin:password123@localhost:5432/production"

# ❌ LLM06: API tokens
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# ❌ LLM06: Encryption keys
SECRET_KEY = "super-secret-key-do-not-share"
JWT_SECRET = "jwt-secret-key-12345"

# Debug mode
DEBUG = True  # ❌ Should be False in production
