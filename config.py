"""Configuration loader for the phishing pipeline."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

# Google Gemini Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite-preview-06-17")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")  # "gemini" or "openai"

# Gmail IMAP Configuration (App Password — no OAuth needed)
GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")
GMAIL_MAX_RESULTS = int(os.getenv("GMAIL_MAX_RESULTS", "50"))
GMAIL_PROCESSED_IDS_FILE = os.getenv("GMAIL_PROCESSED_IDS_FILE", "processed_ids.json")

# Legacy OAuth fields (kept for API compatibility, not used)
GMAIL_CREDENTIALS_PATH = os.getenv("GMAIL_CREDENTIALS_PATH", "credentials.json")
GMAIL_TOKEN_PATH = os.getenv("GMAIL_TOKEN_PATH", "token.pickle")
GMAIL_LABEL = os.getenv("GMAIL_LABEL", "phishing")
GMAIL_SCAN_ALL = os.getenv("GMAIL_SCAN_ALL", "true").lower() == "true"

# Enrichment API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

# TheHive Configuration
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

# Slack Configuration
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# Pipeline Configuration
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))  # 5 minutes
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", "2"))  # seconds

# Scoring Thresholds
VT_DETECTION_THRESHOLD = int(os.getenv("VT_DETECTION_THRESHOLD", "5"))
ABUSEIPDB_CONFIDENCE_THRESHOLD = int(os.getenv("ABUSEIPDB_CONFIDENCE_THRESHOLD", "70"))
GPT_MALICIOUS_THRESHOLD = float(os.getenv("GPT_MALICIOUS_THRESHOLD", "0.8"))
GPT_SUSPICIOUS_THRESHOLD = float(os.getenv("GPT_SUSPICIOUS_THRESHOLD", "0.5"))

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "phishing_pipeline.log")

# Block List Configuration
BLOCK_LIST_FILE = os.getenv("BLOCK_LIST_FILE", "block_list.json")

# Feature Flags
SKIP_GMAIL = os.getenv("SKIP_GMAIL", "false").lower() == "true"
SKIP_THEHIVE = os.getenv("SKIP_THEHIVE", "false").lower() == "true"
SKIP_SLACK = os.getenv("SKIP_SLACK", "false").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
