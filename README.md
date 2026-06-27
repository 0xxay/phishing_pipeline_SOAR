# SOAR-Lite Phishing Response Pipeline

A complete Python-based phishing response pipeline that automatically detects, analyzes, and responds to phishing emails. This SOAR (Security Orchestration, Automation, and Response) system integrates threat intelligence APIs with AI-powered decision making to classify emails and take automated actions.

## Architecture

The pipeline processes phishing emails through five stages:

```
1. INGEST → Poll Gmail for "phishing" labeled emails every 5 minutes
   ↓
2. EXTRACT → Extract IOCs (URLs, IPs, domains, hashes) from email body/attachments
   ↓
3. ENRICH → Query VirusTotal, AbuseIPDB, URLScan.io in parallel
   ↓
4. DECIDE → GPT-4o analyzes enrichment data → Verdict: MALICIOUS/SUSPICIOUS/CLEAN
   ↓
5. RESPOND → Route based on verdict:
   - MALICIOUS → Auto-block IOCs + escalate to TheHive
   - SUSPICIOUS → Analyst alert via Slack
   - CLEAN → Log false positive
```

### Verdict Thresholds

- **MALICIOUS**: VirusTotal detections > 5 OR AbuseIPDB confidence > 70% OR GPT-4o analysis says malicious
- **SUSPICIOUS**: Any red flags below malicious threshold
- **CLEAN**: No significant indicators detected

## Prerequisites

### Required

- Python 3.11+
- OpenAI API key (GPT-4o for scoring)
- Gmail API credentials (for email polling)

### Optional (but recommended for full functionality)

- VirusTotal API key (for URL/hash reputation)
- AbuseIPDB API key (for IP reputation)
- URLScan.io API key (for URL scanning/screenshots)
- TheHive instance running on localhost:9000 (for case management)
- Slack webhook URL (for notifications)

## Setup Instructions

### 1. Clone and Install

```bash
git clone https://github.com/0xxay/phishing_pipeline_SOAR.git
cd phishing_pipeline_SOAR
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Gmail OAuth Setup

One-time setup to enable Gmail API access:

**Step 1: Create Google Cloud Project**
1. Go to https://console.cloud.google.com/
2. Create a new project
3. Enable Gmail API
4. Create OAuth 2.0 Credentials (type: Desktop application)
5. Download the JSON file and save as `credentials.json` in this directory

**Step 2: Run OAuth Flow**
```bash
python -c "from pipeline.ingest.gmail_poller import setup_gmail_oauth; setup_gmail_oauth()"
```

This will open a browser window to authenticate. After authentication, `token.pickle` will be saved for future runs.

### 3. Configure API Keys

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

Edit `.env`:
- `OPENAI_API_KEY`: Get from https://platform.openai.com/api-keys
- `VIRUSTOTAL_API_KEY`: Get from https://www.virustotal.com/gui/user/api-key
- `ABUSEIPDB_API_KEY`: Get from https://www.abuseipdb.com/api
- `URLSCAN_API_KEY`: Get from https://urlscan.io/api/
- `THEHIVE_API_KEY`: Get from TheHive instance
- `SLACK_WEBHOOK_URL`: Create at https://api.slack.com/

### 4. Optional: Setup TheHive

If you want to use TheHive for case management:

1. Install/run TheHive v5
2. Set `THEHIVE_URL` and `THEHIVE_API_KEY` in `.env`
3. Or skip with `SKIP_THEHIVE=true` in `.env`

### 5. Optional: Setup Slack

Create a Slack webhook for notifications:

1. Go to https://api.slack.com/apps
2. Create a new app
3. Enable Incoming Webhooks
4. Copy the webhook URL to `SLACK_WEBHOOK_URL` in `.env`

## Running the Pipeline

### Production: Continuous Polling

Runs polling loop checking Gmail every 5 minutes (configurable):

```bash
python main.py
```

Press Ctrl+C to gracefully shutdown.

### Testing: Single Email Test

Test the pipeline with mock emails without real Gmail/TheHive:

```bash
python test_pipeline.py
```

This runs extract/enrich/decide stages on sample phishing emails using your real API keys (VirusTotal, AbuseIPDB, etc.).

### Testing with Real Email (Optional)

To test on a real email from your Gmail without auto-blocking:

```bash
# Set DRY_RUN=true in .env to test without actions
python main.py  # Will process one email and exit
```

## Configuration

All settings are in `.env`. Key options:

```
# Email polling interval (seconds)
POLL_INTERVAL=300

# Skip certain features
SKIP_GMAIL=false        # Disable Gmail polling
SKIP_THEHIVE=false      # Disable TheHive case creation
SKIP_SLACK=false        # Disable Slack notifications

# Dry run mode (test without taking actions)
DRY_RUN=false

# Verdict thresholds
VT_DETECTION_THRESHOLD=5           # VirusTotal detections to flag as malicious
ABUSEIPDB_CONFIDENCE_THRESHOLD=70  # AbuseIPDB confidence % for malicious

# Logging
LOG_LEVEL=INFO
LOG_FILE=phishing_pipeline.log
```

## Output Files

The pipeline creates several output files:

- **block_list.json**: List of blocked URLs, IPs, domains, and hashes
- **escalation_log.jsonl**: JSONL log of all MALICIOUS verdicts
- **false_positive_log.jsonl**: JSONL log of all CLEAN verdicts
- **phishing_pipeline.log**: Detailed logs with timestamps

## Sample Phishing Email

Here's a test email that will trigger MALICIOUS verdict:

```
Subject: URGENT: Verify Your Account - Click Here Immediately
From: noreply@paypa1.suspicious.com

Your account has been compromised. Please verify your identity immediately by clicking the link below:

Click here: https://paypa1.suspicious.com/verify?token=abc123
Or visit: http://192.168.1.100:8080/phish

If you don't verify within 24 hours, your account will be suspended.

Regards,
PayPal Security Team
```

The pipeline will:
1. Extract URLs and IP
2. Query VirusTotal, AbuseIPDB, URLScan.io
3. Send to GPT-4o for analysis
4. Block the IOCs
5. Create TheHive case
6. Send Slack alert

## IOC Extraction

The pipeline extracts:

- **URLs**: `https?://` patterns
- **IPs**: IPv4 addresses (excludes private ranges)
- **Domains**: Extracted from URLs and standalone domain patterns
- **Hashes**: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
- **Attachment Hashes**: MD5/SHA256 of any email attachments

## Enrichment APIs

### VirusTotal v3
- Checks URL and file hash reputation
- Score calculation: malicious detections × 10 + suspicious × 5
- Returns verdict (malicious/suspicious/clean)

### AbuseIPDB v2
- Checks IP address abuse confidence score (0-100%)
- Maps to verdict: >75% = malicious, >25% = suspicious, <25% = clean
- Includes total abuse reports and country data

### URLScan.io
- Submits URL for scanning and waits for results
- Returns screenshot and detailed verdict
- Rate limited to avoid overload

## Decision Logic

The pipeline uses two-tier decision making:

1. **GPT-4o Analysis** (preferred if API key configured):
   - System prompt: "You are a security analyst"
   - User prompt includes email headers, IOCs, and all enrichment results
   - Returns JSON with verdict, confidence, reasoning, MITRE ATT&CK tactic
   - Extracts verdict and confidence score

2. **Heuristic Fallback** (if GPT unavailable):
   - Counts malicious/suspicious indicators
   - MALICIOUS if: malicious_count > 0
   - SUSPICIOUS if: suspicious_count > 1
   - CLEAN: otherwise

## Response Actions

### MALICIOUS
- ✅ Add IOCs to `block_list.json`
- ✅ Log to `escalation_log.jsonl`
- ✅ Create TheHive case with severity HIGH
- ✅ Send Slack alert (red)

### SUSPICIOUS
- ✅ Send Slack alert (orange) for analyst review
- ✅ Flag in TheHive as medium severity
- ✅ Include enrichment summary for analyst

### CLEAN
- ✅ Log to `false_positive_log.jsonl`
- ❌ No action taken

## Logging

Rich console output with color coding:
- **Green**: Success actions
- **Yellow**: Warnings
- **Red**: Errors
- **Blue**: IOCs found
- **Cyan**: Section headers

Plus detailed file logging to `phishing_pipeline.log`.

## Error Handling

Each enrichment API has retry logic:
- Max 3 retries per API call
- 2-second delay between retries
- Timeouts after 30 seconds
- If one API fails, others continue
- Pipeline completes even with partial enrichment data

## Performance

- Enrichment: Runs VirusTotal, AbuseIPDB, URLScan.io in parallel
- Gmail: Polls every 5 minutes (configurable)
- Decision: GPT-4o call takes ~3-5 seconds
- Total per email: 10-20 seconds (depending on enrichment speed)

## Security Notes

- **Never commit `.env` with real keys** - use `.env.example` as template
- **token.pickle**: OAuth token stored locally - keep secure
- **block_list.json**: Sanitized of sensitive data, safe to share
- **API keys**: All requests authenticated using configured keys
- **HTTPS**: All API calls use HTTPS
- **Rate limiting**: Respected for all APIs (limits queries per API)

## Troubleshooting

### Gmail authentication fails
```
Error: Gmail credentials not found at credentials.json
```
Solution: Run Gmail OAuth setup (see Setup Instructions #2)

### VirusTotal/AbuseIPDB returns 403
```
Error: Failed to check [resource]: 403
```
Solution: Check API key is correct in `.env`

### TheHive case creation fails
```
Error: Failed to create TheHive case: 401
```
Solution: Check TheHive URL and API key, ensure TheHive is running

### GPT-4o analysis fails
```
Error: GPT-4o analysis failed, falling back to heuristic
```
This is normal - heuristic scoring still works. Check OPENAI_API_KEY if GPT-4o is needed.

## File Structure

```
phishing_pipeline_SOAR/
├── main.py                          # Main orchestrator (run this)
├── test_pipeline.py                 # Test suite with mock emails
├── config.py                        # Configuration loader
├── requirements.txt                 # Dependencies
├── .env.example                     # Config template
├── README.md                        # This file
│
├── models/
│   ├── __init__.py
│   └── phishing_case.py            # Data classes: Email, IOCs, Verdict, etc.
│
├── utils/
│   ├── __init__.py
│   └── logger.py                   # Rich logging
│
└── pipeline/
    ├── ingest/
    │   ├── __init__.py
    │   └── gmail_poller.py         # Gmail API polling + OAuth
    ├── extract/
    │   ├── __init__.py
    │   ├── ioc_extractor.py        # URL/IP/domain/hash extraction
    │   ├── header_parser.py        # Email header analysis
    │   └── attachment_handler.py   # Attachment hash computation
    ├── enrich/
    │   ├── __init__.py
    │   ├── virustotal.py           # VirusTotal v3 API
    │   ├── abuseipdb.py            # AbuseIPDB v2 API
    │   └── urlscan.py              # URLScan.io API
    ├── decide/
    │   ├── __init__.py
    │   └── score_aggregator.py     # GPT-4o verdict + heuristic fallback
    ├── respond/
    │   ├── __init__.py
    │   ├── auto_block.py           # Block IOCs + escalate
    │   ├── analyst_alert.py        # Slack alerts for suspicious
    │   └── false_positive.py       # Log clean emails
    └── close/
        ├── __init__.py
        ├── thehive_client.py       # TheHive v5 case creation
        └── slack_notifier.py       # Final Slack summary
```

## Contributing

To add new enrichment sources:

1. Create `pipeline/enrich/newsource.py` with async `enrich(iocs: IOCs) -> List[EnrichmentResult]`
2. Add API key to `config.py`
3. Call from `main.py` in enrichment gather
4. Enrichment will be included in GPT-4o analysis

## License

This project is provided as-is for security research and incident response purposes.

## Support

For issues or questions:
1. Check logs: `tail -f phishing_pipeline.log`
2. Enable debug: `LOG_LEVEL=DEBUG` in `.env`
3. Test with: `python test_pipeline.py`
