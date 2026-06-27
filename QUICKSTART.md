# Quick Start Guide

Get the phishing pipeline running in 5 minutes.

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

## 2. Setup Gmail (one-time)

```bash
# Download credentials.json from Google Cloud Console
# See README.md for detailed steps

# Then run OAuth setup
python -c "from pipeline.ingest.gmail_poller import setup_gmail_oauth; setup_gmail_oauth()"
```

## 3. Configure API Keys

```bash
# Copy and edit config
cp .env.example .env

# Edit .env with your keys:
# - OPENAI_API_KEY (required for GPT-4o verdict)
# - VIRUSTOTAL_API_KEY (optional)
# - ABUSEIPDB_API_KEY (optional)
# - URLSCAN_API_KEY (optional)
# - THEHIVE_API_KEY (optional)
# - SLACK_WEBHOOK_URL (optional)
```

## 4. Test Without Real Gmail

Test the pipeline with mock emails:

```bash
python test_pipeline.py
```

This will:
- Extract IOCs from sample phishing emails
- Query VirusTotal, AbuseIPDB, URLScan.io (if keys configured)
- Run GPT-4o analysis
- Show verdicts and confidence scores

## 5. Run Production Pipeline

Start continuous Gmail polling:

```bash
python main.py
```

The pipeline will:
- Poll Gmail every 5 minutes for emails with "phishing" label
- Extract IOCs (URLs, IPs, domains, hashes)
- Query threat intelligence APIs in parallel
- Analyze with GPT-4o to get verdict
- Auto-block malicious IOCs
- Create TheHive cases
- Send Slack alerts

Press Ctrl+C to stop.

## 6. Monitor Logs

Watch the pipeline in action:

```bash
# Real-time log display
tail -f phishing_pipeline.log

# Check block list
cat block_list.json

# Check escalations
cat escalation_log.jsonl
```

## Minimal Configuration

If you only have OpenAI API key, this will work:

```env
OPENAI_API_KEY=sk-proj-xxx
GMAIL_CREDENTIALS_PATH=credentials.json
# Everything else optional
```

The pipeline will:
- Extract IOCs ✅
- Use GPT-4o for verdict ✅
- Log to block_list.json ✅
- Skip other enrichment APIs ✅

## Troubleshooting

**Gmail not polling?**
- Check credentials.json exists
- Check token.pickle is generated
- Look for auth errors in logs

**No verdicts being generated?**
- Check OPENAI_API_KEY is set
- Pipeline falls back to heuristic scoring if GPT fails

**Slack alerts not sending?**
- Check SLACK_WEBHOOK_URL is set correctly
- Test with: `curl -X POST -H 'Content-type: application/json' --data '{"text":"Test"}' YOUR_WEBHOOK_URL`

**TheHive cases not creating?**
- Check THEHIVE_URL and THEHIVE_API_KEY
- Ensure TheHive instance is running and accessible

## Next Steps

1. Label some test emails as "phishing" in Gmail
2. Wait for poll (default 5 min) or manually modify `POLL_INTERVAL` to 10 seconds for testing
3. Watch logs as pipeline processes them
4. Check block_list.json for blocked IOCs
5. Check Slack channel for alerts
6. Check TheHive for created cases

## Feature Flags

Disable features without removing config:

```env
# Skip Gmail polling
SKIP_GMAIL=true

# Test mode - don't actually block IOCs
DRY_RUN=true

# Skip TheHive integration
SKIP_THEHIVE=true

# Skip Slack notifications
SKIP_SLACK=true
```

## Performance Tips

- **Reduce API calls**: Set `GMAIL_MAX_RESULTS=5` for faster testing
- **Faster polling**: Set `POLL_INTERVAL=60` for 1-minute polling
- **Skip slow APIs**: Comment out URLScan queries in main.py for faster verdicts

## Next: Full Setup

See README.md for:
- Full configuration options
- Error handling details
- Architecture deep-dive
- API integration details
- Security considerations
