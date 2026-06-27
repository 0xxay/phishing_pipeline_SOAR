# Quick Start: Web UI Dashboard

## Installation

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure environment variables** (update `.env`):
```bash
# For Gemini (recommended)
LLM_PROVIDER=gemini
GOOGLE_API_KEY=your-api-key-here

# Or for OpenAI
LLM_PROVIDER=openai
OPENAI_API_KEY=your-api-key-here

# Optional: Configure enrichment APIs for full feature set
VIRUSTOTAL_API_KEY=your-key
ABUSEIPDB_API_KEY=your-key
URLSCAN_API_KEY=your-key
```

## Starting the Dashboard

```bash
python run_ui.py
```

Then open your browser to: **http://localhost:8000**

## Using the Dashboard

### 1. View Statistics
The top stats cards show:
- Total processed emails
- Malicious count (red)
- Suspicious count (yellow)
- Clean count (green)

### 2. Run a Test
Click the **"Run Test Email"** button to:
- Process a sample phishing email through the full pipeline
- See real-time logs in the Live Logs panel
- View results in the Cases table
- Check enrichment data and LLM verdict

### 3. Monitor Live Logs
The **Live Pipeline Logs** panel shows:
- Colored log messages (green=success, red=error, yellow=warning)
- Real-time updates as pipeline runs
- Auto-scrolling to latest message

### 4. Review Cases
The **Recent Cases** table shows:
- Timestamp of when email was processed
- Email subject
- Sender address
- Verdict with confidence score
- Number of IOCs extracted

Click any row to see full details!

### 5. Inspect Case Details
Clicking a case opens a modal showing:
- **Email Info**: Subject, sender, verdict, confidence
- **LLM Reasoning**: Why the verdict was assigned
- **MITRE ATT&CK**: Relevant threat tactic (if any)
- **IOCs**: All extracted indicators (URLs, IPs, domains, hashes)
- **Enrichment**: Results from threat intelligence APIs:
  - VirusTotal: Detection counts and verdicts
  - AbuseIPDB: IP reputation scores
  - URLScan: URL scan results

## What Gets Saved

All case data is automatically saved to `cases.json`:
- Email metadata (subject, sender, body text not stored)
- Extracted IOCs
- Verdict and confidence
- Enrichment results
- LLM reasoning
- MITRE ATT&CK tactics
- TheHive case ID (if created)
- Slack notification status

The last 50 cases are always shown in the UI.

## Keyboard Shortcuts

- **Esc** - Close detail modal
- **Click outside modal** - Close detail modal
- **Scroll in logs** - Auto-stop scrolling (manual scroll)
- **Refresh browser** - Clear in-memory logs (persisted cases remain)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Port 8000 in use** | Change port in `run_ui.py` or kill process using port |
| **Logs not updating** | Check browser console for WebSocket errors; refresh page |
| **Test button disabled** | Pipeline is still processing; wait for completion |
| **No enrichment data** | Add API keys to `.env` (optional but recommended) |
| **Cases not loading** | Check if `cases.json` is readable; verify file permissions |

## Next Steps

1. **Add Real Emails**: Configure Gmail polling in `.env` to process real phishing emails
2. **Enable Notifications**: Set up Slack and TheHive integration
3. **Custom Rules**: Modify heuristic scoring thresholds in config
4. **Deployment**: Run on server with reverse proxy (nginx) for production use

## API Examples

Test the API directly:

```bash
# Get last 50 cases
curl http://localhost:8000/api/cases

# Get pipeline status
curl http://localhost:8000/api/status

# Run test pipeline
curl -X POST http://localhost:8000/api/test

# Watch logs (requires wscat or similar)
wscat -c ws://localhost:8000/ws/logs
```

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | gemini | Which LLM to use: "gemini" or "openai" |
| `GOOGLE_API_KEY` | "" | API key for Google Gemini |
| `GEMINI_MODEL` | gemini-2.5-flash-lite-preview-06-17 | Gemini model version |
| `OPENAI_API_KEY` | "" | API key for OpenAI (if using OpenAI) |
| `OPENAI_MODEL` | gpt-4o | OpenAI model version |
| `VIRUSTOTAL_API_KEY` | "" | VirusTotal API key (optional) |
| `ABUSEIPDB_API_KEY` | "" | AbuseIPDB API key (optional) |
| `URLSCAN_API_KEY` | "" | URLScan API key (optional) |
| `SKIP_GMAIL` | false | Skip Gmail polling |
| `SKIP_THEHIVE` | false | Skip TheHive integration |
| `SKIP_SLACK` | false | Skip Slack notifications |

## Features Enabled/Disabled by Configuration

| Feature | Required | Optional | Default |
|---------|----------|----------|---------|
| LLM Analysis | Yes (choose one) | Gemini or OpenAI | Gemini |
| Web Dashboard | Yes | No | Enabled |
| IOC Extraction | Yes | No | Enabled |
| Threat Intelligence | No | VirusTotal, AbuseIPDB, URLScan | All optional |
| Gmail Integration | No | Google OAuth | Disabled (set `SKIP_GMAIL=false`) |
| TheHive Integration | No | TheHive API | Disabled (set `SKIP_THEHIVE=false`) |
| Slack Notifications | No | Slack Webhook | Disabled (set `SKIP_SLACK=false`) |

## Performance Tips

1. **Increase responsiveness**: Run with fewer enrichment APIs if slow
2. **Reduce log noise**: Set `LOG_LEVEL=WARNING` to skip debug logs
3. **Archive old cases**: Trim `cases.json` periodically (>100MB can slow loads)
4. **Parallel processing**: The pipeline already runs enrichment APIs in parallel
5. **Database caching**: Future version will add caching for enrichment results

## Example Workflow

1. Start dashboard: `python run_ui.py`
2. Visit http://localhost:8000
3. Click "Run Test Email" to see a malicious phishing email detected
4. Watch real-time logs show:
   - IOC extraction (URLs, domains, IP addresses)
   - Enrichment queries to threat intelligence APIs
   - LLM analysis using Gemini (or OpenAI)
   - Verdict: MALICIOUS with 92.5% confidence
5. Click the case row to see full details:
   - Extracted IOCs
   - Enrichment results showing malicious verdicts
   - LLM reasoning explaining why it's malicious
   - MITRE ATT&CK tactic (T1566.001 - Spearphishing Attachment/Link)
6. Cases auto-save to `cases.json` for persistence

That's it! You now have a professional SOAR dashboard for phishing detection.
