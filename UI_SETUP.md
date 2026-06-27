# SOAR Phishing Pipeline - Web UI Setup Guide

## Task 1: LLM Provider Switch (OpenAI to Gemini 2.5 Flash Lite)

### Configuration

The pipeline now supports both OpenAI and Google Gemini as LLM providers. Configuration is controlled via environment variables in `.env`:

```bash
# Default: Gemini (recommended - cheaper and faster)
LLM_PROVIDER=gemini
GOOGLE_API_KEY=your-google-api-key-here
GEMINI_MODEL=gemini-2.5-flash-lite-preview-06-17

# Alternative: OpenAI
LLM_PROVIDER=openai
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4o
```

### Modified Files

1. **config.py**
   - Added `GOOGLE_API_KEY` configuration
   - Added `GEMINI_MODEL` configuration (defaults to gemini-2.5-flash-lite-preview-06-17)
   - Added `LLM_PROVIDER` configuration (defaults to "gemini")

2. **pipeline/decide/score_aggregator.py**
   - Renamed `_gpt_analyze()` → `_llm_analyze()` (provider-agnostic)
   - Added `_gemini_call()` - Synchronous Gemini API call wrapped in asyncio.to_thread
   - Added `_openai_call()` - Asynchronous OpenAI API call
   - Updated `aggregate_score()` to check LLM_PROVIDER and route to appropriate provider
   - Falls back to heuristic scoring if configured API key is missing

3. **requirements.txt**
   - Added `google-generativeai>=0.8.0` for Gemini support
   - Added `fastapi>=0.110.0`, `uvicorn>=0.29.0`, `python-multipart>=0.0.9` for web UI

### Usage

The pipeline automatically uses the configured LLM provider. No code changes needed - just set environment variables:

```bash
# Use Gemini (default)
export GOOGLE_API_KEY="your-key"
export LLM_PROVIDER="gemini"

# Or use OpenAI
export OPENAI_API_KEY="your-key"
export LLM_PROVIDER="openai"
```

---

## Task 2: Web UI Dashboard

### Starting the UI Server

```bash
# Option 1: Run just the UI server
python run_ui.py

# Option 2: Run with uvicorn directly
uvicorn ui.app:app --host 0.0.0.0 --port 8000 --reload

# Option 3: Use in main pipeline (future)
# Add --ui flag to main.py for concurrent execution
```

The dashboard will be available at: **http://localhost:8000**

### Created Files

#### Core Application Files

1. **ui/__init__.py**
   - Package initialization module

2. **ui/app.py** (500+ lines)
   - FastAPI application server
   - WebSocket endpoint for real-time log streaming at `/ws/logs`
   - REST API endpoints:
     - `GET /` - Serves dashboard HTML
     - `GET /api/cases` - Returns last 50 processed cases
     - `GET /api/status` - Returns pipeline status and statistics
     - `POST /api/test` - Runs test pipeline on sample phishing email
   - Global state management for cases and logs
   - Cases persistence to `cases.json`

3. **ui/static/index.html** (1000+ lines)
   - Complete single-file dashboard (no build step, no npm dependencies)
   - Vanilla JavaScript (no frameworks)
   - Professional dark theme (GitHub Dark mode inspired)
   - Responsive design for mobile and desktop
   - Features:
     - **Header**: Title with status indicator
     - **Stats Cards**: Total cases, Malicious count, Suspicious count, Clean count
     - **Action Button**: "Run Test Email" button for on-demand testing
     - **Live Logs Panel**: Real-time scrolling terminal with color-coded log levels
       - RED ([ERROR], MALICIOUS)
       - YELLOW ([WARNING], SUSPICIOUS)
       - GREEN ([SUCCESS], CLEAN)
       - BLUE ([INFO])
     - **Cases Table**: Sortable, filterable cases with:
       - Timestamp
       - Subject
       - Sender
       - Verdict badge (color-coded)
       - Confidence score
       - IOC count
       - View action button
     - **Detail Modal**: Interactive case details showing:
       - Email metadata
       - Full reasoning
       - MITRE ATT&CK tactic
       - All IOCs (URLs, IPs, domains, hashes)
       - Enrichment results from VirusTotal, AbuseIPDB, URLScan

4. **run_ui.py**
   - Standalone launcher script for the web UI
   - Simple uvicorn wrapper for easy startup

### Dashboard Features

#### Statistics Dashboard
- **Total Cases**: Running count of all processed emails
- **Malicious**: Emails detected as malicious (red badge)
- **Suspicious**: Emails flagged for manual review (yellow badge)
- **Clean**: Legitimate emails (green badge)

#### Real-Time Log Streaming
- WebSocket connection to `/ws/logs`
- Auto-scrolling terminal display
- Color-coded by log level:
  - GREEN: SUCCESS, CLEAN verdicts
  - RED: ERROR, MALICIOUS verdicts
  - YELLOW: WARNING, SUSPICIOUS verdicts
  - BLUE: INFO level logs
- Monospace font for readability
- Dark background (#0d1117)

#### Test Pipeline
- "Run Test Email" button sends a test phishing email (from test_pipeline.py)
- Triggers full pipeline: Extract → Enrich → Decide → Respond
- Shows progress in real-time via live logs
- Updates stats and cases table automatically
- Results include:
  - Full verdict with confidence
  - IOCs extracted (URLs, IPs, domains, hashes)
  - Threat intelligence enrichment data
  - MITRE ATT&CK tactics
  - Reasoning from LLM

#### Cases Table
- Shows last 20 cases in reverse chronological order
- Click any row to view full details in modal
- Columns:
  - Time (ISO8601 timestamp)
  - Subject (email subject)
  - Sender (email address)
  - Verdict (MALICIOUS/SUSPICIOUS/CLEAN with color badge)
  - Confidence (0-100%)
  - IOCs (count of indicators)
  - Actions (View button)

#### Interactive Detail Modal
- Opens when clicking a case row
- Shows complete case information:
  - **Email Section**: Subject, sender, verdict, confidence
  - **Reasoning Section**: Full LLM reasoning text
  - **MITRE ATT&CK Section**: Tactic code (if applicable)
  - **IOCs Section**: Organized by type (URLs, IPs, domains, hashes)
  - **Enrichment Section**: Results from each threat intelligence source
    - Source (VirusTotal, AbuseIPDB, URLScan)
    - IOC tested
    - Verdict (malicious/suspicious/clean/unknown)
    - Confidence/Score
- Responsive modal with scrolling for long content
- Close button and click-outside to dismiss

### Data Persistence

Cases are automatically saved to `cases.json` in the project root:

```json
[
  {
    "id": "uuid",
    "timestamp": "2024-01-15T10:30:45.123456",
    "subject": "URGENT: Verify Your Account",
    "sender": "noreply@paypa1.suspicious.com",
    "reply_to": null,
    "verdict": "MALICIOUS",
    "confidence": 92.5,
    "reasoning": "Multiple indicators of phishing attack...",
    "mitre_tactic": "T1566.001",
    "iocs": {
      "urls": ["https://paypa1.suspicious.com/verify?token=abc123"],
      "ips": ["192.168.1.100"],
      "domains": ["paypa1.suspicious.com"],
      "hashes": ["5d41402abc4b2a76b9719d911017c592"]
    },
    "enrichments": [
      {
        "ioc": "paypa1.suspicious.com",
        "source": "virustotal",
        "score": 85,
        "verdict": "malicious",
        "details": {"malicious": 45, "suspicious": 10}
      }
    ],
    "thehive_case_id": "~12345",
    "slack_sent": true,
    "blocked": true
  }
]
```

### API Reference

#### GET /api/cases
Returns last 50 cases

**Response:**
```json
{
  "cases": [
    { case_object },
    ...
  ]
}
```

#### GET /api/status
Returns pipeline status and statistics

**Response:**
```json
{
  "running": false,
  "last_poll": "2024-01-15T10:30:45",
  "started_at": null,
  "total_cases": 42,
  "malicious": 15,
  "suspicious": 12,
  "clean": 15
}
```

#### POST /api/test
Runs test pipeline on sample phishing email, streams results via WebSocket

**Response:**
```json
{
  "success": true,
  "case": { case_object }
}
```

#### WebSocket /ws/logs
Connect for real-time log streaming

**Message Format:**
```
[LEVEL] message text
```
Levels: SUCCESS, INFO, WARNING, ERROR, PING

---

## Technology Stack

### Backend
- **FastAPI**: Modern async web framework
- **Uvicorn**: ASGI server
- **Python 3.8+**: Core language
- **google-generativeai**: Gemini API client
- **openai**: OpenAI API client (optional)

### Frontend
- **Vanilla JavaScript**: No frameworks/build step
- **CSS Variables**: Theme system
- **WebSocket**: Real-time communication
- **Responsive Design**: Mobile-friendly

### Database
- **JSON**: Case storage (cases.json)

---

## Production Considerations

### Security
- Set `allow_origins` to specific domains in CORSMiddleware
- Run behind reverse proxy (nginx, Apache)
- Use HTTPS with valid certificates
- Restrict API endpoints with authentication

### Performance
- Use connection pooling for enrichment APIs
- Implement rate limiting
- Cache enrichment results
- Monitor WebSocket connections (limit concurrent clients)

### Monitoring
- Add Prometheus metrics
- Enable structured logging
- Monitor queue depth
- Track API latency

### Deployment
- Use Docker for containerization
- Run Gunicorn/Uvicorn with multiple workers
- Use systemd or supervisor for process management
- Configure log rotation

---

## Troubleshooting

### WebSocket Connection Issues
- Check browser console for connection errors
- Verify CORS settings
- Check if firewall blocks WebSocket connections
- Try `wss://` if behind HTTPS proxy

### Cases Not Persisting
- Verify `cases.json` file permissions
- Check disk space
- Ensure project root is writable

### LLM Analysis Failing
- Verify API keys are set in `.env`
- Check LLM_PROVIDER is set correctly
- Verify API quotas and rate limits
- Check internet connectivity

### Performance Issues
- Monitor number of concurrent WebSocket clients
- Check enrichment API response times
- Verify database file size (trim old cases if needed)
- Enable uvicorn access logs for debugging

---

## Future Enhancements

1. **Authentication**: Add user login and role-based access
2. **Case Filtering**: Advanced search and filter options
3. **Bulk Operations**: Process multiple emails at once
4. **Webhooks**: Integration with external systems
5. **Alerting**: Email/Slack notifications for critical cases
6. **Analytics**: Dashboard with threat trends and metrics
7. **Export**: CSV/PDF case reports
8. **Playbooks**: Automated response workflows
9. **SOAR Integration**: Connect with TheHive and other platforms
10. **Custom Rules**: User-defined detection rules

---

## References

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Google Gemini API](https://ai.google.dev/)
- [OpenAI API](https://platform.openai.com/docs/)
- [WebSocket API](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
