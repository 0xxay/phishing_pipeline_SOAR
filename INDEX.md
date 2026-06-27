# Phishing Pipeline SOAR - Complete Index

## Project Files Overview

### Documentation (4 files)
- **README.md** - Full technical documentation with architecture, setup, configuration
- **QUICKSTART.md** - 5-minute setup and first run guide
- **IMPLEMENTATION_SUMMARY.md** - Implementation details and statistics
- **INDEX.md** - This file

### Configuration (3 files)
- **.env** - Active configuration (create from .env.example, add your API keys)
- **.env.example** - Configuration template with all options
- **config.py** - Configuration loader (reads from .env)
- **requirements.txt** - Python dependencies

### Entry Points (2 files)
- **main.py** - Main orchestrator, runs continuous polling loop
- **test_pipeline.py** - Test suite with mock emails
- **validate_setup.py** - Setup validation script

### Core Pipeline Modules (25 Python files)

#### Stage 1: Ingest (2 files)
```
pipeline/ingest/
├── __init__.py
└── gmail_poller.py         # Gmail API polling + OAuth2 auth
```

#### Stage 2: Extract (4 files)
```
pipeline/extract/
├── __init__.py
├── ioc_extractor.py        # URL/IP/domain/hash extraction
├── attachment_handler.py   # Attachment hash computation
└── header_parser.py        # Email header analysis
```

#### Stage 3: Enrich (4 files)
```
pipeline/enrich/
├── __init__.py
├── virustotal.py           # VirusTotal v3 API integration
├── abuseipdb.py            # AbuseIPDB v2 API integration
└── urlscan.py              # URLScan.io API integration
```

#### Stage 4: Decide (2 files)
```
pipeline/decide/
├── __init__.py
└── score_aggregator.py     # GPT-4o verdict + heuristic fallback
```

#### Stage 5: Respond (4 files)
```
pipeline/respond/
├── __init__.py
├── auto_block.py           # Block IOCs + escalate
├── analyst_alert.py        # Slack alerts for suspicious
└── false_positive.py       # Log clean emails
```

#### Stage 6: Close (3 files)
```
pipeline/close/
├── __init__.py
├── thehive_client.py       # TheHive v5 case creation
└── slack_notifier.py       # Final Slack notifications
```

#### Data Models (2 files)
```
models/
├── __init__.py
└── phishing_case.py        # Email, IOCs, Verdict, PhishingCase classes
```

#### Utilities (2 files)
```
utils/
├── __init__.py
└── logger.py               # Rich console + file logging
```

## Quick Navigation

### I want to...

**Get started quickly**
→ Read `QUICKSTART.md` (5 minutes)

**Understand the architecture**
→ Read `README.md` Architecture section

**See what's implemented**
→ Read `IMPLEMENTATION_SUMMARY.md`

**Validate my setup**
→ Run `python validate_setup.py`

**Test the pipeline**
→ Run `python test_pipeline.py`

**Run in production**
→ Run `python main.py`

**Add a new enrichment API**
→ Create `pipeline/enrich/newsource.py` following virustotal.py pattern

**Configure logging**
→ Edit `.env` LOG_LEVEL and LOG_FILE

**Configure polling interval**
→ Edit `.env` POLL_INTERVAL (seconds)

**Disable a feature**
→ Edit `.env` SKIP_GMAIL, SKIP_THEHIVE, SKIP_SLACK, or DRY_RUN

## File Statistics

- **Total files**: 33
- **Python files**: 29
- **Python lines**: 2,361
- **Documentation files**: 4
- **Configuration files**: 3
- **Total size**: 347 KB

## Key Components Explained

### Pipeline Flow

```
Email (Gmail)
    ↓
IOCExtractor.extract_all()
    ↓
[VirusTotalEnricher, AbuseIPDBEnricher, URLScanEnricher] (parallel)
    ↓
ScoreAggregator.aggregate_score() (GPT-4o)
    ↓
Verdict (MALICIOUS/SUSPICIOUS/CLEAN)
    ↓
AutoBlocker.execute() OR AnalystAlert.execute() OR FalsePositiveLogger.execute()
    ↓
TheHiveClient.create_case() + SlackNotifier.execute()
```

### Data Models

**Email**: id, subject, sender, reply_to, body, headers, attachments, received_at

**IOCs**: urls, ips, domains, hashes

**EnrichmentResult**: ioc, source, score, verdict, details, raw, error

**Verdict**: value (MALICIOUS/SUSPICIOUS/CLEAN), confidence (0-100), reasoning, mitre_tactic

**PhishingCase**: email, iocs, enrichments, verdict, thehive_case_id, slack_sent, blocked

### Configuration Options

See `.env.example` for all options, including:
- API keys (OpenAI, VirusTotal, AbuseIPDB, URLScan, TheHive, Slack, Gmail)
- Thresholds (detection counts, confidence scores)
- Polling interval
- Feature flags for testing
- Logging options

## API Requirements

### Required
- **OpenAI**: For GPT-4o verdict analysis

### Optional (pipeline works without)
- **Gmail**: For email polling (can test with test_pipeline.py)
- **VirusTotal**: For URL/hash reputation
- **AbuseIPDB**: For IP reputation
- **URLScan.io**: For URL scanning
- **TheHive**: For case management
- **Slack**: For notifications

## Output Files Generated

- **block_list.json**: Blocked IOCs (URLs, IPs, domains, hashes)
- **escalation_log.jsonl**: JSONL log of MALICIOUS verdicts
- **false_positive_log.jsonl**: JSONL log of CLEAN verdicts
- **phishing_pipeline.log**: Detailed timestamped logs

## Next Steps

1. **Setup**: `cp .env.example .env` → edit with API keys
2. **Gmail OAuth**: `python -c "from pipeline.ingest.gmail_poller import setup_gmail_oauth; setup_gmail_oauth()"`
3. **Validate**: `python validate_setup.py`
4. **Test**: `python test_pipeline.py`
5. **Run**: `python main.py`

## Support

- Documentation: See README.md
- Quick reference: See QUICKSTART.md
- Implementation details: See IMPLEMENTATION_SUMMARY.md
- Troubleshooting: See README.md Troubleshooting section
- Validation: Run validate_setup.py

---

**Status**: ✅ COMPLETE - All files implemented and ready to use
