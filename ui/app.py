"""FastAPI web server for the phishing pipeline dashboard."""
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import uuid4
from collections import deque
import os
import shutil

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import config
from models import Email, IOCs, PhishingCase, VerdictType
from pipeline.extract.ioc_extractor import IOCExtractor
from pipeline.extract.attachment_handler import AttachmentHandler
from pipeline.enrich.virustotal import VirusTotalEnricher
from pipeline.enrich.abuseipdb import AbuseIPDBEnricher
from pipeline.enrich.urlscan import URLScanEnricher
from pipeline.decide.score_aggregator import ScoreAggregator
from pipeline.respond.auto_block import AutoBlocker
from pipeline.respond.analyst_alert import AnalystAlert
from pipeline.respond.false_positive import FalsePositiveLogger
from pipeline.close.thehive_client import TheHiveClient
from pipeline.close.slack_notifier import SlackNotifier
from pipeline.ingest.gmail_poller import GmailPoller, setup_gmail_oauth
from utils import log_info, log_success, log_error, log_section, logger

# Create FastAPI app
app = FastAPI(
    title="SOAR Phishing Pipeline",
    description="Real-time phishing email detection and response",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
cases_store: List[Dict[str, Any]] = []
log_history = deque(maxlen=200)
pipeline_status = {"running": False, "last_poll": None, "started_at": None}
polling_task: Optional[asyncio.Task] = None
emails_processed_count = 0
poll_history: List[Dict[str, Any]] = []

# WebSocket connection manager — fan-out to all connected clients
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws) if hasattr(self.active, 'discard') else None
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: str):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# Path to cases.json
CASES_FILE = Path(__file__).parent.parent / "cases.json"
ENV_FILE = Path(__file__).parent.parent / ".env"


def load_cases():
    """Load cases from JSON file."""
    global cases_store
    if CASES_FILE.exists():
        try:
            with open(CASES_FILE, "r") as f:
                cases_store = json.load(f)
        except Exception as e:
            log_error(f"Failed to load cases.json: {e}")
            cases_store = []
    else:
        cases_store = []


def save_cases():
    """Save cases to JSON file."""
    try:
        with open(CASES_FILE, "w") as f:
            json.dump(cases_store, f, indent=2)
    except Exception as e:
        log_error(f"Failed to save cases.json: {e}")


async def broadcast_log(message: str):
    """Broadcast a log message to all connected WebSocket clients and keep history."""
    log_history.append(message)
    await manager.broadcast(message)


def case_to_dict(case: PhishingCase) -> Dict[str, Any]:
    """Convert PhishingCase to dictionary for JSON serialization."""
    return {
        "id": str(uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "subject": case.email.subject,
        "sender": case.email.sender,
        "reply_to": case.email.reply_to,
        "verdict": case.verdict.value.value,
        "confidence": case.verdict.confidence,
        "reasoning": case.verdict.reasoning,
        "mitre_tactic": case.verdict.mitre_tactic,
        "iocs": {
            "urls": case.iocs.urls,
            "ips": case.iocs.ips,
            "domains": case.iocs.domains,
            "hashes": case.iocs.hashes,
        },
        "enrichments": [
            {
                "ioc": e.ioc,
                "source": e.source,
                "score": e.score,
                "verdict": e.verdict,
                "details": e.details,
            }
            for e in case.enrichments
        ],
        "thehive_case_id": case.thehive_case_id,
        "slack_sent": case.slack_sent,
        "blocked": case.blocked,
    }


async def process_test_email() -> PhishingCase:
    """
    Process the sample phishing email from test_pipeline.
    Returns a PhishingCase with full verdict and enrichment.
    """
    log_section("Processing Test Email")

    # Create the test phishing email (sample 1 from test_pipeline.py)
    email_dict = {
        "id": "test_email_1",
        "subject": "URGENT: Verify Your Account - Click Here Immediately",
        "sender": "noreply@paypa1.suspicious.com",
        "reply_to": None,
        "body": """
Dear Customer,

Your account has been compromised. Please verify your identity immediately by clicking the link below:

Click here: https://paypa1.suspicious.com/verify?token=abc123
Or visit: http://192.168.1.100:8080/phish

If you don't verify within 24 hours, your account will be suspended.

Regards,
PayPal Security Team

MD5: 5d41402abc4b2a76b9719d911017c592
SHA256: 2c26b46911185131006ba5991596cdb8f1e89d97c27ce88a9e4fa9d95f6b8f6
""",
        "headers": {
            "From": "noreply@paypa1.suspicious.com",
            "Reply-To": None,
            "Subject": "URGENT: Verify Your Account - Click Here Immediately",
            "Return-Path": "<bounce@malicious.ru>",
        },
        "attachments": [],
    }

    email = Email(
        id=email_dict["id"],
        subject=email_dict["subject"],
        sender=email_dict["sender"],
        reply_to=email_dict.get("reply_to"),
        body=email_dict["body"],
        headers=email_dict["headers"],
        attachments=email_dict["attachments"],
        received_at=datetime.utcnow(),
    )

    await broadcast_log("[INFO] Extracting IOCs from email...")
    # Stage 1: Extract IOCs
    iocs = IOCExtractor.extract_all(email.body)
    attachment_hashes = AttachmentHandler.get_attachment_hashes_list(email)
    iocs.hashes.extend(attachment_hashes)
    await broadcast_log(
        f"[SUCCESS] Extracted {len(iocs.all_iocs())} IOCs (URLs: {len(iocs.urls)}, IPs: {len(iocs.ips)}, Domains: {len(iocs.domains)}, Hashes: {len(iocs.hashes)})"
    )

    # Stage 2: Enrichment
    await broadcast_log("[INFO] Running threat intelligence enrichment...")
    enrichments = []
    try:
        vt_results, abuse_results, urlscan_results = await asyncio.gather(
            VirusTotalEnricher.enrich(iocs),
            AbuseIPDBEnricher.enrich(iocs),
            URLScanEnricher.enrich(iocs),
            return_exceptions=True,
        )

        if isinstance(vt_results, list):
            enrichments.extend(vt_results)
            await broadcast_log(f"[INFO] VirusTotal: {len(vt_results)} results")
        elif isinstance(vt_results, Exception):
            await broadcast_log(f"[WARNING] VirusTotal error: {str(vt_results)}")

        if isinstance(abuse_results, list):
            enrichments.extend(abuse_results)
            await broadcast_log(f"[INFO] AbuseIPDB: {len(abuse_results)} results")
        elif isinstance(abuse_results, Exception):
            await broadcast_log(f"[WARNING] AbuseIPDB error: {str(abuse_results)}")

        if isinstance(urlscan_results, list):
            enrichments.extend(urlscan_results)
            await broadcast_log(f"[INFO] URLScan: {len(urlscan_results)} results")
        elif isinstance(urlscan_results, Exception):
            await broadcast_log(f"[WARNING] URLScan error: {str(urlscan_results)}")

    except Exception as e:
        await broadcast_log(f"[ERROR] Enrichment error: {str(e)}")
        enrichments = []

    await broadcast_log(
        f"[SUCCESS] Total enrichment results: {len(enrichments)}"
    )

    # Stage 3: Decision
    await broadcast_log("[INFO] Running LLM verdict analysis...")
    try:
        verdict = await ScoreAggregator.aggregate_score(email, iocs, enrichments)
        await broadcast_log(
            f"[SUCCESS] Verdict: {verdict.value.value} (Confidence: {verdict.confidence:.1f}%)"
        )
        await broadcast_log(f"[INFO] Reasoning: {verdict.reasoning}")
    except Exception as e:
        await broadcast_log(f"[ERROR] Verdict analysis failed: {str(e)}")
        raise

    # Create case
    case = PhishingCase(
        email=email,
        iocs=iocs,
        enrichments=enrichments,
        verdict=verdict,
    )

    # Stage 4: Response Actions
    await broadcast_log("[INFO] Executing response actions...")
    if verdict.value == VerdictType.MALICIOUS:
        await broadcast_log("[WARNING] MALICIOUS verdict - executing auto-block")
        try:
            await AutoBlocker.execute(case)
            case.blocked = True
        except Exception as e:
            await broadcast_log(f"[WARNING] Auto-block error: {str(e)}")

    elif verdict.value == VerdictType.SUSPICIOUS:
        await broadcast_log("[WARNING] SUSPICIOUS verdict - alerting analyst")
        try:
            await AnalystAlert.execute(case)
        except Exception as e:
            await broadcast_log(f"[WARNING] Analyst alert error: {str(e)}")

    else:  # CLEAN
        await broadcast_log("[SUCCESS] CLEAN verdict - no action needed")
        try:
            await FalsePositiveLogger.execute(case)
        except Exception as e:
            await broadcast_log(f"[INFO] False positive log error: {str(e)}")

    # Stage 5: Case Documentation
    if verdict.value != VerdictType.CLEAN:
        await broadcast_log("[INFO] Creating TheHive case...")
        try:
            thehive_client = TheHiveClient()
            case.thehive_case_id = await thehive_client.create_case(case)
            await broadcast_log(f"[SUCCESS] TheHive case created: {case.thehive_case_id}")
        except Exception as e:
            await broadcast_log(f"[WARNING] TheHive error: {str(e)}")

        if not config.SKIP_SLACK:
            await broadcast_log("[INFO] Sending Slack notification...")
            try:
                await SlackNotifier.execute(case)
                case.slack_sent = True
                await broadcast_log("[SUCCESS] Slack notification sent")
            except Exception as e:
                await broadcast_log(f"[WARNING] Slack error: {str(e)}")

    await broadcast_log("[SUCCESS] Email processing complete")
    return case


# ============================================================================
# API Routes
# ============================================================================


@app.on_event("startup")
async def startup_event():
    """Load cases on startup."""
    load_cases()
    log_info(f"Loaded {len(cases_store)} cases from storage")


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the dashboard HTML."""
    static_dir = Path(__file__).parent / "static"
    index_file = static_dir / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return HTMLResponse(content="Dashboard not found", status_code=404)


@app.get("/api/cases")
async def get_cases():
    """Return last 50 cases."""
    return JSONResponse(content={"cases": cases_store[-50:]})


@app.get("/api/status")
async def get_status():
    """Return pipeline status."""
    return JSONResponse(
        content={
            "running": pipeline_status["running"],
            "last_poll": pipeline_status["last_poll"],
            "started_at": pipeline_status["started_at"],
            "total_cases": len(cases_store),
            "malicious": sum(
                1 for c in cases_store if c["verdict"] == "MALICIOUS"
            ),
            "suspicious": sum(
                1 for c in cases_store if c["verdict"] == "SUSPICIOUS"
            ),
            "clean": sum(1 for c in cases_store if c["verdict"] == "CLEAN"),
        }
    )


@app.post("/api/test")
async def test_pipeline():
    """
    Run the pipeline on a test phishing email and return results.
    Streams logs via WebSocket.
    """
    try:
        # Process the test email
        case = await process_test_email()

        # Save to cases store
        case_dict = case_to_dict(case)
        cases_store.append(case_dict)
        save_cases()

        return JSONResponse(content={"success": True, "case": case_dict})

    except Exception as e:
        await broadcast_log(f"[ERROR] Pipeline test failed: {str(e)}")
        log_error(f"Test pipeline error: {str(e)}")
        logger.exception(e)
        return JSONResponse(
            content={"success": False, "error": str(e)}, status_code=500
        )


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket endpoint for live log streaming — supports multiple clients."""
    await manager.connect(websocket)
    try:
        # Send recent history to this new client
        for msg in log_history:
            await websocket.send_text(msg)
        # Keep connection alive — manager handles outgoing, just wait for disconnect
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_text("[PING]")
    except (WebSocketDisconnect, Exception):
        manager.disconnect(websocket)


async def run_pipeline_on_email(email: Email) -> PhishingCase:
    """Run the full pipeline on an email."""
    await broadcast_log(f"[INFO] Processing email: {email.subject[:50]}...")

    # Stage 1: Extract IOCs
    iocs = IOCExtractor.extract_all(email.body)
    attachment_hashes = AttachmentHandler.get_attachment_hashes_list(email)
    iocs.hashes.extend(attachment_hashes)
    await broadcast_log(
        f"[SUCCESS] Extracted {len(iocs.all_iocs())} IOCs (URLs: {len(iocs.urls)}, IPs: {len(iocs.ips)}, Domains: {len(iocs.domains)}, Hashes: {len(iocs.hashes)})"
    )

    # Stage 2: Enrichment
    await broadcast_log("[INFO] Running threat intelligence enrichment...")
    enrichments = []
    try:
        vt_results, abuse_results, urlscan_results = await asyncio.gather(
            VirusTotalEnricher.enrich(iocs),
            AbuseIPDBEnricher.enrich(iocs),
            URLScanEnricher.enrich(iocs),
            return_exceptions=True,
        )

        if isinstance(vt_results, list):
            enrichments.extend(vt_results)
            await broadcast_log(f"[INFO] VirusTotal: {len(vt_results)} results")
        elif isinstance(vt_results, Exception):
            await broadcast_log(f"[WARNING] VirusTotal error: {str(vt_results)}")

        if isinstance(abuse_results, list):
            enrichments.extend(abuse_results)
            await broadcast_log(f"[INFO] AbuseIPDB: {len(abuse_results)} results")
        elif isinstance(abuse_results, Exception):
            await broadcast_log(f"[WARNING] AbuseIPDB error: {str(abuse_results)}")

        if isinstance(urlscan_results, list):
            enrichments.extend(urlscan_results)
            await broadcast_log(f"[INFO] URLScan: {len(urlscan_results)} results")
        elif isinstance(urlscan_results, Exception):
            await broadcast_log(f"[WARNING] URLScan error: {str(urlscan_results)}")

    except Exception as e:
        await broadcast_log(f"[ERROR] Enrichment error: {str(e)}")
        enrichments = []

    await broadcast_log(f"[SUCCESS] Total enrichment results: {len(enrichments)}")

    # Stage 3: Decision
    await broadcast_log("[INFO] Running LLM verdict analysis...")
    try:
        verdict = await ScoreAggregator.aggregate_score(email, iocs, enrichments)
        await broadcast_log(
            f"[SUCCESS] Verdict: {verdict.value.value} (Confidence: {verdict.confidence:.1f}%)"
        )
        await broadcast_log(f"[INFO] Reasoning: {verdict.reasoning}")
    except Exception as e:
        await broadcast_log(f"[ERROR] Verdict analysis failed: {str(e)}")
        raise

    # Create case
    case = PhishingCase(
        email=email,
        iocs=iocs,
        enrichments=enrichments,
        verdict=verdict,
    )

    # Stage 4: Response Actions
    await broadcast_log("[INFO] Executing response actions...")
    if verdict.value == VerdictType.MALICIOUS:
        await broadcast_log("[WARNING] MALICIOUS verdict - executing auto-block")
        try:
            await AutoBlocker.execute(case)
            case.blocked = True
        except Exception as e:
            await broadcast_log(f"[WARNING] Auto-block error: {str(e)}")

    elif verdict.value == VerdictType.SUSPICIOUS:
        await broadcast_log("[WARNING] SUSPICIOUS verdict - alerting analyst")
        try:
            await AnalystAlert.execute(case)
        except Exception as e:
            await broadcast_log(f"[WARNING] Analyst alert error: {str(e)}")

    else:  # CLEAN
        await broadcast_log("[SUCCESS] CLEAN verdict - no action needed")
        try:
            await FalsePositiveLogger.execute(case)
        except Exception as e:
            await broadcast_log(f"[INFO] False positive log error: {str(e)}")

    # Stage 5: Case Documentation
    if verdict.value != VerdictType.CLEAN:
        await broadcast_log("[INFO] Creating TheHive case...")
        try:
            thehive_client = TheHiveClient()
            case.thehive_case_id = await thehive_client.create_case(case)
            await broadcast_log(f"[SUCCESS] TheHive case created: {case.thehive_case_id}")
        except Exception as e:
            await broadcast_log(f"[WARNING] TheHive error: {str(e)}")

        if not config.SKIP_SLACK:
            await broadcast_log("[INFO] Sending Slack notification...")
            try:
                await SlackNotifier.execute(case)
                case.slack_sent = True
                await broadcast_log("[SUCCESS] Slack notification sent")
            except Exception as e:
                await broadcast_log(f"[WARNING] Slack error: {str(e)}")

    await broadcast_log("[SUCCESS] Email processing complete")
    return case


async def gmail_polling_loop():
    """Background task for Gmail polling."""
    global emails_processed_count, polling_task

    try:
        poller = GmailPoller()
    except Exception as e:
        await broadcast_log(f"[ERROR] Failed to initialize GmailPoller: {str(e)}")
        return

    while polling_task is not None:
        try:
            await broadcast_log(f"[INFO] Polling Gmail for new emails...")
            emails = poller.poll()

            if emails:
                await broadcast_log(f"[SUCCESS] Found {len(emails)} new emails")
                for email in emails:
                    await broadcast_log(f"[GMAIL] New email: {email.subject} from {email.sender}")
                    try:
                        case = await run_pipeline_on_email(email)
                        case_dict = case_to_dict(case)
                        cases_store.append(case_dict)
                        save_cases()
                        emails_processed_count += 1
                    except Exception as e:
                        await broadcast_log(f"[ERROR] Failed to process email: {str(e)}")
            else:
                await broadcast_log("[INFO] No new emails found")

            pipeline_status["last_poll"] = datetime.utcnow().isoformat()

            # Record poll in history
            poll_history.append({
                "timestamp": datetime.utcnow().isoformat(),
                "emails_found": len(emails),
                "status": "success"
            })
            if len(poll_history) > 50:
                poll_history.pop(0)

        except Exception as e:
            await broadcast_log(f"[ERROR] Gmail poll failed: {str(e)}")
            poll_history.append({
                "timestamp": datetime.utcnow().isoformat(),
                "emails_found": 0,
                "status": f"error: {str(e)}"
            })

        # Sleep for configured interval
        await asyncio.sleep(config.POLL_INTERVAL)


def read_env_file() -> Dict[str, str]:
    """Read .env file and return as dict."""
    env_vars = {}
    if ENV_FILE.exists():
        with open(ENV_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars


def write_env_file(env_vars: Dict[str, str]):
    """Write env_vars to .env file, preserving structure."""
    with open(ENV_FILE, "w") as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")


def mask_api_key(key: Optional[str]) -> str:
    """Mask API key, showing only first 8 chars."""
    if not key:
        return "not configured"
    if len(key) <= 8:
        return key
    return key[:8] + "..." + key[-4:]


# ============================================================================
# NEW API Routes - Configuration & Gmail
# ============================================================================


@app.get("/api/config")
async def get_config():
    """Return current configuration (mask API keys)."""
    return JSONResponse(
        content={
            "gmail_label": config.GMAIL_LABEL,
            "poll_interval": config.POLL_INTERVAL,
            "llm_provider": config.LLM_PROVIDER,
            "gemini_model": config.GEMINI_MODEL,
            "vt_configured": bool(config.VIRUSTOTAL_API_KEY),
            "abuseipdb_configured": bool(config.ABUSEIPDB_API_KEY),
            "urlscan_configured": bool(config.URLSCAN_API_KEY),
            "slack_configured": bool(config.SLACK_WEBHOOK_URL),
            "thehive_configured": bool(config.THEHIVE_API_KEY),
            "gmail_credentials_path": str(config.GMAIL_CREDENTIALS_PATH),
            "gmail_authenticated": os.path.exists(config.GMAIL_TOKEN_PATH),
        }
    )


@app.post("/api/config")
async def update_config(request: Request):
    data: Dict[str, Any] = await request.json()
    """Update configuration values in .env file."""
    try:
        env_vars = read_env_file()

        # Only allow non-key fields to be updated
        allowed_fields = {
            "GMAIL_LABEL": "gmail_label",
            "POLL_INTERVAL": "poll_interval",
            "LLM_PROVIDER": "llm_provider",
            "GEMINI_MODEL": "gemini_model",
            "VT_DETECTION_THRESHOLD": "vt_threshold",
            "ABUSEIPDB_CONFIDENCE_THRESHOLD": "abuseipdb_threshold",
        }

        for env_key, data_key in allowed_fields.items():
            if data_key in data:
                env_vars[env_key] = str(data[data_key])

        write_env_file(env_vars)

        # Reload config module
        import importlib
        importlib.reload(config)

        return JSONResponse(content={"success": True, "message": "Configuration updated"})
    except Exception as e:
        await broadcast_log(f"[ERROR] Config update failed: {str(e)}")
        return JSONResponse(
            content={"success": False, "error": str(e)}, status_code=500
        )


@app.post("/api/gmail/upload-credentials")
async def upload_credentials(file: UploadFile = File(...)):
    """Upload Gmail credentials.json file."""
    try:
        credentials_path = Path(config.GMAIL_CREDENTIALS_PATH)

        # Save uploaded file
        content = await file.read()
        with open(credentials_path, "wb") as f:
            f.write(content)

        await broadcast_log(f"[SUCCESS] Gmail credentials uploaded: {credentials_path.name}")
        return JSONResponse(content={"success": True})
    except Exception as e:
        await broadcast_log(f"[ERROR] Credentials upload failed: {str(e)}")
        return JSONResponse(
            content={"success": False, "error": str(e)}, status_code=500
        )


@app.post("/api/gmail/authenticate")
async def authenticate_gmail():
    """Trigger Gmail OAuth flow."""
    try:
        await broadcast_log("[INFO] Starting Gmail OAuth flow...")
        setup_gmail_oauth()
        await broadcast_log("[SUCCESS] Browser opened for authentication - complete login in your browser")
        return JSONResponse(
            content={"success": True, "message": "Browser opened for authentication"}
        )
    except Exception as e:
        await broadcast_log(f"[ERROR] Gmail authentication failed: {str(e)}")
        return JSONResponse(
            content={"success": False, "error": str(e)}, status_code=500
        )


@app.get("/api/gmail/status")
async def get_gmail_status():
    """Return Gmail polling status."""
    return JSONResponse(
        content={
            "polling": pipeline_status["running"],
            "authenticated": os.path.exists(config.GMAIL_TOKEN_PATH),
            "last_poll": pipeline_status["last_poll"],
            "emails_processed": emails_processed_count,
            "poll_interval": config.POLL_INTERVAL,
        }
    )


@app.post("/api/gmail/start")
async def start_gmail_polling():
    """Start background Gmail polling."""
    global polling_task

    try:
        if polling_task is not None and not polling_task.done():
            return JSONResponse(
                content={"success": False, "error": "Polling already running"}
            )

        pipeline_status["running"] = True
        pipeline_status["started_at"] = datetime.utcnow().isoformat()

        polling_task = asyncio.create_task(gmail_polling_loop())
        await broadcast_log("[SUCCESS] Gmail polling started")

        return JSONResponse(content={"success": True, "message": "Gmail polling started"})
    except Exception as e:
        await broadcast_log(f"[ERROR] Failed to start polling: {str(e)}")
        return JSONResponse(
            content={"success": False, "error": str(e)}, status_code=500
        )


@app.post("/api/gmail/stop")
async def stop_gmail_polling():
    """Stop background Gmail polling."""
    global polling_task

    try:
        if polling_task is not None and not polling_task.done():
            polling_task.cancel()
            try:
                await polling_task
            except asyncio.CancelledError:
                pass

        polling_task = None
        pipeline_status["running"] = False
        await broadcast_log("[SUCCESS] Gmail polling stopped")

        return JSONResponse(content={"success": True, "message": "Gmail polling stopped"})
    except Exception as e:
        await broadcast_log(f"[ERROR] Failed to stop polling: {str(e)}")
        return JSONResponse(
            content={"success": False, "error": str(e)}, status_code=500
        )


@app.post("/api/gmail/poll-now")
async def poll_gmail_now():
    """Run an immediate one-shot Gmail poll."""
    async def _poll():
        try:
            await broadcast_log("[INFO] Running immediate Gmail poll...")
            poller = GmailPoller()
            emails = poller.poll()

            if emails:
                await broadcast_log(f"[SUCCESS] Found {len(emails)} new emails")
                for email in emails:
                    await broadcast_log(f"[GMAIL] Processing: {email.subject}")
                    try:
                        case = await run_pipeline_on_email(email)
                        case_dict = case_to_dict(case)
                        cases_store.append(case_dict)
                        save_cases()
                    except Exception as e:
                        await broadcast_log(f"[ERROR] Failed to process email: {str(e)}")
            else:
                await broadcast_log("[INFO] No new emails found")
        except Exception as e:
            await broadcast_log(f"[ERROR] One-shot poll failed: {str(e)}")

    try:
        asyncio.create_task(_poll())
        return JSONResponse(content={"success": True, "message": "Poll initiated"})
    except Exception as e:
        return JSONResponse(
            content={"success": False, "error": str(e)}, status_code=500
        )


@app.get("/api/gmail/poll-history")
async def get_poll_history():
    """Return recent poll history."""
    return JSONResponse(content={"history": poll_history[-10:]})


# Mount static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
