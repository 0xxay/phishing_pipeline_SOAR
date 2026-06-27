# SOAR Pipeline - Future Improvements

This document outlines potential enhancements to the phishing detection and response pipeline that are out-of-scope for the current release but would provide significant value.

## 1. Email Header Scoring

**Description**: SPF/DKIM/DMARC failures are currently parsed but not scored in the verdict calculation.

**Impact**: Email authentication failures are strong phishing indicators and should contribute to the malicious verdict confidence score. This would catch spoofed domains that fail sender validation.

**Implementation**: Add a scoring module that evaluates:
- SPF record pass/fail
- DKIM signature validation
- DMARC alignment
- Return-Path mismatch analysis

Each failure should increment the suspicion score proportionally.

---

## 2. Domain Age via WHOIS

**Description**: Newly registered domains (<30 days old) are a high-risk signal commonly used in phishing campaigns.

**Impact**: Many phishing campaigns use fresh domains that evade reputation-based filtering. Domain age is a free signal available via WHOIS lookups.

**Implementation**: 
- Add WHOIS enrichment module
- Extract creation date from domain registration
- Flag domains < 30 days old as suspicious
- Integrate into ScoreAggregator

**Note**: Consider using python-whois library (lightweight, no API key required)

---

## 3. URLScan Screenshot Display

**Description**: URLScan.io returns screenshot URLs for rendered pages, but they are not displayed in the case detail view.

**Impact**: Analysts need visual evidence of malicious pages. Screenshots show credential harvest forms, fake branding, etc.

**Implementation**:
- Store screenshot URL in enrichment result
- Add thumbnail preview in case detail modal
- Link to full URLScan report for detailed inspection
- Cache screenshots locally to avoid repeated lookups

---

## 4. Deduplication of IOCs

**Description**: If the same IOC appears in multiple emails, we make redundant API calls to VirusTotal, AbuseIPDB, etc.

**Impact**: Reduces API quota waste and improves performance by 10-20% on high-volume systems.

**Implementation**:
- Load block_list.json at startup
- Check IOCs against block_list before enrichment
- Skip enrichment for known IOCs (use cached verdict from block_list)
- Update block_list with new IOCs after enrichment

---

## 5. Confidence Calibration

**Description**: Gemini's confidence score doesn't always correlate with actual threat intelligence verdicts.

**Impact**: A malicious verdict from VT (20+ detections) should boost LLM confidence; conversely, clean VT result should lower it.

**Implementation**:
- Weight Gemini confidence against enrichment signal strength
- Formula: `final_confidence = (gemini_conf * 0.5) + (enrichment_signal * 0.5)`
- Enrichment signal = average verdict score from all APIs
- Re-calibrate thresholds after adjusting confidence

---

## 6. Attachment Sandbox Analysis

**Description**: Attachments are hashed but never executed/analyzed in a sandbox environment.

**Impact**: Detects evasive malware that doesn't trigger static hash signatures.

**Implementation**:
- Integrate with Any.run or Hybrid Analysis (free tiers available)
- Submit attachments > 100 KB to sandbox
- Parse behavior analysis results for code execution, C2 callbacks
- Add verdict from sandbox to enrichment results
- Store sandbox report links in case

---

## 7. SMTP Relay Analysis

**Description**: Email routing hops show the path through mail servers; anomalies indicate spoofing.

**Impact**: Emails relayed through open relays or suspicious servers can be detected without API calls.

**Implementation**:
- Extract Received headers
- Parse each hop for:
  - Mail server hostname/IP
  - Reverse DNS lookups for consistency
  - Known open relay IPs
  - Suspicious geographic routing
- Flag sudden geographic jumps (e.g., US → China → EU) as suspicious

---

## 8. Auto-Label in Gmail

**Description**: Processed emails remain in the phishing label inbox indefinitely.

**Impact**: On restart, GmailPoller re-processes the same emails, creating duplicate cases and wasting enrichment quota.

**Implementation**:
- After successful processing, add custom label `soar-processed` to email
- Modify GmailPoller.poll() query: `label:phishing is:unread label:-soar-processed`
- Prevents re-processing on system restarts
- Allows rollback: remove `soar-processed` label to re-analyze

---

## 9. Webhook Trigger for External Systems

**Description**: Currently only Gmail polling is supported; external systems can't submit emails for analysis.

**Impact**: Enables integration with:
- Security gateways (Proofpoint, Mimecast)
- SIEM systems (Splunk, ELK)
- Manual submissions from analysts
- Custom email parsing pipelines

**Implementation**:
```
POST /api/ingest

{
  "subject": "...",
  "sender": "...",
  "body": "...",
  "headers": {...}
}
```
- Validate JSON schema
- Run full pipeline on submitted email
- Return case ID immediately (async processing)
- Log source of submission (external API key tracking)

---

## 10. TheHive Docker Compose

**Description**: TheHive setup requires manual Docker commands and configuration.

**Impact**: Lowers barrier to entry; one-command deployment with default credentials.

**Implementation**:
```yaml
# docker-compose.yml
version: '3.8'
services:
  thehive:
    image: thehiveproject/thehive:latest
    ports:
      - "9000:9000"
    environment:
      - TH_SECRET=<generated>
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    # ... minimal config
```
- Auto-generate API key on first run
- Store in .env for THEHIVE_API_KEY
- Include instructions for HTTPS setup behind reverse proxy
- Add health check to startup sequence

---

## Priority Ranking

**High Value / Low Effort**:
1. Email Header Scoring (#1)
2. Domain Age via WHOIS (#2)
3. Auto-Label in Gmail (#8)

**High Value / Medium Effort**:
4. Deduplication (#4)
5. Confidence Calibration (#5)
6. SMTP Relay Analysis (#7)

**Medium Value / High Effort**:
7. URLScan Screenshots (#3)
8. Attachment Sandbox (#6)

**Ecosystem / Nice-to-Have**:
9. Webhook Trigger (#9)
10. TheHive Docker (#10)
