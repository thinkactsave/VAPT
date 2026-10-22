# ProofVAPT — Automated Web Application Vulnerability Assessment Platform

ProofVAPT is a backend-orchestrated web application security assessment platform developed as an MSc Cyber Security research prototype. It automates end-to-end security audits—from target scope validation and rate-limited content discovery (ffuf) to multi-stage scanning (OWASP ZAP Automation Framework), finding correlation, OWASP Top 10:2025 coverage tracking, reproducible remediation verification, and executive/technical PDF reporting.

### User Review & Critical Decisions

> [!IMPORTANT]
> The architectural blueprint incorporates all four final technical amendments to ensure airtight scope boundaries across all child processes, aggregate request budget enforcement, complete relational provenance, and academically sound research metrics:

- **Confirmed Decision 1 (Scope-Enforcing Egress Proxy for ffuf, ZAP & Probers)**: Child tools (`ffuf`, OWASP ZAP) execute with their own independent networking engines. To ensure strict scope enforcement across all processes, ProofVAPT routes all outbound scanner traffic (via `ffuf -x`, ZAP outgoing proxy, and Node.js proxy agent) through an internal Scope-Enforcing Egress Proxy. This proxy resolves DNS at connection time, inspects the true destination IP, strictly blocks RFC 1918, loopbacks, link-local, multicast, and cloud metadata (`169.254.169.254`), re-validates destination IPs on every redirect hop, and immediately drops any connection attempt to an off-scope host or port before establishing the TCP handshake. Private lab targets require an isolated lab container network; lab permissions cannot bypass network-level scope restrictions.
- **Confirmed Decision 2 (Aggregate Request Accounting & Global Trip-Wire Stop Condition)**: Rather than relying solely on individual tool-level rate limits, the Scope-Enforcing Egress Proxy maintains an atomic aggregate request counter across ffuf, ZAP, and custom checks. When the cumulative observed request count reaches the target's `max_request_budget`, or when the error rate threshold (e.g. >15% HTTP 5xx responses) is exceeded, the proxy trips a global stop condition, rejects subsequent outbound requests with HTTP 429 / socket close, and triggers the process supervisor to execute clean process-tree termination (`process.kill(-pid)`) across all running workers. Observed request counts reflect real wire traffic recorded in the proxy access log.
- **Confirmed Decision 3 (Relational Provenance: TestExecution & FindingSource Models)**:
  - `TestExecution`: Explicitly logs each registered OWASP test's execution for a scan run (scan ID, test ID, status, outcome, timestamps, evidence pointers, skip/error reasons). The OWASP Top 10:2025 coverage matrix is generated dynamically from these immutable execution records, preventing false claims that an unexecuted category was tested or secure.
  - `FindingSource`: Establishes an association between one deduplicated `UnifiedFinding` and multiple source-tool alerts (`owasp_zap`, `ffuf`, `tls_prober`), preserving each tool's original alert ID, native severity, and raw artifact file pointers without data loss.
- **Confirmed Decision 4 (Rigorous Context-Aware Verification Criteria)**:
  - Cross-Site Scripting (XSS): String reflection alone does not verify XSS. Context-aware validation verifies unencoded execution potential in the target DOM/HTML context; otherwise, the finding is classified as `potential` and flagged for `manual_review_required`.
  - SQL Injection (SQLi): Database error messages alone indicate information disclosure, not confirmed SQLi. Confirmation requires differential Boolean/time-delay response verification; unverified error traces are labeled `potential`.
- **Confirmed Decision 5 (Explicit Academic Evaluation Formulas & Denominator Handling)**: Mathematical expressions for precision, recall, false-positive rate, false-positive reduction, duplicate reduction, time overhead, request overhead, and remediation verification accuracy are explicitly defined with documented ground-truth baselines. Division by zero is explicitly handled as `Undefined` rather than masked with artificial percentages.
- **Confirmed Decision 6 (MSc Research Prototype Classification)**: ProofVAPT is designed, implemented, and presented as an MSc Cyber Security research prototype. Methodological limitations, scanner blind spots, and testing boundaries are documented transparently in generated reports and research outputs.

---

### 1. Overview & Core Concept

- **What It Does**: ProofVAPT orchestrates a standardized 7-stage web security testing pipeline. The user configures an authorized target profile with permitted hostnames, ports, rate limits, and route exclusions. The backend supervisor starts the Scope-Enforcing Proxy, validates destination IPs, executes rate-limited reconnaissance, runs `ffuf` for content discovery, commands the OWASP ZAP Automation Framework (AF) for crawling and passive/active tests, records granular `TestExecution` logs, normalizes and deduplicates findings with multi-tool `FindingSource` records, verifies remediations with targeted retests, and compiles auditable executive and technical PDF reports.
- **Target Audience / Persona**: Cyber security MSc researchers, academic evaluators, and application security engineers requiring transparent, verifiable automated security assessments with documented methodology, reproducible test cases, and empirical ground-truth validation.
- **Key Value**: Bridges the gap between noisy raw scanner outputs and verifiable security posture. By binding discovered routes directly to normalized findings, enforcing strict network-level egress boundaries across all child processes, tracking OWASP 2025 coverage transparently, and verifying fixes with reproducible test scripts, ProofVAPT provides an academically defensible alternative to opaque commercial black-box tools.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. *Target & Scope Authorization*: Security analyst inputs target domain/URL, selects scan profile (Passive-Only, Standard Active, Authenticated Lab), configures request rate limits (requests/sec) and maximum request budget, specifies exclusion paths, and acknowledges scope authorization.
  2. *Live Assessment Console*: Real-time monitoring of backend worker stages (Reconnaissance, ffuf Discovery, ZAP Spider, ZAP Passive, ZAP Active, Finding Correlation, Verification). Interactive controls provide `Start`, `Monitor`, and `Cancel` (with hard process-tree termination). Streaming terminal logs show timestamped backend stdout/stderr and proxy request counters.
  3. *Attack Surface & Route Explorer*: Interactive table of all endpoints discovered by crawlers and `ffuf`, searchable by HTTP method, status code, response size, and content type.
  4. *Correlated Findings & Verification Workbench*: Unified vulnerability view categorized by OWASP Top 10:2025, source tools (`FindingSource`), severity, verification status (`verified`, `potential`, `not_reproduced`, `manual_review_required`), and remediation status (`open`, `fix_in_progress`, `pending_retest`, `remediated_verified`, `reopened`). Analysts can inspect redacted HTTP evidence and trigger single-click reproducible re-tests to verify developer fixes.
  5. *OWASP Top 10:2025 Coverage Dashboard*: Visual breakdown showing the exact status of each category (A01–A10), derived solely from `TestExecution` records. Untested categories are explicitly marked as *Not Tested* or *Manual Review Required*.
  6. *Executive & Technical PDF Report Generator*: Compiles a formal assessment document with executive risk posture, vulnerability distribution charts, CVSS & CRP ratings, remediation playbooks, and methodological limitations.

- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Cyber Security Operations Center (SOC) Console. Utilitarian, crisp, high-contrast dark theme without decorative fluff.
  - *Color System (60-30-10 Rule)*:
    - 60% Canvas: Deep Midnight Slate (`#0B0F17`)
    - 30% Structural Surfaces: Charcoal Slate (`#111827`) with hairline borders (`#1F2937`)
    - 10% Accents: Prober Cyan (`#06B6D4`) for active scanning states, Verified Emerald (`#10B981`) for remediated/verified states
    - Severity Spectrum: Crimson (`#EF4444`, Critical), Amber (`#F59E0B`, High), Yellow (`#FBBF24`, Medium), Sky (`#38BDF8`, Low), Slate (`#94A3B8`, Informational)
  - *Typography*:
    - Display & Titles: `Plus Jakarta Sans`
    - Body Prose: `DM Sans`
    - Telemetry, Ports, Code & Payloads: `JetBrains Mono` with tabular numerals (`tabular-nums`)
  - *Controls & Layout*: 1440px desktop container, collapsible 260px navigation sidebar, single-elevation cards, zero pill badges on static metadata (clean inline text separated by `·`), and strict single-line buttons and tabs.

---

### 3. Technical Architecture & Data Strategy

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              ProofVAPT Frontend (React 19)                              │
│  ┌───────────────────────┬───────────────────────────┬───────────────────────────────┐  │
│  │ Target Scope Manager  │ Live Pipeline Visualizer  │ Correlated Findings Matrix    │  │
│  │ Domain, Ports, Limits │ 7-Stage Stepper & Logs    │ OWASP 2025, CVSS, Remediation │  │
│  └───────────────────────┴───────────────────────────┴───────────────────────────────┘  │
│  ┌───────────────────────┬───────────────────────────┬───────────────────────────────┐  │
│  │ Attack Surface Table  │ Evidence & Diff Inspector │ Executive & Tech PDF Reports  │  │
│  │ Status, Length, Type  │ Redacted Headers & Body   │ Risk Posture, OWASP Coverage  │  │
│  └───────────────────────┴───────────────────────────┴───────────────────────────────┘  │
└────────────────────────────────────────────┬────────────────────────────────────────────┘
                                             │ REST API & Server-Sent Events / Polling
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                        ProofVAPT Backend Core (Node.js/Express)                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Scope-Enforcing Egress Proxy: Dynamic DNS/IP validation, anti-rebinding,          │  │
│  │ redirect re-check, aggregate request accounting, trip-wire budget cut-off         │  │
│  └───────────────────────────────────┬───────────────────────────────────────────────┘  │
│                                      │ All Outbound Traffic Routed Through Proxy
│        ┌─────────────────────────────┼─────────────────────────────┐
│        ▼                             ▼                             ▼
│  ┌───────────────┐           ┌───────────────┐           ┌───────────────────┐
│  │  ffuf Worker  │           │  OWASP ZAP AF │           │ TLS / Header /    │
│  │ -x localhost  │           │ Proxy Config  │           │ Config Prober     │
│  │ Rate Limited  │           │ Spider + Scan │           │ SSL, CORS, HSTS   │
│  └───────┬───────┘           └───────┬───────┘           └─────────┬─────────┘
│          │ JSON Output               │ JSON/XML Output             │ Raw Findings
│          └───────────────────────────┼─────────────────────────────┘
│                                      ▼
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Finding Intelligence: Deduplication, FindingSource Linkage, Redaction Filter       │  │
│  ├───────────────────────────────────────────────────────────────────────────────────┤  │
│  │ TestExecution Registry: Per-test execution logging & OWASP 2025 coverage engine   │  │
│  ├───────────────────────────────────────────────────────────────────────────────────┤  │
│  │ Verification Engine: Context-aware reproduction suite, false-positive filtering   │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
│                                      │
│                                      ▼
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Persistent Storage: SQLite (db.sqlite) + Secure Artifact Store (.data/artifacts/)  │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Detailed Relational Data Models

1. **TargetProfile**:
   - `id`: UUID (Primary Key)
   - `name`: String
   - `mode`: `"live"` | `"lab"`
   - `target_url`: String (validated URL)
   - `hostname`: String (resolved domain)
   - `allowed_ports`: Array<number> (e.g. `[80, 443, 8080]`)
   - `excluded_paths`: Array<string> (e.g. `["/logout", "/admin/delete"]`)
   - `rate_limit_rps`: Number (default: 10 rps)
   - `max_request_budget`: Number (default: 2000 requests)
   - `timeout_ms`: Number (default: 10000ms)
   - `is_isolated_lab_network_confirmed`: Boolean
   - `active_scan_scope_confirmed`: Boolean
   - `created_at`: ISO timestamp

2. **ScanExecution**:
   - `id`: UUID (Primary Key)
   - `target_id`: Foreign Key to TargetProfile
   - `scan_profile`: `"passive_only"` | `"standard_active"` | `"authenticated_lab"`
   - `status`: `"queued"` | `"running"` | `"completed"` | `"aborted"` | `"failed"`
   - `current_stage`: `"scope_validation"` | `"reconnaissance"` | `"discovery"` | `"automated_checks"` | `"correlation"` | `"verification"` | `"reporting"`
   - `stage_progress`: JSON Object detailing per-stage status, percentage, start/end timestamps
   - `observed_request_count`: Number (real wire requests counted by egress proxy)
   - `stop_condition_triggered`: String | null (e.g., `"Aggregate request budget (2000) reached"`)
   - `created_at`, `started_at`, `completed_at`: Timestamps

3. **ToolExecutionRecord**:
   - `id`: UUID (Primary Key)
   - `scan_id`: Foreign Key to ScanExecution
   - `tool_name`: `"ffuf"` | `"owasp_zap_spider"` | `"owasp_zap_active"` | `"tls_header_prober"`
   - `tool_version`: String (validated via preflight check: `ffuf -V`, `zap.sh -version`)
   - `command_line`: String (sanitized arguments vector)
   - `exit_code`: Number
   - `raw_output_path`: String (path in access-controlled `.data/artifacts/` store)
   - `stdout_summary`: String
   - `stderr_summary`: String
   - `started_at`, `ended_at`: Timestamps

4. **AttackSurfaceEndpoint**:
   - `id`: UUID (Primary Key)
   - `scan_id`: Foreign Key to ScanExecution
   - `url`: String
   - `method`: `"GET"` | `"POST"` | `"PUT"` | `"DELETE"` | `"OPTIONS"` | `"HEAD"`
   - `status_code`: Number
   - `content_length`: Number
   - `content_type`: String
   - `discovered_by`: `"recon"` | `"ffuf"` | `"zap_spider"` | `"manual"`
   - `parameters`: Array<{ name: string, type: "query" | "body" | "header" }>

5. **OWASPTestRegistryItem**:
   - `test_id`: String (Primary Key, e.g., `PV-A02-001`, `PV-A05-004`)
   - `name`: String
   - `owasp_category`: `"A01"` through `"A10"` (2025 standard)
   - `description`: String
   - `execution_method`: `"automated_zap"` | `"automated_ffuf"` | `"automated_prober"` | `"manual_review"`
   - `prerequisites`: String
   - `limitations`: String (e.g., "Cannot verify second-order injections without multi-step workflow context")

6. **TestExecution** (New Model — Enforces per-scan audit trails):
   - `id`: UUID (Primary Key)
   - `scan_id`: Foreign Key to ScanExecution
   - `test_id`: Foreign Key to OWASPTestRegistryItem
   - `execution_status`: `"queued"` | `"running"` | `"completed"` | `"skipped"` | `"failed"`
   - `outcome`: `"vulnerable"` | `"clean"` | `"inconclusive"` | `"error"`
   - `evidence_references`: Array<string> (Foreign Keys to FindingEvidence or log refs)
   - `skip_or_error_reason`: String | null (e.g., "Skipped: Active scan not authorized in passive profile")
   - `started_at`, `ended_at`: Timestamps

7. **UnifiedFinding**:
   - `id`: UUID (Primary Key)
   - `scan_id`: Foreign Key to ScanExecution
   - `test_id`: Foreign Key to OWASPTestRegistryItem
   - `title`: String
   - `owasp_category`: String (e.g., `"A02:2025 - Security Misconfiguration"`)
   - `source_severity`: `"CRITICAL"` | `"HIGH"` | `"MEDIUM"` | `"LOW"` | `"INFO"`
   - `official_cvss_score`: Number | null
   - `official_cvss_version`: `"3.1"` | `"4.0"` | null
   - `official_cvss_vector`: String | null
   - `contextual_remediation_priority`: Number (0.0 to 10.0 scale)
   - `affected_url`: String
   - `parameter`: String | null
   - `verification_status`: `"verified"` | `"potential"` | `"not_reproduced"` | `"manual_review_required"`
   - `remediation_status`: `"open"` | `"fix_in_progress"` | `"pending_retest"` | `"remediated_verified"` | `"reopened"`
   - `verification_notes`: String
   - `remediation_guidance`: String
   - `cwe_id`: String (e.g., `"CWE-79"`, `"CWE-693"`)

8. **FindingSource** (New Association Model — Multi-tool Provenance):
   - `id`: UUID (Primary Key)
   - `finding_id`: Foreign Key to UnifiedFinding
   - `tool_name`: `"owasp_zap"` | `"ffuf"` | `"tls_prober"`
   - `source_alert_id`: String (tool-specific alert identifier or plugin ID, e.g., `ZAP-40012`)
   - `original_severity`: String
   - `raw_artifact_path`: String (path to tool output file in `.data/artifacts/`)
   - `created_at`: ISO timestamp

9. **FindingEvidence** (1:N relationship with UnifiedFinding):
   - `id`: UUID (Primary Key)
   - `finding_id`: Foreign Key to UnifiedFinding
   - `request_headers`: String (sanitized / secrets redacted)
   - `request_body`: String | null (redacted)
   - `response_headers`: String
   - `response_body_snippet`: String
   - `matched_pattern`: String (evidence trigger)
   - `raw_tool_finding_json`: String (exact snippet from tool output)
   - `created_at`: ISO timestamp

10. **VerificationAttempt**:
    - `id`: UUID (Primary Key)
    - `finding_id`: Foreign Key to UnifiedFinding
    - `timestamp`: ISO timestamp
    - `retest_type`: `"reproduce_exploit"` | `"check_header"` | `"probe_endpoint"`
    - `outcome`: `"still_vulnerable"` | `"remediated"` | `"inconclusive"`
    - `retest_evidence`: String

---

### 4. Detailed Scan Workflow & Scope-Enforcing Proxy

```
[Target Submitted]
       │
       ▼
[Stage 1: Scope Validation & Egress Proxy Initialization]
 ├─ Parse URL & validate protocol (HTTP/HTTPS only)
 ├─ Start local Scope-Enforcing Egress Proxy on dynamic loopback port
 ├─ Proxy configuration loaded with permitted hostname, ports, and max_request_budget
 ├─ Verify destination IP is NOT in RFC 1918 / Loopback / Metadata (unless isolated lab confirmed)
 └─ Verify active scan scope disclaimer signed (if Active Profile selected)
       │ Pass
       ▼
[Stage 2: Reconnaissance & Target Fingerprinting]
 ├─ Prober requests target via Egress Proxy (proxy validates destination on every hop)
 ├─ Query TLS cipher suites, certificate validity, expiration
 ├─ Inspect security response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
 ├─ Log TestExecution records for executed passive checks
 └─ Identify server banner & framework signatures
       │
       ▼
[Stage 3: Rate-Limited Content Discovery (Real ffuf CLI)]
 ├─ Check ffuf compatibility: ffuf -V
 ├─ Execute ffuf CLI configured to use Egress Proxy:
 │    ffuf -u TARGET/FUZZ -w wordlists/common.txt -x http://127.0.0.1:PROXY_PORT -rate 10 -t 2 -maxtime 120 -of json -o ffuf_out.json
 ├─ Egress Proxy counts requests toward global budget and blocks off-scope redirects
 ├─ Ingest discovered routes -> Store in AttackSurfaceEndpoint table
 └─ Record TestExecution record for PV-A02-005 (Content Discovery)
       │
       ▼
[Stage 4: Automated Crawl & Vulnerability Scan (OWASP ZAP AF)]
 ├─ Generate YAML Automation Framework plan with outgoing proxy set to Egress Proxy
 ├─ Execute ZAP AF jobs:
 │    - spider: Crawl links, forms, and input fields within approved scope
 │    - passiveScan-wait: Analyze response headers, info leakage, cookie flags
 │    - activeScan: Scoped active rules with rate limiting and exclusions (if Active Profile)
 ├─ Save raw ZAP output to .data/artifacts/
 ├─ Terminate ZAP process upon job completion
 └─ Record TestExecution records for each executed ZAP scan rule
       │
       ▼
[Stage 5: Finding Correlation & Provenance Linking]
 ├─ Ingest raw ffuf and ZAP outputs from artifact store
 ├─ Normalize into UnifiedFinding schema
 ├─ Deduplicate identical flaws on the same endpoint (populating FindingSource records for each tool)
 ├─ Link findings to AttackSurfaceEndpoint records
 └─ Redact credentials, API keys, and session cookies from stored evidence
       │
       ▼
[Stage 6: Context-Aware Verification & Remediation Priority]
 ├─ Execute context-aware verification probes for supported findings:
 │    - XSS: Verify unencoded execution context in HTML/DOM; classify as 'potential' if ambiguous
 │    - SQLi: Verify differential response timing or content reflection; error text alone is 'potential'
 ├─ Set verification_status (verified, potential, not_reproduced, manual_review_required)
 ├─ Initialize remediation_status as 'open'
 ├─ Calculate Contextual Remediation Priority (CRP: 0.0–10.0) without altering source CVSS
 └─ Derive OWASP Top 10:2025 coverage matrix strictly from TestExecution records
       │
       ▼
[Stage 7: Report Generation]
 ├─ Generate Executive Summary (Risk Posture, Severity Breakdown, OWASP 2025 Heatmap)
 ├─ Generate Technical Findings Log with full redacted HTTP evidence & remediation steps
 ├─ Record observed request counts from proxy access logs and document scan limitations
 └─ Produce print-ready PDF and JSON/CSV exports
```

---

### 5. OWASP Top 10:2025 Test Registry & Contextual Validation Rules

| Test ID | Category | Automated Check Name | Tool Engine | Contextual Validation Rule | Expected Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `PV-A01-001` | **A01: Broken Access Control** | Role-Aware Path Traversal & IDOR | ZAP Active + Custom Prober | Requires valid test account credentials; verifies unauthorized object access | *Partially Tested* |
| `PV-A02-001` | **A02: Security Misconfiguration** | Missing Security Headers (HSTS/CSP/XFO) | Custom TLS Prober + ZAP Passive | Verifies response headers across all discovered root and API routes | *Tested* |
| `PV-A02-002` | **A02: Security Misconfiguration** | Permissive CORS Configuration | Custom Prober | Wildcard `Access-Control-Allow-Origin: *` must be verified for sensitive data reflection; credential access must be verified | *Tested* |
| `PV-A02-003` | **A02: Security Misconfiguration** | Dangerous HTTP Methods (PUT/DELETE/TRACE) | Custom Prober | `OPTIONS` reflection alone is insufficient; sends benign probe to test actual route execution | *Tested* |
| `PV-A02-004` | **A02: Security Misconfiguration** | Exposed Sensitive Files (.git/.env/backups) | ffuf + Custom Prober | Verifies file contents against signature regex (e.g. valid git index header) | *Tested* |
| `PV-A03-001` | **A03: Software Supply Chain Failures** | Known Vulnerable Libraries (Retire.js) | ZAP Passive | Manifest detection alone is informational; requires verified CVE in loaded JS | *Partially Tested* |
| `PV-A04-001` | **A04: Cryptographic Failures** | Insecure TLS Protocol & Cipher Suites | Custom TLS Prober | Evaluates TLS 1.0/1.1 deprecation, forward secrecy, and certificate expiration | *Tested* |
| `PV-A04-002` | **A04: Cryptographic Failures** | Missing Secure / SameSite Cookie Flags | ZAP Passive + Custom Prober | Verifies cookie attributes transmitted over HTTPS connections | *Tested* |
| `PV-A05-001` | **A05: Injection** | Reflected Cross-Site Scripting (XSS) | ZAP Active Scan | Reflection alone is NOT proof; verifies script breakout or execution context; otherwise flags as *Potential* | *Tested* |
| `PV-A05-002` | **A05: Injection** | SQL Injection (Error & Boolean Differential) | ZAP Active Scan | Database error text alone indicates error disclosure; confirmed SQLi requires differential timing or Boolean response changes | *Tested* |
| `PV-A06-001` | **A06: Insecure Design** | Architectural Rate Limiting Absence | Custom Prober | Evaluates repeated request throttling on sensitive actions; heuristic only | *Manual Review Required* |
| `PV-A07-001` | **A07: Authentication Failures** | Session Fixation & Weak Logout Invalidation | ZAP Passive + Custom Prober | Evaluates session token rotation post-authentication; requires test accounts | *Partially Tested* |
| `PV-A08-001` | **A08: Software & Data Integrity** | Missing Subresource Integrity (SRI) on CDNs | ZAP Passive | Checks external `<script>` and `<link>` tags for valid `integrity` hashes | *Partially Tested* |
| `PV-A09-001` | **A09: Logging & Alerting Failures** | Audit Log Event Generation | Lab Log Prober | Marked as *Unavailable / Manual Review Required* unless administrative log access is provided | *Manual Review Required* |
| `PV-A10-001` | **A10: Mishandling of Exceptional Conditions** | Verbose Stack Trace & Error Disclosure | ZAP Passive + Active Prober | Verified by sending safe malformed input and matching unhandled stack traces | *Tested* |

---

### 6. Phased Implementation Roadmap (12 Weeks to MVP & Evaluation)

- **Phase 1: Foundation, Scope-Enforcing Proxy & Process Supervisor (Weeks 1–2)**
  - Persistent SQLite schema (`db.sqlite`) including `TestExecution` and `FindingSource` tables.
  - Implement Scope-Enforcing Egress Proxy with dynamic destination IP validation, anti-rebinding, redirect re-checks, and aggregate request budget accounting.
  - Node.js process supervisor with process-tree termination (`process.kill(-pid)`), streaming logs, and `Start`/`Monitor`/`Cancel` controls.

- **Phase 2: Discovery & Tool Integration (Weeks 3–4) — [MVP Core 1]**
  - Integrate real `ffuf` binary execution (`ffuf -V` preflight, rate limits, common wordlists, `-x` proxy routing, soft-404 filtering, `-of json` ingestion).
  - Build attack surface endpoint persistence and UI route explorer.

- **Phase 3: Core Security Scanning & ZAP AF (Weeks 5–6) — [MVP Core 2]**
  - Implement custom TLS, SSL certificate, security header, CORS, and cookie auditing engine routed through proxy.
  - Integrate OWASP ZAP Automation Framework (YAML AF plan execution, proxy configuration, spidering, passive scanning, scoped active scan).
  - Ingest raw tool outputs and preserve raw files in access-controlled `.data/artifacts/` store.

- **Phase 4: Findings Intelligence, Provenance & Verification (Weeks 7–8) — [MVP Core 3]**
  - Findings normalization engine and deduplication logic (populating multi-tool `FindingSource` records).
  - Credential and token redaction filter on all captured request/response evidence.
  - Context-aware verification engine with decoupled `verification_status` and `remediation_status`.

- **Phase 5: Reporting, Retesting & Lab Benchmarks (Weeks 9–10) — [MVP Complete]**
  - Remediation re-test workflow (re-verify individual findings; transition to `remediated_verified` upon verified fix).
  - Executive and technical PDF report generation with OWASP 2025 coverage badges derived from `TestExecution` table.
  - Pre-configured lab environments (locally hosted OWASP Juice Shop and DVWA benchmark suites).

- **Phase 6: Research Evaluation & Dissertation Ground Truth (Weeks 11–12)**
  - Execute controlled benchmark runs against locally hosted OWASP Juice Shop with documented ground truth.
  - Measure precision, recall, false-positive rate, duplicate reduction, scan duration, and retest verification accuracy using explicit mathematical formulas.
  - Compile academic research evaluation report.

---

### 7. Explicit Academic Research Evaluation Methodology & Formulas

To ensure empirical validity for the MSc Cyber Security dissertation, ProofVAPT's detection and triage performance will be measured against a documented ground-truth dataset comprising known vulnerable and non-vulnerable test instances in a locally hosted testbed (e.g. OWASP Juice Shop and DVWA):

#### Unit of Analysis & Definitions
- **Unit of Analysis**: An individual test instance defined as a specific tuple of `(Endpoint URL, HTTP Method, Parameter/Component, Vulnerability Class)`.
- **True Positive (TP)**: A genuine vulnerability present in ground truth that was correctly identified by the scanner.
- **False Positive (FP)**: An alert reported on a non-vulnerable route or component where no exploitable flaw exists.
- **False Negative (FN)**: A known vulnerability present in ground truth that the scanner failed to detect.
- **True Negative (TN)**: A non-vulnerable test instance or hardened configuration correctly not flagged.
- **Zero-Denominator Rule**: If any denominator evaluates to zero (e.g., $TP + FP = 0$), the metric is formally reported as `Undefined` rather than masked with an arbitrary percentage.

#### Mathematical Formulas

1. **Precision**:
   $$\text{Precision} = \begin{cases} \frac{TP}{TP + FP} & \text{if } TP + FP > 0 \\ \text{Undefined} & \text{if } TP + FP = 0 \end{cases}$$

2. **Recall (Sensitivity / Detection Rate)**:
   $$\text{Recall} = \begin{cases} \frac{TP}{TP + FN} & \text{if } TP + FN > 0 \\ \text{Undefined} & \text{if } TP + FN = 0 \end{cases}$$

3. **False-Positive Rate (FPR)**:
   $$\text{FPR} = \begin{cases} \frac{FP}{FP + TN} & \text{if } FP + TN > 0 \\ \text{Undefined} & \text{if } FP + TN = 0 \end{cases}$$

4. **False-Positive Reduction ($\Delta_{FP}$)**:
   $$\Delta_{FP} = \begin{cases} \frac{FP_{\text{baseline}} - FP_{\text{new}}}{FP_{\text{baseline}}} \times 100\% & \text{if } FP_{\text{baseline}} > 0 \\ \text{Undefined} & \text{if } FP_{\text{baseline}} = 0 \end{cases}$$

5. **Duplicate Reduction ($\Delta_{\text{dup}}$)**:
   $$\Delta_{\text{dup}} = \begin{cases} \frac{D_{\text{before}} - D_{\text{after}}}{D_{\text{before}}} \times 100\% & \text{if } D_{\text{before}} > 0 \\ \text{Undefined} & \text{if } D_{\text{before}} = 0 \end{cases}$$

6. **Time Overhead ($\Delta_{\text{time}}$)**:
   $$\Delta_{\text{time}} = \begin{cases} \frac{T_{\text{platform}} - T_{\text{baseline}}}{T_{\text{baseline}}} \times 100\% & \text{if } T_{\text{baseline}} > 0 \\ \text{Undefined} & \text{if } T_{\text{baseline}} = 0 \end{cases}$$

7. **Request Overhead ($\Delta_{\text{req}}$)**:
   $$\Delta_{\text{req}} = \begin{cases} \frac{R_{\text{platform}} - R_{\text{baseline}}}{R_{\text{baseline}}} \times 100\% & \text{if } R_{\text{baseline}} > 0 \\ \text{Undefined} & \text{if } R_{\text{baseline}} = 0 \end{cases}$$

8. **Remediation Verification Accuracy**:
   $$\text{Accuracy}_{\text{verify}} = \begin{cases} \frac{\text{Correct Retest Classifications}}{\text{Total Evaluated Retests}} & \text{if Total Evaluated Retests} > 0 \\ \text{Undefined} & \text{if Total Evaluated Retests} = 0 \end{cases}$$

---

### 8. Concrete MVP Acceptance Criteria

1. **Egress Proxy Enforcement Across All Workers**: `ffuf` (via `-x`) and OWASP ZAP (via outgoing proxy configuration) route 100% of outbound HTTP traffic through the local Scope-Enforcing Proxy; requests to private IPs (`10.0.0.0/8`, `127.0.0.1`, `169.254.169.254`) or off-scope hosts are blocked and logged before TCP handshakes.
2. **Global Request Budget Cut-Off**: When aggregate requests across ffuf, ZAP, and custom checks reach `max_request_budget`, the egress proxy immediately terminates further requests, trips the stop condition, and triggers process-tree shutdown.
3. **Audit Trail via TestExecution**: Every check mapped in the OWASP registry records a row in the `TestExecution` table; the dashboard OWASP Top 10:2025 coverage matrix reflects only executed tests and marks unexecuted items as *Not Tested* or *Manual Review Required*.
4. **Multi-Tool Provenance via FindingSource**: Findings detected by both ZAP and custom probers are deduplicated into a single `UnifiedFinding` linked to multiple `FindingSource` entries with source alert IDs and raw output paths.
5. **Context-Aware Verification Rules**: Reflected strings without execution context are classified as *Potential* XSS; database errors without differential execution proof are classified as *Potential* information disclosure.
6. **Hard Process-Tree Cancellation**: Initiating "Cancel Scan" terminates all child process groups (`process.kill(-pid)`) within 3 seconds, preserves partial findings in SQLite, and marks status as `aborted`.
7. **Decoupled Verification and Remediation States**: Retesting a remediated endpoint transitions the finding to `remediated_verified`; inconclusive retests retain `open` and flag `manual_review_required`.
8. **Print-Ready PDF Reporting**: Compiles an executive summary and detailed technical report displaying observed request counts, CVSS & CRP scores, OWASP 2025 coverage badges, and documented research prototype limitations.
