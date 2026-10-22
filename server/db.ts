import fs from 'fs';
import path from 'path';
import {
  TargetProfile,
  ScanExecution,
  ToolExecutionRecord,
  AttackSurfaceEndpoint,
  OWASPTestRegistryItem,
  TestExecution,
  UnifiedFinding,
  FindingSource,
  FindingEvidence,
  VerificationAttempt,
  ProxyAccessLog,
} from '../src/types/proofvapt.js';

const DATA_DIR = path.resolve(process.env.PROOFVAPT_DATA_DIR || path.join(process.cwd(), '.data'));
const ARTIFACTS_DIR = path.resolve(DATA_DIR, 'artifacts');
const DB_FILE = path.resolve(DATA_DIR, 'db.json');

// Ensure storage directories exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(ARTIFACTS_DIR)) {
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
}

interface DatabaseSchema {
  schema_version: number;
  targets: TargetProfile[];
  scans: ScanExecution[];
  tools: ToolExecutionRecord[];
  endpoints: AttackSurfaceEndpoint[];
  test_registry: OWASPTestRegistryItem[];
  test_executions: TestExecution[];
  findings: UnifiedFinding[];
  finding_sources: FindingSource[];
  finding_evidences: FindingEvidence[];
  verification_attempts: VerificationAttempt[];
  proxy_logs: ProxyAccessLog[];
}

const DEFAULT_OWASP_REGISTRY: OWASPTestRegistryItem[] = [
  {
    test_id: 'PV-A01-001',
    name: 'Role-Aware Path Traversal & IDOR Check',
    owasp_category: 'A01',
    category_title: 'A01:2025 - Broken Access Control',
    description: 'Validates route permissions across privilege levels and tests object reference tampering.',
    execution_method: 'automated_zap',
    prerequisites: 'Valid test account credentials or multi-role session tokens.',
    limitations: 'Context-dependent; cannot comprehensively test complex stateful multi-step business logic.',
    validation_criteria: 'Requires confirmed cross-account unauthorized resource retrieval or unauthorized modification.'
  },
  {
    test_id: 'PV-A02-001',
    name: 'Security Header Baseline Audit',
    owasp_category: 'A02',
    category_title: 'A02:2025 - Security Misconfiguration',
    description: 'Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Permissions-Policy on HTTP responses.',
    execution_method: 'automated_prober',
    prerequisites: 'Reachable HTTP/S web service.',
    limitations: 'Static analysis only; reports policy absence across root and API routes.',
    validation_criteria: 'Absence of protective response headers in production/HTTPS context.'
  },
  {
    test_id: 'PV-A02-002',
    name: 'Context-Aware CORS Policy Validation',
    owasp_category: 'A02',
    category_title: 'A02:2025 - Security Misconfiguration',
    description: 'Probes cross-origin resource sharing behavior with null and arbitrary origin headers.',
    execution_method: 'automated_prober',
    prerequisites: 'Reachable HTTP/S web service with cross-origin handlers.',
    limitations: 'Wildcard CORS is only flagged as vulnerable when paired with sensitive data or credentials reflection.',
    validation_criteria: 'Response reflects untrusted origin alongside Access-Control-Allow-Credentials: true or exposes sensitive payloads.'
  },
  {
    test_id: 'PV-A02-003',
    name: 'Dangerous HTTP Method Behavioral Probe',
    owasp_category: 'A02',
    category_title: 'A02:2025 - Security Misconfiguration',
    description: 'Tests if TRACE, PUT, or DELETE methods execute rather than simply reflecting in OPTIONS headers.',
    execution_method: 'automated_prober',
    prerequisites: 'Reachable target endpoints.',
    limitations: 'Safe probing only; does not perform destructive write or delete actions.',
    validation_criteria: 'Requires active behavioral acceptance (e.g. TRACE body reflection or unexpected 200/204 on probe).'
  },
  {
    test_id: 'PV-A02-004',
    name: 'Exposed Sensitive Files & Source Control',
    owasp_category: 'A02',
    category_title: 'A02:2025 - Security Misconfiguration',
    description: 'Searches for exposed .git, .env, backups, database dumps, and server configuration files.',
    execution_method: 'automated_ffuf',
    prerequisites: 'Target route discovery enabled with dictionary wordlist.',
    limitations: 'Must filter out custom soft-404 responses before classifying an exposed file as valid.',
    validation_criteria: 'Payload content verification matches known magic bytes (e.g., git index header, config keys) and status 200.'
  },
  {
    test_id: 'PV-A03-001',
    name: 'Software Supply Chain & Vulnerable Library Audit',
    owasp_category: 'A03',
    category_title: 'A03:2025 - Software Supply Chain Failures',
    description: 'Identifies client-side JavaScript libraries and dependency versions against known CVE databases.',
    execution_method: 'automated_zap',
    prerequisites: 'Crawled HTML and scripts containing version markers.',
    limitations: 'Manifest detection alone is informational; requires confirmed vulnerable component version in active use.',
    validation_criteria: 'Confirmed match of client-side dependency version with documented critical/high CVEs (Retire.js).'
  },
  {
    test_id: 'PV-A04-001',
    name: 'TLS Protocol & Cipher Suite Cryptographic Audit',
    owasp_category: 'A04',
    category_title: 'A04:2025 - Cryptographic Failures',
    description: 'Checks for deprecated TLS v1.0/v1.1 protocols, weak CBC ciphers, and certificate expiration/mismatch.',
    execution_method: 'automated_prober',
    prerequisites: 'HTTPS target on port 443 or custom SSL/TLS port.',
    limitations: 'Does not audit server-side database encryption-at-rest or internal secret storage.',
    validation_criteria: 'Server establishes handshake using obsolete TLS versions or expired/untrusted certificate.'
  },
  {
    test_id: 'PV-A04-002',
    name: 'Cookie Security Attributes Inspection',
    owasp_category: 'A04',
    category_title: 'A04:2025 - Cryptographic Failures',
    description: 'Verifies Secure, HttpOnly, and SameSite flags on Set-Cookie headers over TLS.',
    execution_method: 'automated_zap',
    prerequisites: 'Session cookies generated during crawling or authentication.',
    limitations: 'Limited to cookies observed during crawler and passive scanner passes.',
    validation_criteria: 'Sensitive or session cookies set without Secure flag or appropriate SameSite policy.'
  },
  {
    test_id: 'PV-A05-001',
    name: 'Context-Aware Reflected Cross-Site Scripting (XSS)',
    owasp_category: 'A05',
    category_title: 'A05:2025 - Injection',
    description: 'Injects non-destructive canary tokens into query and body parameters and checks unencoded reflection in executable HTML/JS context.',
    execution_method: 'automated_zap',
    prerequisites: 'Parameterized input endpoints discovered by crawler.',
    limitations: 'String reflection alone is NOT proof of XSS. Flagged as potential unless unescaped DOM breakout is verified.',
    validation_criteria: 'Unsanitized script execution context in response body without contextual encoding.'
  },
  {
    test_id: 'PV-A05-002',
    name: 'Differential SQL Injection Verification',
    owasp_category: 'A05',
    category_title: 'A05:2025 - Injection',
    description: 'Tests parameter inputs with Boolean differential and safe syntax probes to identify SQL parsing flaws.',
    execution_method: 'automated_zap',
    prerequisites: 'Database-backed endpoints with query parameters.',
    limitations: 'Database error messages alone indicate error disclosure (A10); confirmed SQLi requires differential response validation.',
    validation_criteria: 'Consistent Boolean differential response change or controlled time delay differential.'
  },
  {
    test_id: 'PV-A06-001',
    name: 'Rate-Limiting & Architectural Abuse Guard',
    owasp_category: 'A06',
    category_title: 'A06:2025 - Insecure Design',
    description: 'Observes rate limiting and anti-automation protections on authentication and sensitive resource routes.',
    execution_method: 'manual_review',
    prerequisites: 'Design documentation and threat model.',
    limitations: 'Automated scanners cannot evaluate threat models or business logic architecture without human review.',
    validation_criteria: 'Heuristic finding only; requires manual threat modeling and architecture review.'
  },
  {
    test_id: 'PV-A07-001',
    name: 'Authentication Session Handling & Token Exposure',
    owasp_category: 'A07',
    category_title: 'A07:2025 - Authentication Failures',
    description: 'Checks for session tokens exposed in URL query parameters and missing invalidation upon logout.',
    execution_method: 'automated_zap',
    prerequisites: 'Target login and logout workflow.',
    limitations: 'Does not perform brute-force credential attacks.',
    validation_criteria: 'Session identifier leaked in URL path/query or reused across authenticated state transitions.'
  },
  {
    test_id: 'PV-A08-001',
    name: 'Subresource Integrity (SRI) on External Resources',
    owasp_category: 'A08',
    category_title: 'A08:2025 - Software and Data Integrity Failures',
    description: 'Checks third-party CDN scripts and styles for valid cryptographic integrity attributes.',
    execution_method: 'automated_zap',
    prerequisites: 'HTML responses loading external third-party CDN scripts.',
    limitations: 'First-party hosted scripts do not typically require SRI attributes.',
    validation_criteria: 'External CDN script tag lacking valid integrity and crossorigin attributes.'
  },
  {
    test_id: 'PV-A09-001',
    name: 'Security Logging & Alerting Verification',
    owasp_category: 'A09',
    category_title: 'A09:2025 - Logging and Alerting Failures',
    description: 'Verifies whether simulated security events trigger audit log entries and alerts.',
    execution_method: 'manual_review',
    prerequisites: 'Administrative access to centralized logging (SIEM/syslog).',
    limitations: 'Scanners have zero visibility into internal application logs unless API or SIEM integration is provided.',
    validation_criteria: 'Requires manual review or SIEM log verification.'
  },
  {
    test_id: 'PV-A10-001',
    name: 'Verbose Exception & Stack Trace Disclosure',
    owasp_category: 'A10',
    category_title: 'A10:2025 - Mishandling of Exceptional Conditions',
    description: 'Sends malformed input and observes whether stack traces, SQL syntax errors, or debug internals leak in responses.',
    execution_method: 'automated_prober',
    prerequisites: 'Reachable target endpoints.',
    limitations: 'Distinguishes between clean error pages and verbose internal diagnostic leaks.',
    validation_criteria: 'Response body contains runtime stack trace signatures, environment variables, or database query snippets.'
  }
];

class Database {
  private data: DatabaseSchema;

  constructor() {
    this.data = this.load();
  }

  private load(): DatabaseSchema {
    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        // Schema v2 removes historical severity-derived pseudo-CVSS values.
        // Previous releases wrote estimated numbers into the "official CVSS"
        // field without a reproducible CVSS calculator or trusted source. Clear
        // those values once on upgrade, then preserve provenance-qualified
        // values saved by future versions.
        const schemaVersion = Number.isInteger(parsed.schema_version) ? parsed.schema_version : 1;
        const findings: UnifiedFinding[] = (parsed.findings || []).map((finding: UnifiedFinding) =>
          schemaVersion < 2
            ? {
                ...finding,
                official_cvss_score: null,
                official_cvss_version: null,
                official_cvss_vector: null
              }
            : finding
        );

        const state: DatabaseSchema = {
          schema_version: 2,
          targets: parsed.targets || [],
          scans: parsed.scans || [],
          tools: parsed.tools || [],
          endpoints: parsed.endpoints || [],
          test_registry: parsed.test_registry && parsed.test_registry.length > 0 ? parsed.test_registry : DEFAULT_OWASP_REGISTRY,
          test_executions: parsed.test_executions || [],
          findings,
          finding_sources: parsed.finding_sources || [],
          finding_evidences: parsed.finding_evidences || [],
          verification_attempts: parsed.verification_attempts || [],
          proxy_logs: parsed.proxy_logs || [],
        };
        if (schemaVersion < 2) {
          console.warn('[DB] Migrating legacy findings: clearing unsupported CVSS values.');
          this.save(state);
        }
        return state;
      } catch (err) {
        console.error('[DB] Failed to parse db.json, initializing fresh store:', err);
      }
    }

    const initial: DatabaseSchema = {
      schema_version: 2,
      targets: [],
      scans: [],
      tools: [],
      endpoints: [],
      test_registry: DEFAULT_OWASP_REGISTRY,
      test_executions: [],
      findings: [],
      finding_sources: [],
      finding_evidences: [],
      verification_attempts: [],
      proxy_logs: [],
    };
    this.save(initial);
    return initial;
  }

  private save(state?: DatabaseSchema) {
    const toSave = state || this.data;
    try {
      const tempPath = `${DB_FILE}.tmp.${Date.now()}`;
      fs.writeFileSync(tempPath, JSON.stringify(toSave, null, 2), 'utf-8');
      fs.renameSync(tempPath, DB_FILE);
    } catch (err) {
      console.error('[DB] Failed to save state to db.json:', err);
    }
  }

  // Targets
  getTargets(): TargetProfile[] {
    return [...this.data.targets];
  }

  getTarget(id: string): TargetProfile | undefined {
    return this.data.targets.find((t) => t.id === id);
  }

  saveTarget(target: TargetProfile): TargetProfile {
    const idx = this.data.targets.findIndex((t) => t.id === target.id);
    if (idx >= 0) {
      this.data.targets[idx] = target;
    } else {
      this.data.targets.push(target);
    }
    this.save();
    return target;
  }

  deleteTarget(id: string): boolean {
    const initialLen = this.data.targets.length;
    this.data.targets = this.data.targets.filter((t) => t.id !== id);
    this.save();
    return this.data.targets.length < initialLen;
  }

  // Scans
  getScans(): ScanExecution[] {
    return this.data.scans.map((s) => ({
      ...s,
      target: this.getTarget(s.target_id),
    }));
  }

  getScan(id: string): ScanExecution | undefined {
    const scan = this.data.scans.find((s) => s.id === id);
    if (!scan) return undefined;
    return {
      ...scan,
      target: this.getTarget(scan.target_id),
    };
  }

  saveScan(scan: ScanExecution): ScanExecution {
    const idx = this.data.scans.findIndex((s) => s.id === scan.id);
    if (idx >= 0) {
      this.data.scans[idx] = scan;
    } else {
      this.data.scans.push(scan);
    }
    this.save();
    return scan;
  }

  // Tools
  getToolRuns(scanId: string): ToolExecutionRecord[] {
    return this.data.tools.filter((t) => t.scan_id === scanId);
  }

  saveToolRun(tool: ToolExecutionRecord): ToolExecutionRecord {
    const idx = this.data.tools.findIndex((t) => t.id === tool.id);
    if (idx >= 0) {
      this.data.tools[idx] = tool;
    } else {
      this.data.tools.push(tool);
    }
    this.save();
    return tool;
  }

  // Attack Surface Endpoints
  getEndpoints(scanId: string): AttackSurfaceEndpoint[] {
    return this.data.endpoints.filter((e) => e.scan_id === scanId);
  }

  saveEndpoint(endpoint: AttackSurfaceEndpoint): AttackSurfaceEndpoint {
    const exists = this.data.endpoints.find(
      (e) => e.scan_id === endpoint.scan_id && e.url === endpoint.url && e.method === endpoint.method
    );
    if (!exists) {
      this.data.endpoints.push(endpoint);
      this.save();
    }
    return endpoint;
  }

  // OWASP Test Registry
  getTestRegistry(): OWASPTestRegistryItem[] {
    return [...this.data.test_registry];
  }

  // Test Executions
  getTestExecutions(scanId: string): TestExecution[] {
    return this.data.test_executions
      .filter((te) => te.scan_id === scanId)
      .map((te) => ({
        ...te,
        test: this.data.test_registry.find((tr) => tr.test_id === te.test_id),
      }));
  }

  saveTestExecution(te: TestExecution): TestExecution {
    const idx = this.data.test_executions.findIndex((t) => t.id === te.id);
    if (idx >= 0) {
      this.data.test_executions[idx] = te;
    } else {
      this.data.test_executions.push(te);
    }
    this.save();
    return te;
  }

  // Unified Findings
  getFindings(scanId: string): UnifiedFinding[] {
    return this.data.findings
      .filter((f) => f.scan_id === scanId)
      .map((f) => ({
        ...f,
        sources: this.data.finding_sources.filter((s) => s.finding_id === f.id),
        evidence: this.data.finding_evidences.filter((e) => e.finding_id === f.id),
      }));
  }

  getFinding(id: string): UnifiedFinding | undefined {
    const finding = this.data.findings.find((f) => f.id === id);
    if (!finding) return undefined;
    return {
      ...finding,
      sources: this.data.finding_sources.filter((s) => s.finding_id === finding.id),
      evidence: this.data.finding_evidences.filter((e) => e.finding_id === finding.id),
    };
  }

  saveFinding(finding: UnifiedFinding): UnifiedFinding {
    const idx = this.data.findings.findIndex((f) => f.id === finding.id);
    if (idx >= 0) {
      this.data.findings[idx] = finding;
    } else {
      this.data.findings.push(finding);
    }
    this.save();
    return finding;
  }

  // Finding Sources
  saveFindingSource(source: FindingSource): FindingSource {
    const exists = this.data.finding_sources.find(
      (s) => s.finding_id === source.finding_id && s.tool_name === source.tool_name && s.source_alert_id === source.source_alert_id
    );
    if (!exists) {
      this.data.finding_sources.push(source);
      this.save();
    }
    return source;
  }

  // Finding Evidence
  saveFindingEvidence(evidence: FindingEvidence): FindingEvidence {
    this.data.finding_evidences.push(evidence);
    this.save();
    return evidence;
  }

  // Verification Attempts
  getVerificationAttempts(findingId: string): VerificationAttempt[] {
    return this.data.verification_attempts.filter((v) => v.finding_id === findingId);
  }

  saveVerificationAttempt(attempt: VerificationAttempt): VerificationAttempt {
    this.data.verification_attempts.push(attempt);
    this.save();
    return attempt;
  }

  // Proxy Access Logs
  getProxyLogs(scanId: string, limit = 200): ProxyAccessLog[] {
    return this.data.proxy_logs.filter((p) => p.scan_id === scanId).slice(-limit);
  }

  saveProxyLog(log: ProxyAccessLog): ProxyAccessLog {
    this.data.proxy_logs.push(log);
    // Keep max 2000 logs in memory
    if (this.data.proxy_logs.length > 2000) {
      this.data.proxy_logs.shift();
    }
    this.save();
    return log;
  }
}

export const db = new Database();
export { ARTIFACTS_DIR, DATA_DIR };
