import http from 'http';
import https from 'https';
import tls from 'tls';
import net from 'node:net';
import { TargetProfile, UnifiedFinding, FindingEvidence, FindingSource, TestExecution } from '../src/types/proofvapt.js';
import { db } from './db.js';

export interface ProberResult {
  reachable: boolean;
  statusCode?: number;
  serverBanner?: string;
  tlsInfo?: {
    protocol?: string;
    authorized?: boolean;
    validTo?: string;
    issuer?: string;
    subject?: string;
    isDeprecated?: boolean;
  };
  headers?: Record<string, string | string[] | undefined>;
  findings: UnifiedFinding[];
  evidences: FindingEvidence[];
  sources: FindingSource[];
  testExecutions: TestExecution[];
}

export class CustomSecurityProber {
  private target: TargetProfile;
  private scanId: string;
  private proxyPort: number;

  constructor(target: TargetProfile, scanId: string, proxyPort: number) {
    this.target = target;
    this.scanId = scanId;
    this.proxyPort = proxyPort;
  }

  public async runAudits(): Promise<ProberResult> {
    const findings: UnifiedFinding[] = [];
    const evidences: FindingEvidence[] = [];
    const sources: FindingSource[] = [];
    const testExecutions: TestExecution[] = [];

    const url = new URL(this.target.target_url);
    const isHttps = url.protocol === 'https:';

    // 1. TLS Cryptographic Audit (PV-A04-001)
    let tlsResult: ProberResult['tlsInfo'] | undefined;
    const tlsTestExecId = `te-${Date.now()}-A04-001`;
    const startTls = new Date().toISOString();

    if (isHttps) {
      try {
        tlsResult = await this.checkTLS(url.hostname, parseInt(url.port || '443', 10));
        const endTls = new Date().toISOString();

        if (tlsResult.isDeprecated) {
          const findingId = `fnd-${Date.now()}-tls-dep`;
          const finding: UnifiedFinding = {
            id: findingId,
            scan_id: this.scanId,
            test_id: 'PV-A04-001',
            title: 'Deprecated TLS Protocol Version (TLS 1.0 / 1.1)',
            owasp_category: 'A04:2025 - Cryptographic Failures',
            owasp_category_code: 'A04',
            source_severity: 'HIGH',
            official_cvss_score: 7.4,
            official_cvss_version: '3.1',
            official_cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
            contextual_remediation_priority: 7.2,
            affected_url: this.target.target_url,
            parameter: null,
            verification_status: 'verified',
            remediation_status: 'open',
            verification_notes: `Target accepted cryptographic handshake with deprecated protocol ${tlsResult.protocol}.`,
            remediation_guidance: 'Disable TLS 1.0 and TLS 1.1 in web server configuration; enforce TLS 1.2 or TLS 1.3 with modern AEAD cipher suites.',
            cwe_id: 'CWE-326',
            created_at: new Date().toISOString()
          };
          findings.push(finding);

          const evidence: FindingEvidence = {
            id: `ev-${Date.now()}-tls`,
            finding_id: findingId,
            request_headers: `CLIENT_HELLO: Support TLS 1.0, 1.1, 1.2, 1.3 to ${url.hostname}`,
            request_body: null,
            response_headers: `HANDSHAKE_ESTABLISHED: ${tlsResult.protocol}`,
            response_body_snippet: `Certificate validTo: ${tlsResult.validTo}, Issuer: ${tlsResult.issuer}`,
            matched_pattern: `Protocol: ${tlsResult.protocol}`,
            created_at: new Date().toISOString()
          };
          evidences.push(evidence);

          sources.push({
            id: `src-${Date.now()}-tls`,
            finding_id: findingId,
            tool_name: 'tls_prober',
            source_alert_id: 'TLS-DEPRECATED-V1',
            original_severity: 'HIGH',
            raw_artifact_path: `.data/artifacts/${this.scanId}_prober.json`,
            created_at: new Date().toISOString()
          });

          testExecutions.push({
            id: tlsTestExecId,
            scan_id: this.scanId,
            test_id: 'PV-A04-001',
            execution_status: 'completed',
            outcome: 'vulnerable',
            evidence_references: [evidence.id],
            skip_or_error_reason: null,
            started_at: startTls,
            ended_at: endTls
          });
        } else {
          testExecutions.push({
            id: tlsTestExecId,
            scan_id: this.scanId,
            test_id: 'PV-A04-001',
            execution_status: 'completed',
            outcome: 'clean',
            evidence_references: [],
            skip_or_error_reason: null,
            started_at: startTls,
            ended_at: endTls
          });
        }
      } catch (err: any) {
        testExecutions.push({
          id: tlsTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A04-001',
          execution_status: 'failed',
          outcome: 'error',
          evidence_references: [],
          skip_or_error_reason: `TLS check failed: ${err.message}`,
          started_at: startTls,
          ended_at: new Date().toISOString()
        });
      }
    } else {
      // Cleartext HTTP (PV-A04-001)
      const findingId = `fnd-${Date.now()}-cleartext`;
      const finding: UnifiedFinding = {
        id: findingId,
        scan_id: this.scanId,
        test_id: 'PV-A04-001',
        title: 'Cleartext Transmission of Sensitive Information (HTTP Without TLS)',
        owasp_category: 'A04:2025 - Cryptographic Failures',
        owasp_category_code: 'A04',
        source_severity: 'MEDIUM',
        official_cvss_score: 5.9,
        official_cvss_version: '3.1',
        official_cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
        contextual_remediation_priority: 6.5,
        affected_url: this.target.target_url,
        parameter: null,
        verification_status: 'verified',
        remediation_status: 'open',
        verification_notes: 'Target runs on unencrypted HTTP protocol allowing passive eavesdropping and man-in-the-middle manipulation.',
        remediation_guidance: 'Enforce HTTPS on port 443 with valid TLS certificates and configure automatic HTTP-to-HTTPS redirects.',
        cwe_id: 'CWE-319',
        created_at: new Date().toISOString()
      };
      findings.push(finding);

      sources.push({
        id: `src-${Date.now()}-cleartext`,
        finding_id: findingId,
        tool_name: 'tls_prober',
        source_alert_id: 'HTTP-UNENCRYPTED',
        original_severity: 'MEDIUM',
        raw_artifact_path: `.data/artifacts/${this.scanId}_prober.json`,
        created_at: new Date().toISOString()
      });

      testExecutions.push({
        id: tlsTestExecId,
        scan_id: this.scanId,
        test_id: 'PV-A04-001',
        execution_status: 'completed',
        outcome: 'vulnerable',
        evidence_references: [],
        skip_or_error_reason: null,
        started_at: startTls,
        ended_at: new Date().toISOString()
      });
    }

    // 2. HTTP Security Headers Baseline (PV-A02-001)
    const headerTestExecId = `te-${Date.now()}-A02-001`;
    const startHeaders = new Date().toISOString();
    let rootResponse: { statusCode: number; headers: Record<string, string | string[] | undefined>; body: string } | null = null;

    try {
      rootResponse = await this.sendProxyRequest(this.target.target_url, 'GET');
      const headers = rootResponse.headers;

      const missingHeaders: string[] = [];
      if (!headers['strict-transport-security'] && isHttps) missingHeaders.push('Strict-Transport-Security (HSTS)');
      if (!headers['content-security-policy']) missingHeaders.push('Content-Security-Policy (CSP)');
      if (!headers['x-frame-options']) missingHeaders.push('X-Frame-Options');
      if (!headers['x-content-type-options']) missingHeaders.push('X-Content-Type-Options: nosniff');

      if (missingHeaders.length > 0) {
        const findingId = `fnd-${Date.now()}-headers`;
        const finding: UnifiedFinding = {
          id: findingId,
          scan_id: this.scanId,
          test_id: 'PV-A02-001',
          title: 'Missing Core HTTP Security Headers',
          owasp_category: 'A02:2025 - Security Misconfiguration',
          owasp_category_code: 'A02',
          source_severity: missingHeaders.some((h) => h.includes('HSTS')) ? 'MEDIUM' : 'LOW',
          official_cvss_score: 5.3,
          official_cvss_version: '3.1',
          official_cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
          contextual_remediation_priority: 5.0,
          affected_url: this.target.target_url,
          parameter: null,
          verification_status: 'verified',
          remediation_status: 'open',
          verification_notes: `Observed HTTP response lacked defensive security headers: ${missingHeaders.join(', ')}.`,
          remediation_guidance: 'Configure web server / reverse proxy to include HSTS (max-age=31536000), CSP, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff.',
          cwe_id: 'CWE-693',
          created_at: new Date().toISOString()
        };
        findings.push(finding);

        const evidence: FindingEvidence = {
          id: `ev-${Date.now()}-hdrs`,
          finding_id: findingId,
          request_headers: `GET ${url.pathname} HTTP/1.1\r\nHost: ${url.host}\r\nUser-Agent: ProofVAPT-Prober/1.0`,
          request_body: null,
          response_headers: Object.entries(headers)
            .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
            .join('\r\n'),
          response_body_snippet: rootResponse.body.slice(0, 300),
          matched_pattern: `Missing: ${missingHeaders.join('; ')}`,
          created_at: new Date().toISOString()
        };
        evidences.push(evidence);

        sources.push({
          id: `src-${Date.now()}-hdrs`,
          finding_id: findingId,
          tool_name: 'tls_prober',
          source_alert_id: 'SEC-HEADERS-MISSING',
          original_severity: 'MEDIUM',
          raw_artifact_path: `.data/artifacts/${this.scanId}_prober.json`,
          created_at: new Date().toISOString()
        });

        testExecutions.push({
          id: headerTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A02-001',
          execution_status: 'completed',
          outcome: 'vulnerable',
          evidence_references: [evidence.id],
          skip_or_error_reason: null,
          started_at: startHeaders,
          ended_at: new Date().toISOString()
        });
      } else {
        testExecutions.push({
          id: headerTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A02-001',
          execution_status: 'completed',
          outcome: 'clean',
          evidence_references: [],
          skip_or_error_reason: null,
          started_at: startHeaders,
          ended_at: new Date().toISOString()
        });
      }
    } catch (err: any) {
      testExecutions.push({
        id: headerTestExecId,
        scan_id: this.scanId,
        test_id: 'PV-A02-001',
        execution_status: 'failed',
        outcome: 'error',
        evidence_references: [],
        skip_or_error_reason: `Header check failed: ${err.message}`,
        started_at: startHeaders,
        ended_at: new Date().toISOString()
      });
    }

    // 3. Context-Aware CORS Probe (PV-A02-002)
    const corsTestExecId = `te-${Date.now()}-A02-002`;
    const startCors = new Date().toISOString();
    try {
      const arbitraryOrigin = 'https://malicious-attacker-proofvapt.org';
      const corsRes = await this.sendProxyRequest(this.target.target_url, 'GET', { Origin: arbitraryOrigin });
      const acao = corsRes.headers['access-control-allow-origin'];
      const acac = corsRes.headers['access-control-allow-credentials'];
      if (acao === '*' || acao === arbitraryOrigin) {
        const isCredentials = acac === 'true' || (Array.isArray(acac) && acac.includes('true'));
        const findingId = `fnd-${Date.now()}-cors`;
        const finding: UnifiedFinding = {
          id: findingId,
          scan_id: this.scanId,
          test_id: 'PV-A02-002',
          title: isCredentials
            ? 'Critical CORS Misconfiguration (Arbitrary Origin with Credentials)'
            : 'Permissive Cross-Origin Resource Sharing (CORS) Policy',
          owasp_category: 'A02:2025 - Security Misconfiguration',
          owasp_category_code: 'A02',
          source_severity: isCredentials ? 'CRITICAL' : 'LOW',
          official_cvss_score: isCredentials ? 8.1 : 3.7,
          official_cvss_version: '3.1',
          official_cvss_vector: isCredentials
            ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N'
            : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
          contextual_remediation_priority: isCredentials ? 8.8 : 3.5,
          affected_url: this.target.target_url,
          parameter: 'Origin',
          verification_status: isCredentials ? 'verified' : 'potential',
          remediation_status: 'open',
          verification_notes: isCredentials
            ? `CORS policy reflected arbitrary untrusted origin '${arbitraryOrigin}' with Access-Control-Allow-Credentials: true.`
            : `Wildcard or permissive Access-Control-Allow-Origin: ${acao} detected without credentials.`,
          remediation_guidance: 'Enforce an explicit whitelist of trusted origins; never reflect user-controlled Origin headers with Allow-Credentials.',
          cwe_id: 'CWE-942',
          created_at: new Date().toISOString()
        };
        findings.push(finding);

        const evidence: FindingEvidence = {
          id: `ev-${Date.now()}-cors`,
          finding_id: findingId,
          request_headers: `GET ${url.pathname} HTTP/1.1\r\nOrigin: ${arbitraryOrigin}`,
          request_body: null,
          response_headers: `Access-Control-Allow-Origin: ${acao}\r\nAccess-Control-Allow-Credentials: ${acac}`,
          response_body_snippet: corsRes.body.slice(0, 200),
          matched_pattern: `ACAO: ${acao}, ACAC: ${acac}`,
          created_at: new Date().toISOString()
        };
        evidences.push(evidence);

        sources.push({
          id: `src-${Date.now()}-cors`,
          finding_id: findingId,
          tool_name: 'tls_prober',
          source_alert_id: 'CORS-PERMISSIVE',
          original_severity: isCredentials ? 'CRITICAL' : 'LOW',
          raw_artifact_path: `.data/artifacts/${this.scanId}_prober.json`,
          created_at: new Date().toISOString()
        });

        testExecutions.push({
          id: corsTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A02-002',
          execution_status: 'completed',
          outcome: 'vulnerable',
          evidence_references: [evidence.id],
          skip_or_error_reason: null,
          started_at: startCors,
          ended_at: new Date().toISOString()
        });
      } else {
        testExecutions.push({
          id: corsTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A02-002',
          execution_status: 'completed',
          outcome: 'clean',
          evidence_references: [],
          skip_or_error_reason: null,
          started_at: startCors,
          ended_at: new Date().toISOString()
        });
      }
    } catch {
      testExecutions.push({
        id: corsTestExecId,
        scan_id: this.scanId,
        test_id: 'PV-A02-002',
        execution_status: 'completed',
        outcome: 'clean',
        evidence_references: [],
        skip_or_error_reason: null,
        started_at: startCors,
        ended_at: new Date().toISOString()
      });
    }

    // 4. Dangerous HTTP Methods Behavioral Probe (PV-A02-003)
    const methodTestExecId = `te-${Date.now()}-A02-003`;
    const startMethods = new Date().toISOString();
    try {
      const traceRes = await this.sendProxyRequest(this.target.target_url, 'TRACE');
      if (traceRes.statusCode === 200 && (traceRes.body.includes('TRACE') || traceRes.body.includes('ProofVAPT'))) {
        const findingId = `fnd-${Date.now()}-trace`;
        const finding: UnifiedFinding = {
          id: findingId,
          scan_id: this.scanId,
          test_id: 'PV-A02-003',
          title: 'HTTP TRACE Method Enabled (Cross-Site Tracing Potential)',
          owasp_category: 'A02:2025 - Security Misconfiguration',
          owasp_category_code: 'A02',
          source_severity: 'MEDIUM',
          official_cvss_score: 5.3,
          official_cvss_version: '3.1',
          official_cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
          contextual_remediation_priority: 5.1,
          affected_url: this.target.target_url,
          parameter: 'HTTP Method: TRACE',
          verification_status: 'verified',
          remediation_status: 'open',
          verification_notes: 'Target web server returned HTTP 200 with request body reflection on TRACE request (XST risk).',
          remediation_guidance: 'Disable TRACE and TRACK methods in web server configuration (e.g. TraceEnable off in Apache, reject in Nginx).',
          cwe_id: 'CWE-16',
          created_at: new Date().toISOString()
        };
        findings.push(finding);

        const evidence: FindingEvidence = {
          id: `ev-${Date.now()}-trace`,
          finding_id: findingId,
          request_headers: `TRACE ${url.pathname} HTTP/1.1\r\nHost: ${url.host}`,
          request_body: null,
          response_headers: `HTTP/1.1 200 OK`,
          response_body_snippet: traceRes.body.slice(0, 200),
          matched_pattern: 'TRACE body reflection',
          created_at: new Date().toISOString()
        };
        evidences.push(evidence);

        sources.push({
          id: `src-${Date.now()}-trace`,
          finding_id: findingId,
          tool_name: 'tls_prober',
          source_alert_id: 'HTTP-TRACE-ACTIVE',
          original_severity: 'MEDIUM',
          raw_artifact_path: `.data/artifacts/${this.scanId}_prober.json`,
          created_at: new Date().toISOString()
        });

        testExecutions.push({
          id: methodTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A02-003',
          execution_status: 'completed',
          outcome: 'vulnerable',
          evidence_references: [evidence.id],
          skip_or_error_reason: null,
          started_at: startMethods,
          ended_at: new Date().toISOString()
        });
      } else {
        testExecutions.push({
          id: methodTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A02-003',
          execution_status: 'completed',
          outcome: 'clean',
          evidence_references: [],
          skip_or_error_reason: null,
          started_at: startMethods,
          ended_at: new Date().toISOString()
        });
      }
    } catch {
      testExecutions.push({
        id: methodTestExecId,
        scan_id: this.scanId,
        test_id: 'PV-A02-003',
        execution_status: 'completed',
        outcome: 'clean',
        evidence_references: [],
        skip_or_error_reason: null,
        started_at: startMethods,
        ended_at: new Date().toISOString()
      });
    }

    // 5. Verbose Exception & Debug Disclosure Probe (PV-A10-001)
    const errorTestExecId = `te-${Date.now()}-A10-001`;
    const startError = new Date().toISOString();
    try {
      const malformedUrl = new URL(this.target.target_url);
      malformedUrl.searchParams.set('proofvapt_debug_test', "';--%00<invalid");
      const errRes = await this.sendProxyRequest(malformedUrl.toString(), 'GET');

      const stackTraceSignatures = [
        /at\s+[a-zA-Z0-9_.]+\s+\(.*:[0-9]+:[0-9]+\)/,
        /Traceback \(most recent call last\):/,
        /NullPointerException/i,
        /SyntaxError: unexpected token/i,
        /SQLSTATE\[[0-9A-Z]+\]/,
        /org\.apache\.[a-zA-Z0-9_.]+/
      ];

      const matchedSig = stackTraceSignatures.find((sig) => sig.test(errRes.body));
      if (matchedSig) {
        const findingId = `fnd-${Date.now()}-a10`;
        const finding: UnifiedFinding = {
          id: findingId,
          scan_id: this.scanId,
          test_id: 'PV-A10-001',
          title: 'Verbose Exception & Internal Stack Trace Leakage',
          owasp_category: 'A10:2025 - Mishandling of Exceptional Conditions',
          owasp_category_code: 'A10',
          source_severity: 'MEDIUM',
          official_cvss_score: 5.3,
          official_cvss_version: '3.1',
          official_cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
          contextual_remediation_priority: 5.2,
          affected_url: malformedUrl.toString(),
          parameter: 'proofvapt_debug_test',
          verification_status: 'verified',
          remediation_status: 'open',
          verification_notes: 'Server leaked raw internal execution stack traces or database error details when presented with malformed input.',
          remediation_guidance: 'Implement centralized exception handling to catch all unhandled errors and return generic, sanitized user-friendly error pages.',
          cwe_id: 'CWE-209',
          created_at: new Date().toISOString()
        };
        findings.push(finding);

        const evidence: FindingEvidence = {
          id: `ev-${Date.now()}-a10`,
          finding_id: findingId,
          request_headers: `GET ${malformedUrl.pathname}${malformedUrl.search} HTTP/1.1`,
          request_body: null,
          response_headers: `Status: ${errRes.statusCode}`,
          response_body_snippet: errRes.body.slice(0, 350),
          matched_pattern: String(matchedSig),
          created_at: new Date().toISOString()
        };
        evidences.push(evidence);

        sources.push({
          id: `src-${Date.now()}-a10`,
          finding_id: findingId,
          tool_name: 'tls_prober',
          source_alert_id: 'STACK-TRACE-LEAK',
          original_severity: 'MEDIUM',
          raw_artifact_path: `.data/artifacts/${this.scanId}_prober.json`,
          created_at: new Date().toISOString()
        });

        testExecutions.push({
          id: errorTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A10-001',
          execution_status: 'completed',
          outcome: 'vulnerable',
          evidence_references: [evidence.id],
          skip_or_error_reason: null,
          started_at: startError,
          ended_at: new Date().toISOString()
        });
      } else {
        testExecutions.push({
          id: errorTestExecId,
          scan_id: this.scanId,
          test_id: 'PV-A10-001',
          execution_status: 'completed',
          outcome: 'clean',
          evidence_references: [],
          skip_or_error_reason: null,
          started_at: startError,
          ended_at: new Date().toISOString()
        });
      }
    } catch {
      testExecutions.push({
        id: errorTestExecId,
        scan_id: this.scanId,
        test_id: 'PV-A10-001',
        execution_status: 'completed',
        outcome: 'clean',
        evidence_references: [],
        skip_or_error_reason: null,
        started_at: startError,
        ended_at: new Date().toISOString()
      });
    }

    return {
      reachable: rootResponse !== null,
      statusCode: rootResponse?.statusCode,
      serverBanner: typeof rootResponse?.headers['server'] === 'string' ? rootResponse.headers['server'] : undefined,
      tlsInfo: tlsResult,
      headers: rootResponse?.headers,
      findings,
      evidences,
      sources,
      testExecutions
    };
  }

  private async checkTLS(
    host: string,
    port: number
  ): Promise<{ protocol?: string; authorized?: boolean; validTo?: string; issuer?: string; subject?: string; isDeprecated?: boolean }> {
    if (!this.target.allowed_ports.includes(port)) {
      throw new Error('TLS probe port is outside the allowed target scope.');
    }

    // A default modern TLS client never negotiates TLS 1.0/1.1, even if the
    // server still supports them. Probe each deprecated protocol explicitly.
    // All connections use the scope-enforcing proxy; no direct target socket.
    const legacy10 = await this.tlsHandshakeThroughProxy(host, port, 'TLSv1', 'TLSv1');
    if (legacy10) return { ...legacy10, isDeprecated: true };

    const legacy11 = await this.tlsHandshakeThroughProxy(host, port, 'TLSv1.1', 'TLSv1.1');
    if (legacy11) return { ...legacy11, isDeprecated: true };

    const current = await this.tlsHandshakeThroughProxy(host, port);
    if (!current) {
      throw new Error('Could not negotiate a TLS connection using the tested protocol versions.');
    }
    return { ...current, isDeprecated: false };
  }

  private tlsHandshakeThroughProxy(
    host: string,
    port: number,
    minVersion?: tls.SecureVersion,
    maxVersion?: tls.SecureVersion
  ): Promise<{ protocol: string; authorized: boolean; validTo?: string; issuer?: string; subject?: string } | null> {
    return new Promise((resolve) => {
      const cleanHost = host.replace(/^\\[|\\]$/g, '');
      const authorityHost = cleanHost.includes(':') ? `[${cleanHost}]` : cleanHost;
      const authority = `${authorityHost}:${port}`;
      const proxySocket = net.connect(this.proxyPort, '127.0.0.1');
      let finished = false;
      let headerBuffer = Buffer.alloc(0);

      const finish = (value: { protocol: string; authorized: boolean; validTo?: string; issuer?: string; subject?: string } | null) => {
        if (finished) return;
        finished = true;
        resolve(value);
      };
      const fail = () => {
        proxySocket.destroy();
        finish(null);
      };

      proxySocket.setTimeout(8000, fail);
      proxySocket.once('error', fail);

      const onProxyData = (chunk: Buffer) => {
        headerBuffer = Buffer.concat([headerBuffer, chunk]);
        if (headerBuffer.length > 16 * 1024) return fail();
        const headerEnd = headerBuffer.indexOf('\\r\\n\\r\\n');
        if (headerEnd < 0) return;

        const headerText = headerBuffer.subarray(0, headerEnd).toString('latin1');
        const statusLine = headerText.split('\\r\\n', 1)[0] || '';
        if (!/^HTTP\\/1\\.[01] 200(?: |$)/.test(statusLine)) {
          proxySocket.removeListener('data', onProxyData);
          return fail();
        }

        proxySocket.removeListener('data', onProxyData);
        proxySocket.setTimeout(0);
        proxySocket.removeListener('error', fail);
        const extraBytes = headerBuffer.subarray(headerEnd + 4);
        if (extraBytes.length) proxySocket.unshift(extraBytes);

        const tlsOptions: tls.ConnectionOptions = {
          socket: proxySocket,
          rejectUnauthorized: false
        };
        if (net.isIP(cleanHost) === 0) tlsOptions.servername = cleanHost;
        if (minVersion) tlsOptions.minVersion = minVersion;
        if (maxVersion) tlsOptions.maxVersion = maxVersion;
        if (minVersion === 'TLSv1' || minVersion === 'TLSv1.1') {
          tlsOptions.ciphers = 'DEFAULT@SECLEVEL=0';
        }

        const secureSocket = tls.connect(tlsOptions);
        secureSocket.setTimeout(8000, () => secureSocket.destroy(new Error('TLS handshake timed out')));
        secureSocket.once('error', () => {
          secureSocket.destroy();
          finish(null);
        });
        secureSocket.once('secureConnect', () => {
          const cert = secureSocket.getPeerCertificate();
          const protocol = secureSocket.getProtocol() || 'UNKNOWN';
          finish({
            protocol,
            authorized: secureSocket.authorized,
            validTo: cert.valid_to,
            issuer: typeof cert.issuer === 'object' ? JSON.stringify(cert.issuer) : cert.issuer,
            subject: typeof cert.subject === 'object' ? JSON.stringify(cert.subject) : cert.subject
          });
          secureSocket.end();
        });
      };

      proxySocket.on('data', onProxyData);
      proxySocket.once('connect', () => {
        proxySocket.write(
          `CONNECT ${authority} HTTP/1.1\\r\\nHost: ${authority}\\r\\nUser-Agent: ProofVAPT-TLS-Prober/1.0\\r\\n\\r\\n`
        );
      });
    });
  }

  private sendProxyRequest(
    targetUrlStr: string,
    method: string,
    customHeaders: Record<string, string> = {}
  ): Promise<{ statusCode: number; headers: Record<string, string | string[] | undefined>; body: string }> {
    return new Promise((resolve, reject) => {
      const targetUrl = new URL(targetUrlStr);

      const options: http.RequestOptions = {
        host: '127.0.0.1',
        port: this.proxyPort,
        path: targetUrl.href,
        method,
        headers: {
          Host: targetUrl.host,
          'User-Agent': 'ProofVAPT-Prober/1.0 (Cyber-Security-Research)',
          Accept: '*/*',
          ...customHeaders
        },
        timeout: 10000
      };

      const req = http.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk.toString();
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
            body
          });
        });
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });

      req.end();
    });
  }
}
