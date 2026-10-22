import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import net from 'node:net';
import { db } from './db.js';
import { ScopeEnforcingEgressProxy } from './egressProxy.js';
import { VerificationAttempt, UnifiedFinding, TargetProfile } from '../src/types/proofvapt.js';

type ProbeResponse = {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
};

function bareHostname(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

export class RemediationVerificationEngine {
  /**
   * Re-tests a saved finding only inside the original scan's host/port scope.
   * DNS is resolved, checked, then pinned for the request.
   */
  public static async executeRetest(
    findingId: string,
    simulatedFixApplied = false
  ): Promise<{ finding: UnifiedFinding; attempt: VerificationAttempt }> {
    const finding = db.getFinding(findingId);
    if (!finding) throw new Error('Finding not found.');

    const scan = db.getScan(finding.scan_id);
    const target = scan?.target;
    if (!target) throw new Error('Finding has no saved target scope.');

    let url: URL;
    try {
      url = new URL(finding.affected_url);
    } catch {
      throw new Error('Finding URL is invalid and cannot be retested.');
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('Only HTTP and HTTPS findings can be retested.');
    }
    if (bareHostname(url.hostname) !== bareHostname(target.hostname)) {
      throw new Error('Retest blocked: finding host is outside the original scan scope.');
    }

    const port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
    if (!Array.isArray(target.allowed_ports) || !target.allowed_ports.includes(port)) {
      throw new Error('Retest blocked: finding port is outside the original scan scope.');
    }
    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(url.pathname);
    } catch {
      throw new Error('Retest blocked: malformed path encoding.');
    }
    if ((target.excluded_paths || []).some((excluded) =>
      decodedPath === excluded || decodedPath.startsWith(excluded.endsWith('/') ? excluded : excluded + '/')
    )) {
      throw new Error('Retest blocked: finding path is excluded from the authorized assessment.');
    }
    if (simulatedFixApplied && (process.env.NODE_ENV === 'production' || target.mode !== 'lab')) {
      throw new Error('Simulated remediation is available only for non-production lab assessments.');
    }

    let outcome: VerificationAttempt['outcome'] = 'inconclusive';
    let retestEvidence = '';

    try {
      if (simulatedFixApplied) {
        outcome = 'inconclusive';
        retestEvidence = 'Simulation recorded for a non-production lab assessment. No network request was made and remediation is not marked verified.';
      } else {
        const requestHeaders: Record<string, string> = {
          'User-Agent': 'ProofVAPT-Verifier/1.0',
          Accept: '*/*'
        };
        if (finding.test_id === 'PV-A02-002') {
          requestHeaders.Origin = 'https://proofvapt-untrusted.invalid';
        }
        const response = await this.probeUrl(url, target, requestHeaders);

        if (finding.test_id === 'PV-A02-001') {
          const hasHsts = url.protocol !== 'https:' || !!response.headers['strict-transport-security'];
          const hasCsp = !!response.headers['content-security-policy'];
          const hasXfo = !!response.headers['x-frame-options'];
          const hasNosniff = response.headers['x-content-type-options'] === 'nosniff';
          if (hasHsts && hasCsp && hasXfo && hasNosniff) {
            outcome = 'remediated';
            retestEvidence = 'HSTS (when applicable), CSP, X-Frame-Options, and X-Content-Type-Options were present on the retest response.';
          } else {
            outcome = 'still_vulnerable';
            retestEvidence = `Security header baseline remains incomplete. HSTS=${hasHsts}, CSP=${hasCsp}, XFO=${hasXfo}, nosniff=${hasNosniff}.`;
          }
        } else if (finding.test_id === 'PV-A02-004') {
          outcome = 'inconclusive';
          retestEvidence = `Route returned HTTP ${response.statusCode} with ${response.body.length} response bytes. An access-denied or not-found status is encouraging but cannot by itself prove remediation; confirm the intended resource and exposure manually.`;
        } else if (finding.test_id === 'PV-A02-002') {
          const allowOrigin = response.headers['access-control-allow-origin'];
          const allowCredentials = String(response.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
          const reflectsUntrustedOrigin = allowOrigin === 'https://proofvapt-untrusted.invalid';
          if (reflectsUntrustedOrigin && allowCredentials) {
            outcome = 'still_vulnerable';
            retestEvidence = `The target reflects an untrusted Origin and enables credentials. Access-Control-Allow-Origin=${String(allowOrigin)}; credentials=true.`;
          } else if (!allowOrigin) {
            outcome = 'remediated';
            retestEvidence = 'The response did not return an Access-Control-Allow-Origin value for the probe.';
          } else {
            outcome = 'inconclusive';
            retestEvidence = `CORS response observed (Access-Control-Allow-Origin=${String(allowOrigin)}, credentials=${allowCredentials}). Wildcard or reflected origin alone is not sufficient to confirm impact on sensitive data; manually verify the resource and browser credential behavior.`;
          }
        } else {
          outcome = 'inconclusive';
          retestEvidence = `Received HTTP ${response.statusCode}. Endpoint reachability alone does not prove or disprove this finding; a test-specific reproduction is required.`;
        }
      }
    } catch (err) {
      outcome = 'inconclusive';
      retestEvidence = `Retest did not complete: ${err instanceof Error ? err.message : 'network or validation error'}`;
    }

    const timestamp = new Date().toISOString();
    if (outcome === 'remediated') {
      finding.remediation_status = 'remediated_verified';
      finding.verification_status = 'not_reproduced';
      finding.verification_notes = `${finding.verification_notes} [Retest ${timestamp}: condition not reproduced]`.trim();
    } else if (outcome === 'still_vulnerable') {
      finding.remediation_status = 'reopened';
      finding.verification_status = 'verified';
      finding.verification_notes = `${finding.verification_notes} [Retest ${timestamp}: condition persists]`.trim();
    } else {
      finding.remediation_status = 'pending_retest';
      finding.verification_status = 'manual_review_required';
      finding.verification_notes = `${finding.verification_notes} [Retest ${timestamp}: inconclusive; manual review required]`.trim();
    }

    db.saveFinding(finding);

    const attempt: VerificationAttempt = {
      id: `va-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      finding_id: findingId,
      timestamp,
      retest_type: finding.test_id === 'PV-A02-001' ? 'check_header' : 'probe_endpoint',
      outcome,
      retest_evidence: retestEvidence
    };
    db.saveVerificationAttempt(attempt);

    return { finding, attempt };
  }

  private static async probeUrl(
    url: URL,
    target: TargetProfile,
    headers: Record<string, string>
  ): Promise<ProbeResponse> {
    const hostname = bareHostname(url.hostname);
    const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
    if (addresses.length === 0) throw new Error('Target hostname did not resolve.');

    for (const address of addresses) {
      const restricted = ScopeEnforcingEgressProxy.isRestrictedIP(
        address.address,
        target.mode === 'lab' && target.is_isolated_lab_network_confirmed
      );
      if (restricted.restricted) {
        throw new Error(`Retest blocked by destination IP policy: ${restricted.reason || 'restricted IP'}.`);
      }
    }
    const pinnedAddress = addresses[0];

    return new Promise((resolve, reject) => {
      const client = url.protocol === 'https:' ? https : http;
      const options: any = {
        protocol: url.protocol,
        hostname,
        port: url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        headers,
        timeout: Math.min(Math.max(target.timeout_ms || 6000, 1000), 15000),
        lookup: (_hostname: string, _options: unknown, callback: (error: NodeJS.ErrnoException | null, address: string, family: number) => void) => {
          callback(null, pinnedAddress.address, pinnedAddress.family);
        }
      };
      if (url.protocol === 'https:' && net.isIP(hostname) === 0) options.servername = hostname;

      const request = client.request(options, (response) => {
        let body = '';
        let bytesRead = 0;
        const maxBodyBytes = 64 * 1024;
        response.on('data', (chunk: Buffer | string) => {
          if (bytesRead >= maxBodyBytes) return;
          const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          const remaining = maxBodyBytes - bytesRead;
          body += part.subarray(0, remaining).toString('utf8');
          bytesRead += Math.min(part.length, remaining);
          if (bytesRead >= maxBodyBytes) response.destroy();
        });
        response.on('end', () => resolve({ statusCode: response.statusCode || 0, headers: response.headers, body }));
        response.on('close', () => {
          if (bytesRead >= maxBodyBytes) resolve({ statusCode: response.statusCode || 0, headers: response.headers, body });
        });
        response.on('error', reject);
      });

      request.on('error', reject);
      request.setTimeout(options.timeout, () => request.destroy(new Error('Retest request timed out.')));
      request.end();
    });
  }
}
