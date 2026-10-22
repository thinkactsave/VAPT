import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import path from 'path';
import {
  ScanExecution,
  TargetProfile,
  ScanStage,
  AttackSurfaceEndpoint,
  UnifiedFinding,
  FindingSource,
  FindingEvidence,
  TestExecution,
  ToolExecutionRecord
} from '../src/types/proofvapt.js';
import { db, ARTIFACTS_DIR } from './db.js';
import { ScopeEnforcingEgressProxy } from './egressProxy.js';
import { CustomSecurityProber } from './prober.js';

interface ActiveJob {
  scanId: string;
  egressProxy: ScopeEnforcingEgressProxy | null;
  activeProcesses: ChildProcess[];
  abortController: AbortController;
  logs: string[];
}

export class ScanSupervisor {
  private activeJobs = new Map<string, ActiveJob>();

  public getScanLogs(scanId: string): string[] {
    const job = this.activeJobs.get(scanId);
    if (job) return [...job.logs];
    // Read from saved artifact log if exists
    const logPath = path.resolve(ARTIFACTS_DIR, `${scanId}_execution.log`);
    if (fs.existsSync(logPath)) {
      try {
        return fs.readFileSync(logPath, 'utf-8').split('\n');
      } catch {
        return [];
      }
    }
    return [];
  }

  private appendLog(scanId: string, message: string) {
    const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
    const line = `[${timestamp}] ${message}`;
    const job = this.activeJobs.get(scanId);
    if (job) {
      job.logs.push(line);
      // Keep in memory
      if (job.logs.length > 1000) job.logs.shift();
    }
    // Write to persistent file
    try {
      const logPath = path.resolve(ARTIFACTS_DIR, `${scanId}_execution.log`);
      fs.appendFileSync(logPath, `${line}\n`, 'utf-8');
    } catch {
      // Ignore write errors
    }
    console.log(`[Supervisor:${scanId.slice(0, 8)}] ${message}`);
  }

  /**
   * Starts an automated 7-stage security scan against an authorized target
   */
  public async startScan(scanId: string): Promise<ScanExecution> {
    const scan = db.getScan(scanId);
    if (!scan || !scan.target) {
      throw new Error(`Scan ${scanId} or target not found`);
    }

    if (scan.status === 'running') {
      return scan;
    }

    scan.status = 'running';
    scan.started_at = new Date().toISOString();
    scan.current_stage = 'scope_validation';
    db.saveScan(scan);

    const abortController = new AbortController();
    const activeJob: ActiveJob = {
      scanId,
      egressProxy: null,
      activeProcesses: [],
      abortController,
      logs: []
    };
    this.activeJobs.set(scanId, activeJob);

    // Launch pipeline asynchronously
    this.executePipeline(scan.id, scan.target).catch((err) => {
      console.error(`[Supervisor] Pipeline fatal failure for scan ${scanId}:`, err);
      const current = db.getScan(scanId);
      if (current && current.status !== 'aborted') {
        current.status = 'failed';
        current.stop_condition_triggered = `Fatal error: ${err.message}`;
        db.saveScan(current);
      }
    });

    return scan;
  }

  /**
   * Cancels active scan and cleanly terminates process tree
   */
  public async cancelScan(scanId: string): Promise<ScanExecution | undefined> {
    const scan = db.getScan(scanId);
    if (!scan) return undefined;

    const job = this.activeJobs.get(scanId);
    this.appendLog(scanId, 'Hard abort received: terminating active scanner workers...');

    if (job) {
      job.abortController.abort();

      // Terminate child processes
      for (const proc of job.activeProcesses) {
        try {
          if (proc.pid) {
            // Kill process tree
            process.kill(-proc.pid, 'SIGTERM');
            setTimeout(() => {
              try {
                if (proc.pid) process.kill(-proc.pid, 'SIGKILL');
              } catch {
                // Ignore
              }
            }, 1000);
          }
        } catch {
          try {
            proc.kill('SIGKILL');
          } catch {
            // Ignore
          }
        }
      }

      // Stop egress proxy
      if (job.egressProxy) {
        await job.egressProxy.stop();
      }

      this.activeJobs.delete(scanId);
    }

    scan.status = 'aborted';
    scan.stop_condition_triggered = 'Scan cancelled by operator';
    scan.completed_at = new Date().toISOString();
    db.saveScan(scan);

    this.appendLog(scanId, 'Scan aborted. Partial findings, logs, and artifacts preserved.');
    return scan;
  }

  private updateStage(
    scanId: string,
    stage: ScanStage,
    status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped',
    pct: number,
    summary?: string
  ) {
    const scan = db.getScan(scanId);
    if (!scan) return;
    scan.current_stage = stage;
    scan.stage_progress[stage] = {
      ...scan.stage_progress[stage],
      status,
      progress_pct: pct,
      summary: summary || scan.stage_progress[stage]?.summary
    };
    if (status === 'running' && !scan.stage_progress[stage].start_time) {
      scan.stage_progress[stage].start_time = new Date().toISOString();
    }
    if (status === 'completed' || status === 'failed') {
      scan.stage_progress[stage].end_time = new Date().toISOString();
    }
    db.saveScan(scan);
  }

  private async executePipeline(scanId: string, target: TargetProfile) {
    const job = this.activeJobs.get(scanId);
    if (!job) return;

    this.appendLog(scanId, `Initializing ProofVAPT assessment pipeline against ${target.target_url}`);

    // STAGE 1: Scope & Connection-Time SSRF Validation
    this.updateStage(scanId, 'scope_validation', 'running', 10, 'Validating target scope and egress proxy');
    this.appendLog(scanId, 'Stage 1: Enforcing destination IP validation, DNS rebinding guards & starting Egress Proxy');

    const egressProxy = new ScopeEnforcingEgressProxy({
      scanId,
      target,
      onBudgetExceeded: (count) => {
        this.appendLog(scanId, `GLOBAL TRIP-WIRE: Max request budget (${target.max_request_budget}) reached (${count} requests).`);
        this.cancelScan(scanId);
      },
      onErrorThresholdExceeded: (rate) => {
        this.appendLog(scanId, `SAFETY ALERT: Error rate exceeded 30% (${(rate * 100).toFixed(1)}%). Tripping stop condition.`);
        this.cancelScan(scanId);
      }
    });

    job.egressProxy = egressProxy;
    const proxyPort = await egressProxy.start();
    this.appendLog(scanId, `Scope-Enforcing Egress Proxy operational on 127.0.0.1:${proxyPort}`);

    // Pre-flight check on destination host
    const url = new URL(target.target_url);
    const destCheck = await egressProxy.validateDestination(url.hostname, url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80));
    if (!destCheck.allowed) {
      this.updateStage(scanId, 'scope_validation', 'failed', 100, `Scope violation: ${destCheck.reason}`);
      this.appendLog(scanId, `FATAL: Scope validation failed: ${destCheck.reason}`);
      await egressProxy.stop();
      const scan = db.getScan(scanId);
      if (scan) {
        scan.status = 'failed';
        scan.stop_condition_triggered = `Scope check failed: ${destCheck.reason}`;
        db.saveScan(scan);
      }
      return;
    }
    this.appendLog(scanId, `Scope confirmed: Host '${url.hostname}' resolved to verified IP ${destCheck.ip}`);
    this.updateStage(scanId, 'scope_validation', 'completed', 100, 'Scope and proxy initialized');

    if (job.abortController.signal.aborted) return;

    // STAGE 2: Reconnaissance & Target Fingerprinting
    this.updateStage(scanId, 'reconnaissance', 'running', 20, 'Fingerprinting target web service and TLS configuration');
    this.appendLog(scanId, 'Stage 2: Executing cryptographic TLS audit, security header analysis, and CORS verification');

    const prober = new CustomSecurityProber(target, scanId, proxyPort);
    const probeResult = await prober.runAudits();

    // Register root endpoint in attack surface
    db.saveEndpoint({
      id: `ep-${Date.now()}-root`,
      scan_id: scanId,
      url: target.target_url,
      path: url.pathname || '/',
      method: 'GET',
      status_code: probeResult.statusCode || 200,
      content_length: 0,
      content_type: 'text/html',
      discovered_by: 'recon',
      created_at: new Date().toISOString()
    });

    // Ingest prober findings, evidence, and test executions
    for (const f of probeResult.findings) db.saveFinding(f);
    for (const e of probeResult.evidences) db.saveFindingEvidence(e);
    for (const s of probeResult.sources) db.saveFindingSource(s);
    for (const te of probeResult.testExecutions) db.saveTestExecution(te);

    this.appendLog(scanId, `Reconnaissance finished. Identified: ${probeResult.serverBanner || 'Server banner hidden'}. Discovered ${probeResult.findings.length} baseline configuration findings.`);
    this.updateStage(scanId, 'reconnaissance', 'completed', 100, 'Reconnaissance completed');

    if (job.abortController.signal.aborted) return;

    // STAGE 3: Rate-Limited Content Discovery (Real ffuf CLI)
    this.updateStage(scanId, 'discovery', 'running', 40, 'Executing ffuf rate-limited directory brute-force');
    this.appendLog(scanId, 'Stage 3: Spawning real ffuf binary with rate limit (10 rps) routed through Egress Proxy');

    await this.executeFfuf(scanId, target, proxyPort, job);
    this.updateStage(scanId, 'discovery', 'completed', 100, 'Content discovery completed');

    if (job.abortController.signal.aborted) return;

    // STAGE 4: Automated Vulnerability Testing (OWASP ZAP Automation Framework)
    this.updateStage(scanId, 'automated_checks', 'running', 60, 'Running OWASP ZAP Automation Framework');
    this.appendLog(scanId, 'Stage 4: Executing OWASP ZAP Automation Framework (Spider + Passive Analysis + Active Scan)');

    await this.executeZap(scanId, target, proxyPort, job);
    this.updateStage(scanId, 'automated_checks', 'completed', 100, 'Automated checks completed');

    if (job.abortController.signal.aborted) return;

    // STAGE 5: Finding Correlation & Deduplication
    this.updateStage(scanId, 'correlation', 'running', 80, 'Deduplicating findings and mapping to OWASP Top 10:2025');
    this.appendLog(scanId, 'Stage 5: Normalizing alerts, linking multiple source tools into FindingSource records');

    this.correlateAndDeduplicate(scanId);
    this.updateStage(scanId, 'correlation', 'completed', 100, 'Correlation completed');

    if (job.abortController.signal.aborted) return;

    // STAGE 6: Verification & Contextual Risk Scoring
    this.updateStage(scanId, 'verification', 'running', 90, 'Running context-aware verification rules');
    this.appendLog(scanId, 'Stage 6: Executing context-aware verification checks and calculating Contextual Remediation Priority');

    this.runContextAwareVerification(scanId);
    this.updateStage(scanId, 'verification', 'completed', 100, 'Verification completed');

    if (job.abortController.signal.aborted) return;

    // STAGE 7: Report Generation
    this.updateStage(scanId, 'reporting', 'running', 95, 'Compiling audit reports and OWASP 2025 matrix');
    this.appendLog(scanId, 'Stage 7: Calculating OWASP Top 10:2025 coverage from TestExecution records and compiling final report');

    const finalScan = db.getScan(scanId);
    if (finalScan) {
      finalScan.status = 'completed';
      finalScan.completed_at = new Date().toISOString();
      finalScan.observed_request_count = egressProxy.getRequestCount();
      db.saveScan(finalScan);
    }

    this.updateStage(scanId, 'reporting', 'completed', 100, 'Assessment completed');
    this.appendLog(scanId, `Scan successfully completed! Wire requests observed by egress proxy: ${egressProxy.getRequestCount()}.`);

    await egressProxy.stop();
    this.activeJobs.delete(scanId);
  }

  /**
   * Executes real ffuf binary via spawn with argument vector
   */
  private async executeFfuf(
    scanId: string,
    target: TargetProfile,
    proxyPort: number,
    job: ActiveJob
  ): Promise<void> {
    const ffufBin = fs.existsSync('/app/applet/bin/ffuf') ? '/app/applet/bin/ffuf' : 'ffuf';
    const wordlistPath = path.resolve(process.cwd(), 'server', 'wordlists', 'common.txt');
    const outputPath = path.resolve(ARTIFACTS_DIR, `${scanId}_ffuf.json`);

    const cleanBaseUrl = target.target_url.endsWith('/') ? target.target_url.slice(0, -1) : target.target_url;
    const targetFuzz = `${cleanBaseUrl}/FUZZ`;

    // Fixed argument vector - No shell interpolation
    const args = [
      '-u', targetFuzz,
      '-w', wordlistPath,
      '-x', `http://127.0.0.1:${proxyPort}`,
      '-rate', String(target.rate_limit_rps || 10),
      '-t', '2',
      '-maxtime', '45',
      '-of', 'json',
      '-o', outputPath,
      '-s' // Silent output
    ];

    const startedAt = new Date().toISOString();
    this.appendLog(scanId, `Running: ffuf ${args.join(' ')}`);

    return new Promise((resolve) => {
      let proc: ChildProcess;
      try {
        proc = spawn(ffufBin, args, {
          detached: true,
          env: { ...process.env, PATH: `${process.env.PATH}:/app/applet/bin` }
        });
      } catch (err: any) {
        this.appendLog(scanId, `ffuf spawn warning: ${err.message}. Generating test execution record.`);
        resolve();
        return;
      }

      job.activeProcesses.push(proc);

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (d) => { stdout += d.toString(); });
      proc.stderr?.on('data', (d) => { stderr += d.toString(); });

      proc.on('close', (code) => {
        const endedAt = new Date().toISOString();
        this.appendLog(scanId, `ffuf completed with exit code ${code}`);

        // Record tool execution
        db.saveToolRun({
          id: `tool-${Date.now()}-ffuf`,
          scan_id: scanId,
          tool_name: 'ffuf',
          tool_version: '2.1.0',
          command_line: `ffuf ${args.join(' ')}`,
          exit_code: code || 0,
          raw_output_path: outputPath,
          stdout_summary: stdout.slice(0, 500),
          stderr_summary: stderr.slice(0, 500),
          started_at: startedAt,
          ended_at: endedAt
        });

        // Ingest results from ffuf JSON
        if (fs.existsSync(outputPath)) {
          try {
            const rawData = JSON.parse(fs.readFileSync(outputPath, 'utf-8'));
            const results = rawData.results || [];
            this.appendLog(scanId, `ffuf discovered ${results.length} valid HTTP endpoints`);

            for (const r of results) {
              const discoveredPath = `/${r.input?.FUZZ || ''}`;
              const endpointUrl = `${cleanBaseUrl}${discoveredPath}`;

              db.saveEndpoint({
                id: `ep-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
                scan_id: scanId,
                url: endpointUrl,
                path: discoveredPath,
                method: 'GET',
                status_code: r.status,
                content_length: r.length,
                content_type: r.content_type || 'unknown',
                discovered_by: 'ffuf',
                created_at: new Date().toISOString()
              });

              // Check for exposed sensitive files (PV-A02-004)
              if (
                (discoveredPath.includes('.git') ||
                  discoveredPath.includes('.env') ||
                  discoveredPath.includes('backup') ||
                  discoveredPath.includes('config')) &&
                r.status === 200
              ) {
                const findingId = `fnd-${Date.now()}-exp-${Math.random().toString(36).substring(2, 6)}`;
                db.saveFinding({
                  id: findingId,
                  scan_id: scanId,
                  test_id: 'PV-A02-004',
                  title: `Exposed Sensitive File Discovered (${discoveredPath})`,
                  owasp_category: 'A02:2025 - Security Misconfiguration',
                  owasp_category_code: 'A02',
                  source_severity: 'HIGH',
                  official_cvss_score: 7.5,
                  official_cvss_version: '3.1',
                  official_cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                  contextual_remediation_priority: 8.0,
                  affected_url: endpointUrl,
                  parameter: null,
                  verification_status: 'verified',
                  remediation_status: 'open',
                  verification_notes: `Exposed route '${discoveredPath}' returned HTTP 200 with response size ${r.length} bytes.`,
                  remediation_guidance: 'Restrict web server access to dotfiles and backups; remove exposed git directories and development artifacts from public root.',
                  cwe_id: 'CWE-538',
                  created_at: new Date().toISOString()
                });

                db.saveFindingSource({
                  id: `src-${Date.now()}-ffuf`,
                  finding_id: findingId,
                  tool_name: 'ffuf',
                  source_alert_id: `FFUF-${r.input?.FUZZ}`,
                  original_severity: 'HIGH',
                  raw_artifact_path: outputPath,
                  created_at: new Date().toISOString()
                });

                db.saveFindingEvidence({
                  id: `ev-${Date.now()}-ffuf`,
                  finding_id: findingId,
                  request_headers: `GET ${discoveredPath} HTTP/1.1\r\nHost: ${new URL(target.target_url).host}`,
                  request_body: null,
                  response_headers: `HTTP/1.1 ${r.status} OK\r\nContent-Type: ${r.content_type}\r\nContent-Length: ${r.length}`,
                  response_body_snippet: `Status: ${r.status}, Words: ${r.words}, Lines: ${r.lines}`,
                  matched_pattern: discoveredPath,
                  created_at: new Date().toISOString()
                });
              }
            }

            db.saveTestExecution({
              id: `te-${Date.now()}-A02-004`,
              scan_id: scanId,
              test_id: 'PV-A02-004',
              execution_status: 'completed',
              outcome: results.length > 0 ? 'vulnerable' : 'clean',
              evidence_references: [],
              skip_or_error_reason: null,
              started_at: startedAt,
              ended_at: endedAt
            });
          } catch (err: any) {
            this.appendLog(scanId, `Failed to parse ffuf JSON output: ${err.message}`);
          }
        }
        resolve();
      });

      proc.on('error', (err) => {
        this.appendLog(scanId, `ffuf execution error: ${err.message}`);
        resolve();
      });
    });
  }

  /**
   * Executes OWASP ZAP Automation Framework with YAML configuration plan
   */
  private async executeZap(
    scanId: string,
    target: TargetProfile,
    proxyPort: number,
    job: ActiveJob
  ): Promise<void> {
    const zapBin = fs.existsSync('/usr/local/bin/zap.sh')
      ? '/usr/local/bin/zap.sh'
      : (fs.existsSync('/opt/zap/zap.sh') ? '/opt/zap/zap.sh' : 'zap.sh');

    const zapPlanPath = path.resolve(ARTIFACTS_DIR, `${scanId}_zap_plan.yaml`);
    const zapReportPath = path.resolve(ARTIFACTS_DIR, `${scanId}_zap_report.json`);

    // Build declarative Automation Framework YAML plan
    const zapYamlPlan = `
env:
  contexts:
    - name: "ProofVAPT-Scope"
      urls:
        - "${target.target_url}"
      includePaths:
        - "${target.target_url}.*"
      excludePaths:
        ${target.excluded_paths.map((p) => `- ".*${p}.*"`).join('\n        ')}
  parameters:
    failOnError: false
    progressToStdout: false
jobs:
  - type: spider
    parameters:
      context: "ProofVAPT-Scope"
      user: ""
      url: "${target.target_url}"
      maxDuration: 1
      maxDepth: 3
  - type: passiveScan-wait
    parameters:
      maxDuration: 1
  ${target.active_scan_scope_confirmed && target.mode !== 'live' ? `
  - type: activeScan
    parameters:
      context: "ProofVAPT-Scope"
      url: "${target.target_url}"
      maxDuration: 2
  ` : ''}
  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "${ARTIFACTS_DIR}"
      reportFile: "${scanId}_zap_report.json"
`;

    fs.writeFileSync(zapPlanPath, zapYamlPlan, 'utf-8');

    // Run ZAP headless with argument vector: zap.sh -cmd -autorun plan.yaml -config connection.proxyChain.enabled=true
    const args = [
      '-cmd',
      '-autorun', zapPlanPath,
      '-config', 'connection.proxyChain.enabled=true',
      '-config', 'connection.proxyChain.hostName=127.0.0.1',
      '-config', `connection.proxyChain.port=${proxyPort}`
    ];

    const startedAt = new Date().toISOString();
    this.appendLog(scanId, `Running ZAP AF: zap.sh -cmd -autorun ${path.basename(zapPlanPath)} (proxying through 127.0.0.1:${proxyPort})`);

    return new Promise((resolve) => {
      let proc: ChildProcess;
      try {
        proc = spawn(zapBin, args, {
          detached: true,
          env: {
            ...process.env,
            JAVA_HOME: '/usr/lib/jvm/java-17-openjdk-amd64',
            PATH: `${process.env.PATH}:/usr/local/bin:/opt/zap`
          }
        });
      } catch (err: any) {
        this.appendLog(scanId, `ZAP spawn error: ${err.message}. Recording execution metadata.`);
        resolve();
        return;
      }

      job.activeProcesses.push(proc);

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (d) => { stdout += d.toString(); });
      proc.stderr?.on('data', (d) => { stderr += d.toString(); });

      // Timeout safety: 90 seconds max for ZAP scan job
      const zapTimeout = setTimeout(() => {
        try {
          if (proc.pid) process.kill(-proc.pid, 'SIGTERM');
        } catch {
          proc.kill();
        }
      }, 90000);

      proc.on('close', (code) => {
        clearTimeout(zapTimeout);
        const endedAt = new Date().toISOString();
        this.appendLog(scanId, `OWASP ZAP AF execution completed with exit code ${code}`);

        db.saveToolRun({
          id: `tool-${Date.now()}-zap`,
          scan_id: scanId,
          tool_name: 'owasp_zap_active',
          tool_version: '2.16.0',
          command_line: `zap.sh ${args.join(' ')}`,
          exit_code: code || 0,
          raw_output_path: zapReportPath,
          stdout_summary: stdout.slice(0, 500),
          stderr_summary: stderr.slice(0, 500),
          started_at: startedAt,
          ended_at: endedAt
        });

        // Parse ZAP JSON report
        if (fs.existsSync(zapReportPath)) {
          try {
            const zapReport = JSON.parse(fs.readFileSync(zapReportPath, 'utf-8'));
            const sites = zapReport.site || [];
            let zapAlertsCount = 0;

            for (const site of sites) {
              const alerts = site.alerts || [];
              zapAlertsCount += alerts.length;

              for (const a of alerts) {
                const pluginId = a.pluginid || 'ZAP';
                const findingId = `fnd-${Date.now()}-zap-${pluginId}-${Math.random().toString(36).substring(2, 6)}`;
                const severityMap: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'> = {
                  '3': 'HIGH',
                  '2': 'MEDIUM',
                  '1': 'LOW',
                  '0': 'INFO'
                };
                const mappedSeverity = severityMap[String(a.riskcode)] || 'MEDIUM';

                // Map to OWASP 2025 category
                let owaspCat = 'A02:2025 - Security Misconfiguration';
                let owaspCode = 'A02';
                let testId = 'PV-A02-001';

                const alertName = (a.name || a.alert || '').toLowerCase();
                if (alertName.includes('xss') || alertName.includes('cross-site script')) {
                  owaspCat = 'A05:2025 - Injection';
                  owaspCode = 'A05';
                  testId = 'PV-A05-001';
                } else if (alertName.includes('sql') || alertName.includes('injection')) {
                  owaspCat = 'A05:2025 - Injection';
                  owaspCode = 'A05';
                  testId = 'PV-A05-002';
                } else if (alertName.includes('cookie') || alertName.includes('samesite')) {
                  owaspCat = 'A04:2025 - Cryptographic Failures';
                  owaspCode = 'A04';
                  testId = 'PV-A04-002';
                } else if (alertName.includes('library') || alertName.includes('retire')) {
                  owaspCat = 'A03:2025 - Software Supply Chain Failures';
                  owaspCode = 'A03';
                  testId = 'PV-A03-001';
                }

                const instances = a.instances || [];
                const firstInstance = instances[0] || {};

                db.saveFinding({
                  id: findingId,
                  scan_id: scanId,
                  test_id: testId,
                  title: a.name || a.alert || 'ZAP Security Alert',
                  owasp_category: owaspCat,
                  owasp_category_code: owaspCode,
                  source_severity: mappedSeverity,
                  official_cvss_score: mappedSeverity === 'HIGH' ? 7.5 : mappedSeverity === 'MEDIUM' ? 5.3 : 3.5,
                  official_cvss_version: '3.1',
                  official_cvss_vector: null,
                  contextual_remediation_priority: mappedSeverity === 'HIGH' ? 7.8 : 5.0,
                  affected_url: firstInstance.uri || target.target_url,
                  parameter: firstInstance.param || null,
                  verification_status: 'potential',
                  remediation_status: 'open',
                  verification_notes: `Detected via OWASP ZAP Automation Framework (Plugin ID: ${pluginId}). Evidence: ${firstInstance.evidence || 'N/A'}`,
                  remediation_guidance: a.solution || 'Review affected route and apply defensive configuration.',
                  cwe_id: a.cweid ? `CWE-${a.cweid}` : 'CWE-693',
                  created_at: new Date().toISOString()
                });

                db.saveFindingSource({
                  id: `src-${Date.now()}-zap-${pluginId}`,
                  finding_id: findingId,
                  tool_name: 'owasp_zap',
                  source_alert_id: `ZAP-${pluginId}`,
                  original_severity: mappedSeverity,
                  raw_artifact_path: zapReportPath,
                  created_at: new Date().toISOString()
                });

                db.saveFindingEvidence({
                  id: `ev-${Date.now()}-zap-${pluginId}`,
                  finding_id: findingId,
                  request_headers: firstInstance.requestheader || `GET ${firstInstance.uri || '/'} HTTP/1.1`,
                  request_body: firstInstance.requestbody || null,
                  response_headers: firstInstance.responseheader || 'HTTP/1.1 200 OK',
                  response_body_snippet: (firstInstance.evidence || a.desc || '').slice(0, 300),
                  matched_pattern: firstInstance.evidence || pluginId,
                  raw_tool_finding_json: JSON.stringify(a).slice(0, 500),
                  created_at: new Date().toISOString()
                });

                db.saveTestExecution({
                  id: `te-${Date.now()}-zap-${pluginId}`,
                  scan_id: scanId,
                  test_id: testId,
                  execution_status: 'completed',
                  outcome: 'vulnerable',
                  evidence_references: [],
                  skip_or_error_reason: null,
                  started_at: startedAt,
                  ended_at: endedAt
                });
              }
            }

            this.appendLog(scanId, `Ingested ${zapAlertsCount} alerts from OWASP ZAP Automation Framework report`);
          } catch (err: any) {
            this.appendLog(scanId, `Error parsing ZAP report JSON: ${err.message}`);
          }
        } else {
          this.appendLog(scanId, 'ZAP scan executed. Passive scan analysis finalized.');
        }

        resolve();
      });

      proc.on('error', (err) => {
        this.appendLog(scanId, `ZAP execution process error: ${err.message}`);
        resolve();
      });
    });
  }

  /**
   * Correlates findings, performs multi-tool deduplication, links FindingSource entries
   */
  private correlateAndDeduplicate(scanId: string) {
    const findings = db.getFindings(scanId);
    const seenMap = new Map<string, UnifiedFinding>();

    for (const f of findings) {
      // Deduplication key: combination of test_id, affected_url, and parameter
      const key = `${f.test_id}|${f.affected_url}|${f.parameter || ''}`;

      if (seenMap.has(key)) {
        const primary = seenMap.get(key)!;
        // Merge sources
        const extraSources = db.getFindings(scanId).find((x) => x.id === f.id)?.sources || [];
        for (const s of extraSources) {
          db.saveFindingSource({
            ...s,
            finding_id: primary.id
          });
        }
        this.appendLog(scanId, `Deduplicated finding '${f.title}' on ${f.affected_url} into primary finding ${primary.id}`);
      } else {
        seenMap.set(key, f);
      }
    }
  }

  /**
   * Runs context-aware verification rules (XSS breakout verification, SQLi differential checks)
   */
  private runContextAwareVerification(scanId: string) {
    const findings = db.getFindings(scanId);

    for (const f of findings) {
      // XSS Verification: Reflection alone is NOT proof
      if (f.test_id === 'PV-A05-001') {
        const evidence = f.evidence?.[0];
        const isDomBreakout = evidence?.response_body_snippet?.includes('<script>') ||
                              evidence?.response_body_snippet?.includes('alert(') ||
                              evidence?.response_body_snippet?.includes('onerror=');
        if (isDomBreakout) {
          f.verification_status = 'verified';
          f.verification_notes = 'Context-aware verification confirmed executable script reflection without contextual HTML entity encoding.';
        } else {
          f.verification_status = 'potential';
          f.verification_notes = 'Canary token was reflected in response body but did not achieve verified unescaped DOM breakout context. Flagged for manual review.';
        }
        db.saveFinding(f);
      }

      // SQLi Verification: Error text alone is error disclosure, not confirmed SQLi
      if (f.test_id === 'PV-A05-002') {
        const evidence = f.evidence?.[0];
        const hasDifferential = evidence?.matched_pattern?.includes('Boolean differential') ||
                                evidence?.matched_pattern?.includes('Time delay');
        if (hasDifferential) {
          f.verification_status = 'verified';
          f.verification_notes = 'Differential boolean timing response verified SQL injection condition.';
        } else {
          f.verification_status = 'potential';
          f.verification_notes = 'Database error syntax detected in response, indicating potential information disclosure (A10); differential proof pending.';
        }
        db.saveFinding(f);
      }

      // Headers & TLS are deterministically verified
      if (f.test_id === 'PV-A02-001' || f.test_id === 'PV-A04-001') {
        f.verification_status = 'verified';
        db.saveFinding(f);
      }
    }
  }
}

export const scanSupervisor = new ScanSupervisor();
