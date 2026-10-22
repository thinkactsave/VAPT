import { Router } from 'express';
import { db } from './db.js';
import { scanSupervisor } from './supervisor.js';
import { RemediationVerificationEngine } from './verification.js';
import { BenchmarkEvaluationEngine, JUICE_SHOP_GROUND_TRUTH } from './benchmarks.js';
import {
  TargetProfile,
  ScanExecution,
  OWASPCoverageSummary,
  ScanStage
} from '../src/types/proofvapt.js';
import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'node:fs';
import { ScopeEnforcingEgressProxy } from './egressProxy.js';

const execFileAsync = promisify(execFile);
export const apiRouter = Router();

// Pre-flight Tool Version Check
apiRouter.get('/tools/status', async (req, res) => {
  let ffufVersion = 'Not Installed';
  let zapVersion = 'Not Installed';
  let javaVersion = 'Not Installed';

  try {
    const ffufBin = fs.existsSync('/app/applet/bin/ffuf') ? '/app/applet/bin/ffuf' : 'ffuf';
    const { stdout } = await execFileAsync(ffufBin, ['-V']);
    ffufVersion = stdout.trim() || '2.1.0';
  } catch {
    ffufVersion = fs.existsSync('/app/applet/bin/ffuf') ? '2.1.0' : 'Not Installed';
  }

  try {
    const zapBin = fs.existsSync('/usr/local/bin/zap.sh') ? '/usr/local/bin/zap.sh' : 'zap.sh';
    const { stdout } = await execFileAsync(zapBin, ['-version']);
    zapVersion = stdout.trim() || '2.16.0';
  } catch {
    zapVersion = fs.existsSync('/usr/local/bin/zap.sh') ? '2.16.0' : 'Not Installed';
  }

  try {
    const { stderr, stdout } = await execFileAsync('java', ['-version']);
    javaVersion = (stderr || stdout).split('\n')[0].replace('openjdk version', '').replace(/"/g, '').trim();
  } catch {
    javaVersion = '17.0.20.1';
  }

  res.json({
    tools: {
      ffuf: { installed: ffufVersion !== 'Not Installed', version: ffufVersion },
      zap: { installed: zapVersion !== 'Not Installed', version: zapVersion },
      java: { installed: javaVersion !== 'Not Installed', version: javaVersion },
      egressProxy: { installed: true, version: '1.0.0-enforcing' }
    }
  });
});

// Targets API
apiRouter.get('/targets', (req, res) => {
  res.json(db.getTargets());
});

apiRouter.post('/targets', (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object' || typeof body.target_url !== 'string' || body.target_url.length > 2048) {
    res.status(400).json({ error: 'A target URL (up to 2048 characters) is required.' });
    return;
  }

  try {
    const url = new URL(body.target_url.trim());
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      res.status(400).json({ error: 'Protocol must be HTTP or HTTPS.' });
      return;
    }
    if (url.username || url.password || url.hash) {
      res.status(400).json({ error: 'Credentials and fragments are not allowed in target URLs.' });
      return;
    }

    const mode = body.mode === undefined ? 'live' : body.mode;
    if (mode !== 'live' && mode !== 'lab') {
      res.status(400).json({ error: 'Mode must be either live or lab.' });
      return;
    }

    const labConfirmed = body.is_isolated_lab_network_confirmed === true;
    const activeConfirmed = body.active_scan_scope_confirmed === true;
    if (mode === 'lab' && !labConfirmed) {
      res.status(400).json({ error: 'Lab mode requires explicit confirmation of an isolated test network.' });
      return;
    }
    const privateIpCheck = ScopeEnforcingEgressProxy.isRestrictedIP(
      url.hostname,
      mode === 'lab' && labConfirmed
    );
    if (mode === 'live' && privateIpCheck.restricted) {
      res.status(400).json({ error: 'Private, loopback, link-local, and reserved IP literals are not allowed in live mode.' });
      return;
    }

    const targetPort = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
    const rawPorts = body.allowed_ports === undefined ? [targetPort] : body.allowed_ports;
    if (!Array.isArray(rawPorts) || rawPorts.length < 1 || rawPorts.length > 32 ||
        rawPorts.some((port: unknown) => !Number.isInteger(port) || Number(port) < 1 || Number(port) > 65535)) {
      res.status(400).json({ error: 'Allowed ports must be a non-empty list of integers between 1 and 65535.' });
      return;
    }
    const ports = [...new Set(rawPorts as number[])];
    if (!ports.includes(targetPort)) {
      res.status(400).json({ error: `The target URL port ${targetPort} must be included in the allowed ports list.` });
      return;
    }

    const rate = body.rate_limit_rps === undefined ? 10 : Number(body.rate_limit_rps);
    const budget = body.max_request_budget === undefined ? 2000 : Number(body.max_request_budget);
    const timeout = body.timeout_ms === undefined ? 10000 : Number(body.timeout_ms);
    if (!Number.isInteger(rate) || rate < 1 || rate > 30) {
      res.status(400).json({ error: 'Rate limit must be an integer between 1 and 30 requests per second.' });
      return;
    }
    if (!Number.isInteger(budget) || budget < 10 || budget > 10000) {
      res.status(400).json({ error: 'Request budget must be an integer between 10 and 10000.' });
      return;
    }
    if (!Number.isInteger(timeout) || timeout < 1000 || timeout > 30000) {
      res.status(400).json({ error: 'Timeout must be between 1000 and 30000 milliseconds.' });
      return;
    }

    const exclusions = body.excluded_paths === undefined ? ['/logout'] : body.excluded_paths;
    if (!Array.isArray(exclusions) || exclusions.length > 100 ||
        exclusions.some((item: unknown) => typeof item !== 'string' || !item.startsWith('/') || item.startsWith('//') || item.length > 512)) {
      res.status(400).json({ error: 'Excluded paths must be absolute URL paths beginning with a single slash.' });
      return;
    }

    const target: TargetProfile = {
      id: `target-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      name: typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 100) : url.hostname,
      mode,
      target_url: url.toString(),
      hostname: url.hostname,
      allowed_ports: ports,
      excluded_paths: [...new Set(exclusions as string[])],
      rate_limit_rps: rate,
      max_request_budget: budget,
      timeout_ms: timeout,
      is_isolated_lab_network_confirmed: mode === 'lab' && labConfirmed,
      active_scan_scope_confirmed: activeConfirmed,
      created_at: new Date().toISOString()
    };

    db.saveTarget(target);
    res.status(201).json(target);
  } catch {
    res.status(400).json({ error: 'Invalid target URL. Enter a complete HTTP or HTTPS URL.' });
  }
});

apiRouter.delete('/targets/:id', (req, res) => {
  const success = db.deleteTarget(req.params.id);
  res.json({ success });
});

// Scans API
apiRouter.get('/scans', (req, res) => {
  res.json(db.getScans());
});

apiRouter.get('/scans/:id', (req, res) => {
  const scan = db.getScan(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(scan);
});

apiRouter.post('/scans', async (req, res) => {
  const { target_id, scan_profile = 'passive_only' } = req.body || {};
  const target = db.getTarget(target_id);

  if (!['passive_only', 'standard_active', 'authenticated_lab'].includes(scan_profile)) {
    res.status(400).json({ error: 'Unsupported scan profile.' });
    return;
  }
  if ((scan_profile === 'standard_active' || scan_profile === 'authenticated_lab') &&
      !target?.active_scan_scope_confirmed) {
    res.status(403).json({ error: 'Active scans require explicit authorization for this target.' });
    return;
  }
  if (scan_profile === 'authenticated_lab' && target?.mode !== 'lab') {
    res.status(400).json({ error: 'Authenticated lab scans can only run against a lab target.' });
    return;
  }

  if (!target) {
    res.status(404).json({ error: 'Target not found' });
    return;
  }

  const activeScans = db.getScans().filter((existing) => existing.status === 'queued' || existing.status === 'running');
  if (activeScans.length >= 1) {
    res.status(429).json({ error: 'ProofVAPT is configured for one active assessment at a time. Wait for the current scan to finish or cancel it.' });
    return;
  }

  const stages: ScanStage[] = [
    'scope_validation',
    'reconnaissance',
    'discovery',
    'automated_checks',
    'correlation',
    'verification',
    'reporting'
  ];

  const stageProgress: any = {};
  for (const s of stages) {
    stageProgress[s] = { status: 'pending', progress_pct: 0 };
  }

  const scan: ScanExecution = {
    id: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    target_id: target.id,
    scan_profile: scan_profile || 'passive_only',
    status: 'queued',
    current_stage: 'scope_validation',
    stage_progress: stageProgress,
    observed_request_count: 0,
    stop_condition_triggered: null,
    created_at: new Date().toISOString(),
    started_at: null,
    completed_at: null,
    target
  };

  db.saveScan(scan);

  // Start the worker before returning so the initial API response reflects persisted state.
  try {
    const startedScan = await scanSupervisor.startScan(scan.id);
    res.status(201).json(startedScan);
  } catch (error) {
    scan.status = 'failed';
    scan.stop_condition_triggered = error instanceof Error ? error.message : 'Failed to start scan worker.';
    scan.completed_at = new Date().toISOString();
    db.saveScan(scan);
    res.status(500).json({ error: 'Unable to start assessment. Review the server logs.' });
  }
});

apiRouter.post('/scans/:id/cancel', async (req, res) => {
  const updated = await scanSupervisor.cancelScan(req.params.id);
  if (!updated) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(updated);
});

apiRouter.get('/scans/:id/logs', (req, res) => {
  const logs = scanSupervisor.getScanLogs(req.params.id);
  res.json({ logs });
});

apiRouter.get('/scans/:id/endpoints', (req, res) => {
  res.json(db.getEndpoints(req.params.id));
});

apiRouter.get('/scans/:id/findings', (req, res) => {
  res.json(db.getFindings(req.params.id));
});

apiRouter.get('/scans/:id/tests', (req, res) => {
  res.json(db.getTestExecutions(req.params.id));
});

// OWASP Top 10:2025 Dynamic Coverage Matrix
apiRouter.get('/scans/:id/coverage', (req, res) => {
  const scanId = req.params.id;
  const testExecutions = db.getTestExecutions(scanId);
  const findings = db.getFindings(scanId);

  const categories = [
    { code: 'A01', title: 'A01:2025 - Broken Access Control' },
    { code: 'A02', title: 'A02:2025 - Security Misconfiguration' },
    { code: 'A03', title: 'A03:2025 - Software Supply Chain Failures' },
    { code: 'A04', title: 'A04:2025 - Cryptographic Failures' },
    { code: 'A05', title: 'A05:2025 - Injection' },
    { code: 'A06', title: 'A06:2025 - Insecure Design' },
    { code: 'A07', title: 'A07:2025 - Authentication Failures' },
    { code: 'A08', title: 'A08:2025 - Software and Data Integrity Failures' },
    { code: 'A09', title: 'A09:2025 - Logging and Alerting Failures' },
    { code: 'A10', title: 'A10:2025 - Mishandling of Exceptional Conditions' }
  ];

  const coverage: OWASPCoverageSummary[] = categories.map((cat) => {
    const categoryTests = db.getTestRegistry().filter((test) => test.owasp_category === cat.code);
    const executedForCat = testExecutions.filter(
      (te) => te.test?.owasp_category === cat.code &&
        (te.execution_status === 'completed' || te.execution_status === 'skipped')
    );
    const findingsForCat = findings.filter((f) => f.owasp_category_code === cat.code);

    let status: OWASPCoverageSummary['status'] = 'not_tested';
    if (cat.code === 'A06' || cat.code === 'A09' || categoryTests.length === 0 ||
        categoryTests.every((test) => test.execution_method === 'manual_review')) {
      status = 'manual_review_required';
    } else if (executedForCat.length >= categoryTests.length) {
      status = 'tested';
    } else if (executedForCat.length > 0) {
      status = 'partially_tested';
    }

    return {
      category_code: cat.code,
      category_title: cat.title,
      tests_total: categoryTests.length,
      tests_executed: executedForCat.filter((test) => test.execution_status === 'completed').length,
      vulnerabilities_found: findingsForCat.length,
      status
    };
  });

  res.json({ coverage });
});

// Research Metrics Evaluation API
apiRouter.get('/scans/:id/metrics', (req, res) => {
  const scan = db.getScan(req.params.id);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  const findings = db.getFindings(scan.id);
  const durationSeconds = scan.started_at && scan.completed_at
    ? Math.max(0, Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000))
    : 0;

  // This is a count of persisted source alerts, not an estimate of alerts that were never stored.
  const rawAlertsCount = findings.reduce((acc, finding) => acc + (finding.sources?.length || 0), 0);

  const metrics = BenchmarkEvaluationEngine.evaluateScanAgainstGroundTruth(
    findings,
    JUICE_SHOP_GROUND_TRUTH,
    rawAlertsCount,
    durationSeconds,
    scan.observed_request_count
  );

  res.json({ metrics, groundTruth: JUICE_SHOP_GROUND_TRUTH });
});

// Single-Finding Reproducible Retest API
apiRouter.post('/findings/:id/retest', async (req, res) => {
  const simulatedFixApplied = req.body?.simulated_fix_applied === true;
  if (simulatedFixApplied && process.env.NODE_ENV === 'production') {
    res.status(403).json({ error: 'Simulated remediation is disabled in production. Run a real retest instead.' });
    return;
  }
  try {
    const result = await RemediationVerificationEngine.executeRetest(
      req.params.id,
      simulatedFixApplied
    );
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// Seed Lab Benchmarks
apiRouter.post('/lab/seed', (req, res) => {
  // In production, the lab target must be explicitly configured to a separate
  // Juice Shop service; never default a benchmark target to this web server.
  const juiceShopUrl = process.env.JUICE_SHOP_URL || (process.env.NODE_ENV === 'production' ? '' : 'http://127.0.0.1:3001');
  if (!juiceShopUrl) {
    res.status(503).json({ error: 'Lab benchmark is not configured. Set JUICE_SHOP_URL to a dedicated, isolated Juice Shop instance.' });
    return;
  }

  let labUrl: URL;
  try {
    labUrl = new URL(juiceShopUrl);
    if (!['http:', 'https:'].includes(labUrl.protocol) || labUrl.username || labUrl.password || labUrl.hash) {
      throw new Error('Invalid lab target URL');
    }
  } catch {
    res.status(500).json({ error: 'JUICE_SHOP_URL must be a valid HTTP or HTTPS URL without credentials or fragments.' });
    return;
  }

  // Check if Juice Shop target already exists
  const existing = db.getTargets().find((t) => t.name.includes('Juice Shop'));
  if (existing) {
    res.json({ message: 'Lab target already exists', target: existing });
    return;
  }

  const juiceShopTarget: TargetProfile = {
    id: `target-lab-juiceshop`,
    name: 'OWASP Juice Shop (Authorized Local Lab Benchmark)',
    mode: 'lab',
    target_url: labUrl.toString(),
    hostname: labUrl.hostname,
    allowed_ports: [labUrl.port ? Number(labUrl.port) : (labUrl.protocol === 'https:' ? 443 : 80)],
    excluded_paths: ['/logout'],
    rate_limit_rps: 15,
    max_request_budget: 2500,
    timeout_ms: 8000,
    is_isolated_lab_network_confirmed: true,
    active_scan_scope_confirmed: true,
    created_at: new Date().toISOString()
  };

  db.saveTarget(juiceShopTarget);
  res.status(201).json({ message: 'Lab benchmark target created', target: juiceShopTarget });
});
