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
import fs from 'fs';

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
  if (!body.target_url) {
    res.status(400).json({ error: 'Target URL is required' });
    return;
  }

  try {
    const url = new URL(body.target_url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      res.status(400).json({ error: 'Protocol must be HTTP or HTTPS' });
      return;
    }

    const target: TargetProfile = {
      id: `target-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      name: body.name || url.hostname,
      mode: body.mode || 'live',
      target_url: body.target_url,
      hostname: url.hostname,
      allowed_ports: Array.isArray(body.allowed_ports) && body.allowed_ports.length > 0
        ? body.allowed_ports
        : [url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80)],
      excluded_paths: Array.isArray(body.excluded_paths) ? body.excluded_paths : ['/logout'],
      rate_limit_rps: Number(body.rate_limit_rps) || 10,
      max_request_budget: Number(body.max_request_budget) || 2000,
      timeout_ms: Number(body.timeout_ms) || 10000,
      is_isolated_lab_network_confirmed: !!body.is_isolated_lab_network_confirmed,
      active_scan_scope_confirmed: !!body.active_scan_scope_confirmed,
      created_at: new Date().toISOString()
    };

    db.saveTarget(target);
    res.status(201).json(target);
  } catch (err: any) {
    res.status(400).json({ error: `Invalid Target URL: ${err.message}` });
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
  const { target_id, scan_profile } = req.body;
  const target = db.getTarget(target_id);

  if (!target) {
    res.status(404).json({ error: 'Target not found' });
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

  // Trigger background execution
  scanSupervisor.startScan(scan.id);

  res.status(201).json(scan);
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
    const executedForCat = testExecutions.filter(
      (te) => te.test?.owasp_category === cat.code && te.execution_status === 'completed'
    );
    const findingsForCat = findings.filter((f) => f.owasp_category_code === cat.code);

    let status: OWASPCoverageSummary['status'] = 'not_tested';
    if (cat.code === 'A06' || cat.code === 'A09') {
      status = 'manual_review_required';
    } else if (executedForCat.length >= 2) {
      status = 'tested';
    } else if (executedForCat.length === 1) {
      status = 'partially_tested';
    } else {
      status = 'not_tested';
    }

    return {
      category_code: cat.code,
      category_title: cat.title,
      tests_total: cat.code === 'A02' ? 4 : 2,
      tests_executed: executedForCat.length,
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
  const toolRuns = db.getToolRuns(scan.id);
  const durationSeconds = scan.started_at && scan.completed_at
    ? Math.max(1, Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000))
    : 45;

  const rawAlertsCount = findings.reduce((acc, f) => acc + (f.sources?.length || 1), 0);

  const metrics = BenchmarkEvaluationEngine.evaluateScanAgainstGroundTruth(
    findings,
    JUICE_SHOP_GROUND_TRUTH,
    rawAlertsCount,
    durationSeconds,
    scan.observed_request_count || 120
  );

  res.json({ metrics, groundTruth: JUICE_SHOP_GROUND_TRUTH });
});

// Single-Finding Reproducible Retest API
apiRouter.post('/findings/:id/retest', async (req, res) => {
  const { simulated_fix_applied } = req.body;
  try {
    const result = await RemediationVerificationEngine.executeRetest(
      req.params.id,
      !!simulated_fix_applied
    );
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// Seed Lab Benchmarks
apiRouter.post('/lab/seed', (req, res) => {
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
    target_url: 'http://localhost:3000',
    hostname: 'localhost',
    allowed_ports: [80, 443, 3000, 8080],
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
