/**
 * ProofVAPT - Automated Web Application Vulnerability Assessment Platform
 * MSc Cyber Security Research Prototype
 */

import React, { useState, useEffect, useCallback } from 'react';
import { ShieldAlert as ShieldAlertIcon } from 'lucide-react';
import { TopBar } from './components/TopBar.js';
import { Sidebar } from './components/Sidebar.js';
import { DashboardOverview } from './components/DashboardOverview.js';
import { PipelineVisualizer } from './components/PipelineVisualizer.js';
import { AttackSurfaceExplorer } from './components/AttackSurfaceExplorer.js';
import { FindingsExplorer } from './components/FindingsExplorer.js';
import { OWASPCoverageMatrix } from './components/OWASPCoverageMatrix.js';
import { EvaluationSuite } from './components/EvaluationSuite.js';
import { ReportView } from './components/ReportView.js';
import { TargetScopeManager } from './components/TargetScopeManager.js';
import {
  ScanExecution,
  TargetProfile,
  AttackSurfaceEndpoint,
  UnifiedFinding,
  OWASPCoverageSummary,
  TestExecution,
  OWASPTestRegistryItem,
  ResearchMetrics,
  ScanProfile
} from './types/proofvapt.js';
import { JUICE_SHOP_GROUND_TRUTH } from '../server/benchmarks.js';

const API_TOKEN_STORAGE_KEY = 'proofvapt_api_token';

export default function App() {
  const [apiToken, setApiToken] = useState<string>(() => {
    try { return sessionStorage.getItem(API_TOKEN_STORAGE_KEY) || ''; } catch { return ''; }
  });
  const [tokenInput, setTokenInput] = useState('');
  const [authState, setAuthState] = useState<'checking' | 'required' | 'ready'>('checking');
  const [authMessage, setAuthMessage] = useState('');
  const apiFetch = useCallback(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    if (apiToken) headers.set('Authorization', `Bearer ${apiToken}`);
    return fetch(input, { ...init, headers });
  }, [apiToken]);

  useEffect(() => {
    let cancelled = false;
    setAuthState('checking');
    const headers = new Headers();
    if (apiToken) headers.set('Authorization', `Bearer ${apiToken}`);
    fetch('/api/session', { headers })
      .then((res) => {
        if (cancelled) return;
        if (res.ok) {
          setAuthMessage('');
          setAuthState('ready');
          return;
        }
        if (apiToken) {
          try { sessionStorage.removeItem(API_TOKEN_STORAGE_KEY); } catch {}
          setApiToken('');
          setAuthMessage('The supplied token was not accepted. Check the deployment secret and try again.');
        } else {
          setAuthMessage('Enter the API token provided by the person who deployed this instance.');
        }
        setAuthState('required');
      })
      .catch(() => {
        if (cancelled) return;
        setAuthMessage('Could not reach the server. Check the deployment URL and try again.');
        setAuthState('required');
      });
    return () => { cancelled = true; };
  }, [apiToken]);

  const submitApiToken = (event: React.FormEvent) => {
    event.preventDefault();
    const value = tokenInput.trim();
    if (!value) {
      setAuthMessage('Enter the API token to continue.');
      return;
    }
    try { sessionStorage.setItem(API_TOKEN_STORAGE_KEY, value); } catch {}
    setApiToken(value);
    setAuthState('checking');
    setAuthMessage('Checking token…');
  };

  const signOut = () => {
    try { sessionStorage.removeItem(API_TOKEN_STORAGE_KEY); } catch {}
    setApiToken('');
    setAuthState('required');
    setTokenInput('');
    setAuthMessage('You have disconnected this browser session.');
  };

  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isTargetModalOpen, setIsTargetModalOpen] = useState<boolean>(false);
  const [scans, setScans] = useState<ScanExecution[]>([]);
  const [currentScan, setCurrentScan] = useState<ScanExecution | null>(null);
  const [endpoints, setEndpoints] = useState<AttackSurfaceEndpoint[]>([]);
  const [findings, setFindings] = useState<UnifiedFinding[]>([]);
  const [testExecutions, setTestExecutions] = useState<TestExecution[]>([]);
  const [coverage, setCoverage] = useState<OWASPCoverageSummary[]>([]);
  const [testRegistry, setTestRegistry] = useState<OWASPTestRegistryItem[]>([]);
  const [metrics, setMetrics] = useState<ResearchMetrics | null>(null);
  const [groundTruth, setGroundTruth] = useState<typeof JUICE_SHOP_GROUND_TRUTH>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [toolStatus, setToolStatus] = useState<any>(null);

  // Fetch Tool Versions
  const fetchToolStatus = async () => {
    try {
      const res = await apiFetch('/api/tools/status');
      if (res.ok) {
        const data = await res.json();
        setToolStatus(data.tools);
      }
    } catch {
      // Ignore
    }
  };

  // Fetch Scans List
  const fetchScans = useCallback(async () => {
    try {
      const res = await apiFetch('/api/scans');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
        setCurrentScan((selected) => selected || (data.length > 0 ? data[0] : null));
      } else {
        throw new Error('Could not load assessments.');
      }
    } catch (error) {
      console.error('Failed to load assessments:', error);
    }
  }, [apiFetch]);

  // Fetch Details for Current Scan
  const fetchScanDetails = useCallback(async (scanId: string) => {
    try {
      const [scanRes, epRes, fndRes, teRes, covRes, logsRes, metRes] = await Promise.all([
        apiFetch(`/api/scans/${scanId}`),
        apiFetch(`/api/scans/${scanId}/endpoints`),
        apiFetch(`/api/scans/${scanId}/findings`),
        apiFetch(`/api/scans/${scanId}/tests`),
        apiFetch(`/api/scans/${scanId}/coverage`),
        apiFetch(`/api/scans/${scanId}/logs`),
        apiFetch(`/api/scans/${scanId}/metrics`)
      ]);

      if (scanRes.ok) {
        const scanData = await scanRes.json();
        setCurrentScan(scanData);
      }
      if (epRes.ok) setEndpoints(await epRes.json());
      if (fndRes.ok) setFindings(await fndRes.json());
      if (teRes.ok) setTestExecutions(await teRes.json());
      if (covRes.ok) {
        const covData = await covRes.json();
        setCoverage(covData.coverage || []);
      }
      if (logsRes.ok) {
        const logData = await logsRes.json();
        setLogs(logData.logs || []);
      }
      if (metRes.ok) {
        const metData = await metRes.json();
        setMetrics(metData.metrics || null);
        setGroundTruth(Array.isArray(metData.groundTruth) ? metData.groundTruth : []);
      }
    } catch (err) {
      console.error('Failed to fetch scan details:', err);
    }
  }, [apiFetch]);

  // Load existing data only after this browser has passed the API access check.
  useEffect(() => {
    if (authState !== 'ready') return;
    fetchToolStatus();
    fetchScans();
  }, [authState, fetchScans, apiFetch]);

  // Polling while scan is running
  useEffect(() => {
    if (authState !== 'ready' || !currentScan) return;

    fetchScanDetails(currentScan.id);

    if (currentScan.status === 'running' || currentScan.status === 'queued') {
      const interval = setInterval(() => {
        fetchScanDetails(currentScan.id);
        fetchScans();
      }, 1500);
      return () => clearInterval(interval);
    }
  }, [authState, currentScan?.id, currentScan?.status, fetchScanDetails, fetchScans]);

  // Actions
  const handleStartScan = async () => {
    if (!currentScan?.target_id) return;
    try {
      const res = await apiFetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: currentScan.target_id,
          scan_profile: currentScan.scan_profile || 'passive_only'
        })
      });
      if (res.ok) {
        const newScan = await res.json();
        setCurrentScan(newScan);
        fetchScans();
        setActiveTab('pipeline');
      }
    } catch (err) {
      console.error('Failed to launch scan:', err);
    }
  };

  const handleCancelScan = async () => {
    if (!currentScan) return;
    try {
      const res = await apiFetch(`/api/scans/${currentScan.id}/cancel`, {
        method: 'POST'
      });
      if (res.ok) {
        const updated = await res.json();
        setCurrentScan(updated);
        fetchScans();
      }
    } catch (err) {
      console.error('Failed to cancel scan:', err);
    }
  };

  const handleCreateTargetAndScan = async (
    targetData: Partial<TargetProfile>,
    scanProfile: ScanProfile
  ) => {
    // 1. Create Target
    const targetRes = await apiFetch('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(targetData)
    });

    if (!targetRes.ok) {
      const err = await targetRes.json();
      throw new Error(err.error || 'Failed to save target profile');
    }

    const createdTarget: TargetProfile = await targetRes.json();

    // 2. Launch Scan
    const scanRes = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_id: createdTarget.id,
        scan_profile: scanProfile
      })
    });

    if (!scanRes.ok) {
      const err = await scanRes.json();
      throw new Error(err.error || 'Failed to launch scan execution');
    }

    const createdScan = await scanRes.json();
    setCurrentScan(createdScan);
    fetchScans();
    setActiveTab('pipeline');
  };

  const handleRetestFinding = async (findingId: string, simulatedFix = false) => {
    try {
      const res = await apiFetch(`/api/findings/${findingId}/retest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ simulated_fix_applied: simulatedFix })
      });
      if (res.ok) {
        if (currentScan) fetchScanDetails(currentScan.id);
      }
    } catch (err) {
      console.error('Retest failed:', err);
    }
  };

  const handleSeedLab = async () => {
    const res = await apiFetch('/api/lab/seed', { method: 'POST' });
    const labData = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(labData.error || 'Could not configure the Juice Shop lab.');
    }
    if (!labData.target?.id) {
      throw new Error('The lab endpoint did not return a target profile.');
    }

    const scanRes = await apiFetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_id: labData.target.id,
        scan_profile: 'standard_active'
      })
    });
    const scanData = await scanRes.json().catch(() => ({}));
    if (!scanRes.ok) {
      throw new Error(scanData.error || 'Could not start the lab assessment.');
    }

    setCurrentScan(scanData);
    await fetchScans();
    setActiveTab('pipeline');
  };

  if (authState !== 'ready') {
    return (
      <main className="access-screen">
        <section className="access-panel" aria-labelledby="access-title">
          <div className="access-brand">
            <span className="access-mark"><ShieldAlertIcon /></span>
            <span>ProofVAPT</span>
          </div>
          <p className="eyebrow">Security assessment workspace</p>
          <h1 id="access-title">{authState === 'checking' ? 'Checking access' : 'Connect to your workspace'}</h1>
          <p className="access-copy">This instance can run security scans and store assessment evidence. Access is restricted to the operator holding the deployment token.</p>
          {authState === 'checking' ? (
            <div className="access-status" role="status">Validating session…</div>
          ) : (
            <form className="access-form" onSubmit={submitApiToken}>
              <label htmlFor="api-token">Deployment API token</label>
              <input
                id="api-token"
                type="password"
                autoComplete="current-password"
                value={tokenInput}
                onChange={(event) => setTokenInput(event.target.value)}
                placeholder="Paste the token supplied by your administrator"
                required
              />
              {authMessage && <p className="access-message" role="status">{authMessage}</p>}
              <button type="submit">Connect securely</button>
            </form>
          )}
          <p className="access-footnote">Use a private deployment behind HTTPS. Do not share this token or commit it to source control.</p>
        </section>
      </main>
    );
  }

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col font-sans proofvapt-shell">
      {/* Strict Top Bar Contract */}
      <TopBar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenTargetModal={() => setIsTargetModalOpen(true)}
        toolStatus={toolStatus}
      />

      <div className="flex-1 flex">
        {/* SOC Command Sidebar */}
        <div className="no-print">
          <Sidebar
            activeTab={activeTab}
            onSelectTab={setActiveTab}
            activeScan={currentScan || undefined}
            endpointsCount={endpoints.length}
            findingsCount={findings.length}
          />
        </div>

        {/* Main Content Area */}
        <main className="flex-1 min-w-0 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          {activeTab === 'overview' && (
            <DashboardOverview
              scans={scans}
              currentScan={currentScan || undefined}
              findings={findings}
              endpoints={endpoints}
              onStartNewScan={() => setIsTargetModalOpen(true)}
              onSelectScan={(id) => {
                const s = scans.find((x) => x.id === id);
                if (s) setCurrentScan(s);
              }}
              onNavigateTab={setActiveTab}
              onSeedLab={handleSeedLab}
            />
          )}

          {activeTab === 'pipeline' && (
            <PipelineVisualizer
              scan={currentScan || undefined}
              logs={logs}
              onStartScan={handleStartScan}
              onCancelScan={handleCancelScan}
            />
          )}

          {activeTab === 'surface' && (
            <AttackSurfaceExplorer
              endpoints={endpoints}
              targetUrl={currentScan?.target?.target_url}
            />
          )}

          {activeTab === 'findings' && (
            <FindingsExplorer
              findings={findings}
              onRetestFinding={handleRetestFinding}
            />
          )}

          {activeTab === 'owasp' && (
            <OWASPCoverageMatrix
              coverage={coverage}
              testExecutions={testExecutions}
              testRegistry={testRegistry}
            />
          )}

          {activeTab === 'benchmarks' && (
            <EvaluationSuite
              metrics={metrics}
              groundTruth={groundTruth}
              onRefreshEvaluation={() => {
                if (currentScan) fetchScanDetails(currentScan.id);
              }}
            />
          )}

          {activeTab === 'report' && (
            <ReportView
              scan={currentScan}
              findings={findings}
              coverage={coverage}
            />
          )}
        </main>
      </div>

      <div className="no-print flex justify-end px-4 py-2 border-t border-[#1F2937] bg-[#0B0F17]">
        <button onClick={signOut} className="text-xs text-slate-400 hover:text-white transition-colors" type="button">
          Disconnect browser session
        </button>
      </div>

      {/* Target Scope Configuration Modal */}
      <TargetScopeManager
        isOpen={isTargetModalOpen}
        onClose={() => setIsTargetModalOpen(false)}
        onSubmit={handleCreateTargetAndScan}
        onSeedLab={handleSeedLab}
      />
    </div>
  );
}
