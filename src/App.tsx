/**
 * ProofVAPT - Automated Web Application Vulnerability Assessment Platform
 * MSc Cyber Security Research Prototype
 */

import React, { useState, useEffect, useCallback } from 'react';
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

export default function App() {
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
  const [logs, setLogs] = useState<string[]>([]);
  const [toolStatus, setToolStatus] = useState<any>(null);

  // Fetch Tool Versions
  const fetchToolStatus = async () => {
    try {
      const res = await fetch('/api/tools/status');
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
      const res = await fetch('/api/scans');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
        if (data.length > 0 && !currentScan) {
          setCurrentScan(data[0]);
        }
      }
    } catch {
      // Ignore
    }
  }, [currentScan]);

  // Fetch Details for Current Scan
  const fetchScanDetails = useCallback(async (scanId: string) => {
    try {
      const [scanRes, epRes, fndRes, teRes, covRes, logsRes, metRes] = await Promise.all([
        fetch(`/api/scans/${scanId}`),
        fetch(`/api/scans/${scanId}/endpoints`),
        fetch(`/api/scans/${scanId}/findings`),
        fetch(`/api/scans/${scanId}/tests`),
        fetch(`/api/scans/${scanId}/coverage`),
        fetch(`/api/scans/${scanId}/logs`),
        fetch(`/api/scans/${scanId}/metrics`)
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
      }
    } catch (err) {
      console.error('Failed to fetch scan details:', err);
    }
  }, []);

  // Initial Load & Auto-Seed
  useEffect(() => {
    fetchToolStatus();
    fetchScans();

    // Check if targets exist; if not, seed Juice Shop lab target automatically
    fetch('/api/targets')
      .then((res) => res.json())
      .then((targets) => {
        if (!targets || targets.length === 0) {
          fetch('/api/lab/seed', { method: 'POST' })
            .then(() => fetchScans());
        }
      })
      .catch(() => {});
  }, [fetchScans]);

  // Polling while scan is running
  useEffect(() => {
    if (!currentScan) return;

    fetchScanDetails(currentScan.id);

    if (currentScan.status === 'running' || currentScan.status === 'queued') {
      const interval = setInterval(() => {
        fetchScanDetails(currentScan.id);
        fetchScans();
      }, 1500);
      return () => clearInterval(interval);
    }
  }, [currentScan?.id, currentScan?.status, fetchScanDetails, fetchScans]);

  // Actions
  const handleStartScan = async () => {
    if (!currentScan?.target_id) return;
    try {
      const res = await fetch('/api/scans', {
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
      const res = await fetch(`/api/scans/${currentScan.id}/cancel`, {
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
    const targetRes = await fetch('/api/targets', {
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
      const res = await fetch(`/api/findings/${findingId}/retest`, {
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
    try {
      const res = await fetch('/api/lab/seed', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.target) {
          // Launch scan against seeded target
          const scanRes = await fetch('/api/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              target_id: data.target.id,
              scan_profile: 'standard_active'
            })
          });
          if (scanRes.ok) {
            const scan = await scanRes.json();
            setCurrentScan(scan);
            fetchScans();
            setActiveTab('pipeline');
          }
        }
      }
    } catch (err) {
      console.error('Failed to seed lab:', err);
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col font-sans">
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
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
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
              groundTruth={JUICE_SHOP_GROUND_TRUTH}
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
