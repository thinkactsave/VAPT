import React from 'react';
import {
  Globe,
  Bug,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  ExternalLink,
  ShieldAlert,
  Flame,
  ArrowRight
} from 'lucide-react';
import { ScanExecution, UnifiedFinding, AttackSurfaceEndpoint } from '../types/proofvapt.js';

interface DashboardOverviewProps {
  scans: ScanExecution[];
  currentScan?: ScanExecution;
  findings: UnifiedFinding[];
  endpoints: AttackSurfaceEndpoint[];
  onStartNewScan: () => void;
  onSelectScan: (scanId: string) => void;
  onNavigateTab: (tab: string) => void;
  onSeedLab: () => Promise<void>;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  scans,
  currentScan,
  findings,
  endpoints,
  onStartNewScan,
  onSelectScan,
  onNavigateTab,
  onSeedLab
}) => {
  const criticalCount = findings.filter((f) => f.source_severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.source_severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.source_severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.source_severity === 'LOW').length;
  const verifiedCount = findings.filter((f) => f.verification_status === 'verified').length;
  const [isStartingLab, setIsStartingLab] = React.useState(false);
  const [labError, setLabError] = React.useState<string | null>(null);
  const startLab = async () => {
    setIsStartingLab(true);
    setLabError(null);
    try {
      await onSeedLab();
    } catch (error) {
      setLabError(error instanceof Error ? error.message : 'Could not start the lab assessment.');
    } finally {
      setIsStartingLab(false);
    }
  };

  const target = currentScan?.target;
  const wireRequests = currentScan?.observed_request_count || 0;
  const maxBudget = target?.max_request_budget || 2000;
  const budgetPct = Math.min(100, Math.round((wireRequests / maxBudget) * 100));

  return (
    <div className="space-y-6">
      {/* Top Banner / Assessment Status */}
      {labError && (
        <div role="alert" className="rounded-lg border border-amber-900/60 bg-amber-950/20 px-4 py-3 text-xs text-amber-200">
          {labError}
        </div>
      )}
      <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-[#83cfc0] uppercase tracking-wider font-mono">
              Active Assessment Engine
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-400">OWASP Top 10:2025 Standard</span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            {target ? target.name : 'ProofVAPT Security Assessment Console'}
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Automated multi-stage vulnerability discovery using real <code className="text-[#a1e2d5] font-mono">ffuf</code> content fuzzing,{' '}
            <code className="text-[#a1e2d5] font-mono">OWASP ZAP AF</code> crawler & scanner, and dynamic Scope-Enforcing Egress Proxy protection.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={startLab}
            disabled={isStartingLab}
            className="px-3.5 py-2 text-xs font-medium text-slate-300 bg-[#202932] hover:bg-slate-700/80 border border-slate-700 rounded-lg transition-colors whitespace-nowrap"
          >
            {isStartingLab ? 'Starting lab…' : 'Start Juice Shop scan'}
          </button>
          <button
            onClick={onStartNewScan}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#0a1714] bg-[#83cfc0] hover:bg-[#a1e2d5] rounded-lg transition-colors whitespace-nowrap shadow-sm shadow-cyan-950"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Launch Assessment</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Attack Surface */}
        <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Discovered Endpoints</span>
            <Globe className="w-4 h-4 text-[#83cfc0]" />
          </div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">
            {endpoints.length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1.5">
            <span>ffuf routes & crawler links</span>
          </div>
        </div>

        {/* KPI 2: Correlated Findings */}
        <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Unified Findings</span>
            <Bug className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">
            {findings.length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-2">
            <span className="text-rose-400 font-mono">{criticalCount} Crit</span>
            <span>·</span>
            <span className="text-amber-400 font-mono">{highCount} High</span>
            <span>·</span>
            <span className="text-yellow-400 font-mono">{mediumCount} Med</span>
          </div>
        </div>

        {/* KPI 3: Verified Flaws */}
        <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Verification Rate</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono tabular-nums">
            {findings.length > 0 ? `${Math.round((verifiedCount / findings.length) * 100)}%` : '0%'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            <span className="font-mono text-slate-300">{verifiedCount}</span> of {findings.length} verified with proof
          </div>
        </div>

        {/* KPI 4: Proxy Wire Traffic */}
        <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Observed Wire Requests</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">
            {wireRequests}
          </div>
          <div className="mt-1.5 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                budgetPct > 80 ? 'bg-rose-500' : 'bg-[#83cfc0]'
              }`}
              style={{ width: `${budgetPct}%` }}
            />
          </div>
          <div className="text-[10px] text-slate-500 mt-1 flex justify-between font-mono">
            <span>Proxy Budget: {maxBudget}</span>
            <span>{budgetPct}%</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Pipeline Progress + Severities */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Current Scan Progress */}
        <div className="lg:col-span-2 bg-[#141a21] border border-[#2a333d] rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#83cfc0]" />
              <span>Assessment Pipeline State</span>
            </h2>
            <button
              onClick={() => onNavigateTab('pipeline')}
              className="text-xs text-[#83cfc0] hover:text-[#a1e2d5] flex items-center gap-1 font-medium"
            >
              <span>View Live Logs</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {currentScan ? (
            <div className="space-y-4">
              <div className="p-3 bg-slate-900/70 border border-[#2a333d] rounded-lg flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-white">
                    Target: {currentScan.target?.name}
                  </div>
                  <div className="text-[11px] font-mono text-[#83cfc0]">
                    {currentScan.target?.target_url}
                  </div>
                </div>
                <div className="text-right">
                  <span
                    className={`text-xs px-2.5 py-1 rounded-md font-mono font-medium uppercase ${
                      currentScan.status === 'running'
                        ? 'text-[#83cfc0] bg-cyan-950/70 border border-[#2b4e48]'
                        : currentScan.status === 'completed'
                        ? 'text-emerald-400 bg-emerald-950/70 border border-emerald-800'
                        : 'text-amber-400 bg-amber-950/70 border border-amber-800'
                    }`}
                  >
                    {currentScan.status}
                  </span>
                </div>
              </div>

              {/* 7 Stage Indicators */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {Object.entries(currentScan.stage_progress || {}).map(([stageName, p]) => (
                  <div
                    key={stageName}
                    className={`p-2.5 rounded-lg border text-xs ${
                      p.status === 'completed'
                        ? 'bg-emerald-950/20 border-emerald-900/60 text-emerald-300'
                        : p.status === 'running'
                        ? 'bg-cyan-950/30 border-[#2b4e48] text-[#a1e2d5]'
                        : 'bg-slate-900/40 border-[#2a333d]/80 text-slate-500'
                    }`}
                  >
                    <div className="text-[10px] uppercase font-mono tracking-wider truncate mb-1">
                      {stageName.replace('_', ' ')}
                    </div>
                    <div className="font-semibold capitalize text-[11px]">
                      {p.status}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="py-8 text-center text-slate-500 text-xs">
              No scan currently in memory. Launch a new assessment to begin.
            </div>
          )}
        </div>

        {/* Right Column: Severity Breakdown & Fast Navigation */}
        <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-400" />
            <span>Finding Severity Distribution</span>
          </h2>

          <div className="space-y-2.5 pt-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-rose-400 font-medium">Critical</span>
              <span className="font-mono text-white tabular-nums">{criticalCount}</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-rose-500 h-full"
                style={{ width: `${findings.length ? (criticalCount / findings.length) * 100 : 0}%` }}
              />
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-amber-400 font-medium">High</span>
              <span className="font-mono text-white tabular-nums">{highCount}</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-amber-500 h-full"
                style={{ width: `${findings.length ? (highCount / findings.length) * 100 : 0}%` }}
              />
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-yellow-400 font-medium">Medium</span>
              <span className="font-mono text-white tabular-nums">{mediumCount}</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-yellow-500 h-full"
                style={{ width: `${findings.length ? (mediumCount / findings.length) * 100 : 0}%` }}
              />
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-sky-400 font-medium">Low</span>
              <span className="font-mono text-white tabular-nums">{lowCount}</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-sky-400 h-full"
                style={{ width: `${findings.length ? (lowCount / findings.length) * 100 : 0}%` }}
              />
            </div>
          </div>

          <div className="pt-3 border-t border-[#2a333d] flex flex-col gap-2">
            <button
              onClick={() => onNavigateTab('findings')}
              className="w-full py-2 px-3 text-xs font-medium text-slate-300 bg-[#202932] hover:bg-slate-700/80 rounded-lg transition-colors flex items-center justify-between"
            >
              <span>Explore All {findings.length} Findings</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => onNavigateTab('owasp')}
              className="w-full py-2 px-3 text-xs font-medium text-slate-300 bg-[#202932] hover:bg-slate-700/80 rounded-lg transition-colors flex items-center justify-between"
            >
              <span>OWASP Top 10:2025 Matrix</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
