import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  Square,
  CheckCircle,
  Loader2,
  AlertCircle,
  Clock,
  Terminal,
  Copy,
  Check
} from 'lucide-react';
import { ScanExecution, ScanStage } from '../types/proofvapt.js';

interface PipelineVisualizerProps {
  scan?: ScanExecution;
  logs: string[];
  onStartScan: () => void;
  onCancelScan: () => void;
}

const STAGE_CONFIG: Array<{ id: ScanStage; label: string; desc: string }> = [
  { id: 'scope_validation', label: '1. Scope & Egress Validation', desc: 'DNS resolution, anti-SSRF IP check, egress proxy' },
  { id: 'reconnaissance', label: '2. Reconnaissance & Fingerprinting', desc: 'TLS protocol ciphers, HSTS, CSP, and CORS audit' },
  { id: 'discovery', label: '3. Content Discovery (ffuf)', desc: 'Real ffuf dictionary discovery with rate limit' },
  { id: 'automated_checks', label: '4. Vulnerability Audit (ZAP AF)', desc: 'ZAP spider, passive rules, and scoped active scan' },
  { id: 'correlation', label: '5. Correlation & Provenance', desc: 'Deduplication and FindingSource linking' },
  { id: 'verification', label: '6. Context-Aware Verification', desc: 'DOM execution checks & CRP calculation' },
  { id: 'reporting', label: '7. Audit Reporting & Matrix', desc: 'OWASP 2025 coverage and executive PDF export' }
];

export const PipelineVisualizer: React.FC<PipelineVisualizerProps> = ({
  scan,
  logs,
  onStartScan,
  onCancelScan
}) => {
  const [copied, setCopied] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleCopyLogs = () => {
    navigator.clipboard.writeText(logs.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isRunning = scan?.status === 'running';

  return (
    <div className="space-y-6">
      {/* Header & Controls Strip */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider font-mono">
              7-Stage Orchestrator
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-400">Node Process Supervisor</span>
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Automated Penetration-Testing Pipeline
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Backend-owned job execution with process-tree signal trapping and real-time wire monitoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isRunning ? (
            <button
              onClick={onCancelScan}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition-colors shadow-sm shadow-rose-950"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>Cancel Scan (Hard Abort)</span>
            </button>
          ) : (
            <button
              onClick={onStartScan}
              disabled={!scan}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:pointer-events-none rounded-lg transition-colors shadow-sm shadow-cyan-950"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run Assessment</span>
            </button>
          )}
        </div>
      </div>

      {/* 7-Stage Horizontal Pipeline Flow */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-4 font-mono">
          Pipeline Execution Stages
        </h3>

        <div className="space-y-3">
          {STAGE_CONFIG.map((stage, idx) => {
            const progress = scan?.stage_progress?.[stage.id];
            const status = progress?.status || 'pending';
            const isActive = scan?.current_stage === stage.id && scan?.status === 'running';

            return (
              <div
                key={stage.id}
                className={`p-3.5 rounded-xl border transition-all flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                  isActive
                    ? 'bg-cyan-950/20 border-cyan-500/40 shadow-sm shadow-cyan-950/50'
                    : status === 'completed'
                    ? 'bg-emerald-950/10 border-emerald-900/40'
                    : status === 'failed'
                    ? 'bg-rose-950/20 border-rose-900/50'
                    : 'bg-slate-900/40 border-slate-800/80 text-slate-500'
                }`}
              >
                <div className="flex items-start sm:items-center gap-3">
                  <div className="mt-0.5 sm:mt-0 shrink-0">
                    {status === 'completed' ? (
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                    ) : isActive ? (
                      <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
                    ) : status === 'failed' ? (
                      <AlertCircle className="w-5 h-5 text-rose-400" />
                    ) : (
                      <div className="w-5 h-5 rounded-full border border-slate-700 flex items-center justify-center text-[10px] text-slate-500 font-mono">
                        {idx + 1}
                      </div>
                    )}
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200">
                      {stage.label}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      {stage.desc}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono shrink-0">
                  {progress?.summary && (
                    <span className="text-slate-400 text-[11px] truncate max-w-xs hidden md:inline">
                      {progress.summary}
                    </span>
                  )}
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${
                      status === 'completed'
                        ? 'text-emerald-400 bg-emerald-950/60'
                        : isActive
                        ? 'text-cyan-400 bg-cyan-950/60'
                        : status === 'failed'
                        ? 'text-rose-400 bg-rose-950/60'
                        : 'text-slate-500 bg-slate-900'
                    }`}
                  >
                    {isActive ? 'In Progress' : status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Streaming Terminal Console */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
        <div className="px-4 py-3 bg-slate-900/80 border-b border-[#1F2937] flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Worker Execution Terminal (stdout / stderr)</span>
          </div>
          <button
            onClick={handleCopyLogs}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        <div className="p-4 bg-[#080C14] text-slate-300 font-mono text-xs h-72 overflow-y-auto space-y-1">
          {logs.length > 0 ? (
            logs.map((log, index) => (
              <div
                key={index}
                className={`leading-relaxed ${
                  log.includes('FATAL') || log.includes('error') || log.includes('BLOCKED')
                    ? 'text-rose-400'
                    : log.includes('Stage') || log.includes('finished') || log.includes('completed')
                    ? 'text-emerald-400'
                    : log.includes('Running:') || log.includes('discovered')
                    ? 'text-cyan-300'
                    : 'text-slate-400'
                }`}
              >
                {log}
              </div>
            ))
          ) : (
            <div className="text-slate-600 italic py-8 text-center">
              Awaiting scan execution. Streaming process logs will appear here.
            </div>
          )}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  );
};
