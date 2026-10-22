import React, { useState } from 'react';
import {
  Grid,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  FileCheck2,
  Lock,
  ExternalLink
} from 'lucide-react';
import { OWASPCoverageSummary, TestExecution, OWASPTestRegistryItem } from '../types/proofvapt.js';

interface OWASPCoverageMatrixProps {
  coverage: OWASPCoverageSummary[];
  testExecutions: TestExecution[];
  testRegistry: OWASPTestRegistryItem[];
}

export const OWASPCoverageMatrix: React.FC<OWASPCoverageMatrixProps> = ({
  coverage,
  testExecutions,
  testRegistry
}) => {
  const [expandedCat, setExpandedCat] = useState<string | null>('A02');

  const testedCount = coverage.filter((c) => c.status === 'tested').length;
  const partialCount = coverage.filter((c) => c.status === 'partially_tested').length;
  const manualCount = coverage.filter((c) => c.status === 'manual_review_required').length;
  const notTestedCount = coverage.filter((c) => c.status === 'not_tested').length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-[#83cfc0] uppercase tracking-wider font-mono">
              OWASP Top 10:2025 Registry
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-400">Derived from TestExecution DB</span>
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Security Testing Coverage Matrix
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Transparent coverage auditing. Untested categories are never reported as secure; logic flaws and logging checks explicitly require manual review.
          </p>
        </div>

        {/* Coverage Summary Badges */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 rounded-md bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
            {testedCount} Tested
          </span>
          <span className="px-2.5 py-1 rounded-md bg-[#142620] text-[#83cfc0] border border-[#2b4e48]/40">
            {partialCount} Partial
          </span>
          <span className="px-2.5 py-1 rounded-md bg-amber-950/60 text-amber-400 border border-amber-800/40">
            {manualCount} Manual Review
          </span>
        </div>
      </div>

      {/* 10 Categories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {coverage.map((cat) => {
          const isExpanded = expandedCat === cat.category_code;
          const registryTests = testRegistry.filter((t) => t.owasp_category === cat.category_code);
          const executions = testExecutions.filter((te) => te.test?.owasp_category === cat.category_code);

          return (
            <div
              key={cat.category_code}
              className={`bg-[#141a21] border rounded-xl overflow-hidden transition-all ${
                cat.status === 'tested'
                  ? 'border-emerald-900/50'
                  : cat.status === 'partially_tested'
                  ? 'border-cyan-900/50'
                  : cat.status === 'manual_review_required'
                  ? 'border-amber-900/50'
                  : 'border-[#2a333d]'
              }`}
            >
              {/* Card Header */}
              <div
                onClick={() => setExpandedCat(isExpanded ? null : cat.category_code)}
                className="p-4 cursor-pointer hover:bg-slate-900/40 transition-colors flex items-start justify-between gap-3"
              >
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold font-mono text-[#83cfc0]">
                      {cat.category_code}
                    </span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase font-semibold ${
                        cat.status === 'tested'
                          ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                          : cat.status === 'partially_tested'
                          ? 'bg-[#142620] text-[#a1e2d5] border border-[#2b4e48]/60'
                          : cat.status === 'manual_review_required'
                          ? 'bg-amber-950/80 text-amber-300 border border-amber-800/60'
                          : 'bg-slate-900 text-slate-500 border border-[#2a333d]'
                      }`}
                    >
                      {cat.status.replace('_', ' ')}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-white tracking-tight">
                    {cat.category_title.split('- ')[1] || cat.category_title}
                  </h3>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right font-mono text-xs">
                    <div className="text-white tabular-nums">
                      {cat.tests_executed} / {cat.tests_total} Tests
                    </div>
                    {cat.vulnerabilities_found > 0 ? (
                      <span className="text-rose-400 text-[10px] block font-semibold">
                        {cat.vulnerabilities_found} Flaw{cat.vulnerabilities_found > 1 ? 's' : ''} Found
                      </span>
                    ) : (
                      <span className="text-slate-500 text-[10px] block">0 Alerts</span>
                    )}
                  </div>
                  {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                </div>
              </div>

              {/* Collapsible Details */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-2 border-t border-[#2a333d]/60 space-y-3 bg-slate-950/30 text-xs">
                  <div className="text-slate-400 text-[11px] font-mono">
                    Registered Automated Tests & Diagnostic Scope:
                  </div>

                  {registryTests.map((t) => {
                    const exec = executions.find((e) => e.test_id === t.test_id);
                    return (
                      <div
                        key={t.test_id}
                        className="p-3 bg-[#11171e] border border-[#2a333d] rounded-lg space-y-1.5"
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="text-[#a1e2d5] font-semibold">{t.test_id}: {t.name}</span>
                          <span
                            className={`text-[9px] px-1.5 py-0.5 rounded uppercase font-semibold ${
                              exec?.outcome === 'vulnerable'
                                ? 'bg-rose-950/60 text-rose-300 border border-rose-800/40'
                                : exec?.outcome === 'clean'
                                ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {exec ? `Executed: ${exec.outcome}` : 'Pending Execution'}
                          </span>
                        </div>
                        <p className="text-slate-300 text-[11px]">{t.description}</p>
                        <div className="text-[10px] text-slate-500 space-y-0.5">
                          <div>
                            <span className="text-slate-400 font-medium">Method:</span> {t.execution_method} · <span className="text-slate-400 font-medium">Prereqs:</span> {t.prerequisites}
                          </div>
                          <div>
                            <span className="text-amber-400/80 font-medium">Limitations:</span> {t.limitations}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
