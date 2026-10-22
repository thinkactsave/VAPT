import React, { useState, useMemo } from 'react';
import {
  Search,
  Bug,
  ShieldCheck,
  RotateCcw,
  ExternalLink,
  ChevronRight,
  Filter,
  Flame,
  CheckCircle2,
  Clock
} from 'lucide-react';
import { UnifiedFinding, SeverityLevel, VerificationStatus, RemediationStatus } from '../types/proofvapt.js';
import { EvidenceModal } from './EvidenceModal.js';

interface FindingsExplorerProps {
  findings: UnifiedFinding[];
  onRetestFinding: (findingId: string, simulatedFix?: boolean) => Promise<void>;
}

export const FindingsExplorer: React.FC<FindingsExplorerProps> = ({
  findings,
  onRetestFinding
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [verificationFilter, setVerificationFilter] = useState<string>('all');
  const [remediationFilter, setRemediationFilter] = useState<string>('all');
  const [selectedFinding, setSelectedFinding] = useState<UnifiedFinding | null>(null);
  const [retestingId, setRetestingId] = useState<string | null>(null);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchesSearch =
        f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.affected_url.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.cwe_id.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesSeverity = severityFilter === 'all' || f.source_severity === severityFilter;
      const matchesCategory = categoryFilter === 'all' || f.owasp_category_code === categoryFilter;
      const matchesVerification = verificationFilter === 'all' || f.verification_status === verificationFilter;
      const matchesRemediation = remediationFilter === 'all' || f.remediation_status === remediationFilter;

      return matchesSearch && matchesSeverity && matchesCategory && matchesVerification && matchesRemediation;
    });
  }, [findings, searchTerm, severityFilter, categoryFilter, verificationFilter, remediationFilter]);

  const handleRetest = async (id: string, simulated = false) => {
    setRetestingId(id);
    try {
      await onRetestFinding(id, simulated);
    } finally {
      setRetestingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-[#83cfc0] uppercase tracking-wider font-mono">
              Unified Findings & Intelligence
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-400 font-mono tabular-nums">{findings.length} Deduplicated Alerts</span>
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Correlated Vulnerability Register
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Deduplicated results from <code className="text-[#a1e2d5] font-mono">OWASP ZAP</code> and custom probers with multi-tool provenance and decoupled remediation tracking.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-[#2a333d]">
          <span className="text-emerald-400 font-semibold">{findings.filter((f) => f.remediation_status === 'remediated_verified').length}</span> Remediated
          <span>·</span>
          <span className="text-rose-400 font-semibold">{findings.filter((f) => f.source_severity === 'CRITICAL' || f.source_severity === 'HIGH').length}</span> Crit/High
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {/* Search */}
        <div className="md:col-span-2 relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search title, URL, or CWE (e.g. CWE-79)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#141a21] border border-[#2a333d] rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#4e9385] font-mono"
          />
        </div>

        {/* Severity Filter */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-[#141a21] border border-[#2a333d] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#4e9385]"
        >
          <option value="all">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Informational</option>
        </select>

        {/* OWASP Category Filter */}
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="bg-[#141a21] border border-[#2a333d] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#4e9385]"
        >
          <option value="all">All OWASP 2025</option>
          <option value="A01">A01: Broken Access Control</option>
          <option value="A02">A02: Security Misconfiguration</option>
          <option value="A03">A03: Software Supply Chain</option>
          <option value="A04">A04: Cryptographic Failures</option>
          <option value="A05">A05: Injection</option>
          <option value="A06">A06: Insecure Design</option>
          <option value="A07">A07: Authentication Failures</option>
          <option value="A08">A08: Integrity Failures</option>
          <option value="A09">A09: Logging Failures</option>
          <option value="A10">A10: Exceptional Conditions</option>
        </select>

        {/* Remediation Status Filter */}
        <select
          value={remediationFilter}
          onChange={(e) => setRemediationFilter(e.target.value)}
          className="bg-[#141a21] border border-[#2a333d] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#4e9385]"
        >
          <option value="all">All Remediation States</option>
          <option value="open">Open</option>
          <option value="remediated_verified">Remediated Verified</option>
          <option value="pending_retest">Pending Retest</option>
          <option value="reopened">Reopened</option>
        </select>
      </div>

      {/* High-Density Findings Table */}
      <div className="bg-[#141a21] border border-[#2a333d] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#171e25] border-b border-[#2a333d] text-slate-400 uppercase font-mono tracking-wider">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Vulnerability Title</th>
                <th className="py-3 px-4">OWASP 2025</th>
                <th className="py-3 px-4">CVSS / Priority</th>
                <th className="py-3 px-4">Tool Provenance</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredFindings.length > 0 ? (
                filteredFindings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-900/40 transition-colors">
                    {/* Severity */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                          f.source_severity === 'CRITICAL'
                            ? 'bg-rose-950/80 text-rose-300 border border-rose-800/70'
                            : f.source_severity === 'HIGH'
                            ? 'bg-amber-950/80 text-amber-300 border border-amber-800/70'
                            : f.source_severity === 'MEDIUM'
                            ? 'bg-yellow-950/80 text-yellow-300 border border-yellow-800/70'
                            : 'bg-sky-950/80 text-sky-300 border border-sky-800/70'
                        }`}
                      >
                        {f.source_severity}
                      </span>
                    </td>

                    {/* Title & CWE */}
                    <td className="py-3 px-4 max-w-sm">
                      <div className="text-white font-medium hover:text-[#a1e2d5] transition-colors cursor-pointer" onClick={() => setSelectedFinding(f)}>
                        {f.title}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                        {f.affected_url}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                        {f.cwe_id}
                      </div>
                    </td>

                    {/* OWASP 2025 */}
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px] text-slate-300">
                      <span className="text-[#83cfc0] font-semibold">{f.owasp_category_code}</span>
                      <span className="text-slate-500 text-[10px] block truncate max-w-[140px]">
                        {f.owasp_category.split('- ')[1] || f.owasp_category}
                      </span>
                    </td>

                    {/* CVSS & CRP */}
                    <td className="py-3 px-4 whitespace-nowrap font-mono">
                      <div className="text-slate-300 tabular-nums">
                        CVSS: <span className="font-semibold text-white">{f.official_cvss_score != null ? f.official_cvss_score.toFixed(1) : 'Not scored'}</span>
                      </div>
                      <div className="text-[10px] text-[#83cfc0] tabular-nums">
                        CRP: {f.contextual_remediation_priority.toFixed(1)} / 10
                      </div>
                    </td>

                    {/* Source Tools */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex flex-wrap gap-1">
                        {f.sources && f.sources.length > 0 ? (
                          f.sources.map((s) => (
                            <span
                              key={s.id}
                              className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-slate-800 text-slate-300 border border-slate-700"
                            >
                              {s.tool_name}
                            </span>
                          ))
                        ) : (
                          <span className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-slate-800 text-slate-300">
                            tls_prober
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Decoupled Status */}
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-[10px]">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            f.remediation_status === 'remediated_verified'
                              ? 'bg-emerald-400'
                              : f.remediation_status === 'open'
                              ? 'bg-rose-400'
                              : 'bg-amber-400'
                          }`}
                        />
                        <span className="uppercase text-slate-300 font-medium">
                          {f.remediation_status.replace('_', ' ')}
                        </span>
                      </div>
                      <span className="text-slate-500 text-[9px] block capitalize mt-0.5">
                        Verification: {f.verification_status.replace('_', ' ')}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setSelectedFinding(f)}
                          className="px-2.5 py-1 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
                        >
                          Evidence
                        </button>
                        <button
                          onClick={() => handleRetest(f.id, false)}
                          disabled={retestingId === f.id}
                          className="p-1 text-slate-400 hover:text-[#83cfc0] rounded hover:bg-slate-800 transition-colors"
                          title="Run targeted retest"
                        >
                          <RotateCcw className={`w-3.5 h-3.5 ${retestingId === f.id ? 'animate-spin text-[#83cfc0]' : ''}`} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 text-xs">
                    {findings.length === 0
                      ? 'No vulnerabilities reported yet. Run an assessment to scan endpoints.'
                      : 'No findings match the active filters.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal Inspector */}
      {selectedFinding && (
        <EvidenceModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onRetest={(id, sim) => handleRetest(id, sim)}
          isRetesting={retestingId === selectedFinding.id}
        />
      )}
    </div>
  );
};
