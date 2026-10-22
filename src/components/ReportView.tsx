import React from 'react';
import {
  Printer,
  ShieldCheck,
  AlertTriangle,
  Download,
  FileText,
  Calendar,
  Globe,
  Lock,
  Layers
} from 'lucide-react';
import { ScanExecution, UnifiedFinding, OWASPCoverageSummary } from '../types/proofvapt.js';

interface ReportViewProps {
  scan: ScanExecution | null;
  findings: UnifiedFinding[];
  coverage: OWASPCoverageSummary[];
}

export const ReportView: React.FC<ReportViewProps> = ({
  scan,
  findings,
  coverage
}) => {
  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJSON = () => {
    const data = {
      assessment_title: 'ProofVAPT Web Application Security Assessment Report',
      scan,
      findings,
      coverage,
      generated_at: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ProofVAPT_Assessment_${scan?.id || 'export'}.json`;
    a.click();
  };

  const criticalCount = findings.filter((f) => f.source_severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.source_severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.source_severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.source_severity === 'LOW').length;

  const target = scan?.target;

  return (
    <div className="space-y-6">
      {/* Action Header Bar (Hidden in Print) */}
      <div className="no-print bg-[#141a21] border border-[#2a333d] rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-[#83cfc0] uppercase tracking-wider font-mono">
              Audit Report Generator
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-400">Executive & Technical PDF Format</span>
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Security Assessment & Remediation Report
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Formal penetration testing report with OWASP Top 10:2025 breakdown, redacting evidence traces, and prioritized fixes.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadJSON}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors border border-slate-700 font-mono"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#0a1714] bg-[#83cfc0] hover:bg-[#a1e2d5] rounded-lg transition-colors shadow-sm shadow-cyan-950 font-mono"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save as PDF</span>
          </button>
        </div>
      </div>

      {/* Formal Printable Document Body */}
      <div className="bg-[#141a21] print:bg-white border border-[#2a333d] print:border-none rounded-xl p-8 print:p-0 space-y-8 print:text-black">
        {/* Document Title Header */}
        <div className="border-b border-[#2a333d] print:border-slate-300 pb-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-mono font-semibold text-[#83cfc0] print:text-slate-600 uppercase tracking-wider">
                MSc Cyber Security Assessment Platform
              </div>
              <h1 className="text-2xl font-bold text-white print:text-slate-900 tracking-tight mt-1">
                ProofVAPT Security Assessment Report
              </h1>
              <div className="text-xs text-slate-400 print:text-slate-600 font-mono mt-1">
                Automated Web Application Vulnerability & Attack Surface Assessment
              </div>
            </div>

            <div className="text-right text-xs font-mono text-slate-400 print:text-slate-600 space-y-0.5">
              <div>Date: {new Date().toLocaleDateString()}</div>
              <div>Report ID: {scan?.id ? scan.id.slice(0, 16) : 'PV-DRAFT'}</div>
              <div>Status: {scan?.status?.toUpperCase() || 'COMPLETED'}</div>
            </div>
          </div>
        </div>

        {/* Section 1: Executive Summary */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-white print:text-slate-900 uppercase font-mono tracking-wider border-b border-[#2a333d] print:border-slate-300 pb-1">
            01. Executive Summary & Risk Posture
          </h2>
          <p className="text-xs text-slate-300 print:text-slate-700 leading-relaxed">
            ProofVAPT conducted an automated web application vulnerability assessment against the authorized target scope{' '}
            <strong className="text-white print:text-black font-mono">{target?.target_url || 'Target Endpoint'}</strong>.
            The assessment utilized a combination of rate-limited content discovery (<code className="font-mono">ffuf</code>), crawling and passive/active vulnerability analysis (<code className="font-mono">OWASP ZAP Automation Framework</code>), and context-aware verification probers routed through a Scope-Enforcing Egress Proxy.
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 font-mono">
            <div className="p-3 bg-[#11171e] print:bg-slate-100 rounded-lg border border-[#2a333d] print:border-slate-300">
              <span className="text-[10px] text-rose-400 print:text-rose-700 block uppercase font-bold">Critical Risk</span>
              <span className="text-xl font-bold text-white print:text-slate-900 tabular-nums">{criticalCount}</span>
            </div>
            <div className="p-3 bg-[#11171e] print:bg-slate-100 rounded-lg border border-[#2a333d] print:border-slate-300">
              <span className="text-[10px] text-amber-400 print:text-amber-700 block uppercase font-bold">High Risk</span>
              <span className="text-xl font-bold text-white print:text-slate-900 tabular-nums">{highCount}</span>
            </div>
            <div className="p-3 bg-[#11171e] print:bg-slate-100 rounded-lg border border-[#2a333d] print:border-slate-300">
              <span className="text-[10px] text-yellow-400 print:text-yellow-700 block uppercase font-bold">Medium Risk</span>
              <span className="text-xl font-bold text-white print:text-slate-900 tabular-nums">{mediumCount}</span>
            </div>
            <div className="p-3 bg-[#11171e] print:bg-slate-100 rounded-lg border border-[#2a333d] print:border-slate-300">
              <span className="text-[10px] text-sky-400 print:text-sky-700 block uppercase font-bold">Low / Info</span>
              <span className="text-xl font-bold text-white print:text-slate-900 tabular-nums">{lowCount}</span>
            </div>
          </div>
        </div>

        {/* Section 2: Scope & Execution Parameters */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-white print:text-slate-900 uppercase font-mono tracking-wider border-b border-[#2a333d] print:border-slate-300 pb-1">
            02. Assessment Scope & Safety Boundaries
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1 text-slate-300 print:text-slate-700">
              <div><span className="text-slate-500 font-medium">Target Hostname:</span> {target?.hostname}</div>
              <div><span className="text-slate-500 font-medium">Allowed Ports:</span> {target?.allowed_ports?.join(', ')}</div>
              <div><span className="text-slate-500 font-medium">Excluded Routes:</span> {target?.excluded_paths?.join(', ')}</div>
            </div>
            <div className="space-y-1 text-slate-300 print:text-slate-700">
              <div><span className="text-slate-500 font-medium">Rate Limit:</span> {target?.rate_limit_rps} requests/sec</div>
              <div><span className="text-slate-500 font-medium">Observed Wire Traffic:</span> {scan?.observed_request_count || 0} requests</div>
              <div><span className="text-slate-500 font-medium">Egress Proxy Status:</span> Active (Anti-SSRF Enforced)</div>
            </div>
          </div>
        </div>

        {/* Section 3: OWASP Top 10:2025 Coverage */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-white print:text-slate-900 uppercase font-mono tracking-wider border-b border-[#2a333d] print:border-slate-300 pb-1">
            03. OWASP Top 10:2025 Coverage Mapping
          </h2>
          <p className="text-xs text-slate-400 print:text-slate-600">
            Audit coverage status derived strictly from executed test records. Untested areas are explicitly flagged.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
            {coverage.map((c) => (
              <div
                key={c.category_code}
                className="p-2.5 bg-[#11171e] print:bg-slate-50 border border-[#2a333d] print:border-slate-200 rounded flex items-center justify-between"
              >
                <div>
                  <span className="font-bold text-[#83cfc0] print:text-slate-800 mr-2">{c.category_code}</span>
                  <span className="text-slate-300 print:text-slate-700">{c.category_title.split('- ')[1] || c.category_title}</span>
                </div>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded uppercase font-semibold ${
                    c.status === 'tested'
                      ? 'text-emerald-400 bg-emerald-950/60 print:bg-emerald-100 print:text-emerald-800'
                      : c.status === 'partially_tested'
                      ? 'text-[#83cfc0] bg-[#142620] print:bg-cyan-100 print:text-cyan-800'
                      : 'text-amber-400 bg-amber-950/60 print:bg-amber-100 print:text-amber-800'
                  }`}
                >
                  {c.status.replace('_', ' ')}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Section 4: Detailed Technical Findings Log */}
        <div className="space-y-4 print-page-break">
          <h2 className="text-sm font-bold text-white print:text-slate-900 uppercase font-mono tracking-wider border-b border-[#2a333d] print:border-slate-300 pb-1">
            04. Detailed Vulnerability Findings & Technical Proof
          </h2>

          {findings.length > 0 ? (
            findings.map((f, idx) => (
              <div
                key={f.id}
                className="p-4 bg-[#11171e] print:bg-white border border-[#2a333d] print:border-slate-300 rounded-lg space-y-3 text-xs"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-slate-500 font-bold">#{idx + 1}</span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold uppercase ${
                          f.source_severity === 'CRITICAL'
                            ? 'bg-rose-950/80 text-rose-300 print:bg-rose-100 print:text-rose-800'
                            : f.source_severity === 'HIGH'
                            ? 'bg-amber-950/80 text-amber-300 print:bg-amber-100 print:text-amber-800'
                            : 'bg-yellow-950/80 text-yellow-300 print:bg-yellow-100 print:text-yellow-800'
                        }`}
                      >
                        {f.source_severity}
                      </span>
                      <span className="font-mono text-[#83cfc0] print:text-slate-700 font-semibold">{f.owasp_category_code}</span>
                      <span className="font-mono text-slate-400">{f.cwe_id}</span>
                    </div>
                    <h3 className="text-sm font-bold text-white print:text-slate-900">
                      {f.title}
                    </h3>
                    <div className="font-mono text-[11px] text-slate-400 print:text-slate-600 mt-0.5">
                      URL: {f.affected_url}
                    </div>
                  </div>

                  <div className="text-right font-mono text-[11px] text-slate-400 shrink-0">
                    <div>CVSS: {f.official_cvss_score || 'N/A'}</div>
                    <div className="text-[#83cfc0] print:text-slate-800">Priority: {f.contextual_remediation_priority.toFixed(1)}/10</div>
                  </div>
                </div>

                {/* Evidence Snippet */}
                {f.evidence?.[0] && (
                  <div className="border border-[#2a333d] print:border-slate-200 rounded p-2.5 bg-[#0c1015] print:bg-slate-50 text-[11px] font-mono overflow-x-auto space-y-1">
                    <div className="text-slate-500 print:text-slate-600 text-[10px] uppercase">Redacted Request Evidence:</div>
                    <div className="text-[#a1e2d5] print:text-slate-800 truncate">{f.evidence[0].request_headers}</div>
                    <div className="text-slate-500 print:text-slate-600 text-[10px] uppercase pt-1">Response Evidence:</div>
                    <div className="text-slate-300 print:text-slate-700 truncate">{f.evidence[0].response_body_snippet}</div>
                  </div>
                )}

                {/* Remediation */}
                <div className="space-y-1">
                  <div className="font-semibold text-slate-200 print:text-slate-800">Remediation Guidance:</div>
                  <p className="text-slate-400 print:text-slate-600 leading-relaxed">{f.remediation_guidance}</p>
                </div>
              </div>
            ))
          ) : (
            <div className="py-6 text-slate-500 text-xs">No vulnerabilities recorded in this scan execution.</div>
          )}
        </div>

        {/* Section 5: Academic Research Limitations */}
        <div className="border-t border-[#2a333d] print:border-slate-300 pt-6 space-y-2 text-xs text-slate-400 print:text-slate-600">
          <div className="font-bold text-white print:text-slate-900 uppercase font-mono">
            05. Academic Methodology & Research Prototype Limitations
          </div>
          <p className="leading-relaxed">
            ProofVAPT is developed as an MSc Cyber Security research prototype. Automated security scanners cannot replace manual penetration testing or architectural threat modeling. Logical access flaws, complex business-logic race conditions, and second-order server-side vulnerabilities require contextual human verification. All assessments were executed strictly against authorized targets adhering to non-destructive testing policies.
          </p>
        </div>
      </div>
    </div>
  );
};
