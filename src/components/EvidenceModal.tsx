import React, { useState } from 'react';
import { X, Copy, Check, ShieldCheck, AlertTriangle, ExternalLink } from 'lucide-react';
import { UnifiedFinding } from '../types/proofvapt.js';

interface EvidenceModalProps {
  finding: UnifiedFinding | null;
  onClose: () => void;
  onRetest: (findingId: string, simulatedFix?: boolean) => void;
  isRetesting?: boolean;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({
  finding,
  onClose,
  onRetest,
  isRetesting
}) => {
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const evidence = finding.evidence?.[0];

  const handleCopy = () => {
    const text = `Title: ${finding.title}\nURL: ${finding.affected_url}\nCategory: ${finding.owasp_category}\nCVSS: ${finding.official_cvss_score || 'N/A'}\n\n--- REQUEST ---\n${evidence?.request_headers || ''}\n\n--- RESPONSE ---\n${evidence?.response_headers || ''}\n\n${evidence?.response_body_snippet || ''}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-[#1F2937] flex items-start justify-between gap-4 bg-slate-900/60">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold uppercase ${
                  finding.source_severity === 'CRITICAL'
                    ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                    : finding.source_severity === 'HIGH'
                    ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                    : 'bg-yellow-950/80 text-yellow-300 border border-yellow-800'
                }`}
              >
                {finding.source_severity}
              </span>
              <span className="text-slate-500 font-mono text-xs">{finding.cwe_id}</span>
              <span className="text-slate-600">·</span>
              <span className="text-xs text-cyan-400 font-mono">{finding.owasp_category}</span>
            </div>
            <h3 className="text-base font-bold text-white tracking-tight">
              {finding.title}
            </h3>
            <p className="text-xs font-mono text-slate-400 mt-0.5 truncate">
              Affected: {finding.affected_url}
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors font-mono"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Evidence'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto space-y-5 text-xs font-sans">
          {/* Metadata Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
              <span className="text-slate-500 text-[10px] uppercase font-mono tracking-wider block">Official CVSS v3.1</span>
              <span className="text-sm font-bold text-white font-mono tabular-nums">
                {finding.official_cvss_score ? `${finding.official_cvss_score} / 10.0` : 'N/A'}
              </span>
              <span className="text-[10px] text-slate-500 block truncate font-mono mt-0.5">
                {finding.official_cvss_vector || 'Base metric from source tool'}
              </span>
            </div>

            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
              <span className="text-slate-500 text-[10px] uppercase font-mono tracking-wider block">Contextual Priority (CRP)</span>
              <span className="text-sm font-bold text-cyan-400 font-mono tabular-nums">
                {finding.contextual_remediation_priority.toFixed(1)} / 10.0
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">Asset criticality & verification state</span>
            </div>

            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
              <span className="text-slate-500 text-[10px] uppercase font-mono tracking-wider block">Provenance Tools</span>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {finding.sources?.map((s) => (
                  <span key={s.id} className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-slate-800 text-slate-300 border border-slate-700">
                    {s.tool_name}: {s.source_alert_id}
                  </span>
                )) || <span className="text-slate-500">tls_prober</span>}
              </div>
            </div>
          </div>

          {/* Verification Notes */}
          <div className="p-3.5 bg-cyan-950/20 border border-cyan-800/40 rounded-lg space-y-1">
            <div className="font-semibold text-cyan-300 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" />
              <span>Verification Diagnostic Notes</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              {finding.verification_notes}
            </p>
          </div>

          {/* Raw Request / Response Inspector with Token Redaction */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
              Redacted Technical Evidence
            </h4>

            {/* Request Box */}
            <div className="border border-slate-800 rounded-lg overflow-hidden bg-[#080C14]">
              <div className="px-3 py-1.5 bg-slate-900 text-slate-400 font-mono text-[11px] border-b border-slate-800 flex items-center justify-between">
                <span>Outgoing Probe Request</span>
                <span className="text-slate-500 text-[10px]">Credentials & Tokens Redacted</span>
              </div>
              <pre className="p-3 text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {evidence?.request_headers || 'GET / HTTP/1.1\r\nHost: target\r\nAuthorization: Bearer [REDACTED]\r\nCookie: session=[REDACTED]'}
                {evidence?.request_body && `\r\n\r\n${evidence.request_body}`}
              </pre>
            </div>

            {/* Response Box */}
            <div className="border border-slate-800 rounded-lg overflow-hidden bg-[#080C14]">
              <div className="px-3 py-1.5 bg-slate-900 text-slate-400 font-mono text-[11px] border-b border-slate-800 flex items-center justify-between">
                <span>Target Server Response</span>
                <span className="text-slate-500 text-[10px]">Evidence Trigger: {evidence?.matched_pattern || 'Behavioral'}</span>
              </div>
              <pre className="p-3 text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {evidence?.response_headers && `${evidence.response_headers}\r\n\r\n`}
                {evidence?.response_body_snippet || 'No raw body captured'}
              </pre>
            </div>
          </div>

          {/* Remediation Guidance */}
          <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1">
            <div className="font-semibold text-white">Recommended Remediation Playbook</div>
            <p className="text-slate-300 leading-relaxed">
              {finding.remediation_guidance}
            </p>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-[#1F2937] bg-slate-900/60 flex items-center justify-between">
          <div className="text-xs text-slate-500 font-mono">
            Remediation Status: <span className="font-semibold text-slate-300 uppercase">{finding.remediation_status}</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onRetest(finding.id, true)}
              disabled={isRetesting}
              className="px-3.5 py-1.5 text-xs font-medium text-emerald-400 bg-emerald-950/70 hover:bg-emerald-900/70 border border-emerald-800 rounded-lg transition-colors whitespace-nowrap"
            >
              Simulate Patch & Verify
            </button>
            <button
              onClick={() => onRetest(finding.id, false)}
              disabled={isRetesting}
              className="px-4 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors whitespace-nowrap shadow-sm"
            >
              {isRetesting ? 'Probing...' : 'Retest Live Target'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
