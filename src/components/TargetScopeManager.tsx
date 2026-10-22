import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Globe,
  Sliders,
  Play
} from 'lucide-react';
import { TargetProfile, ScanProfile } from '../types/proofvapt.js';

interface TargetScopeManagerProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (target: Partial<TargetProfile>, scanProfile: ScanProfile) => Promise<void>;
  onSeedLab: () => void;
}

export const TargetScopeManager: React.FC<TargetScopeManagerProps> = ({
  isOpen,
  onClose,
  onSubmit,
  onSeedLab
}) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [name, setName] = useState('');
  const [mode, setMode] = useState<'live' | 'lab'>('live');
  const [scanProfile, setScanProfile] = useState<ScanProfile>('passive_only');
  const [allowedPorts, setAllowedPorts] = useState('80, 443');
  const [excludedPaths, setExcludedPaths] = useState('/logout, /admin/delete');
  const [rateLimit, setRateLimit] = useState(10);
  const [requestBudget, setRequestBudget] = useState(2000);
  const [labConfirmed, setLabConfirmed] = useState(false);
  const [activeConfirmed, setActiveConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const isPrivateOrLocal =
    targetUrl.includes('localhost') ||
    targetUrl.includes('127.0.0.1') ||
    targetUrl.includes('10.') ||
    targetUrl.includes('192.168.') ||
    targetUrl.includes('172.');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!targetUrl) {
      setError('Target URL is required');
      return;
    }

    try {
      const parsed = new URL(targetUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        setError('URL must begin with http:// or https://');
        return;
      }
    } catch {
      setError('Please enter a valid HTTP/HTTPS URL');
      return;
    }

    if (isPrivateOrLocal && mode !== 'lab') {
      setError('Private network & localhost destinations are only permitted under "Isolated Lab Benchmark" mode.');
      return;
    }

    if (isPrivateOrLocal && !labConfirmed) {
      setError('You must confirm that this private target runs inside an isolated lab network with egress restrictions.');
      return;
    }

    if (scanProfile === 'standard_active' && !activeConfirmed) {
      setError('Active scanning requires explicit scope authorization confirmation.');
      return;
    }

    setIsSubmitting(true);
    try {
      const ports = allowedPorts
        .split(',')
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !isNaN(p) && p > 0 && p <= 65535);

      const exclusions = excludedPaths
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean);

      await onSubmit(
        {
          name: name || new URL(targetUrl).hostname,
          mode,
          target_url: targetUrl,
          allowed_ports: ports.length > 0 ? ports : [80, 443],
          excluded_paths: exclusions,
          rate_limit_rps: rateLimit,
          max_request_budget: requestBudget,
          is_isolated_lab_network_confirmed: labConfirmed,
          active_scan_scope_confirmed: activeConfirmed
        },
        scanProfile
      );
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickJuiceShop = () => {
    setTargetUrl('http://localhost:3000');
    setName('OWASP Juice Shop (Local Lab Benchmark)');
    setMode('lab');
    setScanProfile('standard_active');
    setAllowedPorts('80, 443, 3000');
    setRateLimit(15);
    setRequestBudget(2500);
    setLabConfirmed(true);
    setActiveConfirmed(true);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl w-full max-w-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-[#1F2937] bg-slate-900/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-950/70 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                Register Target & Configure Scope
              </h3>
              <p className="text-xs text-slate-400">
                Define authorized boundary, egress rate limits, and scan policies.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 overflow-y-auto space-y-4 text-xs font-sans">
          {error && (
            <div className="p-3 bg-rose-950/50 border border-rose-800 text-rose-300 rounded-lg text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Quick Benchmark Preset */}
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
            <div>
              <div className="font-semibold text-white">Preset: OWASP Juice Shop Lab</div>
              <div className="text-[11px] text-slate-400">Quick-load configured local vulnerable benchmark target.</div>
            </div>
            <button
              type="button"
              onClick={handleQuickJuiceShop}
              className="px-3 py-1.5 text-xs font-medium text-cyan-300 bg-cyan-950/80 hover:bg-cyan-900/80 border border-cyan-800 rounded-lg transition-colors"
            >
              Load Lab Preset
            </button>
          </div>

          {/* Operational Mode Segmented Control */}
          <div className="space-y-1.5">
            <label className="font-semibold text-slate-300">Operational Mode</label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setMode('live')}
                className={`p-2.5 rounded-lg border text-left transition-all ${
                  mode === 'live'
                    ? 'bg-cyan-950/40 border-cyan-500/60 text-white shadow-sm'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="font-semibold text-xs">Live Authorized Assessment</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Strict anti-SSRF; public domain targets only</div>
              </button>
              <button
                type="button"
                onClick={() => setMode('lab')}
                className={`p-2.5 rounded-lg border text-left transition-all ${
                  mode === 'lab'
                    ? 'bg-cyan-950/40 border-cyan-500/60 text-white shadow-sm'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="font-semibold text-xs">Isolated Lab Benchmark</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Allows local container & lab targets (Juice Shop/DVWA)</div>
              </button>
            </div>
          </div>

          {/* Target URL */}
          <div className="space-y-1.5">
            <label className="font-semibold text-slate-300">Target Base URL *</label>
            <input
              type="text"
              placeholder="https://app.example.com or http://localhost:3000"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full bg-[#080C14] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Target Name */}
          <div className="space-y-1.5">
            <label className="font-semibold text-slate-300">Target Friendly Name (Optional)</label>
            <input
              type="text"
              placeholder="e.g. Staging Customer Portal"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-[#080C14] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Scan Profile */}
          <div className="space-y-1.5">
            <label className="font-semibold text-slate-300">Testing Profile</label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setScanProfile('passive_only')}
                className={`p-2 rounded-lg border text-center transition-all ${
                  scanProfile === 'passive_only'
                    ? 'bg-slate-800 border-cyan-500 text-cyan-300 font-semibold'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400'
                }`}
              >
                Passive Only
              </button>
              <button
                type="button"
                onClick={() => setScanProfile('standard_active')}
                className={`p-2 rounded-lg border text-center transition-all ${
                  scanProfile === 'standard_active'
                    ? 'bg-slate-800 border-cyan-500 text-cyan-300 font-semibold'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400'
                }`}
              >
                Standard Active
              </button>
              <button
                type="button"
                onClick={() => setScanProfile('authenticated_lab')}
                className={`p-2 rounded-lg border text-center transition-all ${
                  scanProfile === 'authenticated_lab'
                    ? 'bg-slate-800 border-cyan-500 text-cyan-300 font-semibold'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400'
                }`}
              >
                Authenticated Lab
              </button>
            </div>
          </div>

          {/* Ports & Exclusions */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">Permitted Ports Whitelist</label>
              <input
                type="text"
                placeholder="80, 443, 8080"
                value={allowedPorts}
                onChange={(e) => setAllowedPorts(e.target.value)}
                className="w-full bg-[#080C14] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">Path Exclusions</label>
              <input
                type="text"
                placeholder="/logout, /delete"
                value={excludedPaths}
                onChange={(e) => setExcludedPaths(e.target.value)}
                className="w-full bg-[#080C14] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>

          {/* Rate Limit & Request Budget */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">Egress Rate Limit (req/sec)</label>
              <input
                type="number"
                min="1"
                max="50"
                value={rateLimit}
                onChange={(e) => setRateLimit(parseInt(e.target.value, 10))}
                className="w-full bg-[#080C14] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-300">Max Request Budget (Stop Condition)</label>
              <input
                type="number"
                min="100"
                max="10000"
                value={requestBudget}
                onChange={(e) => setRequestBudget(parseInt(e.target.value, 10))}
                className="w-full bg-[#080C14] border border-[#1F2937] rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>

          {/* SSRF & Lab Network Confirmation */}
          {isPrivateOrLocal && (
            <div className="p-3 bg-amber-950/20 border border-amber-800/40 rounded-lg space-y-2">
              <div className="font-semibold text-amber-400 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" />
                <span>Private Target Isolation Enforcement</span>
              </div>
              <label className="flex items-start gap-2 cursor-pointer text-slate-300 text-[11px]">
                <input
                  type="checkbox"
                  checked={labConfirmed}
                  onChange={(e) => setLabConfirmed(e.target.checked)}
                  className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                />
                <span>
                  I confirm that this private network or localhost endpoint is hosted in an isolated lab container network with egress restrictions.
                </span>
              </label>
            </div>
          )}

          {/* Active Scan Disclaimer */}
          {scanProfile === 'standard_active' && (
            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2">
              <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Scope Authorization Confirmation</span>
              </div>
              <label className="flex items-start gap-2 cursor-pointer text-slate-300 text-[11px]">
                <input
                  type="checkbox"
                  checked={activeConfirmed}
                  onChange={(e) => setActiveConfirmed(e.target.checked)}
                  className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                />
                <span>
                  I certify that I am explicitly authorized to perform non-destructive security vulnerability testing against this target system.
                </span>
              </label>
            </div>
          )}

          {/* Form Actions */}
          <div className="pt-3 border-t border-[#1F2937] flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-lg transition-colors shadow-sm shadow-cyan-950"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isSubmitting ? 'Starting Scan...' : 'Start Assessment'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
