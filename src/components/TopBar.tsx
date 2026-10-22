import React from 'react';
import { ShieldCheck, Plus, Terminal } from 'lucide-react';

interface TopBarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  onOpenTargetModal: () => void;
  toolStatus?: {
    ffuf: { installed: boolean; version: string };
    zap: { installed: boolean; version: string };
  };
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  onSelectTab,
  onOpenTargetModal,
  toolStatus
}) => {
  return (
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 bg-[#0d1116] border-b border-[#2a333d] shrink-0 sticky top-0 z-30">
      {/* Zone 1: Single text element wordmark */}
      <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
        <div className="w-8 h-8 rounded-lg bg-cyan-950/70 border border-[#4e9385]/30 flex items-center justify-center text-[#83cfc0]">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-base font-bold tracking-tight text-white font-['Plus_Jakarta_Sans']">
            ProofVAPT
          </span>
          <span className="text-xs text-slate-500 hidden sm:inline">
            Automated Web App Pentesting & Verification
          </span>
        </div>
      </div>

      {/* Zone 2: 4-5 clean single-line navigation links */}
      <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-400">
        <button
          onClick={() => onSelectTab('overview')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'overview' ? 'text-[#83cfc0]' : ''
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => onSelectTab('pipeline')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'pipeline' ? 'text-[#83cfc0]' : ''
          }`}
        >
          Pipeline
        </button>
        <button
          onClick={() => onSelectTab('surface')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'surface' ? 'text-[#83cfc0]' : ''
          }`}
        >
          Attack Surface
        </button>
        <button
          onClick={() => onSelectTab('findings')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'findings' ? 'text-[#83cfc0]' : ''
          }`}
        >
          Findings & Verification
        </button>
        <button
          onClick={() => onSelectTab('owasp')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'owasp' ? 'text-[#83cfc0]' : ''
          }`}
        >
          OWASP 2025 Matrix
        </button>
        <button
          onClick={() => onSelectTab('benchmarks')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'benchmarks' ? 'text-[#83cfc0]' : ''
          }`}
        >
          Research Benchmarks
        </button>
      </nav>

      {/* Zone 3: 1 primary action button */}
      <div className="flex items-center gap-3 shrink-0">
        {toolStatus && (
          <div className="hidden xl:flex items-center gap-2 text-xs text-slate-400 bg-[#11171e] border border-[#2a333d] rounded-md px-2.5 py-1 font-mono">
            <span className="flex items-center gap-1 text-slate-300">
              <Terminal className="w-3 h-3 text-[#83cfc0]" />
              ffuf v{toolStatus.ffuf.version.split(' ')[0]}
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-300">ZAP v{toolStatus.zap.version}</span>
          </div>
        )}
        <button
          onClick={onOpenTargetModal}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-[#0a1714] bg-[#83cfc0] rounded-lg hover:bg-[#a1e2d5] transition-colors whitespace-nowrap shrink-0 shadow-sm shadow-cyan-950"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Assessment</span>
        </button>
      </div>
    </header>
  );
};
