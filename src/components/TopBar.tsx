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
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 bg-[#0B0F17] border-b border-[#1F2937] shrink-0 sticky top-0 z-30">
      {/* Zone 1: Single text element wordmark */}
      <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
        <div className="w-8 h-8 rounded-lg bg-cyan-950/70 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
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
            activeTab === 'overview' ? 'text-cyan-400' : ''
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => onSelectTab('pipeline')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'pipeline' ? 'text-cyan-400' : ''
          }`}
        >
          Pipeline
        </button>
        <button
          onClick={() => onSelectTab('surface')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'surface' ? 'text-cyan-400' : ''
          }`}
        >
          Attack Surface
        </button>
        <button
          onClick={() => onSelectTab('findings')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'findings' ? 'text-cyan-400' : ''
          }`}
        >
          Findings & Verification
        </button>
        <button
          onClick={() => onSelectTab('owasp')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'owasp' ? 'text-cyan-400' : ''
          }`}
        >
          OWASP 2025 Matrix
        </button>
        <button
          onClick={() => onSelectTab('benchmarks')}
          className={`transition-colors whitespace-nowrap shrink-0 hover:text-white ${
            activeTab === 'benchmarks' ? 'text-cyan-400' : ''
          }`}
        >
          Research Benchmarks
        </button>
      </nav>

      {/* Zone 3: 1 primary action button */}
      <div className="flex items-center gap-3 shrink-0">
        {toolStatus && (
          <div className="hidden xl:flex items-center gap-2 text-xs text-slate-400 bg-slate-900/60 border border-slate-800 rounded-md px-2.5 py-1 font-mono">
            <span className="flex items-center gap-1 text-slate-300">
              <Terminal className="w-3 h-3 text-cyan-400" />
              ffuf v{toolStatus.ffuf.version.split(' ')[0]}
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-300">ZAP v{toolStatus.zap.version}</span>
          </div>
        )}
        <button
          onClick={onOpenTargetModal}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 rounded-lg hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0 shadow-sm shadow-cyan-950"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Assessment</span>
        </button>
      </div>
    </header>
  );
};
