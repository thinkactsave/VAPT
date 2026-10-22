import React from 'react';
import {
  LayoutDashboard,
  Cpu,
  Globe,
  Bug,
  Grid,
  CheckCircle2,
  FileText,
  FlaskConical,
  ShieldAlert
} from 'lucide-react';
import { ScanExecution } from '../types/proofvapt.js';

interface SidebarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  activeScan?: ScanExecution;
  endpointsCount: number;
  findingsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  activeScan,
  endpointsCount,
  findingsCount
}) => {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    {
      id: 'pipeline',
      label: 'Scan activity',
      icon: Cpu,
      badge: activeScan?.status === 'running' ? 'Active' : undefined,
      badgeColor: 'text-cyan-400 bg-cyan-950/60'
    },
    {
      id: 'surface',
      label: 'Attack Surface',
      icon: Globe,
      badge: endpointsCount > 0 ? String(endpointsCount) : undefined
    },
    {
      id: 'findings',
      label: 'Findings & Verification',
      icon: Bug,
      badge: findingsCount > 0 ? String(findingsCount) : undefined,
      badgeColor: 'text-amber-400 bg-amber-950/60'
    },
    { id: 'owasp', label: 'OWASP 2025 Matrix', icon: Grid },
    { id: 'benchmarks', label: 'Research Benchmarks', icon: FlaskConical },
    { id: 'report', label: 'Report', icon: FileText }
  ];

  return (
    <aside className="w-64 bg-[#0B0F17] border-r border-[#1F2937] flex flex-col shrink-0 min-h-[calc(100vh-57px)]">
      {/* Target Scope Card in Sidebar */}
      <div className="p-4 border-b border-[#1F2937]">
        <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
          Authorized Scope Target
        </div>
        {activeScan?.target ? (
          <div className="space-y-1">
            <div className="text-xs font-semibold text-white truncate" title={activeScan.target.target_url}>
              {activeScan.target.name}
            </div>
            <div className="text-[11px] font-mono text-cyan-400 truncate">
              {activeScan.target.target_url}
            </div>
            <div className="flex items-center gap-2 text-[10px] text-slate-400 pt-1">
              <span>Ports: {activeScan.target.allowed_ports.join(', ')}</span>
              <span>·</span>
              <span className="capitalize">{activeScan.scan_profile.replace('_', ' ')}</span>
            </div>
          </div>
        ) : (
          <div className="text-xs text-slate-500 italic">
            No active scan target selected. Click "New Assessment" to register.
          </div>
        )}
      </div>

      {/* Navigation List */}
      <nav className="flex-1 p-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-lg transition-colors text-left ${
                isActive
                  ? 'bg-slate-800/80 text-cyan-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-medium ${
                    item.badgeColor || 'text-slate-300 bg-slate-800'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* System Status Footnote */}
      <div className="p-3 border-t border-[#1F2937] text-[11px] text-slate-500 space-y-1 font-mono">
        <div className="flex items-center justify-between">
          <span>Egress Proxy</span>
          <span className={activeScan?.status === 'running' ? 'text-emerald-400' : 'text-slate-500'}>
            {activeScan?.status === 'running' ? 'Active for scan' : 'Starts with scan'}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span>Worker Supervisor</span>
          <span className="text-slate-500">Node workers</span>
        </div>
      </div>
    </aside>
  );
};
