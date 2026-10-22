import React, { useState, useMemo } from 'react';
import { Search, Globe, Filter, ExternalLink, Shield } from 'lucide-react';
import { AttackSurfaceEndpoint } from '../types/proofvapt.js';

interface AttackSurfaceExplorerProps {
  endpoints: AttackSurfaceEndpoint[];
  targetUrl?: string;
}

export const AttackSurfaceExplorer: React.FC<AttackSurfaceExplorerProps> = ({
  endpoints,
  targetUrl
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [originFilter, setOriginFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      const matchesSearch =
        ep.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ep.path.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesOrigin =
        originFilter === 'all' || ep.discovered_by === originFilter;

      let matchesStatus = true;
      if (statusFilter === '2xx') matchesStatus = ep.status_code >= 200 && ep.status_code < 300;
      else if (statusFilter === '3xx') matchesStatus = ep.status_code >= 300 && ep.status_code < 400;
      else if (statusFilter === '4xx') matchesStatus = ep.status_code >= 400 && ep.status_code < 500;
      else if (statusFilter === '5xx') matchesStatus = ep.status_code >= 500;

      return matchesSearch && matchesOrigin && matchesStatus;
    });
  }, [endpoints, searchTerm, originFilter, statusFilter]);

  return (
    <div className="space-y-6">
      {/* Header Strip */}
      <div className="bg-[#141a21] border border-[#2a333d] rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-[#83cfc0] uppercase tracking-wider font-mono">
              Attack Surface Discovery
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-slate-400 font-mono tabular-nums">{endpoints.length} Routes Identified</span>
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Discovered Web Endpoints & Resources
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Aggregated attack surface mapped by <code className="text-[#a1e2d5] font-mono">ffuf</code> content fuzzing, crawler spiders, and HTTP recon.
          </p>
        </div>

        {targetUrl && (
          <div className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-[#2a333d] truncate max-w-sm">
            Base: {targetUrl}
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search discovered paths or parameters..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#141a21] border border-[#2a333d] rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#4e9385] font-mono"
          />
        </div>

        {/* Origin Filter Segmented Control */}
        <div className="flex items-center gap-1 p-1 bg-[#141a21] border border-[#2a333d] rounded-lg shrink-0">
          <button
            onClick={() => setOriginFilter('all')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              originFilter === 'all' ? 'bg-cyan-500/20 text-[#a1e2d5]' : 'text-slate-400 hover:text-white'
            }`}
          >
            All Sources
          </button>
          <button
            onClick={() => setOriginFilter('ffuf')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap font-mono ${
              originFilter === 'ffuf' ? 'bg-cyan-500/20 text-[#a1e2d5]' : 'text-slate-400 hover:text-white'
            }`}
          >
            ffuf ({endpoints.filter((e) => e.discovered_by === 'ffuf').length})
          </button>
          <button
            onClick={() => setOriginFilter('zap_spider')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap font-mono ${
              originFilter === 'zap_spider' ? 'bg-cyan-500/20 text-[#a1e2d5]' : 'text-slate-400 hover:text-white'
            }`}
          >
            ZAP Spider
          </button>
          <button
            onClick={() => setOriginFilter('recon')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap font-mono ${
              originFilter === 'recon' ? 'bg-cyan-500/20 text-[#a1e2d5]' : 'text-slate-400 hover:text-white'
            }`}
          >
            Recon
          </button>
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1 p-1 bg-[#141a21] border border-[#2a333d] rounded-lg shrink-0">
          <button
            onClick={() => setStatusFilter('all')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              statusFilter === 'all' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            All Status
          </button>
          <button
            onClick={() => setStatusFilter('2xx')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap text-emerald-400 ${
              statusFilter === '2xx' ? 'bg-emerald-950/60' : 'hover:bg-slate-800/40'
            }`}
          >
            2xx
          </button>
          <button
            onClick={() => setStatusFilter('3xx')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap text-sky-400 ${
              statusFilter === '3xx' ? 'bg-sky-950/60' : 'hover:bg-slate-800/40'
            }`}
          >
            3xx
          </button>
          <button
            onClick={() => setStatusFilter('4xx')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap text-amber-400 ${
              statusFilter === '4xx' ? 'bg-amber-950/60' : 'hover:bg-slate-800/40'
            }`}
          >
            4xx
          </button>
        </div>
      </div>

      {/* High-Density Data Grid */}
      <div className="bg-[#141a21] border border-[#2a333d] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#171e25] border-b border-[#2a333d] text-slate-400 uppercase font-mono tracking-wider">
              <tr>
                <th className="py-3 px-4">Method</th>
                <th className="py-3 px-4">Endpoint Path</th>
                <th className="py-3 px-4 text-center">Status</th>
                <th className="py-3 px-4 text-right">Length</th>
                <th className="py-3 px-4">Content-Type</th>
                <th className="py-3 px-4">Discovered By</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEndpoints.length > 0 ? (
                filteredEndpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2.5 px-4 whitespace-nowrap font-bold text-slate-300">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] ${
                          ep.method === 'GET'
                            ? 'bg-sky-950/60 text-sky-400 border border-sky-800/40'
                            : ep.method === 'POST'
                            ? 'bg-amber-950/60 text-amber-400 border border-amber-800/40'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {ep.method}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 truncate max-w-md">
                      <span className="text-white font-medium">{ep.path}</span>
                    </td>
                    <td className="py-2.5 px-4 text-center whitespace-nowrap tabular-nums">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                          ep.status_code >= 200 && ep.status_code < 300
                            ? 'text-emerald-400 bg-emerald-950/50'
                            : ep.status_code >= 300 && ep.status_code < 400
                            ? 'text-sky-400 bg-sky-950/50'
                            : 'text-amber-400 bg-amber-950/50'
                        }`}
                      >
                        {ep.status_code}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right text-slate-400 tabular-nums">
                      {ep.content_length > 0 ? `${ep.content_length} B` : '-'}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs font-sans text-[11px]">
                      {ep.content_type || 'application/octet-stream'}
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                          ep.discovered_by === 'ffuf'
                            ? 'bg-[#142620] text-[#a1e2d5] border border-[#2b4e48]/40'
                            : 'bg-indigo-950/60 text-indigo-300 border border-indigo-800/40'
                        }`}
                      >
                        {ep.discovered_by}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans text-xs">
                    {endpoints.length === 0
                      ? 'No attack surface endpoints discovered yet. Launch an assessment to populate routes.'
                      : 'No endpoints match current search filter.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
