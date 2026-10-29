import React, { useState } from 'react';
import {
  History,
  Trash2,
  Search,
  Eye,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { RiskClassification, ScanHistoryEntry } from '../types/scanner';

interface ScanHistorySectionProps {
  history: ScanHistoryEntry[];
  historyEnabled: boolean;
  onToggleHistoryEnabled: (enabled: boolean) => void;
  onClearHistory: () => void;
  onSelectHistoryEntry: (entry: ScanHistoryEntry) => void;
  onNavigateToScanner: () => void;
}

function getRiskColorClass(classification: RiskClassification): string {
  switch (classification) {
    case 'LOW RISK INDICATORS':
      return 'text-emerald-400';
    case 'MILD SUSPICION':
      return 'text-amber-300';
    case 'MODERATE RISK':
      return 'text-amber-400';
    case 'HIGH RISK':
      return 'text-rose-400';
    case 'VERY HIGH RISK':
      return 'text-rose-500';
  }
}

function getRiskIcon(classification: RiskClassification) {
  switch (classification) {
    case 'LOW RISK INDICATORS':
      return <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />;
    case 'MILD SUSPICION':
    case 'MODERATE RISK':
      return <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" aria-hidden="true" />;
    case 'HIGH RISK':
    case 'VERY HIGH RISK':
      return <ShieldAlert className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />;
  }
}

export const ScanHistorySection: React.FC<ScanHistorySectionProps> = ({
  history,
  historyEnabled,
  onToggleHistoryEnabled,
  onClearHistory,
  onSelectHistoryEntry,
  onNavigateToScanner,
}) => {
  const [searchQuery, setSearchQuery] = useState('');

  const filteredHistory = history.filter((item) => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return true;
    return (
      item.hostname.toLowerCase().includes(q) ||
      item.registrableDomain.toLowerCase().includes(q) ||
      item.classification.toLowerCase().includes(q)
    );
  });

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8 space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Local Scan History
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Review previous URL scan summaries stored locally in your browser without reopening links.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Toggle History Persistence */}
          <label className="inline-flex items-center gap-2.5 text-xs sm:text-sm font-medium text-slate-200 bg-[#111827] border border-slate-800 rounded-lg px-3.5 py-2 cursor-pointer">
            <input
              type="checkbox"
              checked={historyEnabled}
              onChange={(e) => onToggleHistoryEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-sky-400 focus:ring-sky-400"
            />
            <span>Save Scan History Locally</span>
          </label>

          <button
            type="button"
            onClick={onClearHistory}
            disabled={history.length === 0}
            className="inline-flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-950/20 px-3.5 py-2 text-xs sm:text-sm font-medium text-rose-300 hover:bg-rose-950/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Trash2 className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Privacy & Storage Transparency Notice */}
      <div className="rounded-xl border border-slate-800 bg-[#111827] p-4 flex items-start gap-3 text-xs sm:text-sm text-slate-300">
        <Info className="h-5 w-5 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
        <div className="space-y-1">
          <p className="font-medium text-slate-200">
            Local Browser Storage & Redaction Policy
          </p>
          <p className="text-slate-400 leading-relaxed">
            Scan history is kept only inside your browser&apos;s <code className="font-mono text-slate-300">localStorage</code> and is never transmitted to external servers. Query parameter values (which may contain session tokens or personal identifiers) are automatically redacted before storage. Note that browser local storage is not encrypted storage—use the toggle above to disable history on shared computers.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      {history.length > 0 && (
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          <div className="relative max-w-md flex-1">
            <Search
              className="h-4 w-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2"
              aria-hidden="true"
            />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by domain or risk classification..."
              aria-label="Filter scan history by domain or risk classification"
              className="w-full rounded-lg border border-slate-800 bg-[#111827] pl-10 pr-4 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"
            />
          </div>
          <div className="text-xs text-slate-400 font-mono tabular-nums">
            Showing {filteredHistory.length} of {history.length} saved scans
          </div>
        </div>
      )}

      {/* History Table / Empty State */}
      {history.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#111827] py-14 px-6 text-center">
          <History className="h-10 w-10 text-slate-500 mx-auto mb-3" aria-hidden="true" />
          <h2 className="text-base font-semibold text-slate-200">
            {historyEnabled ? 'No Saved Scans Yet' : 'Scan History Is Disabled'}
          </h2>
          <p className="mt-1.5 text-sm text-slate-400 max-w-md mx-auto">
            {historyEnabled
              ? 'When you analyze URLs in the scanner, their domain, risk score, and summary will appear here for quick reference.'
              : 'Local scan history is currently turned off. Enable "Save Scan History Locally" above if you want to retain scan summaries in this browser.'}
          </p>
          <button
            type="button"
            onClick={onNavigateToScanner}
            className="mt-5 inline-flex items-center gap-2 rounded-lg bg-sky-400 px-4 py-2.5 text-xs font-semibold text-slate-950 hover:bg-sky-300 transition-colors cursor-pointer"
          >
            Go to URL Scanner
          </button>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800 bg-[#111827] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs font-semibold text-slate-400 bg-slate-900/50">
                  <th className="py-3.5 px-4">Scanned Domain</th>
                  <th className="py-3.5 px-4">Risk Classification</th>
                  <th className="py-3.5 px-4 text-right">Risk Score</th>
                  <th className="py-3.5 px-4">Timestamp</th>
                  <th className="py-3.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-sm">
                {filteredHistory.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3.5 px-4">
                      <div className="font-mono font-medium text-slate-100">
                        {entry.hostname}
                      </div>
                      <div className="font-mono text-xs text-slate-400 truncate max-w-xs sm:max-w-md">
                        Registrable: {entry.registrableDomain} · {entry.redactedUrl}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        {getRiskIcon(entry.classification)}
                        <span
                          className={`text-xs font-semibold ${getRiskColorClass(
                            entry.classification
                          )}`}
                        >
                          {entry.classification}
                        </span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-right font-mono font-semibold tabular-nums text-slate-100">
                      {entry.riskScore} / 100
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-400 tabular-nums whitespace-nowrap">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onSelectHistoryEntry(entry)}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-sky-300 hover:bg-slate-700 hover:text-white transition-colors cursor-pointer"
                      >
                        <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Inspect Summary</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
