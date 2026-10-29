import React from 'react';
import { Shield, Plus, MessageSquare } from 'lucide-react';

interface NavbarProps {
  onNewScan: () => void;
  hasResult: boolean;
  isChatOpen: boolean;
  onToggleChat: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onNewScan,
  hasResult,
  isChatOpen,
  onToggleChat,
}) => {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#0B1120]/95 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3.5 sm:px-6 lg:px-8">
        {/* Brand Title */}
        <button
          type="button"
          onClick={onNewScan}
          className="flex items-center gap-2.5 text-left text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0 hover:text-sky-300 transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400 cursor-pointer"
        >
          <Shield className="h-5 w-5 text-sky-400 shrink-0" aria-hidden="true" />
          <span>CyberShield AI</span>
        </button>

        {/* Actions */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onToggleChat}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              isChatOpen
                ? 'border-sky-400 bg-sky-400/15 text-sky-300'
                : 'border-slate-700 bg-slate-800/70 text-slate-200 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <MessageSquare className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>AI Security Chat</span>
          </button>

          <button
            type="button"
            onClick={onNewScan}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 rounded-lg hover:bg-sky-300 transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400 cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{hasResult ? 'Scan Another URL' : 'New Scan'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
