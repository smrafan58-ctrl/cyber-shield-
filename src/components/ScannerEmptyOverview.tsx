import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Globe,
  BookOpen,
  ArrowRight,
} from 'lucide-react';
import { EXAMPLE_TEST_FIXTURES } from '../engine/urlAnalyzer';

interface ScannerEmptyOverviewProps {
  onSelectFixtureUrl: (url: string) => void;
  onOpenSafetyGuide: () => void;
}

export const ScannerEmptyOverview: React.FC<ScannerEmptyOverviewProps> = ({
  onSelectFixtureUrl,
  onOpenSafetyGuide,
}) => {
  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8 space-y-10">
      {/* 3-Column Overview of What the Engine Analyzes */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="rounded-xl border border-slate-800 bg-[#111827] p-6">
          <div className="flex items-center gap-2.5 text-sky-400 mb-3">
            <Globe className="h-5 w-5 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-100">
              Domain & Subdomain Hierarchy
            </h2>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
            Extracts the true registrable domain, subdomain depth, top-level suffix, port, and protocol so deceptive prefixes like <code className="font-mono text-slate-300">google.com.security-check.example.org</code> are exposed immediately.
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-6">
          <div className="flex items-center gap-2.5 text-amber-400 mb-3">
            <AlertTriangle className="h-5 w-5 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-100">
              Brand Spoofing & Typosquatting
            </h2>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
            Detects homoglyph character substitutions (such as <code className="font-mono text-slate-300">paypa1</code> or <code className="font-mono text-slate-300">g00gle</code>), Punycode IDNs, <code className="font-mono text-slate-300">@</code> authority deception, and fake banking or digital arrest scam paths.
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-6">
          <div className="flex items-center gap-2.5 text-emerald-400 mb-3">
            <ShieldCheck className="h-5 w-5 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-100">
              Transparent Heuristic Scoring
            </h2>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
            Every scan produces a reproducible 0–100 risk score backed by explicit indicator explanations, severity labels, and context-aware safety guidance—without opening the target link.
          </p>
        </div>
      </div>

      {/* Benchmark Test Fixtures Section (Single-Elevation Cards) */}
      <section
        aria-labelledby="benchmark-fixtures-heading"
        className="pt-2"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2
              id="benchmark-fixtures-heading"
              className="text-lg font-semibold text-slate-100"
            >
              Interactive URL Verification Fixtures
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
              Select any reference fixture below to run a live deterministic analysis and inspect the breakdown.
            </p>
          </div>
          <button
            type="button"
            onClick={onOpenSafetyGuide}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-400 hover:text-sky-300 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <BookOpen className="h-4 w-4" aria-hidden="true" />
            <span>Read Cybersecurity Safety Guide</span>
          </button>
        </div>

        <div className="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {EXAMPLE_TEST_FIXTURES.map((fixture) => (
            <div
              key={fixture.url}
              className="rounded-xl border border-slate-800 bg-[#111827] p-5 flex flex-col justify-between hover:border-slate-700 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between gap-2 text-xs text-slate-400">
                  <span className="font-medium text-sky-400">
                    {fixture.category}
                  </span>
                </div>
                <div className="mt-2 font-mono text-xs sm:text-sm text-slate-100 break-all">
                  {fixture.url}
                </div>
                <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                  {fixture.description}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex justify-end">
                <button
                  type="button"
                  onClick={() => onSelectFixtureUrl(fixture.url)}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-400 hover:text-sky-300 cursor-pointer"
                >
                  <span>Analyze Fixture</span>
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
