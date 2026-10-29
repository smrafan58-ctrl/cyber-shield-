import React, { useState } from 'react';
import {
  Search,
  ClipboardPaste,
  XCircle,
  AlertTriangle,
  Lock,
  ShieldCheck,
  History,
  Trash2,
  ArrowUpRight,
} from 'lucide-react';
import { EXAMPLE_TEST_FIXTURES } from '../engine/constants';
import {
  ExampleFixture,
  RiskClassification,
  URLAnalysisResult,
} from '../types/scanner';
import { AudioTranscribeButton } from './AudioTranscribeButton';

function normalizeSpokenUrlTranscript(transcript: string): string {
  const cleaned = transcript
    .trim()
    .replace(/^["'`]+|["'`.,!?]+$/g, '')
    .replace(/\bhttps?\s+colon\s+slash\s+slash\b/gi, 'https://')
    .replace(/\bcolon\s+slash\s+slash\b/gi, '://')
    .replace(/\s+dot\s+/gi, '.')
    .replace(/\s+slash\s+/gi, '/')
    .replace(/\s+dash\s+|\s+hyphen\s+/gi, '-')
    .replace(/\s+/g, '');
  return cleaned;
}

interface URLInputSectionProps {
  urlInput: string;
  onUrlInputChange: (val: string) => void;
  onScanSubmit: (urlToScan?: string) => void;
  onClear: () => void;
  validationError: { title: string; message: string } | null;
  isScanning: boolean;
  inputRef: React.RefObject<HTMLInputElement | null>;
  scanHistory: URLAnalysisResult[];
  onSelectHistoryItem: (item: URLAnalysisResult) => void;
  onClearHistory: () => void;
}

function getHistoryRiskAccent(classification: RiskClassification) {
  switch (classification) {
    case 'LOW RISK INDICATORS':
      return {
        scoreText: 'text-emerald-400',
        barBg: 'bg-emerald-500',
      };
    case 'MILD SUSPICION':
      return {
        scoreText: 'text-amber-300',
        barBg: 'bg-amber-400',
      };
    case 'MODERATE RISK':
      return {
        scoreText: 'text-amber-400',
        barBg: 'bg-amber-500',
      };
    case 'HIGH RISK':
      return {
        scoreText: 'text-rose-400',
        barBg: 'bg-rose-500',
      };
    case 'VERY HIGH RISK':
      return {
        scoreText: 'text-rose-500',
        barBg: 'bg-rose-600',
      };
  }
}

export const URLInputSection: React.FC<URLInputSectionProps> = ({
  urlInput,
  onUrlInputChange,
  onScanSubmit,
  onClear,
  validationError,
  isScanning,
  inputRef,
  scanHistory,
  onSelectHistoryItem,
  onClearHistory,
}) => {
  const [clipboardFeedback, setClipboardFeedback] = useState<string | null>(null);

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onScanSubmit();
  };

  const handlePasteClipboard = async () => {
    setClipboardFeedback(null);
    if (!navigator.clipboard || !navigator.clipboard.readText) {
      setClipboardFeedback(
        'Clipboard read access is restricted by your browser. Please press Ctrl+V or Cmd+V inside the URL box.'
      );
      inputRef.current?.focus();
      return;
    }

    try {
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        setClipboardFeedback('Your clipboard is currently empty.');
        return;
      }
      onUrlInputChange(text.trim());
      setClipboardFeedback(null);
      inputRef.current?.focus();
    } catch {
      setClipboardFeedback(
        'Browser blocked automatic clipboard read in this preview frame. Click the input field and press Ctrl+V (or Cmd+V).'
      );
      inputRef.current?.focus();
    }
  };

  const handleFixtureSelect = (fixture: ExampleFixture) => {
    setClipboardFeedback(null);
    onUrlInputChange(fixture.url);
    onScanSubmit(fixture.url);
  };

  return (
    <section className="py-6 sm:py-8">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 space-y-5">
        {/* Brand Identity & Hero Header */}
        <div className="text-center max-w-3xl mx-auto">
          <p className="text-xs font-semibold tracking-wide text-sky-400 mb-2">
            Scan Smart. Stay Safe. Stop Cyber Threats.
          </p>
          <h1
            className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-white mb-3"
            style={{ textWrap: 'balance' }}
          >
            Is This Link Safe?
          </h1>
          <p className="text-base sm:text-lg text-slate-200 leading-relaxed">
            Check suspicious URLs for phishing patterns, deceptive domains, and other warning signs before visiting them.
          </p>
          <p className="mt-1.5 text-xs sm:text-sm text-slate-400">
            Analyze suspicious URLs and understand the risks before you click.
          </p>
        </div>

        {/* Scanner Form Container */}
        <div className="rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-6 shadow-xl">
          <form onSubmit={handleFormSubmit} noValidate>
            <label
              htmlFor="url-scanner-input"
              className="block text-sm font-medium text-slate-200 mb-2"
            >
              Enter or paste a single URL to inspect
            </label>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="relative flex-1">
                <input
                  ref={inputRef}
                  id="url-scanner-input"
                  type="text"
                  inputMode="url"
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={urlInput}
                  onChange={(e) => {
                    setClipboardFeedback(null);
                    onUrlInputChange(e.target.value);
                  }}
                  placeholder="https://example.com"
                  aria-invalid={Boolean(validationError)}
                  aria-describedby="url-privacy-notice"
                  className="w-full rounded-lg border border-slate-700 bg-[#0B1120] px-4 py-3 text-sm sm:text-base font-mono text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-400/25"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                <button
                  type="submit"
                  disabled={isScanning}
                  className="flex-1 sm:flex-initial inline-flex items-center justify-center gap-2 rounded-lg bg-sky-400 px-5 py-3 text-sm font-semibold text-slate-950 hover:bg-sky-300 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Search className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>{isScanning ? 'Analyzing...' : 'Scan URL'}</span>
                </button>

                <button
                  type="button"
                  onClick={handlePasteClipboard}
                  title="Paste URL from clipboard"
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-3 text-sm font-medium text-slate-200 hover:bg-slate-700 hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <ClipboardPaste className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>Paste</span>
                </button>

                <AudioTranscribeButton
                  mode="url"
                  disabled={isScanning}
                  onStatusMessage={(msg) => setClipboardFeedback(msg)}
                  onTranscribed={(transcript) => {
                    const normalizedUrl = normalizeSpokenUrlTranscript(transcript);
                    setClipboardFeedback(null);
                    onUrlInputChange(normalizedUrl);
                    inputRef.current?.focus();
                  }}
                />

                <button
                  type="button"
                  onClick={() => {
                    setClipboardFeedback(null);
                    onClear();
                  }}
                  disabled={!urlInput && !validationError}
                  title="Clear URL input and reset results"
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/40 px-3.5 py-3 text-sm font-medium text-slate-300 hover:bg-slate-800 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <XCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>Clear</span>
                </button>
              </div>
            </div>

            {/* Clipboard Permission Feedback */}
            {clipboardFeedback && (
              <div
                role="status"
                className="mt-3 rounded-lg border border-amber-500/30 bg-amber-950/30 px-3.5 py-2.5 text-xs text-amber-200"
              >
                {clipboardFeedback}
              </div>
            )}

            {/* Validation Error Notice */}
            {validationError && (
              <div
                role="alert"
                className="mt-4 rounded-lg border border-rose-500/40 bg-rose-950/30 p-4 text-sm text-rose-200"
              >
                <div className="flex items-start gap-3">
                  <AlertTriangle
                    className="h-5 w-5 text-rose-400 shrink-0 mt-0.5"
                    aria-hidden="true"
                  />
                  <div>
                    <h2 className="font-semibold text-rose-300">
                      {validationError.title}
                    </h2>
                    <p className="mt-1 text-rose-200/90 leading-relaxed">
                      {validationError.message}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Privacy & Untrusted Input Notice */}
            <div
              id="url-privacy-notice"
              className="mt-4 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 pt-3 border-t border-slate-800/80"
            >
              <div className="flex items-center gap-2">
                <Lock className="h-3.5 w-3.5 text-sky-400 shrink-0" aria-hidden="true" />
                <span>
                  Safe static inspection: Submitted URLs are never opened, fetched, or executed in your browser.
                </span>
              </div>
              <div className="flex items-center gap-1.5 text-slate-400">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
                <span>Single-URL scope · Query values redacted</span>
              </div>
            </div>
          </form>

          {/* Interactive Test Fixtures */}
          <div className="mt-5 pt-4 border-t border-slate-800/80">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-slate-400 mr-1">
                Try deterministic test URLs:
              </span>
              {EXAMPLE_TEST_FIXTURES.map((fixture) => (
                <button
                  key={fixture.url}
                  type="button"
                  onClick={() => handleFixtureSelect(fixture)}
                  className="px-2.5 py-1 text-xs font-mono rounded-md border border-slate-700/80 bg-slate-800/50 text-slate-300 hover:border-sky-500/50 hover:text-sky-300 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {fixture.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Local Storage Scan History Section (Last 5 Analyzed URLs) */}
        <section
          aria-labelledby="recent-scan-history-heading"
          className="rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-6"
        >
          <div className="flex items-center justify-between gap-4 border-b border-slate-800 pb-3.5">
            <div className="flex items-center gap-2.5">
              <History className="h-4 w-4 text-sky-400 shrink-0" aria-hidden="true" />
              <div>
                <h2
                  id="recent-scan-history-heading"
                  className="text-sm font-semibold text-slate-100"
                >
                  Recent Scan History
                </h2>
                <p className="text-xs text-slate-400">
                  Last 5 analyzed URLs and risk scores saved in local storage for quick reference
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-slate-400 tabular-nums">
                {scanHistory.length} / 5 saved
              </span>
              {scanHistory.length > 0 && (
                <button
                  type="button"
                  onClick={onClearHistory}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-rose-300 transition-colors cursor-pointer"
                >
                  <Trash2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>Clear History</span>
                </button>
              )}
            </div>
          </div>

          {scanHistory.length === 0 ? (
            <div className="py-6 text-center text-xs text-slate-400">
              No URLs scanned yet in this browser. Scan a link above to automatically keep track of your last 5 analyzed URLs and risk scores.
            </div>
          ) : (
            <ul className="divide-y divide-slate-800/80">
              {scanHistory.map((item) => {
                const accent = getHistoryRiskAccent(item.classification);
                return (
                  <li key={item.domain.normalizedUrl || item.id}>
                    <button
                      type="button"
                      onClick={() => onSelectHistoryItem(item)}
                      className="w-full py-3.5 px-2 -mx-2 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-left hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm font-semibold text-slate-100 group-hover:text-sky-300 transition-colors truncate">
                            {item.domain.hostname}
                          </span>
                          <span aria-hidden="true" className="text-slate-600">
                            ·
                          </span>
                          <span className="text-xs text-slate-400 font-mono tabular-nums shrink-0">
                            {item.indicators.length}{' '}
                            {item.indicators.length === 1 ? 'finding' : 'findings'}
                          </span>
                        </div>
                        <p className="mt-0.5 text-xs font-mono text-slate-400 truncate">
                          {item.domain.redactedUrl}
                        </p>
                      </div>

                      <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0">
                        <div className="text-left sm:text-right">
                          <div className="flex items-baseline sm:justify-end gap-1.5 font-mono tabular-nums">
                            <span
                              className={`text-sm font-bold ${accent.scoreText}`}
                            >
                              {item.riskScore}
                            </span>
                            <span className="text-xs text-slate-500">/ 100</span>
                            <span aria-hidden="true" className="text-slate-600">
                              ·
                            </span>
                            <span
                              className={`text-xs font-semibold ${accent.scoreText}`}
                            >
                              {item.classification}
                            </span>
                          </div>
                          <div className="mt-1 h-1 w-28 sm:ml-auto rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full ${accent.barBg}`}
                              style={{
                                width: `${Math.max(4, item.riskScore)}%`,
                              }}
                            />
                          </div>
                        </div>

                        <span className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 group-hover:text-sky-300 shrink-0">
                          <span>View Report</span>
                          <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                        </span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>
    </section>
  );
};
