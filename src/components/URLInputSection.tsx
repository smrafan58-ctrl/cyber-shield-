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
  Globe,
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
  isAuthenticated?: boolean;
  onGoogleSignIn?: () => void;
  authStatusMessage?: string | null;
}

function getHistoryRiskAccent(classification: RiskClassification) {
  switch (classification) {
    case 'LOW RISK INDICATORS':
      return {
        scoreText: 'text-emerald-700',
        strokeHex: '#059669',
        barBg: 'bg-emerald-600',
      };
    case 'MILD SUSPICION':
      return {
        scoreText: 'text-amber-700',
        strokeHex: '#D97706',
        barBg: 'bg-amber-500',
      };
    case 'MODERATE RISK':
      return {
        scoreText: 'text-orange-700',
        strokeHex: '#EA580C',
        barBg: 'bg-orange-500',
      };
    case 'HIGH RISK':
      return {
        scoreText: 'text-rose-700',
        strokeHex: '#E11D48',
        barBg: 'bg-rose-600',
      };
    case 'VERY HIGH RISK':
      return {
        scoreText: 'text-red-700',
        strokeHex: '#DC2626',
        barBg: 'bg-red-600',
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
  isAuthenticated = false,
  onGoogleSignIn,
  authStatusMessage,
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
    <section className="py-8 sm:py-12">

      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 space-y-8">
        {/* Unified Architectural Showcase: Warm Apricot-Champagne Masthead + Cream URL Console */}
        <div className="rounded-2xl border border-[#E6C9AE] bg-[#FFFDF9] shadow-editorial overflow-hidden">
          {/* Top Half: Warm Golden Peach & Terracotta Editorial Hero */}
          <div className="bg-editorial-grid border-b border-[#E6C9AE] px-6 py-10 sm:px-12 sm:py-12 text-center">
            <p className="text-xs sm:text-sm font-semibold tracking-wide text-[#B84A24] mb-3">
              Scan Smart · Stay Safe · Stop Cyber Threats
            </p>
            <h1
              className="font-display text-3xl sm:text-5xl font-bold tracking-tight text-[#231710] leading-[1.14] max-w-2xl mx-auto"
              style={{ textWrap: 'balance' }}
            >
              Is This Link Safe{' '}
              <span className="italic font-normal text-[#C85A32]">
                Before You Click?
              </span>
            </h1>
            <p className="mt-4 text-sm sm:text-base text-[#4A3528] max-w-2xl mx-auto leading-relaxed">
              Check suspicious URLs for phishing patterns, deceptive lookalike domains, unusual ports, and high-risk paths through deterministic static inspection.
            </p>
          </div>

          {/* Bottom Half: URL Inspection Command Console */}
          <div className="p-6 sm:p-9 bg-[#FFFDF9]">
            <form onSubmit={handleFormSubmit} noValidate>
              <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
                <label
                  htmlFor="url-scanner-input"
                  className="text-sm font-semibold text-[#231710]"
                >
                  Enter or paste a single URL to inspect
                </label>
                <span className="text-xs font-mono text-[#7A5C49] tabular-nums">
                  {urlInput.trim().length > 0
                    ? `${urlInput.trim().length} chars`
                    : 'HTTP / HTTPS supported'}
                </span>
              </div>

              <div className="flex flex-col lg:flex-row items-stretch lg:items-center gap-3">
                <div className="relative flex-1">
                  <Globe
                    className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-[#C85A32]"
                    aria-hidden="true"
                  />
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
                    placeholder="https://example.com/login/verify"
                    aria-invalid={Boolean(validationError)}
                    aria-describedby="url-privacy-notice"
                    className="w-full rounded-lg border border-[#E6C9AE] bg-[#FDF5EB] pl-11 pr-4 py-3.5 text-sm sm:text-base font-mono text-[#231710] placeholder:text-[#9C7D68] focus:border-[#C85A32] focus:bg-[#FFFDF9] focus:outline-none focus:ring-3 focus:ring-[#C85A32]/15 transition-all"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                  <button
                    type="submit"
                    disabled={isScanning}
                    className="flex-1 sm:flex-initial inline-flex items-center justify-center gap-2 rounded-lg bg-warm-cta px-6 py-3.5 text-sm font-semibold text-white disabled:opacity-50 transition-all whitespace-nowrap shrink-0 cursor-pointer shadow-xs"
                  >
                    <Search className="h-4 w-4 shrink-0" aria-hidden="true" />
                    <span>{isScanning ? 'Analyzing...' : 'Scan URL'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handlePasteClipboard}
                    title="Paste URL from clipboard"
                    className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[#EEDBC8] bg-[#FDF5EB] px-4 py-3.5 text-xs sm:text-sm font-medium text-[#231710] hover:border-[#C85A32] hover:bg-[#FDECD8] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <ClipboardPaste
                      className="h-4 w-4 shrink-0 text-[#C85A32]"
                      aria-hidden="true"
                    />
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
                    className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[#EEDBC8] bg-[#FFFDF9] px-4 py-3.5 text-xs sm:text-sm font-medium text-[#7A5C49] hover:bg-[#FDECD8] hover:text-[#231710] disabled:opacity-40 disabled:cursor-not-allowed transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <XCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
                    <span>Clear</span>
                  </button>
                </div>
              </div>

              {/* Clipboard / Voice Transcription Status Feedback */}
              {clipboardFeedback && (
                <div
                  role="status"
                  className="mt-3.5 rounded-lg border border-amber-300 bg-amber-50/90 px-4 py-2.5 text-xs text-amber-900"
                >
                  {clipboardFeedback}
                </div>
              )}

              {/* Validation Error Notice */}
              {validationError && (
                <div
                  role="alert"
                  className="mt-4 rounded-lg border border-rose-300 bg-rose-50/90 p-4 text-sm text-rose-900"
                >
                  <div className="flex items-start gap-3">
                    <AlertTriangle
                      className="h-5 w-5 text-rose-600 shrink-0 mt-0.5"
                      aria-hidden="true"
                    />
                    <div>
                      <h2 className="font-semibold text-rose-800">
                        {validationError.title}
                      </h2>
                      <p className="mt-1 text-rose-800/90 leading-relaxed">
                        {validationError.message}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Privacy & Untrusted Input Notice */}
              <div
                id="url-privacy-notice"
                className="mt-5 flex flex-wrap items-center justify-between gap-3 text-xs text-[#7A5C49] pt-4 border-t border-[#EEDBC8]"
              >
                <div className="flex items-center gap-2">
                  <Lock
                    className="h-3.5 w-3.5 text-[#C85A32] shrink-0"
                    aria-hidden="true"
                  />
                  <span>
                    Safe static inspection: Submitted URLs are never opened, fetched, or executed in your browser.
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-[#7A5C49]">
                  <ShieldCheck
                    className="h-3.5 w-3.5 text-emerald-600 shrink-0"
                    aria-hidden="true"
                  />
                  <span>Single-URL scope · Query values redacted</span>
                </div>
              </div>
            </form>

            {/* Interactive Diagnostic Specimens */}
            <div className="mt-5 pt-5 border-t border-[#EEDBC8]">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                <span className="text-xs font-semibold text-[#231710]">
                  Diagnostic Verification Presets
                </span>
                <span className="text-xs text-[#7A5C49]">
                  Select a sample URL to inspect heuristic scoring
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {EXAMPLE_TEST_FIXTURES.map((fixture, idx) => (
                  <button
                    key={fixture.url}
                    type="button"
                    onClick={() => handleFixtureSelect(fixture)}
                    className="group text-left rounded-lg border border-[#EEDBC8] bg-[#FDF5EB] px-4 py-3 hover:border-[#C85A32] hover:bg-[#FDECD8] transition-all cursor-pointer"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-[#231710] group-hover:text-[#A94622] transition-colors truncate">
                        0{idx + 1}. {fixture.label}
                      </span>
                      <ArrowUpRight
                        className="h-3.5 w-3.5 text-[#C85A32] opacity-70 group-hover:opacity-100 shrink-0 transition-opacity"
                        aria-hidden="true"
                      />
                    </div>
                    <p className="mt-1 text-[11px] font-mono text-[#7A5C49] truncate">
                      {fixture.url}
                    </p>
                  </button>
                ))}
              </div>

            </div>
          </div>
        </div>

        {/* Local Storage + Firestore Cloud Scan History Section (Last 5 Analyzed URLs) */}
        <section
          data-testid="recent-scan-history"
          aria-labelledby="recent-scan-history-heading"
          className="rounded-2xl border border-[#E6C9AE] bg-[#FFFDF9] p-6 sm:p-8 shadow-editorial"
        >
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#EEDBC8] pb-4">
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#E6C9AE] bg-[#FDECD8] text-[#C85A32] shrink-0">
                <History className="h-4.5 w-4.5" aria-hidden="true" />
              </span>
              <div>
                <h2
                  id="recent-scan-history-heading"
                  className="font-display text-lg font-bold text-[#231710]"
                >
                  Recent Scan History
                </h2>
                <p className="text-xs text-[#7A5C49]">
                  {isAuthenticated
                    ? 'Synced with Firebase Cloud Firestore & local storage (Last 5 analyzed URLs)'
                    : 'Last 5 analyzed URLs saved in local storage · Sign in with Google to sync to Firestore'}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {!isAuthenticated && onGoogleSignIn && (
                <button
                  type="button"
                  onClick={onGoogleSignIn}
                  className="text-xs font-semibold text-[#C85A32] hover:text-[#A94622] underline underline-offset-4 cursor-pointer whitespace-nowrap"
                >
                  Sync with Google
                </button>
              )}
              <span className="text-xs font-mono text-[#7A5C49] tabular-nums">
                {scanHistory.length} / 5 saved
              </span>
              {scanHistory.length > 0 && (
                <button
                  type="button"
                  onClick={onClearHistory}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[#EEDBC8] bg-[#FDF5EB] px-3 py-1.5 text-xs font-medium text-[#4A3528] hover:bg-rose-50 hover:border-rose-300 hover:text-rose-700 transition-colors cursor-pointer whitespace-nowrap shrink-0"
                >
                  <Trash2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>Clear History</span>
                </button>
              )}
            </div>
          </div>

          {authStatusMessage && (
            <div
              role="status"
              className="mt-4 rounded-lg border border-amber-300 bg-amber-50/90 px-4 py-2.5 text-xs text-amber-900"
            >
              {authStatusMessage}
            </div>
          )}

          {scanHistory.length === 0 ? (
            <div className="py-8 text-center">
              <p className="text-sm font-medium text-[#231710]">
                No URLs analyzed in this session yet
              </p>
              <p className="mt-1 text-xs text-[#7A5C49] max-w-md mx-auto">
                Scan any link above or select one of the diagnostic presets to automatically record your last 5 analyzed URLs and risk scores here.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-[#EEDBC8]">
              {scanHistory.map((item, idx) => {
                const accent = getHistoryRiskAccent(item.classification);
                const ringRadius = 15;
                const ringCirc = 2 * Math.PI * ringRadius;
                const ringOffset =
                  ringCirc - (item.riskScore / 100) * ringCirc;

                return (
                  <li
                    key={item.domain.normalizedUrl || item.id}
                    data-testid="recent-scan-history-item"
                  >
                    <button
                      type="button"
                      onClick={() => onSelectHistoryItem(item)}
                      className="w-full py-4 px-3 -mx-3 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-left hover:bg-[#FDF5EB] transition-colors group cursor-pointer"
                    >
                      <div className="flex items-center gap-3.5 min-w-0 flex-1">
                        {/* Editorial Index */}
                        <span className="hidden sm:inline-block text-xs font-mono text-[#9C7D68] tabular-nums w-6 shrink-0">
                          0{idx + 1}.
                        </span>

                        {/* Mini SVG Circular Risk Ring */}
                        <div className="relative h-10 w-10 shrink-0 flex items-center justify-center">
                          <svg
                            className="h-10 w-10 -rotate-90 transform"
                            viewBox="0 0 38 38"
                            aria-hidden="true"
                          >
                            <circle
                              cx="19"
                              cy="19"
                              r={ringRadius}
                              stroke="#F5E6D6"
                              strokeWidth="3.5"
                              fill="transparent"
                            />
                            <circle
                              cx="19"
                              cy="19"
                              r={ringRadius}
                              stroke={accent.strokeHex}
                              strokeWidth="3.5"
                              strokeDasharray={ringCirc}
                              strokeDashoffset={ringOffset}
                              strokeLinecap="round"
                              fill="transparent"
                            />
                          </svg>
                          <span
                            className={`absolute text-[11px] font-bold font-mono tabular-nums ${accent.scoreText}`}
                          >
                            {item.riskScore}
                          </span>
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-semibold text-[#231710] group-hover:text-[#C85A32] transition-colors truncate">
                              {item.domain.hostname}
                            </span>
                            <span aria-hidden="true" className="text-[#C7A98E]">
                              ·
                            </span>
                            <span className="text-xs text-[#7A5C49] font-mono tabular-nums shrink-0">
                              {item.domain.protocol}
                            </span>
                            <span aria-hidden="true" className="text-[#C7A98E]">
                              ·
                            </span>
                            <span className="text-xs text-[#7A5C49] font-mono tabular-nums shrink-0">
                              {item.indicators.length}{' '}
                              {item.indicators.length === 1 ? 'finding' : 'findings'}
                            </span>
                          </div>
                          <p className="mt-0.5 text-xs font-mono text-[#7A5C49] truncate">
                            {item.domain.redactedUrl}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center justify-between sm:justify-end gap-5 shrink-0">
                        <div className="text-left sm:text-right">
                          <div className="flex items-baseline sm:justify-end gap-1.5 font-mono tabular-nums">
                            <span
                              className={`text-sm font-bold ${accent.scoreText}`}
                            >
                              {item.riskScore}
                            </span>
                            <span className="text-xs text-[#9C7D68]">/ 100</span>
                            <span aria-hidden="true" className="text-[#C7A98E]">
                              ·
                            </span>
                            <span
                              className={`text-xs font-semibold ${accent.scoreText}`}
                            >
                              {item.classification}
                            </span>
                          </div>
                          <div className="mt-1.5 h-1.5 w-32 sm:ml-auto rounded-full bg-[#F5E6D6] overflow-hidden">
                            <div
                              className={`h-full ${accent.barBg}`}
                              style={{
                                width: `${Math.max(4, item.riskScore)}%`,
                              }}
                            />
                          </div>
                        </div>

                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-[#C85A32] group-hover:text-[#A94622] shrink-0 whitespace-nowrap">
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


