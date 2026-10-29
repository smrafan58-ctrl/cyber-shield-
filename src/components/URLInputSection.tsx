import React, { useState } from 'react';
import {
  Search,
  ClipboardPaste,
  XCircle,
  AlertTriangle,
  Lock,
  ShieldCheck,
} from 'lucide-react';
import { EXAMPLE_TEST_FIXTURES } from '../engine/urlAnalyzer';
import { ExampleFixture } from '../types/scanner';

interface URLInputSectionProps {
  urlInput: string;
  onUrlInputChange: (val: string) => void;
  onScanSubmit: (urlToScan?: string) => void;
  onClear: () => void;
  validationError: { title: string; message: string } | null;
  isScanning: boolean;
  inputRef: React.RefObject<HTMLInputElement | null>;
}

export const URLInputSection: React.FC<URLInputSectionProps> = ({
  urlInput,
  onUrlInputChange,
  onScanSubmit,
  onClear,
  validationError,
  isScanning,
  inputRef,
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
    <section className="border-b border-slate-800/80 bg-gradient-to-b from-[#0F172A] to-[#0B1120] py-10 sm:py-14">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        {/* Brand Identity & Hero Header */}
        <div className="text-center max-w-3xl mx-auto mb-8">
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

              <div className="flex items-center gap-2.5 shrink-0">
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
      </div>
    </section>
  );
};
