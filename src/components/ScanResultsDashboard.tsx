import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Copy,
  Check,
  Download,
  BookOpen,
  RotateCcw,
  Globe,
} from 'lucide-react';
import {
  IndicatorSeverity,
  RiskClassification,
  URLAnalysisResult,
} from '../types/scanner';
import {
  formatConciseClipboardSummary,
  formatScanReportText,
} from '../engine/reportExporter';

interface ScanResultsDashboardProps {
  result: URLAnalysisResult;
  onScanAnother: () => void;
  onOpenSafetyGuide: () => void;
}

function getRiskVisualTheme(classification: RiskClassification) {
  switch (classification) {
    case 'LOW RISK INDICATORS':
      return {
        textColor: 'text-emerald-400',
        strokeColor: '#10B981',
        barBg: 'bg-emerald-500',
        surfaceBorder: 'border-emerald-500/30',
        surfaceBg: 'bg-emerald-950/15',
        Icon: ShieldCheck,
      };
    case 'MILD SUSPICION':
      return {
        textColor: 'text-amber-300',
        strokeColor: '#FBBF24',
        barBg: 'bg-amber-400',
        surfaceBorder: 'border-amber-500/30',
        surfaceBg: 'bg-amber-950/15',
        Icon: AlertTriangle,
      };
    case 'MODERATE RISK':
      return {
        textColor: 'text-amber-400',
        strokeColor: '#F59E0B',
        barBg: 'bg-amber-500',
        surfaceBorder: 'border-amber-500/40',
        surfaceBg: 'bg-amber-950/20',
        Icon: AlertTriangle,
      };
    case 'HIGH RISK':
      return {
        textColor: 'text-rose-400',
        strokeColor: '#F43F5E',
        barBg: 'bg-rose-500',
        surfaceBorder: 'border-rose-500/40',
        surfaceBg: 'bg-rose-950/20',
        Icon: ShieldAlert,
      };
    case 'VERY HIGH RISK':
      return {
        textColor: 'text-rose-500',
        strokeColor: '#EF4444',
        barBg: 'bg-rose-600',
        surfaceBorder: 'border-rose-500/50',
        surfaceBg: 'bg-rose-950/25',
        Icon: ShieldAlert,
      };
  }
}

function getSeverityTextColor(severity: IndicatorSeverity): string {
  switch (severity) {
    case 'Critical':
      return 'text-rose-400 font-semibold';
    case 'High':
      return 'text-rose-300 font-semibold';
    case 'Medium':
      return 'text-amber-300 font-semibold';
    case 'Low':
      return 'text-sky-300 font-medium';
    case 'Informational':
      return 'text-slate-300 font-medium';
  }
}

export const ScanResultsDashboard: React.FC<ScanResultsDashboardProps> = ({
  result,
  onScanAnother,
  onOpenSafetyGuide,
}) => {
  const [copiedSummary, setCopiedSummary] = useState(false);

  const theme = getRiskVisualTheme(result.classification);
  const StatusIcon = theme.Icon;

  // Circular gauge geometry
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset =
    circumference - (result.riskScore / 100) * circumference;

  const handleCopySummary = async () => {
    const summaryText = formatConciseClipboardSummary(result);
    try {
      await navigator.clipboard.writeText(summaryText);
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2500);
    } catch {
      // Fallback copy via textarea
      const textarea = document.createElement('textarea');
      textarea.value = summaryText;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2500);
    }
  };

  const handleDownloadTxt = () => {
    const reportContent = formatScanReportText(result);
    const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const safeHost = result.domain.hostname.replace(/[^a-z0-9.-]/gi, '_');
    link.href = url;
    link.download = `cybershield-report-${safeHost}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Top Row: A. Risk Score Card + D. Recommended Action Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* A. Risk Score Card (7 cols) */}
        <section
          aria-labelledby="risk-score-heading"
          className={`lg:col-span-7 rounded-xl border ${theme.surfaceBorder} bg-[#111827] p-6 flex flex-col justify-between`}
        >
          <div>
            <div className="flex items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <h2
                  id="risk-score-heading"
                  className="text-base font-semibold text-slate-100"
                >
                  Heuristic Threat Assessment
                </h2>
                <p className="text-xs text-slate-400 mt-0.5 font-mono truncate max-w-md">
                  Target: {result.domain.hostname}
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-400 tabular-nums">
                <span>{result.indicators.length} Findings</span>
                <span aria-hidden="true">·</span>
                <span>Deterministic Engine</span>
              </div>
            </div>

            <div className="mt-6 flex flex-col sm:flex-row items-center gap-6">
              {/* Circular Gauge */}
              <div className="relative flex items-center justify-center shrink-0">
                <svg className="h-36 w-36 -rotate-90 transform" viewBox="0 0 128 128">
                  <circle
                    cx="64"
                    cy="64"
                    r={radius}
                    stroke="#1E293B"
                    strokeWidth="10"
                    fill="transparent"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r={radius}
                    stroke={theme.strokeColor}
                    strokeWidth="10"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    fill="transparent"
                    className="transition-all duration-500 ease-out"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span
                    data-testid="risk-score-value"
                    className={`text-3xl font-bold font-mono tabular-nums ${theme.textColor}`}
                  >
                    {result.riskScore}
                  </span>
                  <span className="text-xs text-slate-400 font-mono tabular-nums">
                    / 100
                  </span>
                </div>
              </div>

              {/* Classification & One-Sentence Explanation */}
              <div className="flex-1 text-center sm:text-left">
                <div className="inline-flex items-center gap-2">
                  <StatusIcon
                    className={`h-5 w-5 ${theme.textColor} shrink-0`}
                    aria-hidden="true"
                  />
                  <span
                    data-testid="risk-classification-label"
                    className={`text-lg font-bold tracking-tight ${theme.textColor}`}
                  >
                    {result.classification}
                  </span>
                </div>

                <p className="mt-2.5 text-sm sm:text-base text-slate-200 leading-relaxed">
                  {result.summaryExplanation}
                </p>

                {/* Linear Progress Bar */}
                <div className="mt-4">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5 font-mono tabular-nums">
                    <span>Risk Gauge</span>
                    <span>{result.riskScore} / 100</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full ${theme.barBg} transition-all duration-500`}
                      style={{ width: `${Math.max(3, result.riskScore)}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Mandatory Disclaimer */}
          <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-400">
            <Info className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
            <p className="leading-relaxed">{result.disclaimer}</p>
          </div>
        </section>

        {/* D. Recommended Action Card (5 cols) */}
        <section
          aria-labelledby="recommended-actions-heading"
          className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#111827] p-6 flex flex-col justify-between"
        >
          <div>
            <div className="border-b border-slate-800 pb-4">
              <h2
                id="recommended-actions-heading"
                className="text-base font-semibold text-slate-100"
              >
                Recommended Safety Actions
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                {result.guidance.headline}
              </p>
            </div>

            <div className="mt-4 pb-4 border-b border-slate-800/80">
              <p className={`text-sm font-medium ${theme.textColor} leading-relaxed`}>
                {result.guidance.primaryAdvice}
              </p>
            </div>

            <ul className="mt-4 space-y-2.5 text-xs sm:text-sm text-slate-300">
              {result.guidance.universalRules.map((rule) => (
                <li key={rule} className="flex items-start gap-2.5">
                  <ShieldCheck
                    className="h-4 w-4 text-sky-400 shrink-0 mt-0.5"
                    aria-hidden="true"
                  />
                  <span>{rule}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* E. Result Actions */}
          <div className="mt-6 pt-4 border-t border-slate-800 grid grid-cols-2 gap-2.5">
            <button
              type="button"
              onClick={handleCopySummary}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2.5 text-xs font-medium text-slate-100 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedSummary ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                  <span>Copied Summary</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5 text-sky-400 shrink-0" />
                  <span>Copy Scan Summary</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleDownloadTxt}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2.5 text-xs font-medium text-slate-100 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="h-3.5 w-3.5 text-sky-400 shrink-0" />
              <span>Download Report (.TXT)</span>
            </button>

            <button
              type="button"
              onClick={onScanAnother}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800/40 px-3 py-2.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5 text-slate-400 shrink-0" />
              <span>Scan Another URL</span>
            </button>

            <button
              type="button"
              onClick={onOpenSafetyGuide}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-2.5 text-xs font-medium text-sky-300 hover:bg-sky-500/20 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <BookOpen className="h-3.5 w-3.5 text-sky-400 shrink-0" />
              <span>View Safety Guide</span>
            </button>
          </div>
        </section>
      </div>

      {/* Bottom Row: B. Detected Indicators (7 cols) + C. Domain Information Card (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* B. Detected Indicators */}
        <section
          aria-labelledby="detected-indicators-heading"
          className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#111827] p-6"
        >
          <div className="flex items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h2
                id="detected-indicators-heading"
                className="text-base font-semibold text-slate-100"
              >
                Detected URL Indicators
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Explicit security signals contributing to the heuristic score
              </p>
            </div>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {result.indicators.length} triggered
            </span>
          </div>

          {result.indicators.length === 0 ? (
            <div className="py-10 text-center">
              <ShieldCheck
                className="h-10 w-10 text-emerald-400 mx-auto mb-3"
                aria-hidden="true"
              />
              <h3 className="text-sm font-semibold text-slate-200">
                No Suspicious URL Heuristics Triggered
              </h3>
              <p className="mt-1.5 text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
                This URL uses HTTPS, a standard domain structure, and did not match known brand impersonation or deceptive path patterns. Continue to verify the sender before logging in.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/90">
              {result.indicators.map((ind) => (
                <article key={ind.id} className="py-4 first:pt-4 last:pb-0">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <h3 className="text-sm font-semibold text-slate-100">
                      {ind.name}
                    </h3>
                    <div className="flex items-center gap-2 text-xs font-mono tabular-nums">
                      <span className={getSeverityTextColor(ind.severity)}>
                        Severity: {ind.severity}
                      </span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="text-slate-400">+{ind.weight} pts</span>
                    </div>
                  </div>

                  <p className="mt-1.5 text-sm text-slate-300 leading-relaxed">
                    {ind.explanation}
                  </p>

                  <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
                    <span>
                      Matched Component:{' '}
                      <code className="font-mono text-sky-300 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                        {ind.component}
                      </code>
                    </span>
                  </div>

                  <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                    <strong className="font-medium text-slate-300">
                      Why this matters:
                    </strong>{' '}
                    {ind.reasonItMatters}
                  </p>
                </article>
              ))}
            </div>
          )}
        </section>

        {/* C. Domain Information Card */}
        <section
          aria-labelledby="domain-info-heading"
          className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#111827] p-6"
        >
          <div className="flex items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-sky-400 shrink-0" aria-hidden="true" />
              <h2
                id="domain-info-heading"
                className="text-base font-semibold text-slate-100"
              >
                Extracted Domain Details
              </h2>
            </div>
            <span className="text-xs text-slate-400">Parsed Safely</span>
          </div>

          <dl className="mt-4 divide-y divide-slate-800/80 text-xs sm:text-sm">
            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Hostname</dt>
              <dd className="font-mono text-slate-100 text-right break-all">
                {result.domain.hostname}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Registrable Domain</dt>
              <dd className="font-mono font-semibold text-sky-300 text-right break-all">
                {result.domain.registrableDomain}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Subdomain</dt>
              <dd className="font-mono text-slate-200 text-right break-all">
                {result.domain.subdomain}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Top-Level Domain (TLD)</dt>
              <dd className="font-mono text-slate-200 text-right">
                {result.domain.tld === 'IP Literal' || result.domain.tld === 'None'
                  ? result.domain.tld
                  : `.${result.domain.tld}`}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Protocol</dt>
              <dd className="font-mono text-slate-200 text-right">
                {result.domain.protocol}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Port</dt>
              <dd className="font-mono text-slate-200 text-right tabular-nums">
                {result.domain.port}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Path</dt>
              <dd className="font-mono text-slate-200 text-right break-all">
                {result.domain.path}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">URL Length</dt>
              <dd className="font-mono text-slate-200 text-right tabular-nums">
                {result.domain.urlLength} chars
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Query Parameters</dt>
              <dd className="font-mono text-slate-200 text-right tabular-nums">
                {result.domain.queryParamCount === 0
                  ? '0 (None)'
                  : `${result.domain.queryParamCount} (Values Redacted)`}
              </dd>
            </div>

            <div className="py-2.5 flex items-start justify-between gap-4">
              <dt className="text-slate-400 shrink-0">Domain Registration Age</dt>
              <dd className="font-mono text-slate-400 text-right">Not checked</dd>
            </div>

            <div className="py-2.5 flex flex-col gap-1">
              <dt className="text-slate-400">External Reputation Status</dt>
              <dd className="font-mono text-xs text-slate-300 bg-slate-900/90 border border-slate-800 rounded p-2.5">
                <div>{result.reputation.summaryLabel}</div>
                {result.reputation.checked && result.reputation.lastCheckedAt && (
                  <div className="mt-1 text-slate-400">
                    Provider: {result.reputation.providerName} · Checked:{' '}
                    {new Date(result.reputation.lastCheckedAt).toLocaleTimeString()}
                  </div>
                )}
              </dd>
            </div>

            <div className="py-2.5 flex flex-col gap-1">
              <dt className="text-slate-400">Sanitized URL (Query Values Redacted)</dt>
              <dd className="font-mono text-xs text-slate-300 bg-slate-900/90 border border-slate-800 rounded p-2.5 break-all">
                {result.domain.redactedUrl}
              </dd>
            </div>
          </dl>
        </section>
      </div>
    </div>
  );
};
