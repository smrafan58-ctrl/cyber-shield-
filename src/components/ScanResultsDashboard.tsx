import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Copy,
  Check,
  Download,
  RotateCcw,
  Globe,
  ArrowLeft,
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
}

function getRiskVisualTheme(classification: RiskClassification) {
  switch (classification) {
    case 'LOW RISK INDICATORS':
      return {
        textColor: 'text-emerald-700',
        strokeColor: '#059669',
        barBg: 'bg-emerald-600',
        surfaceBorder: 'border-emerald-200',
        headerSurface: 'bg-emerald-50/50',
        Icon: ShieldCheck,
      };
    case 'MILD SUSPICION':
      return {
        textColor: 'text-amber-700',
        strokeColor: '#D97706',
        barBg: 'bg-amber-500',
        surfaceBorder: 'border-amber-200',
        headerSurface: 'bg-amber-50/50',
        Icon: AlertTriangle,
      };
    case 'MODERATE RISK':
      return {
        textColor: 'text-orange-700',
        strokeColor: '#EA580C',
        barBg: 'bg-orange-500',
        surfaceBorder: 'border-orange-200',
        headerSurface: 'bg-orange-50/50',
        Icon: AlertTriangle,
      };
    case 'HIGH RISK':
      return {
        textColor: 'text-rose-700',
        strokeColor: '#E11D48',
        barBg: 'bg-rose-600',
        surfaceBorder: 'border-rose-200',
        headerSurface: 'bg-rose-50/50',
        Icon: ShieldAlert,
      };
    case 'VERY HIGH RISK':
      return {
        textColor: 'text-red-700',
        strokeColor: '#DC2626',
        barBg: 'bg-red-600',
        surfaceBorder: 'border-red-300',
        headerSurface: 'bg-red-50/50',
        Icon: ShieldAlert,
      };
  }
}

function getSeverityTextColor(severity: IndicatorSeverity): string {
  switch (severity) {
    case 'Critical':
      return 'text-red-700 font-semibold';
    case 'High':
      return 'text-rose-700 font-semibold';
    case 'Medium':
      return 'text-amber-700 font-semibold';
    case 'Low':
      return 'text-[#C85A32] font-semibold';
    case 'Informational':
      return 'text-[#7A5C49] font-medium';
  }
}

export const ScanResultsDashboard: React.FC<ScanResultsDashboardProps> = ({
  result,
  onScanAnother,
}) => {
  const [copiedSummary, setCopiedSummary] = useState(false);

  const theme = getRiskVisualTheme(result.classification);
  const StatusIcon = theme.Icon;

  // Dual-ring circular gauge geometry
  const radius = 58;
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
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-6">

      {/* Top Bar Navigation Back to Scanner */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-1">
        <button
          type="button"
          onClick={onScanAnother}
          className="inline-flex items-center gap-2 text-xs sm:text-sm font-semibold text-[#C85A32] hover:text-[#A94622] transition-colors cursor-pointer whitespace-nowrap"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          <span>Back to URL Scanner</span>
        </button>
        <div className="flex items-center gap-2 text-xs font-mono text-[#7A5C49] tabular-nums">
          <span>Target: {result.domain.hostname}</span>
          <span aria-hidden="true">·</span>
          <span>{result.domain.urlLength} chars</span>
        </div>
      </div>

      {/* Structural URL Anatomy Ribbon */}
      <section
        aria-label="Parsed URL Structural Anatomy"
        className="rounded-2xl border border-[#E6C9AE] bg-[#FFFDF9] shadow-editorial overflow-hidden"
      >
        <div className="bg-[#FDECD8] border-b border-[#E6C9AE] px-6 py-3 flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs font-semibold text-[#231710]">
            Deconstructed URL Anatomy
          </span>
          <span className="text-xs font-mono text-[#7A5C49] truncate max-w-xl">
            {result.domain.redactedUrl}
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-[#EEDBC8] bg-[#FFFDF9]">
          <div className="px-5 py-3.5">
            <div className="text-[11px] text-[#7A5C49]">Protocol</div>
            <div
              className={`mt-0.5 text-sm font-mono font-semibold ${
                result.domain.protocol === 'HTTP'
                  ? 'text-amber-700'
                  : 'text-emerald-700'
              }`}
            >
              {result.domain.protocol}
            </div>
          </div>
          <div className="px-5 py-3.5">
            <div className="text-[11px] text-[#7A5C49]">Subdomain</div>
            <div className="mt-0.5 text-sm font-mono text-[#231710] truncate">
              {result.domain.subdomain}
            </div>
          </div>
          <div className="px-5 py-3.5 bg-[#FDF5EB]">
            <div className="text-[11px] font-medium text-[#A94622]">
              Registrable Domain
            </div>
            <div className="mt-0.5 text-sm font-mono font-bold text-[#C85A32] truncate">
              {result.domain.registrableDomain}
            </div>
          </div>
          <div className="px-5 py-3.5">
            <div className="text-[11px] text-[#7A5C49]">Port</div>
            <div className="mt-0.5 text-sm font-mono text-[#231710] tabular-nums">
              {result.domain.port}
            </div>
          </div>
          <div className="col-span-2 sm:col-span-1 px-5 py-3.5">
            <div className="text-[11px] text-[#7A5C49]">Path & Query</div>
            <div className="mt-0.5 text-sm font-mono text-[#231710] truncate">
              {result.domain.path}
            </div>
          </div>
        </div>
      </section>

      {/* Top Row: A. Risk Score Card + D. Recommended Action Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* A. Risk Score Card (7 cols) */}
        <section
          aria-labelledby="risk-score-heading"
          className={`lg:col-span-7 rounded-2xl border ${theme.surfaceBorder} bg-[#FFFDF9] p-6 sm:p-8 flex flex-col justify-between shadow-editorial`}
        >
          <div>
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#EEDBC8] pb-4">
              <div>
                <h2
                  id="risk-score-heading"
                  className="font-display text-xl font-bold text-[#231710]"
                >
                  Heuristic Threat Assessment
                </h2>
                <p className="text-xs text-[#7A5C49] mt-0.5 font-mono truncate max-w-md">
                  Target: {result.domain.hostname}
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs text-[#7A5C49] font-mono tabular-nums">
                <span>{result.indicators.length} Findings</span>
                <span aria-hidden="true">·</span>
                <span>Weighted 0–100 Model</span>
              </div>
            </div>

            <div className="mt-7 flex flex-col sm:flex-row items-center gap-7">
              {/* Dual-Ring Circular Gauge */}
              <div className="relative flex items-center justify-center shrink-0">
                <svg
                  className="h-40 w-40 -rotate-90 transform"
                  viewBox="0 0 140 140"
                  aria-hidden="true"
                >
                  {/* Subtle outer architectural reference ring */}
                  <circle
                    cx="70"
                    cy="70"
                    r="66"
                    stroke="#E6C9AE"
                    strokeWidth="1"
                    strokeDasharray="3 3"
                    fill="transparent"
                  />
                  {/* Track circle */}
                  <circle
                    cx="70"
                    cy="70"
                    r={radius}
                    stroke="#F5E6D6"
                    strokeWidth="10"
                    fill="transparent"
                  />
                  {/* Value arc */}
                  <circle
                    cx="70"
                    cy="70"
                    r={radius}
                    stroke={theme.strokeColor}
                    strokeWidth="10"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    fill="transparent"
                    className="transition-all duration-700 ease-out"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span
                    data-testid="risk-score-value"
                    className={`text-4xl font-bold font-mono tabular-nums tracking-tight ${theme.textColor}`}
                  >
                    {result.riskScore}
                  </span>
                  <span className="text-xs text-[#7A5C49] font-mono tabular-nums mt-0.5">
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
                    className={`text-lg sm:text-xl font-bold tracking-tight ${theme.textColor}`}
                  >
                    {result.classification}
                  </span>
                </div>

                <p className="mt-2.5 text-sm sm:text-base text-[#4A3528] leading-relaxed">
                  {result.summaryExplanation}
                </p>

                {/* Linear Progress Bar with Threshold Markers */}
                <div className="mt-5">
                  <div className="flex items-center justify-between text-xs text-[#7A5C49] mb-1.5 font-mono tabular-nums">
                    <span>Composite Risk Score</span>
                    <span>{result.riskScore} / 100</span>
                  </div>
                  <div className="h-2.5 w-full rounded-full bg-[#F5E6D6] overflow-hidden">
                    <div
                      className={`h-full ${theme.barBg} transition-all duration-700`}
                      style={{ width: `${Math.max(3, result.riskScore)}%` }}
                    />
                  </div>
                  <div className="mt-1.5 flex items-center justify-between text-[10px] font-mono text-[#9C7D68] tabular-nums">
                    <span>0 Low</span>
                    <span>15 Mild</span>
                    <span>35 Mod</span>
                    <span>60 High</span>
                    <span>80+ Critical</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Mandatory Disclaimer */}
          <div className="mt-7 pt-4 border-t border-[#EEDBC8] flex items-start gap-2.5 text-xs text-[#7A5C49]">
            <Info
              className="h-4 w-4 text-[#C85A32] shrink-0 mt-0.5"
              aria-hidden="true"
            />
            <p className="leading-relaxed">{result.disclaimer}</p>
          </div>
        </section>

        {/* D. Recommended Action Card (5 cols) */}
        <section
          aria-labelledby="recommended-actions-heading"
          className="lg:col-span-5 rounded-2xl border border-[#E6C9AE] bg-[#FFFDF9] p-6 sm:p-8 flex flex-col justify-between shadow-editorial"
        >
          <div>
            <div className="border-b border-[#EEDBC8] pb-4">
              <h2
                id="recommended-actions-heading"
                className="font-display text-xl font-bold text-[#231710]"
              >
                Recommended Safety Actions
              </h2>
              <p className="text-xs text-[#7A5C49] mt-0.5">
                {result.guidance.headline}
              </p>
            </div>

            <div className="mt-4 pb-4 border-b border-[#EEDBC8]">
              <p className={`text-sm font-semibold ${theme.textColor} leading-relaxed`}>
                {result.guidance.primaryAdvice}
              </p>
            </div>

            <ul className="mt-4 space-y-3 text-xs sm:text-sm text-[#4A3528]">
              {result.guidance.universalRules.map((rule, idx) => (
                <li key={rule} className="flex items-start gap-3">
                  <span className="font-mono text-xs font-semibold text-[#C85A32] tabular-nums mt-0.5 shrink-0">
                    0{idx + 1}.
                  </span>
                  <span className="leading-relaxed">{rule}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* E. Result Actions */}
          <div className="mt-6 pt-4 border-t border-[#EEDBC8] flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={onScanAnother}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-warm-cta px-4 py-2.5 text-xs font-semibold text-white transition-all whitespace-nowrap shrink-0 cursor-pointer shadow-xs"
            >
              <RotateCcw className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>Scan Another URL</span>
            </button>

            <button
              type="button"
              onClick={handleCopySummary}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#EEDBC8] bg-[#FDF5EB] px-3.5 py-2.5 text-xs font-medium text-[#231710] hover:border-[#C85A32] hover:bg-[#FDECD8] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedSummary ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-600 shrink-0" aria-hidden="true" />
                  <span>Copied Summary</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5 text-[#C85A32] shrink-0" aria-hidden="true" />
                  <span>Copy Scan Summary</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleDownloadTxt}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#EEDBC8] bg-[#FDF5EB] px-3.5 py-2.5 text-xs font-medium text-[#231710] hover:border-[#C85A32] hover:bg-[#FDECD8] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="h-3.5 w-3.5 text-[#C85A32] shrink-0" aria-hidden="true" />
              <span>Download Report as TXT</span>
            </button>
          </div>
        </section>
      </div>

      {/* Bottom Row: B. Detected Indicators (7 cols) + C. Domain Information Card (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* B. Detected Indicators */}
        <section
          aria-labelledby="detected-indicators-heading"
          className="lg:col-span-7 rounded-2xl border border-[#E6C9AE] bg-[#FFFDF9] p-6 sm:p-8 shadow-editorial"
        >
          <div className="flex items-center justify-between gap-4 border-b border-[#EEDBC8] pb-4">
            <div>
              <h2
                id="detected-indicators-heading"
                className="font-display text-xl font-bold text-[#231710]"
              >
                Detected URL Indicators
              </h2>
              <p className="text-xs text-[#7A5C49] mt-0.5">
                Explicit security signals contributing to the heuristic score
              </p>
            </div>
            <span className="text-xs font-mono text-[#7A5C49] tabular-nums">
              {result.indicators.length} triggered
            </span>
          </div>

          {result.indicators.length === 0 ? (
            <div className="py-12 text-center">
              <ShieldCheck
                className="h-11 w-11 text-emerald-600 mx-auto mb-3"
                aria-hidden="true"
              />
              <h3 className="text-base font-semibold text-[#231710]">
                No Suspicious URL Heuristics Triggered
              </h3>
              <p className="mt-1.5 text-xs sm:text-sm text-[#7A5C49] max-w-md mx-auto leading-relaxed">
                This URL uses HTTPS, a standard domain structure, and did not match known brand impersonation or deceptive path patterns. Continue to verify the sender before logging in.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#EEDBC8]">
              {result.indicators.map((ind, idx) => (
                <article key={ind.id} className="py-5 first:pt-5 last:pb-0">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <h3 className="text-sm sm:text-base font-semibold text-[#231710]">
                      <span className="font-mono text-xs text-[#9C7D68] mr-2 tabular-nums">
                        0{idx + 1}.
                      </span>
                      {ind.name}
                    </h3>
                    <div className="flex items-center gap-2 text-xs font-mono tabular-nums">
                      <span className={getSeverityTextColor(ind.severity)}>
                        Severity: {ind.severity}
                      </span>
                      <span aria-hidden="true" className="text-[#C7A98E]">
                        ·
                      </span>
                      <span className="text-[#231710] font-semibold">
                        +{ind.weight} pts
                      </span>
                    </div>
                  </div>

                  <p className="mt-2 text-sm text-[#4A3528] leading-relaxed">
                    {ind.explanation}
                  </p>

                  <div className="mt-2.5 flex flex-wrap items-center gap-2 text-xs text-[#7A5C49]">
                    <span>Matched Component:</span>
                    <code className="font-mono text-[#A94622] font-semibold break-all">
                      {ind.component}
                    </code>
                  </div>

                  <p className="mt-2 text-xs text-[#7A5C49] leading-relaxed">
                    <strong className="font-semibold text-[#231710]">
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
          className="lg:col-span-5 rounded-2xl border border-[#E6C9AE] bg-[#FFFDF9] p-6 sm:p-8 shadow-editorial"
        >
          <div className="flex items-center justify-between gap-4 border-b border-[#EEDBC8] pb-4">
            <div className="flex items-center gap-2.5">
              <Globe
                className="h-4.5 w-4.5 text-[#C85A32] shrink-0"
                aria-hidden="true"
              />
              <h2
                id="domain-info-heading"
                className="font-display text-xl font-bold text-[#231710]"
              >
                Extracted Domain Details
              </h2>
            </div>
            <span className="text-xs text-[#7A5C49]">Parsed Safely</span>
          </div>

          <dl className="mt-4 divide-y divide-[#EEDBC8] text-xs sm:text-sm">
            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Hostname</dt>
              <dd className="font-mono text-[#231710] text-right break-all">
                {result.domain.hostname}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Registrable Domain</dt>
              <dd className="font-mono font-semibold text-[#C85A32] text-right break-all">
                {result.domain.registrableDomain}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Subdomain</dt>
              <dd className="font-mono text-[#231710] text-right break-all">
                {result.domain.subdomain}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Top-Level Domain (TLD)</dt>
              <dd className="font-mono text-[#231710] text-right">
                {result.domain.tld === 'IP Literal' ||
                result.domain.tld === 'None'
                  ? result.domain.tld
                  : `.${result.domain.tld}`}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Protocol</dt>
              <dd className="font-mono text-[#231710] text-right">
                {result.domain.protocol}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Port</dt>
              <dd className="font-mono text-[#231710] text-right tabular-nums">
                {result.domain.port}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Path</dt>
              <dd className="font-mono text-[#231710] text-right break-all">
                {result.domain.path}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">URL Length</dt>
              <dd className="font-mono text-[#231710] text-right tabular-nums">
                {result.domain.urlLength} chars
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Query Parameters</dt>
              <dd className="font-mono text-[#231710] text-right tabular-nums">
                {result.domain.queryParamCount === 0
                  ? '0 (None)'
                  : `${result.domain.queryParamCount} (Values Redacted)`}
              </dd>
            </div>

            <div className="py-3 flex items-start justify-between gap-4">
              <dt className="text-[#7A5C49] shrink-0">Domain Registration Age</dt>
              <dd className="font-mono text-[#7A5C49] text-right">Not checked</dd>
            </div>

            <div className="py-3 flex flex-col gap-1">
              <dt className="text-[#7A5C49]">External Reputation Status</dt>
              <dd className="font-mono text-xs text-[#4A3528] pt-0.5">
                <div>{result.reputation.summaryLabel}</div>
                {result.reputation.checked && result.reputation.lastCheckedAt && (
                  <div className="mt-1 text-[#7A5C49]">
                    Provider: {result.reputation.providerName} · Checked:{' '}
                    {new Date(result.reputation.lastCheckedAt).toLocaleTimeString()}
                  </div>
                )}
              </dd>
            </div>

            <div className="py-3 flex flex-col gap-1">
              <dt className="text-[#7A5C49]">
                Sanitized URL (Query Values Redacted)
              </dt>
              <dd className="font-mono text-xs text-[#4A3528] pt-0.5 break-all">
                {result.domain.redactedUrl}
              </dd>
            </div>
          </dl>
        </section>
      </div>
    </div>
  );
};


