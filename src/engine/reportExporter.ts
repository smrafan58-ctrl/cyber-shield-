import { URLAnalysisResult } from '../types/scanner';

/**
 * Generates a plain-text report for clipboard copy or .txt file download.
 * Never outputs raw query parameter values to protect session tokens or PII.
 */
export function formatScanReportText(result: URLAnalysisResult): string {
  const lines: string[] = [
    '====================================================================',
    'CYBERSHIELD AI — URL THREAT ANALYSIS REPORT',
    '====================================================================',
    `Scan Timestamp (UTC): ${result.timestamp}`,
    `Report ID:            ${result.id}`,
    '',
    '--- RISK ASSESSMENT ------------------------------------------------',
    `Risk Score:           ${result.riskScore}/100`,
    `Classification:       ${result.classification}`,
    `Summary:              ${result.summaryExplanation}`,
    `Reputation Status:    ${result.reputation.summaryLabel}`,
    '',
    '--- EXTRACTED DOMAIN DETAILS ---------------------------------------',
    `Submitted URL (Safe): ${result.domain.redactedUrl}`,
    `Hostname:             ${result.domain.hostname}`,
    `Registrable Domain:   ${result.domain.registrableDomain}`,
    `Subdomain:            ${result.domain.subdomain}`,
    `Top-Level Domain:     ${result.domain.tld}`,
    `Protocol:             ${result.domain.protocol}`,
    `Port:                 ${result.domain.port}`,
    `Path:                 ${result.domain.path}`,
    `URL Length:           ${result.domain.urlLength} characters`,
    `Query Parameters:     ${result.domain.queryParamCount} (values redacted for privacy)`,
    '',
    '--- DETECTED HEURISTIC INDICATORS ----------------------------------',
  ];

  if (result.indicators.length === 0) {
    lines.push('No suspicious URL heuristic indicators were triggered.');
  } else {
    result.indicators.forEach((ind, index) => {
      lines.push(
        `${index + 1}. [${ind.severity.toUpperCase()}] ${ind.name} (+${ind.weight} pts)`,
        `   Component:   ${ind.component}`,
        `   Explanation: ${ind.explanation}`,
        `   Why It Matters: ${ind.reasonItMatters}`,
        ''
      );
    });
  }

  lines.push(
    '--- RECOMMENDED SAFETY ACTIONS -------------------------------------',
    `Primary Guidance: ${result.guidance.primaryAdvice}`,
    ''
  );

  result.guidance.universalRules.forEach((rule) => {
    lines.push(`* ${rule}`);
  });

  lines.push(
    '',
    '--- DISCLAIMER -----------------------------------------------------',
    result.disclaimer,
    '===================================================================='
  );

  return lines.join('\n');
}

/**
 * Generates a concise summary suitable for quick clipboard sharing.
 */
export function formatConciseClipboardSummary(result: URLAnalysisResult): string {
  const indicatorNames =
    result.indicators.length > 0
      ? result.indicators.map((i) => `${i.name} (${i.severity})`).join('; ')
      : 'None detected';

  return [
    `CyberShield AI URL Scan Summary`,
    `Target Hostname: ${result.domain.hostname} (Registrable: ${result.domain.registrableDomain})`,
    `Sanitized URL: ${result.domain.redactedUrl}`,
    `Risk Score: ${result.riskScore}/100 — ${result.classification}`,
    `Summary: ${result.summaryExplanation}`,
    `Indicators (${result.indicators.length}): ${indicatorNames}`,
    `Recommendation: ${result.guidance.primaryAdvice}`,
    `Disclaimer: ${result.disclaimer}`,
  ].join('\n');
}
