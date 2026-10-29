import React from 'react';
import {
  Shield,
  Cpu,
  Lock,
  AlertCircle,
  Server,
  CheckCircle2,
} from 'lucide-react';
import { HEURISTIC_WEIGHTS, MANDATORY_DISCLAIMER } from '../engine/urlAnalyzer';

interface AboutSectionProps {
  reputationConfigured: boolean;
  reputationProviders: string[];
  backendRuntime: string;
  onNavigateToScanner: () => void;
}

export const AboutSection: React.FC<AboutSectionProps> = ({
  reputationConfigured,
  reputationProviders,
  backendRuntime,
  onNavigateToScanner,
}) => {
  const handleDownloadJavaSource = async () => {
    try {
      const res = await fetch('/api/java-source');
      if (!res.ok) return;
      const sourceText = await res.text();
      const blob = new Blob([sourceText], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'CyberShieldServer.java';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch {
      // Ignore error
    }
  };

  const weightRows = [
    { label: 'Suspicious URL authority structure (@ symbol)', weight: HEURISTIC_WEIGHTS.AUTHORITY_DECEPTION },
    { label: 'Suspicious brand impersonation in subdomain or domain', weight: HEURISTIC_WEIGHTS.BRAND_IMPERSONATION },
    { label: 'Strong typosquatting or homoglyph signal', weight: HEURISTIC_WEIGHTS.TYPOSQUATTING },
    { label: 'Government, digital arrest, or urgent fine pattern on non-gov domain', weight: HEURISTIC_WEIGHTS.GOV_DIGITAL_ARREST_PATTERN },
    { label: 'Hostname is a raw IPv4/IPv6 address', weight: HEURISTIC_WEIGHTS.IP_HOSTNAME },
    { label: 'Suspicious login, verification, or payment combination', weight: HEURISTIC_WEIGHTS.HIGH_RISK_PATH_COMBO },
    { label: 'External redirect parameter in query string', weight: HEURISTIC_WEIGHTS.OPEN_REDIRECT_PATTERN },
    { label: 'Excessive or chained subdomains', weight: HEURISTIC_WEIGHTS.EXCESSIVE_SUBDOMAINS },
    { label: 'Unencrypted HTTP protocol instead of HTTPS', weight: HEURISTIC_WEIGHTS.HTTP_PROTOCOL },
    { label: 'Suspiciously long hostname (> 42 characters)', weight: HEURISTIC_WEIGHTS.LONG_HOSTNAME },
    { label: 'Obfuscated or heavy URL percent-encoding', weight: HEURISTIC_WEIGHTS.SUSPICIOUS_ENCODING },
    { label: 'Multiple hyphens in hostname (3+ hyphens)', weight: HEURISTIC_WEIGHTS.EXCESSIVE_HYPHENS },
    { label: 'Punycode / Internationalized Domain Name (xn--)', weight: HEURISTIC_WEIGHTS.PUNYCODE_IDN },
    { label: 'URL shortener hiding final destination', weight: HEURISTIC_WEIGHTS.URL_SHORTENER },
    { label: 'Non-standard network port', weight: HEURISTIC_WEIGHTS.UNUSUAL_PORT },
    { label: 'High-abuse top-level domain suffix', weight: HEURISTIC_WEIGHTS.SUSPICIOUS_TLD },
    { label: 'Excessive query parameters (5+ parameters)', weight: HEURISTIC_WEIGHTS.EXCESSIVE_PARAMS },
    { label: 'Unusually long overall URL (> 120 characters)', weight: HEURISTIC_WEIGHTS.LONG_URL },
  ];

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8 space-y-8">
      {/* Main About Header */}
      <div className="rounded-xl border border-slate-800 bg-[#111827] p-6 sm:p-8">
        <div className="flex items-center gap-2.5 text-sky-400 text-xs font-semibold mb-2">
          <Shield className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>About CyberShield AI</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
          Transparent, Deterministic URL Threat Analysis
        </h1>
        <p className="mt-3 text-sm sm:text-base text-slate-200 max-w-4xl leading-relaxed">
          CyberShield AI is an educational cybersecurity awareness tool that analyzes URL characteristics to help users recognize suspicious links. Its heuristic results are not a guarantee of website safety.
        </p>
        <p className="mt-3 text-xs text-slate-400">
          {MANDATORY_DISCLAIMER}
        </p>
      </div>

      {/* Core Pillars Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Purpose & Supported URL Analysis Features */}
        <section className="rounded-xl border border-slate-800 bg-[#111827] p-6">
          <div className="flex items-center gap-2.5 mb-3">
            <Cpu className="h-5 w-5 text-sky-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-100">
              Purpose & Supported URL Analysis Features
            </h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed mb-4">
            This platform focuses strictly on single-URL inspection. Instead of generating arbitrary or unexplainable AI numbers, every risk score is computed deterministically from explicit structural and lexical URL signals:
          </p>
          <ul className="space-y-2 text-xs sm:text-sm text-slate-300">
            <li className="flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
              <span>Safe URL parsing and registrable domain separation across standard and multi-part public suffixes (<code className="font-mono text-slate-200">.co.in</code>, <code className="font-mono text-slate-200">.gov.in</code>, <code className="font-mono text-slate-200">.co.uk</code>).</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
              <span>Conservative brand impersonation and homoglyph/typosquatting detection that distinguishes official domains (<code className="font-mono text-slate-200">accounts.google.com</code>) from deceptive subdomains and lookalikes.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
              <span>Detection of authority deception (<code className="font-mono text-slate-200">@</code> symbol), raw IP hosts, Punycode IDNs, open-redirect parameters, URL shorteners, and high-risk authentication or digital arrest scam paths.</span>
            </li>
          </ul>
        </section>

        {/* Limitations */}
        <section className="rounded-xl border border-slate-800 bg-[#111827] p-6">
          <div className="flex items-center gap-2.5 mb-3">
            <AlertCircle className="h-5 w-5 text-amber-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-100">
              Architectural Scope & Limitations
            </h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed mb-4">
            Understanding what a static URL analyzer cannot see is essential for staying safe online:
          </p>
          <ul className="space-y-2 text-xs sm:text-sm text-slate-300">
            <li className="flex items-start gap-2">
              <span className="font-mono text-amber-400 font-bold">·</span>
              <span><strong>A low risk score does not prove a website is safe:</strong> A newly registered or compromised domain with a clean-looking name (such as <code className="font-mono text-slate-200">https://clean-domain.com</code>) may host malicious content without triggering lexical URL heuristics.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-amber-400 font-bold">·</span>
              <span><strong>Heuristic signals are not proof of malice:</strong> Legitimate developer environments or internal services may use HTTP, IP addresses, or custom ports.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-amber-400 font-bold">·</span>
              <span><strong>URL-only scope:</strong> CyberShield AI does not scan SMS paragraphs, email bodies, file attachments, APKs, or QR images, and never fetches or executes remote web pages.</span>
            </li>
          </ul>
        </section>

        {/* Privacy Principles */}
        <section className="rounded-xl border border-slate-800 bg-[#111827] p-6">
          <div className="flex items-center gap-2.5 mb-3">
            <Lock className="h-5 w-5 text-emerald-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-100">
              Security & Privacy Principles
            </h2>
          </div>
          <ul className="space-y-2.5 text-xs sm:text-sm text-slate-300">
            <li>
              <strong className="text-slate-100">No Automatic Navigation or Fetching:</strong> Submitted URLs are treated as untrusted input. The app never opens, previews, or fetches the target URL from your browser or the backend server.
            </li>
            <li>
              <strong className="text-slate-100">Query Parameter Redaction:</strong> URL query values (which may contain session tokens, password reset keys, or personal data) are automatically masked as <code className="font-mono text-slate-200">[REDACTED]</code> in scan reports and local history.
            </li>
            <li>
              <strong className="text-slate-100">User-Controlled Local History:</strong> Scan history stays in your browser&apos;s <code className="font-mono text-slate-200">localStorage</code>, can be cleared at any time, and can be disabled with a single toggle.
            </li>
          </ul>
        </section>

        {/* Java Backend & Threat Intelligence Status */}
        <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2.5 mb-3">
              <Server className="h-5 w-5 text-sky-400 shrink-0" aria-hidden="true" />
              <h2 className="text-base font-semibold text-slate-100">
                Java Backend & Threat Intelligence Status
              </h2>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              The backend runs on Java 17 (<code className="font-mono text-slate-200">backend/CyberShieldServer.java</code>) using <code className="font-mono text-slate-200">com.sun.net.httpserver.HttpServer</code> and <code className="font-mono text-slate-200">java.net.URI</code> for deterministic server-side URL parsing, rate-limiting, and optional Google Safe Browsing v4 lookups.
            </p>
            <div className="mt-4 pt-3 border-t border-slate-800 font-mono text-xs space-y-1.5">
              <div className="text-slate-300">
                Backend Runtime:{' '}
                <span className="text-emerald-400 font-semibold">
                  {backendRuntime}
                </span>
              </div>
              <div className="text-slate-300">
                Reputation Mode:{' '}
                <span className="text-sky-400 font-semibold">
                  {reputationConfigured
                    ? `Live Reputation + Heuristics (${reputationProviders.join(', ')})`
                    : 'Local URL heuristic analysis — external reputation not checked.'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <button
              type="button"
              onClick={handleDownloadJavaSource}
              className="rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer"
            >
              Download CyberShieldServer.java
            </button>
            <button
              type="button"
              onClick={onNavigateToScanner}
              className="rounded-lg bg-sky-400 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-300 transition-colors cursor-pointer"
            >
              Open URL Scanner
            </button>
          </div>
        </section>
      </div>

      {/* Documented Scoring Weights Table */}
      <section
        aria-labelledby="scoring-weights-heading"
        className="rounded-xl border border-slate-800 bg-[#111827] p-6"
      >
        <div className="border-b border-slate-800 pb-4 mb-4">
          <h2
            id="scoring-weights-heading"
            className="text-base font-semibold text-slate-100"
          >
            Documented Heuristic Weight Model (0–100 Scale)
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            These weights are transparent starting heuristics capped at 100, not statistically calibrated probabilities of fraud.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs sm:text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Heuristic Indicator</th>
                <th className="py-2.5 px-3 text-right">Weight Added</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {weightRows.map((row) => (
                <tr key={row.label} className="hover:bg-slate-800/30">
                  <td className="py-2.5 px-3 text-slate-200">{row.label}</td>
                  <td className="py-2.5 px-3 text-right font-mono font-semibold text-sky-400 tabular-nums">
                    +{row.weight}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
