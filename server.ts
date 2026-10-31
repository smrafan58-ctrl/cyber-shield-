import express, { type Request, type Response } from 'express';
import { URL } from 'node:url';

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));

// Apply security headers with iframe support for AI Studio preview
app.use((_req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' https://d3js.org; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors *; base-uri 'self'; form-action 'self'"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(self), payment=(), usb=()');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  next();
});

// Simple In-Memory Rate Limiter (120 requests per minute per IP)
const rateLimits = new Map<string, { count: number; windowStart: number }>();
app.use((req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const bucket = rateLimits.get(ip);
  if (!bucket || now - bucket.windowStart > 60_000) {
    rateLimits.set(ip, { count: 1, windowStart: now });
  } else {
    bucket.count++;
    if (bucket.count > 120) {
      return res.status(429).send('<!DOCTYPE html><html><body><h1>429 Too Many Requests</h1></body></html>');
    }
  }
  // Periodically clean up old buckets
  if (rateLimits.size > 2000) {
    for (const [k, v] of rateLimits.entries()) {
      if (now - v.windowStart > 120_000) rateLimits.delete(k);
    }
  }
  next();
});

export const MANDATORY_DISCLAIMER =
  'Risk scores are based on observable URL patterns and available reputation data. They do not guarantee that a website is safe or malicious.';

export const UNIVERSAL_SAFETY_RULES = [
  'Do not enter passwords on suspicious sites.',
  'Never share OTPs or banking credentials.',
  'Do not pay fines or transfer money based solely on a link\'s claims.',
  'Access official services through independently verified websites or applications.'
];

const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'co.in', 'gov.in', 'nic.in', 'org.in', 'ac.in', 'net.in', 'res.in', 'edu.in', 'mil.in',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'co.nz', 'com.br', 'com.sg', 'edu.sg', 'gov.sg',
  'co.za', 'com.mx', 'com.hk', 'com.tr', 'co.kr', 'co.id', 'com.my'
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'rb.gy', 'tiny.cc', 'shorturl.at', 'v.gd', 'bit.do', 'bl.ink'
]);

const FREQUENTLY_ABUSED_TLDS = new Set([
  'xyz', 'top', 'click', 'loan', 'work', 'gq', 'tk', 'ml', 'cf', 'ga',
  'zip', 'mov', 'icu', 'buzz', 'monster', 'rest', 'support'
]);

interface BrandRule {
  brandName: string;
  tokens: string[];
  officialDomains: Set<string>;
  typosquatPatterns: RegExp[];
}

const PROTECTED_BRANDS: BrandRule[] = [
  {
    brandName: 'Google',
    tokens: ['google', 'gmail', 'googlepay', 'gpay'],
    officialDomains: new Set(['google.com', 'google.co.in', 'google.co.uk', 'gmail.com', 'withgoogle.com', 'youtube.com']),
    typosquatPatterns: [/g00gle/i, /goog1e/i, /g0ogle/i, /googie/i, /go0gle/i]
  },
  {
    brandName: 'Microsoft',
    tokens: ['microsoft', 'office365', 'onedrive', 'outlook', 'sharepoint'],
    officialDomains: new Set(['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'sharepoint.com', 'onedrive.com', 'microsoftonline.com']),
    typosquatPatterns: [/micr0soft/i, /mircosoft/i, /micros0ft/i, /rnicrosoft/i, /outl00k/i]
  },
  {
    brandName: 'Apple',
    tokens: ['apple', 'icloud', 'appleid'],
    officialDomains: new Set(['apple.com', 'icloud.com', 'me.com']),
    typosquatPatterns: [/app1e/i, /ic1oud/i, /apple-id/i]
  },
  {
    brandName: 'Amazon',
    tokens: ['amazon', 'aws', 'primevideo'],
    officialDomains: new Set(['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com', 'primevideo.com']),
    typosquatPatterns: [/amaz0n/i, /arnazon/i, /amzon/i, /amazonn/i]
  },
  {
    brandName: 'PayPal',
    tokens: ['paypal'],
    officialDomains: new Set(['paypal.com', 'paypal.me']),
    typosquatPatterns: [/paypa1/i, /pay-pal/i, /paypaI/i, /paypai/i, /pаypal/i]
  },
  {
    brandName: 'Netflix',
    tokens: ['netflix'],
    officialDomains: new Set(['netflix.com']),
    typosquatPatterns: [/netf1ix/i, /netfllx/i, /netflx/i, /netflix-verify/i]
  },
  {
    brandName: 'Facebook / Meta',
    tokens: ['facebook', 'meta', 'instagram', 'whatsapp'],
    officialDomains: new Set(['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'fb.com']),
    typosquatPatterns: [/faceb00k/i, /facebok/i, /instagrarn/i, /whatsap/i, /whats-app/i]
  },
  {
    brandName: 'Banking Portal',
    tokens: ['chase', 'wellsfargo', 'bankofamerica', 'citibank', 'sbi', 'hdfcbank', 'icicibank'],
    officialDomains: new Set(['chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citi.com', 'onlinesbi.sbi', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com']),
    typosquatPatterns: [/ch4se/i, /we11sfargo/i, /bank0famerica/i, /sbi-secure/i, /hdfc-verify/i]
  },
  {
    brandName: 'Law Enforcement / Government Portal',
    tokens: ['digital-arrest', 'cybercrime', 'police-fine', 'incometax', 'court-summons', 'echallan'],
    officialDomains: new Set(['incometax.gov.in', 'cybercrime.gov.in', 'echallan.parivahan.gov.in', 'usa.gov', 'fbi.gov', 'gov.uk']),
    typosquatPatterns: [/digital-?arrest/i, /cybercrime-?gov/i, /police-?notice/i, /urgent-?fine/i]
  }
];

export interface IndicatorItem {
  id: string;
  name: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  explanation: string;
  component: string;
  reasonItMatters: string;
  weight: number;
}

export interface DomainDetails {
  hostname: string;
  registrableDomain: string;
  subdomain: string;
  tld: string;
  protocol: string;
  port: string;
  path: string;
  queryParamCount: number;
  redactedUrl: string;
}

export interface GuidanceDetails {
  headline: string;
  primaryAdvice: string;
  universalRules: string[];
}

export interface ScanResult {
  scanId: string;
  timestamp: string;
  riskScore: number;
  classification: string;
  summaryExplanation: string;
  domain: DomainDetails;
  indicators: IndicatorItem[];
  guidance: GuidanceDetails;
  disclaimer: string;
}

// In-Memory LRU History Store (max 5 entries)
class ScanHistoryStore {
  private history: ScanResult[] = [];

  record(item: ScanResult): void {
    const existingIdx = this.history.findIndex(
      (h) => h.domain.hostname.toLowerCase() === item.domain.hostname.toLowerCase()
    );
    if (existingIdx !== -1) {
      this.history.splice(existingIdx, 1);
    }
    this.history.unshift(item);
    if (this.history.length > 5) {
      this.history = this.history.slice(0, 5);
    }
  }

  getRecent(): ScanResult[] {
    return [...this.history];
  }

  clear(): void {
    this.history = [];
  }
}

export const historyStore = new ScanHistoryStore();

export function redactSensitiveInput(rawUrl: string): string {
  if (!rawUrl) return '';
  let cleaned = rawUrl.replace(/(AIza[0-9A-Za-z_-]{15,}|sk-[0-9A-Za-z_-]{15,}|ghp_[0-9A-Za-z]{15,})/gi, '[REDACTED_KEY]');
  cleaned = cleaned.replace(/:\/\/([^:@]+):([^@]+)@/g, '://$1:[REDACTED_PASSWORD]@');
  return cleaned;
}

function parseRegistrableDomain(hostname: string): { registrable: string; sub: string; tld: string } {
  const host = hostname.toLowerCase();
  const parts = host.split('.');
  if (parts.length <= 1) return { registrable: host, sub: 'None', tld: 'None' };

  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_TLDS.has(lastTwo)) {
      const reg = parts.slice(-3).join('.');
      const sub = parts.slice(0, -3).join('.') || 'None';
      return { registrable: reg, sub, tld: lastTwo };
    }
  }

  const reg = parts.slice(-2).join('.');
  const sub = parts.slice(0, -2).join('.') || 'None';
  const tld = parts[parts.length - 1];
  return { registrable: reg, sub, tld };
}

export function analyzeUrlStructured(rawUrl: string): { valid: boolean; errorReason?: string; result?: ScanResult } {
  if (!rawUrl || !rawUrl.trim()) {
    return { valid: false, errorReason: 'Please enter a web address to analyze.' };
  }
  const trimmed = rawUrl.trim();
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    return { valid: false, errorReason: 'URL contains invalid control characters.' };
  }

  let parseTarget = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(parseTarget)) {
    parseTarget = 'https://' + parseTarget;
  }

  let parsed: URL;
  try {
    parsed = new URL(parseTarget);
  } catch {
    return { valid: false, errorReason: 'Malformed URL structure. Ensure it follows standard domain formatting.' };
  }

  const protocol = parsed.protocol.replace(':', '').toUpperCase();
  if (protocol !== 'HTTP' && protocol !== 'HTTPS') {
    return { valid: false, errorReason: `Unsupported protocol "${protocol}://". CyberShield analyzes web links (HTTP/HTTPS).` };
  }

  const hostname = parsed.hostname;
  if (!hostname || hostname.includes('\\') || hostname.includes(' ')) {
    return { valid: false, errorReason: 'Invalid hostname format.' };
  }

  const { registrable, sub, tld } = parseRegistrableDomain(hostname);
  const isHttp = protocol === 'HTTP';
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');

  const indicators: IndicatorItem[] = [];

  // 1. IP literal check
  if (isIp) {
    indicators.push({
      id: 'ip-literal-host',
      name: 'Host Formatted as Raw IP Address',
      severity: 'CRITICAL',
      explanation: `The link directs to raw numeric IP (${hostname}) instead of a named domain.`,
      component: hostname,
      reasonItMatters: 'Legitimate services use registered domain names. Raw IPs bypass domain reputation filters and are frequently used in automated attacks.',
      weight: 35
    });
  }

  // 2. Abused TLD
  if (FREQUENTLY_ABUSED_TLDS.has(tld.toLowerCase())) {
    indicators.push({
      id: 'abused-tld',
      name: `Frequently Abused Top-Level Domain (.${tld})`,
      severity: 'MEDIUM',
      explanation: `The .${tld} top-level domain exhibits high abuse and disposable spam rates.`,
      component: '.' + tld,
      reasonItMatters: 'Disproportionately used for disposable spam campaigns and brand impersonation due to low registration friction.',
      weight: 20
    });
  }

  // 3. URL shortener
  if (URL_SHORTENERS.has(registrable.toLowerCase())) {
    indicators.push({
      id: 'url-shortener',
      name: 'URL Shortener Gateway',
      severity: 'HIGH',
      explanation: `Domain ${registrable} is a shortening service that conceals the ultimate landing location.`,
      component: registrable,
      reasonItMatters: 'Shortened URLs obstruct sender transparency and prevent direct verification before following.',
      weight: 25
    });
  }

  // 4. Multiple subdomain nesting
  if (sub !== 'None' && sub.split('.').length >= 3) {
    indicators.push({
      id: 'excessive-subdomains',
      name: 'Deeply Nested Subdomain Chain',
      severity: 'MEDIUM',
      explanation: `Subdomain prefix "${sub}" contains multiple levels of nesting.`,
      component: sub,
      reasonItMatters: 'Attackers chain multiple subdomains to imitate valid domain names or confuse visual parsing on mobile screens.',
      weight: 15
    });
  }

  // 5. Unencrypted HTTP
  if (isHttp) {
    indicators.push({
      id: 'unencrypted-http',
      name: 'Unencrypted HTTP Connection',
      severity: 'MEDIUM',
      explanation: 'Traffic is transmitted in plain text without SSL/TLS certificate encryption.',
      component: 'http://',
      reasonItMatters: 'Login credentials and session cookies transmitted over HTTP can be intercepted by anyone on the local network.',
      weight: 15
    });
  }

  // 6. Brand Spoofing / Typosquatting checks
  const lowerHost = hostname.toLowerCase();
  for (const brand of PROTECTED_BRANDS) {
    const isOfficial = brand.officialDomains.has(registrable.toLowerCase());

    if (!isOfficial) {
      // Subdomain spoofing
      if (sub !== 'None') {
        const subLower = sub.toLowerCase();
        for (const token of brand.tokens) {
          if (subLower.includes(token)) {
            indicators.push({
              id: 'brand-impersonation',
              name: `Possible Brand Impersonation (${brand.brandName})`,
              severity: 'CRITICAL',
              explanation: `The subdomain contains '${token}', but the actual registrable domain is '${registrable}'.`,
              component: sub,
              reasonItMatters: `Attackers prepend trusted names to deceive users. Only the registrable domain (${registrable}) controls this site.`,
              weight: 35
            });
            break;
          }
        }
      }

      // Typosquatting on domain
      for (const pattern of brand.typosquatPatterns) {
        if (pattern.test(lowerHost)) {
          indicators.push({
            id: 'typosquatting-signal',
            name: `Lookalike Typosquatting Pattern (${brand.brandName})`,
            severity: 'HIGH',
            explanation: `Host '${hostname}' matches character substitution or hyphenated imitation patterns for ${brand.brandName}.`,
            component: hostname,
            reasonItMatters: 'Attackers swap lookalike characters (such as 0 for o, 1 for l, or rn for m) to fool users into submitting credentials.',
            weight: 25
          });
          break;
        }
      }
    }
  }

  // 7. Deceptive path tokens
  const pathLower = parsed.pathname.toLowerCase();
  const DECEPTIVE_PATHS = ['wp-admin', 'cpanel', 'webmail', 'secure', 'verify', 'account-suspended', 'digital-arrest', 'police-notice', 'urgent-fine', 'kyc-update'];
  for (const p of DECEPTIVE_PATHS) {
    if (pathLower.includes(p)) {
      indicators.push({
        id: 'deceptive-path-token',
        name: `High-Risk Action Path (/${p})`,
        severity: 'MEDIUM',
        explanation: `Path contains security-sensitive action token '${p}'.`,
        component: parsed.pathname,
        reasonItMatters: 'Phishing kits commonly use urgent administrative or verification paths to simulate legitimate portal workflows.',
        weight: 15
      });
      break;
    }
  }

  // Deduplicate indicators by id
  const seenIds = new Set<string>();
  const uniqueIndicators = indicators.filter((ind) => {
    if (seenIds.has(ind.id)) return false;
    seenIds.add(ind.id);
    return true;
  });

  const totalPoints = uniqueIndicators.reduce((sum, ind) => sum + ind.weight, 0);
  const riskScore = Math.min(100, Math.max(0, totalPoints));

  let classification = 'LOW RISK INDICATORS';
  let headline = 'Low Risk Indicators Detected';
  let primaryAdvice = 'No overt deceptive heuristics matched. Verify sender context before entering private credentials.';
  if (riskScore >= 70) {
    classification = 'CRITICAL RISK DETECTED';
    headline = 'Critical Threat Patterns Identified';
    primaryAdvice = 'DO NOT open this link or submit passwords, payment information, or personal identifiers.';
  } else if (riskScore >= 45) {
    classification = 'HIGH RISK INDICATORS';
    headline = 'High Risk URL Patterns Detected';
    primaryAdvice = 'Treat this link with extreme caution. The domain anatomy exhibits hallmarks of phishing or brand spoofing.';
  } else if (riskScore >= 20) {
    classification = 'MODERATE RISK DETECTED';
    headline = 'Moderate Risk Signals Present';
    primaryAdvice = 'Inspect the true registrable domain closely. Do not proceed if prompted to bypass security warnings.';
  } else if (riskScore > 0) {
    classification = 'MILD RISK INDICATORS';
    headline = 'Minor Risk Factors Identified';
    primaryAdvice = 'Review destination carefully. Ensure the sender is verified.';
  }

  // Redact query parameter values in sanitized URL
  let queryCount = 0;
  const sanitizedParams = new URLSearchParams();
  parsed.searchParams.forEach((_val, key) => {
    queryCount++;
    sanitizedParams.append(key, '[REDACTED]');
  });
  const portDisplay = parsed.port || (isHttp ? '80' : '443');
  const sanitizedQuery = sanitizedParams.toString() ? '?' + sanitizedParams.toString() : '';
  const redactedUrl = `${protocol.toLowerCase()}://${hostname}${parsed.port ? ':' + parsed.port : ''}${parsed.pathname}${sanitizedQuery}`;

  const result: ScanResult = {
    scanId: 'scan_' + Math.random().toString(36).substring(2, 10),
    timestamp: new Date().toISOString(),
    riskScore,
    classification,
    summaryExplanation: uniqueIndicators.length === 0
      ? 'Deterministic heuristic analysis evaluated URL anatomy, registrable domain structure, brand spoofing rules, and protocol safety. Zero high-risk deception signals were triggered.'
      : `Deterministic heuristic analysis triggered ${uniqueIndicators.length} risk factor${uniqueIndicators.length === 1 ? '' : 's'}, yielding a composite score of ${riskScore}/100.`,
    domain: {
      hostname,
      registrableDomain: registrable,
      subdomain: sub,
      tld,
      protocol,
      port: portDisplay,
      path: parsed.pathname || '/',
      queryParamCount: queryCount,
      redactedUrl
    },
    indicators: uniqueIndicators,
    guidance: {
      headline,
      primaryAdvice,
      universalRules: UNIVERSAL_SAFETY_RULES
    },
    disclaimer: MANDATORY_DISCLAIMER
  };

  historyStore.record(result);
  return { valid: true, result };
}

// Format TXT report
export function formatTxtReport(res: ScanResult): string {
  const lines: string[] = [
    '========================================================================',
    '                   CYBERSHIELD AI — SCAN REPORT',
    '========================================================================',
    `Timestamp          : ${res.timestamp}`,
    `Target Hostname    : ${res.domain.hostname}`,
    `Registrable Domain : ${res.domain.registrableDomain}`,
    `Subdomain          : ${res.domain.subdomain}`,
    `Protocol / Port    : ${res.domain.protocol} / ${res.domain.port}`,
    `Path               : ${res.domain.path}`,
    `Composite Risk     : ${res.riskScore} / 100`,
    `Classification     : ${res.classification}`,
    `Sanitized URL      : ${res.domain.redactedUrl}`,
    '------------------------------------------------------------------------',
    'SUMMARY EXPLANATION:',
    res.summaryExplanation,
    '------------------------------------------------------------------------',
    `DETECTED INDICATORS (${res.indicators.length} Triggered):`
  ];
  if (res.indicators.length === 0) {
    lines.push('  None. No suspicious URL heuristics triggered.');
  } else {
    res.indicators.forEach((ind, i) => {
      lines.push(`  ${i + 1}. [${ind.severity}] ${ind.name} (+${ind.weight} pts)`);
      lines.push(`     Matched: ${ind.component}`);
      lines.push(`     Why: ${ind.reasonItMatters}`);
    });
  }
  lines.push('------------------------------------------------------------------------');
  lines.push('RECOMMENDED DEFENSIVE ACTIONS:');
  lines.push('  ' + res.guidance.primaryAdvice);
  res.guidance.universalRules.forEach((rule, i) => {
    lines.push(`  ${i + 1}. ${rule}`);
  });
  lines.push('========================================================================');
  lines.push('DISCLAIMER:');
  lines.push(res.disclaimer);
  lines.push('========================================================================');
  return lines.join('\n');
}

// HTML View Rendering Helpers
function htmlEscape(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getRiskTheme(classification: string) {
  const upper = (classification || '').toUpperCase();
  if (upper.includes('CRITICAL')) {
    return { strokeHex: '#DC2626', badgeBg: '#FEF2F2', badgeBorder: '#FECACA', textClass: 'tone-red', barClass: 'bar-red', borderClass: 'border-l-red' };
  } else if (upper.includes('HIGH')) {
    return { strokeHex: '#EA580C', badgeBg: '#FFF7ED', badgeBorder: '#FED7AA', textClass: 'tone-orange', barClass: 'bar-orange', borderClass: 'border-l-orange' };
  } else if (upper.includes('MODERATE')) {
    return { strokeHex: '#C2410C', badgeBg: '#FBEFE1', badgeBorder: '#F5D0A9', textClass: 'tone-terracotta', barClass: 'bar-orange', borderClass: 'border-l-orange' };
  } else if (upper.includes('MILD')) {
    return { strokeHex: '#D97706', badgeBg: '#FFFBEB', badgeBorder: '#FDE68A', textClass: 'tone-amber', barClass: 'bar-amber', borderClass: 'border-l-amber' };
  }
  return { strokeHex: '#059669', badgeBg: '#ECFDF5', badgeBorder: '#A7F3D0', textClass: 'tone-emerald', barClass: 'bar-emerald', borderClass: 'border-l-emerald' };
}

function renderHtmlPage(title: string, bodyContent: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <script>
    (function() {
      // Pre-define inert window.ethereum / web3 stub so browser wallet extensions (e.g. MetaMask inpage.js)
      // do not throw "Failed to connect to MetaMask" or "Error restoring session" in non-Web3 pages
      try {
        var noopProvider = {
          isMetaMask: false,
          isConnected: function() { return false; },
          request: function() { return Promise.resolve(null); },
          send: function() { return Promise.resolve(null); },
          sendAsync: function(_p, cb) { if (typeof cb === 'function') cb(null, { result: null }); },
          enable: function() { return Promise.resolve([]); },
          on: function() { return this; },
          removeListener: function() { return this; },
          removeAllListeners: function() { return this; }
        };
        if (typeof window.ethereum === 'undefined') {
          Object.defineProperty(window, 'ethereum', {
            value: noopProvider,
            writable: true,
            configurable: true
          });
        }
      } catch (_e) {}

      function isExtensionNoise(str) {
        if (!str) return false;
        var s = String(str).toLowerCase();
        return s.indexOf('metamask') !== -1 ||
               s.indexOf('error restoring session') !== -1 ||
               s.indexOf('failed to connect') !== -1 ||
               s.indexOf('nkbihfbeogaeaoehlefnkodbefgpgknn') !== -1 ||
               s.indexOf('chrome-extension://') !== -1 ||
               s.indexOf('moz-extension://') !== -1 ||
               s.indexOf('safari-web-extension://') !== -1 ||
               s.indexOf('inpage.js') !== -1 ||
               s.indexOf('contentscript.js') !== -1;
      }
      function checkArgs(args) {
        for (var i = 0; i < args.length; i++) {
          var a = args[i];
          if (!a) continue;
          if (typeof a === 'string' && isExtensionNoise(a)) return true;
          if (typeof a === 'object') {
            if (isExtensionNoise(a.message) || isExtensionNoise(a.stack) || isExtensionNoise(a.filename)) return true;
            try { if (isExtensionNoise(JSON.stringify(a))) return true; } catch(err) {}
          }
        }
        return false;
      }
      var origError = console.error;
      var origWarn = console.warn;
      var origInfo = console.info;
      console.error = function() {
        if (checkArgs(arguments)) return;
        return origError.apply(console, arguments);
      };
      console.warn = function() {
        if (checkArgs(arguments)) return;
        return origWarn.apply(console, arguments);
      };
      console.info = function() {
        if (checkArgs(arguments)) return;
        return origInfo.apply(console, arguments);
      };
      window.onerror = function(msg, url, line, col, error) {
        if (isExtensionNoise(msg) || isExtensionNoise(url) || (error && (isExtensionNoise(error.message) || isExtensionNoise(error.stack)))) {
          return true;
        }
        return false;
      };
      window.addEventListener('error', function(e) {
        var combined = (e.message || '') + ' ' + (e.filename || '') + ' ' + (e.error && e.error.stack ? e.error.stack : '');
        if (isExtensionNoise(combined)) {
          e.stopImmediatePropagation();
          e.stopPropagation();
          e.preventDefault();
          return true;
        }
      }, true);
      window.addEventListener('unhandledrejection', function(e) {
        var r = e.reason;
        var combined = r ? ((r.message || String(r)) + ' ' + (r.stack || '')) : '';
        if (isExtensionNoise(combined)) {
          e.stopImmediatePropagation();
          e.stopPropagation();
          e.preventDefault();
          return true;
        }
      }, true);
    })();
  </script>
  <title>${htmlEscape(title)}</title>
  <meta name="description" content="CyberShield AI — URL Threat Detection & Cybersecurity Awareness Platform for analyzing suspicious links, phishing patterns, deceptive domains, and brand impersonation." />
  <meta property="og:title" content="${htmlEscape(title)}" />
  <meta property="og:description" content="URL Threat Detection & Cybersecurity Awareness Platform for analyzing suspicious links, phishing patterns, deceptive domains, and brand impersonation." />
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23C2410C'%3E%3Cpath d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z'/%3E%3C/svg%3E" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <script src="https://d3js.org/d3.v7.min.js" defer></script>
  <style>
    :root {
      --bg-canvas: #F7F4EE;
      --bg-card: #FFFFFF;
      --bg-subtle: #F3EFE9;
      --bg-warm-tint: #FBEFE1;
      --border-main: #E3DAD0;
      --border-soft: #EDE6DC;
      --text-main: #1C1917;
      --text-body: #44403C;
      --text-muted: #78716C;
      --accent: #C2410C;
      --accent-hover: #9A3412;
      --font-sans: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      --shadow-sm: 0 1px 2px rgba(28,25,23,0.05);
      --shadow-md: 0 4px 12px rgba(28,25,23,0.06), 0 1px 2px rgba(28,25,23,0.04);
      --shadow-lg: 0 12px 32px rgba(28,25,23,0.12), 0 2px 6px rgba(28,25,23,0.06);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-canvas);
      color: var(--text-main);
      font-family: var(--font-sans);
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }
    .top-navbar {
      background: var(--bg-card);
      border-bottom: 1px solid var(--border-main);
      position: sticky;
      top: 0;
      z-index: 30;
      box-shadow: var(--shadow-sm);
    }
    .navbar-inner {
      max-width: 1240px;
      margin: 0 auto;
      padding: 0.85rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
    }
    .brand-wordmark {
      display: inline-flex;
      align-items: center;
      gap: 0.6rem;
      font-size: 1.15rem;
      font-weight: 800;
      color: var(--text-main);
      text-decoration: none;
      white-space: nowrap;
      letter-spacing: -0.02em;
    }
    .brand-shield-icon { color: var(--accent); display: flex; align-items: center; }
    .nav-links { display: flex; align-items: center; gap: 1.75rem; }
    .nav-link { font-size: 0.875rem; font-weight: 600; color: var(--text-body); text-decoration: none; }
    .nav-link:hover { color: var(--accent); }
    .btn-nav-action {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.5rem 1rem;
      border-radius: 0.5rem;
      background: var(--accent);
      color: #FFFFFF;
      font-size: 0.8125rem;
      font-weight: 700;
      text-decoration: none;
      cursor: pointer;
      border: none;
    }
    .btn-nav-action:hover { background: var(--accent-hover); }
    .main-content { flex: 1; padding: 2rem 1rem 3.5rem; }
    .container-narrow { max-width: 980px; margin: 0 auto; }
    .container-wide { max-width: 1240px; margin: 0 auto; }
    .stack-lg > * + * { margin-top: 2rem; }
    .stack-md > * + * { margin-top: 1.5rem; }
    .card-editorial {
      background: var(--bg-card);
      border: 1px solid var(--border-main);
      border-radius: 0.85rem;
      box-shadow: var(--shadow-sm);
    }
    .section-pad { padding: 1.75rem 2rem; }
    .hero-masthead {
      background: linear-gradient(180deg, #FDF4E8 0%, #FAF0E4 100%);
      border-bottom: 1px solid var(--border-main);
      padding: 2.75rem 2rem 2.25rem;
      text-align: center;
    }
    .hero-badge {
      display: inline-block;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--accent);
      background: #FFFFFF;
      border: 1px solid var(--border-soft);
      padding: 0.3rem 0.85rem;
      border-radius: 99px;
      margin-bottom: 1rem;
    }
    .hero-title {
      font-size: clamp(1.85rem, 3.4vw, 2.75rem);
      font-weight: 800;
      line-height: 1.2;
      color: var(--text-main);
      max-width: 42rem;
      margin: 0 auto;
      letter-spacing: -0.025em;
    }
    .hero-subtitle {
      margin: 1rem auto 0;
      max-width: 44rem;
      font-size: 0.95rem;
      color: var(--text-body);
      line-height: 1.6;
    }
    .console-body { padding: 2rem; }
    .label-row {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      justify-content: space-between;
      gap: 0.5rem;
      margin-bottom: 0.65rem;
    }
    .input-label { font-size: 0.875rem; font-weight: 700; color: var(--text-main); }
    .meta-mono { font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); }
    .meta-quiet { font-size: 0.78rem; color: var(--text-muted); }
    .scanner-bar { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: stretch; }
    .input-wrapper { position: relative; flex: 1 1 320px; }
    .input-icon {
      position: absolute;
      left: 1rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      display: flex;
      pointer-events: none;
    }
    .btn-voice-icon {
      position: absolute;
      right: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.35rem;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .btn-voice-icon:hover { color: var(--accent); }
    .btn-voice-icon.listening { color: #DC2626; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
    .url-input {
      width: 100%;
      border: 1.5px solid var(--border-main);
      background: var(--bg-card);
      border-radius: 0.6rem;
      padding: 0.85rem 2.5rem 0.85rem 2.75rem;
      font-family: var(--font-mono);
      font-size: 0.925rem;
      color: var(--text-main);
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .url-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(194,65,12,0.15); }
    .url-input.input-invalid { border-color: #DC2626 !important; box-shadow: 0 0 0 3px rgba(220,38,38,0.15) !important; }
    .button-group { display: flex; gap: 0.65rem; align-items: center; flex-wrap: wrap; }
    .btn-primary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      background: var(--accent);
      color: #FFFFFF;
      border: none;
      border-radius: 0.6rem;
      padding: 0.85rem 1.4rem;
      font-size: 0.875rem;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      white-space: nowrap;
      transition: background 0.15s ease, transform 0.1s ease;
    }
    .btn-primary:hover { background: var(--accent-hover); transform: translateY(-1px); }
    .btn-scan-now {
      padding: 0.85rem 1.6rem;
      font-size: 0.925rem;
      font-weight: 700;
    }
    .client-alert {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-top: 0.85rem;
      padding: 0.75rem 1rem;
      border-radius: 0.5rem;
      background: #FEF2F2;
      border: 1px solid #FECACA;
      color: #991B1B;
      font-size: 0.825rem;
      font-weight: 600;
      text-align: left;
    }
    .client-alert.hidden { display: none !important; }
    .spinner-icon {
      width: 14px;
      height: 14px;
      border: 2px solid #FFFFFF;
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
      display: inline-block;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .btn-secondary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
      background: #FFFFFF;
      color: var(--text-main);
      border: 1px solid var(--border-main);
      border-radius: 0.6rem;
      padding: 0.85rem 1.15rem;
      font-size: 0.8125rem;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      white-space: nowrap;
    }
    .btn-secondary:hover { background: var(--bg-subtle); }
    .alert-error {
      margin-top: 1rem;
      padding: 1rem 1.25rem;
      border-radius: 0.6rem;
      border: 1px solid #FECACA;
      background: #FEF2F2;
      color: #991B1B;
    }
    .presets-block { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border-soft); }
    .presets-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 0.75rem;
      margin-top: 0.75rem;
    }
    .preset-card {
      width: 100%;
      text-align: left;
      background: #FFFFFF;
      border: 1px solid var(--border-soft);
      border-radius: 0.6rem;
      padding: 0.85rem 1rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .preset-card:hover { border-color: var(--accent); background: var(--bg-warm-tint); }
    .preset-card-top { display: flex; justify-content: space-between; align-items: center; }
    .preset-title { font-size: 0.82rem; font-weight: 700; color: var(--text-main); }
    .preset-arrow { font-size: 0.85rem; color: var(--accent); font-weight: 700; }
    .preset-url {
      margin-top: 0.3rem;
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .section-header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border-soft);
    }
    .section-title { font-size: 1.25rem; font-weight: 800; color: var(--text-main); }
    .badge-finding {
      font-size: 0.72rem;
      font-weight: 700;
      background: var(--bg-subtle);
      color: var(--text-body);
      padding: 0.25rem 0.65rem;
      border-radius: 99px;
      border: 1px solid var(--border-soft);
    }
    .history-list { list-style: none; }
    .history-row + .history-row { border-top: 1px solid var(--border-soft); }
    .history-item-btn {
      width: 100%;
      background: transparent;
      border: none;
      padding: 1rem 0.5rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      text-align: left;
      cursor: pointer;
      border-radius: 0.5rem;
    }
    .history-item-btn:hover { background: var(--bg-subtle); }
    .history-left { display: flex; align-items: center; gap: 0.85rem; min-width: 0; flex: 1; }
    .history-hostname { font-family: var(--font-mono); font-size: 0.875rem; font-weight: 700; color: var(--text-main); }
    .history-url { font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 460px; }
    .rules-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; margin-top: 1.25rem; }
    .rule-item { display: flex; gap: 0.75rem; padding: 1rem; background: var(--bg-subtle); border-radius: 0.6rem; border: 1px solid var(--border-soft); }
    .rule-num { font-family: var(--font-mono); font-weight: 800; font-size: 0.85rem; color: var(--accent); }
    .rule-item strong { display: block; font-size: 0.875rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem; }
    .rule-item p { font-size: 0.8rem; color: var(--text-body); line-height: 1.45; }
    .back-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
    .back-link { font-size: 0.875rem; font-weight: 700; color: var(--accent); text-decoration: none; }
    .btn-copy { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.75rem; font-size: 0.75rem; font-weight: 600; border: 1px solid var(--border-main); border-radius: 0.4rem; background: #fff; cursor: pointer; }
    .btn-copy:hover { background: var(--bg-subtle); }
    .anatomy-header { display: flex; justify-content: space-between; padding: 0.75rem 1.25rem; background: var(--bg-subtle); font-size: 0.8rem; border-bottom: 1px solid var(--border-soft); }
    .anatomy-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); border-bottom: 1px solid var(--border-soft); }
    .anatomy-cell { padding: 0.85rem 1.25rem; border-right: 1px solid var(--border-soft); }
    .anatomy-cell:last-child { border-right: none; }
    .anatomy-highlight { background: var(--bg-warm-tint); }
    .anatomy-label { font-size: 0.7rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .anatomy-val { font-family: var(--font-mono); font-size: 0.825rem; font-weight: 600; margin-top: 0.25rem; word-break: break-all; }
    .dashboard-grid-12 { display: grid; grid-template-columns: repeat(12, 1fr); gap: 1.25rem; }
    .col-span-7 { grid-column: span 7; }
    .col-span-5 { grid-column: span 5; }
    .score-hero-row { display: flex; flex-wrap: wrap; gap: 1.75rem; align-items: center; margin-top: 1.25rem; }
    .d3-gauge-card { display: flex; flex-direction: column; align-items: center; justify-content: center; background: var(--bg-subtle); border: 1px solid var(--border-soft); border-radius: 0.75rem; padding: 1rem 1.25rem 0.85rem; min-width: 240px; flex-shrink: 0; }
    .d3-gauge-mount { position: relative; width: 220px; height: 135px; display: flex; align-items: center; justify-content: center; }
    .d3-gauge-svg { width: 220px; height: 135px; overflow: visible; }
    .d3-gauge-readout { text-align: center; margin-top: -0.25rem; }
    .gauge-big-num { font-family: var(--font-mono); font-size: 2rem; font-weight: 800; line-height: 1; }
    .threat-level-tier-badge { display: inline-flex; align-items: center; gap: 0.35rem; margin-top: 0.4rem; padding: 0.2rem 0.65rem; border-radius: 99px; font-family: var(--font-mono); font-size: 0.72rem; font-weight: 800; letter-spacing: 0.05em; text-transform: uppercase; }
    .classification-pill { display: inline-block; padding: 0.35rem 0.85rem; border-radius: 99px; font-size: 0.75rem; font-weight: 800; letter-spacing: 0.04em; text-transform: uppercase; }
    .summary-prose { font-size: 0.875rem; color: var(--text-body); margin-top: 0.75rem; line-height: 1.5; }
    .linear-meter-block { margin-top: 1.25rem; }
    .meter-track { height: 8px; border-radius: 99px; background: var(--bg-subtle); overflow: hidden; margin-top: 0.35rem; }
    .meter-fill { height: 100%; border-radius: 99px; }
    .meter-ticks { display: flex; justify-content: space-between; margin-top: 0.3rem; font-size: 0.65rem; color: var(--text-muted); }
    .primary-advice { margin-top: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-soft); font-size: 0.925rem; font-weight: 700; }
    .guidance-list { list-style: none; margin-top: 1rem; }
    .guidance-list li { display: flex; gap: 0.65rem; font-size: 0.85rem; color: var(--text-body); margin-bottom: 0.65rem; }
    .action-bar-footer { margin-top: 1.5rem; padding-top: 1.25rem; border-top: 1px solid var(--border-soft); display: flex; flex-wrap: wrap; gap: 0.65rem; }
    .indicator-article { padding: 1.25rem 0; border-bottom: 1px solid var(--border-soft); }
    .indicator-article:last-child { border-bottom: none; }
    .indicator-top { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 0.5rem; }
    .indicator-title { font-size: 0.95rem; font-weight: 700; color: var(--text-main); }
    .indicator-exp { margin-top: 0.45rem; font-size: 0.875rem; color: var(--text-body); }
    .indicator-comp { margin-top: 0.45rem; font-size: 0.78rem; color: var(--text-muted); }
    .indicator-comp code { font-family: var(--font-mono); font-weight: 600; color: var(--accent); background: var(--bg-subtle); padding: 0.15rem 0.35rem; border-radius: 0.3rem; }
    .indicator-why { margin-top: 0.45rem; font-size: 0.78rem; color: var(--text-muted); }
    .domain-dl { margin-top: 0.5rem; font-size: 0.825rem; }
    .dl-row { display: flex; justify-content: space-between; gap: 1rem; padding: 0.65rem 0; border-bottom: 1px solid var(--border-soft); }
    .dl-row dt { color: var(--text-muted); font-weight: 500; }
    .dl-row dd { text-align: right; word-break: break-all; color: var(--text-main); font-weight: 600; }
    .tone-emerald { color: #047857; } .tone-amber { color: #B45309; } .tone-orange { color: #C2410C; } .tone-red { color: #B91C1C; } .tone-terracotta { color: #C2410C; }
    .bar-emerald { background: #059669; } .bar-amber { background: #D97706; } .bar-orange { background: #EA580C; } .bar-red { background: #DC2626; }
    .chat-launcher-wrap { position: fixed; bottom: 1.25rem; right: 1.25rem; z-index: 40; }
    .chat-launcher-wrap.hidden { display: none !important; }
    .chat-launcher-btn { display: inline-flex; align-items: center; gap: 0.75rem; background: #FFFFFF; border: 1.5px solid var(--border-main); border-radius: 99px; padding: 0.65rem 1.15rem 0.65rem 0.65rem; text-decoration: none; color: var(--text-main); box-shadow: var(--shadow-lg); cursor: pointer; }
    .chat-launcher-icon { width: 2.2rem; height: 2.2rem; border-radius: 99px; background: var(--accent); color: #fff; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .chat-launcher-title { display: block; font-size: 0.85rem; font-weight: 700; }
    .chat-launcher-sub { display: block; font-size: 0.7rem; color: var(--text-muted); }
    .chat-drawer { position: fixed; bottom: 1rem; right: 1rem; z-index: 50; width: min(440px, calc(100vw - 2rem)); max-height: calc(100vh - 2rem); background: #FFFFFF; border: 1.5px solid var(--border-main); border-radius: 1rem; box-shadow: var(--shadow-lg); overflow: hidden; display: flex; flex-direction: column; }
    .chat-drawer.hidden { display: none !important; }
    .chat-header { background: var(--bg-warm-tint); border-bottom: 1px solid var(--border-main); padding: 0.85rem 1rem; display: flex; justify-content: space-between; align-items: center; }
    .chat-header-title { font-size: 0.95rem; font-weight: 800; color: var(--text-main); }
    .chat-header-sub { font-size: 0.7rem; color: var(--text-muted); font-weight: 600; }
    .chat-header-actions { display: flex; gap: 0.4rem; align-items: center; }
    .chat-mini-btn { background: #FFFFFF; border: 1px solid var(--border-main); border-radius: 0.4rem; padding: 0.25rem 0.55rem; font-size: 0.72rem; font-weight: 600; color: var(--text-body); cursor: pointer; }
    .chat-config-bar { background: var(--bg-subtle); border-bottom: 1px solid var(--border-soft); padding: 0.6rem 1rem; font-size: 0.72rem; }
    .chat-thread { height: 280px; max-height: 40vh; overflow-y: auto; padding: 0.85rem 1rem; background: #FFFFFF; display: flex; flex-direction: column; gap: 0.65rem; }
    .chat-msg-row { display: flex; }
    .chat-user { justify-content: flex-end; }
    .chat-model { justify-content: flex-start; }
    .chat-bubble { max-width: 85%; padding: 0.65rem 0.9rem; border-radius: 0.85rem; font-size: 0.8rem; line-height: 1.45; white-space: pre-wrap; word-break: break-word; }
    .chat-user .chat-bubble { background: var(--accent); color: #fff; border-bottom-right-radius: 0.2rem; }
    .chat-model .chat-bubble { background: var(--bg-subtle); border: 1px solid var(--border-soft); color: var(--text-main); border-bottom-left-radius: 0.2rem; }
    .chat-prompts-bar { display: flex; gap: 0.4rem; overflow-x: auto; padding: 0.5rem 0.75rem; background: var(--bg-subtle); border-top: 1px solid var(--border-soft); }
    .chat-prompt-chip { flex-shrink: 0; background: #FFFFFF; border: 1px solid var(--border-soft); border-radius: 0.35rem; padding: 0.25rem 0.55rem; font-size: 0.68rem; color: var(--text-body); cursor: pointer; white-space: nowrap; }
    .chat-prompt-chip:hover { border-color: var(--accent); color: var(--accent); background: var(--bg-warm-tint); }
    .chat-input-bar { display: flex; gap: 0.5rem; padding: 0.65rem 0.75rem; border-top: 1px solid var(--border-soft); background: #FFFFFF; align-items: center; }
    .chat-input { flex: 1; border: 1.5px solid var(--border-main); border-radius: 0.5rem; padding: 0.5rem 0.75rem; font-size: 0.8rem; }
    .chat-input:focus { outline: none; border-color: var(--accent); }
    .btn-chat-voice { background: transparent; border: none; color: var(--text-muted); padding: 0.4rem; cursor: pointer; }
    .site-footer { background: #FFFFFF; border-top: 1px solid var(--border-soft); padding: 1.75rem 1.5rem; margin-top: 2rem; }
    .footer-inner { max-width: 1240px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem; font-size: 0.78rem; color: var(--text-muted); }
    .toast-container { position: fixed; top: 1.5rem; right: 1.5rem; z-index: 100; display: flex; flex-direction: column; gap: 0.5rem; pointer-events: none; }
    .toast-item { background: #1C1917; color: #FFFFFF; padding: 0.65rem 1rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600; box-shadow: var(--shadow-lg); transition: all 0.25s ease; }
    @media (max-width: 860px) {
      .dashboard-grid-12 { grid-template-columns: 1fr; }
      .col-span-7, .col-span-5 { grid-column: span 1; }
      .chat-drawer { width: 100vw; right: 0; bottom: 0; border-radius: 1rem 1rem 0 0; }
    }
  </style>
</head>
<body>
  <header class="top-navbar">
    <div class="navbar-inner">
      <a href="/" class="brand-wordmark">
        <span class="brand-shield-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.54-3.13 8.78-7 9.88-3.87-1.1-7-5.34-7-9.88V6.3l7-3.12z"/></svg></span>
        <span>CyberShield AI</span>
      </a>
      <nav class="nav-links" aria-label="Primary Navigation">
        <a href="/" class="nav-link">URL Scanner</a>
        <a href="/#diagnostic-presets" class="nav-link">Diagnostic Presets</a>
        <a href="/#recent-history" class="nav-link">Recent History</a>
        <a href="/#safety-rules" class="nav-link">Safety Rules</a>
      </nav>
      <div class="nav-cta">
        <button type="button" id="btn-nav-advisor" class="btn-nav-action">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
          <span>AI Security Advisor</span>
        </button>
      </div>
    </div>
  </header>

  ${bodyContent}

  <div id="chat-launcher-container" class="chat-launcher-wrap">
    <button type="button" id="btn-open-chat" class="chat-launcher-btn" aria-label="Open CyberShield Security Advisor">
      <span class="chat-launcher-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></span>
      <span>
        <strong class="chat-launcher-title">AI Security Advisor</strong>
        <span class="chat-launcher-sub">Ask questions about link safety</span>
      </span>
    </button>
  </div>

  <aside id="chat-drawer-panel" class="chat-drawer hidden" aria-label="CyberShield Security Advisor">
    <div class="chat-header">
      <div>
        <h2 class="chat-header-title">CyberShield Security Advisor</h2>
        <p class="chat-header-sub">URL Threat Analyst</p>
      </div>
      <div class="chat-header-actions">
        <button type="button" id="btn-reset-chat" class="chat-mini-btn">Reset</button>
        <button type="button" id="btn-close-chat" class="chat-mini-btn" aria-label="Close Advisor">✕</button>
      </div>
    </div>
    <div class="chat-config-bar">
      <label for="chatbot-role-select"><strong>Mode:</strong></label>
      <select id="chatbot-role-select" style="padding: 0.2rem 0.5rem; border-radius: 0.3rem; border: 1px solid var(--border-main);">
        <option value="threat-analyst">URL Threat Analyst</option>
        <option value="scam-educator">Scam & Phishing Educator</option>
        <option value="incident-advisor">Incident Safety Advisor</option>
      </select>
    </div>
    <div id="chat-messages-container" class="chat-thread">
      <div class="chat-msg-row chat-model">
        <div class="chat-bubble">
          <div class="chat-text">Hello! I am your CyberShield AI Security Advisor. Ask me anything about suspicious links, brand impersonation, lookalike domains, or safety steps.</div>
        </div>
      </div>
    </div>
    <div class="chat-prompts-bar">
      <button type="button" class="chat-prompt-chip" data-prompt="How do attackers use subdomains to spoof brands?">How do subdomains spoof brands?</button>
      <button type="button" class="chat-prompt-chip" data-prompt="What is a digital arrest scam link?">What is a digital arrest link?</button>
      <button type="button" class="chat-prompt-chip" data-prompt="I clicked a suspicious link—what should I do first?">Clicked a link: what to do?</button>
    </div>
    <form id="chat-input-form" class="chat-input-bar">
      <input id="chat-user-input" type="text" placeholder="Ask a security question..." class="chat-input" maxlength="500" />
      <button type="button" id="btn-chat-mic" class="btn-chat-voice" title="Dictate message"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg></button>
      <button type="submit" class="btn-primary" style="padding: 0.5rem 1rem;">Send</button>
    </form>
  </aside>

  <footer class="site-footer">
    <div class="footer-inner">
      <div><strong>CyberShield AI</strong> · Deterministic Threat Engine</div>
      <p style="max-width: 38rem;">${htmlEscape(MANDATORY_DISCLAIMER)}</p>
    </div>
  </footer>

  <div id="toast-container" class="toast-container" aria-live="polite"></div>

  <script>
    (function() {
      function showToast(msg) {
        var c = document.getElementById('toast-container');
        if (!c) return;
        var t = document.createElement('div');
        t.className = 'toast-item';
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(function() {
          t.style.opacity = '0';
          setTimeout(function() { if (t.parentNode) t.parentNode.removeChild(t); }, 300);
        }, 2500);
      }

      function copyTextSafely(text) {
        if (!text) return;
        function fallback() {
          try {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            ta.style.top = '0';
            ta.setAttribute('readonly', '');
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch(e) {}
            document.body.removeChild(ta);
            showToast('Sanitized URL copied');
          } catch(err) {
            showToast('URL: ' + (text.length > 30 ? text.substring(0, 30) + '...' : text));
          }
        }
        try {
          if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function() {
              showToast('Sanitized URL copied');
            }).catch(fallback);
          } else { fallback(); }
        } catch(e) { fallback(); }
      }

      var copyBtn = document.getElementById('btn-copy-url');
      if (copyBtn) {
        copyBtn.addEventListener('click', function() {
          var text = copyBtn.getAttribute('data-copy');
          copyTextSafely(text);
        });
      }

      var drawer = document.getElementById('chat-drawer-panel');
      var launcher = document.getElementById('chat-launcher-container');
      var navAdvisorBtn = document.getElementById('btn-nav-advisor');
      var openBtn = document.getElementById('btn-open-chat');
      var closeBtn = document.getElementById('btn-close-chat');
      var chatThread = document.getElementById('chat-messages-container');

      function openDrawer() {
        if (drawer) drawer.classList.remove('hidden');
        if (launcher) launcher.classList.add('hidden');
        if (navAdvisorBtn) navAdvisorBtn.querySelector('span').textContent = 'Hide Advisor';
        if (chatThread) chatThread.scrollTop = chatThread.scrollHeight;
        var inp = document.getElementById('chat-user-input');
        if (inp) inp.focus();
      }

      function closeDrawer() {
        if (drawer) drawer.classList.add('hidden');
        if (launcher) launcher.classList.remove('hidden');
        if (navAdvisorBtn) navAdvisorBtn.querySelector('span').textContent = 'AI Security Advisor';
      }

      if (openBtn) openBtn.addEventListener('click', openDrawer);
      if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
      if (navAdvisorBtn) {
        navAdvisorBtn.addEventListener('click', function() {
          if (drawer && !drawer.classList.contains('hidden')) closeDrawer();
          else openDrawer();
        });
      }

      var chatForm = document.getElementById('chat-input-form');
      var chatInput = document.getElementById('chat-user-input');
      var roleSelect = document.getElementById('chatbot-role-select');
      var resetBtn = document.getElementById('btn-reset-chat');

      if (resetBtn) {
        resetBtn.addEventListener('click', function() {
          if (chatThread) {
            chatThread.innerHTML = '<div class="chat-msg-row chat-model"><div class="chat-bubble"><div class="chat-text">Conversation reset. Ask any question about URL safety.</div></div></div>';
            showToast('Advisor reset');
          }
        });
      }

      function appendMsg(role, text) {
        if (!chatThread) return;
        var row = document.createElement('div');
        row.className = 'chat-msg-row ' + (role === 'user' ? 'chat-user' : 'chat-model');
        var bubble = document.createElement('div');
        bubble.className = 'chat-bubble';
        var txt = document.createElement('div');
        txt.className = 'chat-text';
        txt.textContent = text;
        bubble.appendChild(txt);
        row.appendChild(bubble);
        chatThread.appendChild(row);
        chatThread.scrollTop = chatThread.scrollHeight;
      }

      function sendChat(msgText) {
        if (!msgText || !msgText.trim()) return;
        var text = msgText.trim();
        appendMsg('user', text);
        if (chatInput) chatInput.value = '';
        var role = roleSelect ? roleSelect.value : 'threat-analyst';

        fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text, rolePreset: role })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          appendMsg('model', data.reply || 'Analysis completed.');
        })
        .catch(function() {
          appendMsg('model', 'Advisor advice: Never input sensitive credentials on unverified domains.');
        });
      }

      if (chatForm) {
        chatForm.addEventListener('submit', function(e) {
          e.preventDefault();
          if (chatInput) sendChat(chatInput.value);
        });
      }

      var chips = document.querySelectorAll('.chat-prompt-chip');
      chips.forEach(function(chip) {
        chip.addEventListener('click', function() {
          var p = chip.getAttribute('data-prompt');
          if (p) sendChat(p);
        });
      });

      function setupVoice(btn, targetInput) {
        if (!btn || !targetInput) return;
        var SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (!SpeechRec) {
          btn.title = 'Speech recognition not supported';
          return;
        }
        var rec = new SpeechRec();
        rec.continuous = false;
        rec.interimResults = false;
        var listening = false;

        btn.addEventListener('click', function(e) {
          e.preventDefault();
          if (listening) { rec.stop(); return; }
          try {
            rec.start();
            listening = true;
            btn.classList.add('listening');
            showToast('Listening...');
          } catch(err) {}
        });

        rec.onresult = function(ev) {
          listening = false;
          btn.classList.remove('listening');
          if (ev.results && ev.results[0] && ev.results[0][0]) {
            targetInput.value = ev.results[0][0].transcript.trim();
          }
        };
        rec.onerror = rec.onend = function() {
          listening = false;
          btn.classList.remove('listening');
        };
      }

      // URL Input Client-Side Validation & Clean Submit Handling
      var scanForm = document.getElementById('scan-form');
      var scanInput = document.getElementById('url-scanner-input');
      var validationAlert = document.getElementById('client-validation-alert');
      var validationText = document.getElementById('client-validation-text');
      var scanNowBtn = document.getElementById('btn-scan-now');
      var clearInputBtn = document.getElementById('btn-clear-input');

      function validateUrlString(val) {
        if (!val || !val.trim()) {
          return { valid: false, error: 'Please enter a web address to initiate the security check.' };
        }
        var s = val.trim();
        if (s.indexOf(' ') !== -1) {
          return { valid: false, error: 'Web addresses cannot contain spaces. Please check for accidental spaces.' };
        }
        if (/[\x00-\x1F\x7F]/.test(s)) {
          return { valid: false, error: 'The URL contains invalid control characters.' };
        }
        if (/^(javascript|data|file|vbscript|about):/i.test(s)) {
          return { valid: false, error: 'Only web links (HTTP or HTTPS) can be inspected.' };
        }
        var testUrl = s;
        if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(testUrl)) {
          testUrl = 'https://' + testUrl;
        }
        try {
          var u = new URL(testUrl);
          var h = u.hostname;
          if (!h || (h.indexOf('.') === -1 && !/^(\d{1,3}\.){3}\d{1,3}$/.test(h) && h !== 'localhost')) {
            return { valid: false, error: 'Please enter a valid domain name (e.g., example.com or https://example.com).' };
          }
          if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            return { valid: false, error: 'Please submit a standard web URL beginning with http:// or https://' };
          }
          return { valid: true, sanitized: testUrl };
        } catch(e) {
          return { valid: false, error: 'Invalid URL structure. Ensure it follows standard domain format (e.g., example.com).' };
        }
      }

      if (scanForm && scanInput) {
        scanForm.addEventListener('submit', function(e) {
          var res = validateUrlString(scanInput.value);
          if (!res.valid) {
            e.preventDefault();
            if (validationAlert && validationText) {
              validationText.textContent = res.error;
              validationAlert.classList.remove('hidden');
            }
            scanInput.focus();
            scanInput.classList.add('input-invalid');
            return false;
          }
          if (validationAlert) validationAlert.classList.add('hidden');
          scanInput.classList.remove('input-invalid');
          if (scanNowBtn) {
            scanNowBtn.disabled = true;
            scanNowBtn.innerHTML = '<span class="spinner-icon"></span><span>Scanning...</span>';
          }
        });

        scanInput.addEventListener('input', function() {
          if (validationAlert && !validationAlert.classList.contains('hidden')) {
            var res = validateUrlString(scanInput.value);
            if (res.valid) {
              validationAlert.classList.add('hidden');
              scanInput.classList.remove('input-invalid');
            }
          }
        });

        if (clearInputBtn) {
          clearInputBtn.addEventListener('click', function(e) {
            if (scanInput.value) {
              e.preventDefault();
              scanInput.value = '';
              scanInput.focus();
              if (validationAlert) validationAlert.classList.add('hidden');
              scanInput.classList.remove('input-invalid');
            }
          });
        }
      }

      // D3.js Threat Level Semicircular Gauge Initialization
      function initD3ThreatGauge() {
        var mount = document.getElementById('d3-threat-gauge');
        if (!mount || typeof window.d3 === 'undefined') return;
        var score = parseFloat(mount.getAttribute('data-score') || '0');
        if (isNaN(score)) score = 0;
        score = Math.max(0, Math.min(100, score));
        var d3 = window.d3;
        mount.innerHTML = '';

        var width = 220;
        var height = 135;
        var cx = 110;
        var cy = 108;
        var innerR = 62;
        var outerR = 84;

        var svg = d3.select(mount)
          .append('svg')
          .attr('viewBox', '0 0 ' + width + ' ' + height)
          .attr('class', 'd3-gauge-svg')
          .attr('role', 'img')
          .attr('aria-label', 'D3 Threat Level Gauge: ' + score + ' out of 100');

        var g = svg.append('g')
          .attr('transform', 'translate(' + cx + ',' + cy + ')');

        var scale = d3.scaleLinear().domain([0, 100]).range([-Math.PI / 2, Math.PI / 2]);

        var zones = [
          { label: 'LOW', start: 0, end: 19, color: '#059669' },
          { label: 'MEDIUM', start: 20, end: 44, color: '#D97706' },
          { label: 'HIGH', start: 45, end: 100, color: '#DC2626' }
        ];

        var arcGen = d3.arc()
          .innerRadius(innerR)
          .outerRadius(outerR)
          .startAngle(function(d) { return scale(d.start); })
          .endAngle(function(d) { return scale(d.end); })
          .padAngle(0.025)
          .cornerRadius(3);

        g.selectAll('.d3-zone-arc')
          .data(zones)
          .enter()
          .append('path')
          .attr('class', 'd3-zone-arc')
          .attr('d', arcGen)
          .attr('fill', function(d) { return d.color; })
          .attr('opacity', function(d) {
            var active = (score <= 19 && d.label === 'LOW') ||
                         (score >= 20 && score <= 44 && d.label === 'MEDIUM') ||
                         (score >= 45 && d.label === 'HIGH');
            return active ? 1.0 : 0.32;
          });

        // Zone Labels
        g.append('text')
          .attr('x', -88).attr('y', 16)
          .attr('text-anchor', 'start')
          .attr('font-size', '9.5px')
          .attr('font-weight', '700')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('fill', '#047857')
          .text('LOW');

        g.append('text')
          .attr('x', -18).attr('y', -91)
          .attr('text-anchor', 'middle')
          .attr('font-size', '9.5px')
          .attr('font-weight', '700')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('fill', '#B45309')
          .text('MEDIUM');

        g.append('text')
          .attr('x', 88).attr('y', 16)
          .attr('text-anchor', 'end')
          .attr('font-size', '9.5px')
          .attr('font-weight', '700')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('fill', '#B91C1C')
          .text('HIGH');

        // Needle Group with D3 transition
        var needleGroup = g.append('g')
          .attr('class', 'd3-needle')
          .attr('transform', 'rotate(-90)');

        needleGroup.append('path')
          .attr('d', 'M -3.5 0 L 0 -72 L 3.5 0 Z')
          .attr('fill', '#1C1917');

        needleGroup.append('circle')
          .attr('cx', 0).attr('cy', 0).attr('r', 6.5)
          .attr('fill', '#1C1917');

        needleGroup.append('circle')
          .attr('cx', 0).attr('cy', 0).attr('r', 2.5)
          .attr('fill', '#FFFFFF');

        var targetDeg = -90 + (score / 100) * 180;
        needleGroup.transition()
          .duration(750)
          .attr('transform', 'rotate(' + targetDeg.toFixed(1) + ')');
      }

      if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(initD3ThreatGauge, 60);
      } else {
        window.addEventListener('DOMContentLoaded', function() { setTimeout(initD3ThreatGauge, 60); });
      }
      window.addEventListener('load', initD3ThreatGauge);

      setupVoice(document.getElementById('btn-voice-input'), document.getElementById('url-scanner-input'));
      setupVoice(document.getElementById('btn-chat-mic'), document.getElementById('chat-user-input'));
    })();
  </script>
</body>
</html>`;
}

// Scanner Home Page Renderer
function renderScannerPage(rawInput: string, errorMsg?: string): string {
  const safeInput = htmlEscape(redactSensitiveInput(rawInput || ''));
  const recent = historyStore.getRecent();

  const body = `
  <main class="main-content">
    <div class="container-narrow stack-lg">
      <section class="card-editorial overflow-hidden">
        <div class="hero-masthead">
          <span class="hero-badge">Real-Time Threat Intelligence · Zero Unwanted Data</span>
          <h1 class="hero-title">Is This Link Safe Before You Click?</h1>
          <p class="hero-subtitle">Instantly scan suspicious links for deceptive brand impersonation, typosquatting homoglyphs, lookalike domains, unencrypted routes, and phishing lures.</p>
        </div>

        <div class="console-body">
          <form action="/scan" method="POST" id="scan-form" novalidate>
            <div class="label-row">
              <label for="url-scanner-input" class="input-label">Enter or paste a single web address to analyze</label>
              <span class="meta-mono">HTTP / HTTPS</span>
            </div>
            <div class="scanner-bar">
              <div class="input-wrapper">
                <span class="input-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
                <input id="url-scanner-input" name="url" type="text" value="${safeInput}" placeholder="https://example.com/login/verify" class="url-input" required autocomplete="off" spellcheck="false" />
                <button type="button" id="btn-voice-input" class="btn-voice-icon" title="Dictate URL"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg></button>
              </div>
              <div class="button-group">
                <button type="submit" id="btn-scan-now" class="btn-primary btn-scan-now">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                  <span>Scan Now</span>
                </button>
                <a href="/" class="btn-secondary" id="btn-clear-input">Clear</a>
              </div>
            </div>
            <div id="client-validation-alert" class="client-alert hidden" role="alert" aria-live="assertive">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span id="client-validation-text"></span>
            </div>
          </form>

          ${errorMsg ? `<div class="alert-error" role="alert"><strong>Input Validation Notice:</strong> ${htmlEscape(errorMsg)}</div>` : ''}

          <div style="display: flex; justify-content: space-between; margin-top: 1rem; font-size: 0.75rem; color: var(--text-muted);">
            <span>Safe static inspection: Submitted URLs are never opened, fetched, or executed in your browser.</span>
            <span>Query values &amp; credentials automatically redacted</span>
          </div>

          <div class="presets-block" id="diagnostic-presets">
            <div style="display: flex; justify-content: space-between; align-items: baseline;">
              <strong style="font-size: 0.875rem;">Diagnostic Verification Presets</strong>
              <span class="meta-quiet">Click a test URL to evaluate heuristic detection</span>
            </div>
            <div class="presets-grid">
              <form action="/scan" method="POST"><input type="hidden" name="url" value="https://www.wikipedia.org/" /><button type="submit" class="preset-card"><div class="preset-card-top"><span class="preset-title">01. Benign Reference Domain</span><span class="preset-arrow">↗</span></div><div class="preset-url">https://www.wikipedia.org</div></button></form>
              <form action="/scan" method="POST"><input type="hidden" name="url" value="http://example.com" /><button type="submit" class="preset-card"><div class="preset-card-top"><span class="preset-title">02. Unencrypted HTTP Link</span><span class="preset-arrow">↗</span></div><div class="preset-url">http://example.com</div></button></form>
              <form action="/scan" method="POST"><input type="hidden" name="url" value="https://google.com.security-check.example.org" /><button type="submit" class="preset-card"><div class="preset-card-top"><span class="preset-title">03. Subdomain Brand Spoofing</span><span class="preset-arrow">↗</span></div><div class="preset-url">https://google.com.security-check.example.org</div></button></form>
              <form action="/scan" method="POST"><input type="hidden" name="url" value="https://paypa1-security-verification.top/login" /><button type="submit" class="preset-card"><div class="preset-card-top"><span class="preset-title">04. Typosquatting Homoglyph</span><span class="preset-arrow">↗</span></div><div class="preset-url">https://paypa1-security-verification.top/login</div></button></form>
              <form action="/scan" method="POST"><input type="hidden" name="url" value="http://192.168.1.1/admin/login" /><button type="submit" class="preset-card"><div class="preset-card-top"><span class="preset-title">05. Raw Numeric IP Address</span><span class="preset-arrow">↗</span></div><div class="preset-url">http://192.168.1.1/admin/login</div></button></form>
              <form action="/scan" method="POST"><input type="hidden" name="url" value="https://bit.ly/3xSampleShortenedUrl" /><button type="submit" class="preset-card"><div class="preset-card-top"><span class="preset-title">06. Opaque URL Shortener</span><span class="preset-arrow">↗</span></div><div class="preset-url">https://bit.ly/3xSampleShortenedUrl</div></button></form>
            </div>
          </div>
        </div>
      </section>

      <section id="recent-history" class="card-editorial section-pad">
        <div class="section-header">
          <div>
            <h2 class="section-title">Recent Scan History</h2>
            <p class="meta-quiet">In-memory session log (capped strictly at the newest 5 scans)</p>
          </div>
          ${recent.length > 0 ? `<form action="/clear-history" method="POST"><button type="submit" class="btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">Clear History</button></form>` : ''}
        </div>
        ${recent.length === 0 ? `
          <div style="padding: 2.5rem 1rem; text-align: center;">
            <strong>No URLs Analyzed Yet In This Session</strong>
            <p class="meta-quiet" style="margin-top: 0.35rem;">Enter a URL in the scanner above or select a preset to evaluate risk.</p>
          </div>
        ` : `
          <ul class="history-list">
            ${recent.map((item, i) => {
              const theme = getRiskTheme(item.classification);
              return `
                <li class="history-row">
                  <form action="/scan" method="POST" style="margin: 0;">
                    <input type="hidden" name="url" value="${htmlEscape(item.domain.redactedUrl)}" />
                    <button type="submit" class="history-item-btn">
                      <div class="history-left">
                        <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">0${i + 1}.</span>
                        <div>
                          <div style="display: flex; gap: 0.5rem; align-items: baseline;">
                            <span class="history-hostname">${htmlEscape(item.domain.hostname)}</span>
                            <span class="meta-mono">${htmlEscape(item.domain.protocol)}</span>
                            <span class="meta-mono">· ${item.indicators.length} finding${item.indicators.length === 1 ? '' : 's'}</span>
                          </div>
                          <div class="history-url">${htmlEscape(item.domain.redactedUrl)}</div>
                        </div>
                      </div>
                      <div style="display: flex; align-items: center; gap: 1rem;">
                        <span style="font-family: var(--font-mono); font-weight: 700;" class="${theme.textClass}">${item.riskScore}/100</span>
                        <span style="font-size: 0.75rem; font-weight: 700;" class="${theme.textClass}">${htmlEscape(item.classification)}</span>
                        <span style="font-size: 0.8rem; color: var(--accent);">View Report ↗</span>
                      </div>
                    </button>
                  </form>
                </li>
              `;
            }).join('')}
          </ul>
        `}
      </section>

      <section id="safety-rules" class="card-editorial section-pad">
        <div class="section-header">
          <div>
            <h2 class="section-title">Universal URL Verification Rules</h2>
            <p class="meta-quiet">Defensive habits against phishing, spoofing, and malicious links</p>
          </div>
        </div>
        <div class="rules-grid">
          <div class="rule-item"><span class="rule-num">01.</span><div><strong>Verify the Registrable Domain</strong><p>Always inspect the rightmost labels before the first single slash (/). Subdomains can be forged freely by an attacker.</p></div></div>
          <div class="rule-item"><span class="rule-num">02.</span><div><strong>Never Enter Credentials on Unverified Links</strong><p>Do not submit passwords, OTPs, or banking details on pages reached via unsolicited email or SMS.</p></div></div>
          <div class="rule-item"><span class="rule-num">03.</span><div><strong>Watch for Lookalike Substitutions</strong><p>Check carefully for homoglyphs like 'paypa1' or 'g00gle' and hyphenated prefixes designed to imitate official portals.</p></div></div>
          <div class="rule-item"><span class="rule-num">04.</span><div><strong>Reject Coercive Fine or Arrest Claims</strong><p>Law enforcement agencies and courts never demand urgent payment transfers or conduct arrests via web links.</p></div></div>
        </div>
      </section>
    </div>
  </main>
  `;
  return renderHtmlPage('CyberShield AI — URL Threat Detection & Phishing Risk Analyzer', body);
}

// Scan Results Page Renderer
function renderResultsPage(res: ScanResult): string {
  const theme = getRiskTheme(res.classification);
  const threatTier = res.riskScore >= 45 ? 'HIGH' : (res.riskScore >= 20 ? 'MEDIUM' : 'LOW');
  const needleDeg = -90 + (Math.min(100, Math.max(0, res.riskScore)) / 100) * 180;

  const body = `
  <main class="main-content">
    <div class="container-wide stack-md">
      <div class="back-row">
        <a href="/" class="back-link">← Back to URL Scanner</a>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <button type="button" id="btn-copy-url" class="btn-copy" data-copy="${htmlEscape(res.domain.redactedUrl)}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span>Copy Sanitized Link</span>
          </button>
          <span class="meta-mono">Host: ${htmlEscape(res.domain.hostname)}</span>
        </div>
      </div>

      <section class="card-editorial overflow-hidden">
        <div class="anatomy-header">
          <strong style="font-size: 0.8rem;">Deconstructed URL Anatomy</strong>
          <span class="meta-mono">${htmlEscape(res.domain.redactedUrl)}</span>
        </div>
        <div class="anatomy-grid">
          <div class="anatomy-cell">
            <div class="anatomy-label">Protocol</div>
            <div class="anatomy-val ${res.domain.protocol === 'HTTP' ? 'tone-amber' : 'tone-emerald'}">${htmlEscape(res.domain.protocol)}</div>
          </div>
          <div class="anatomy-cell">
            <div class="anatomy-label">Subdomain</div>
            <div class="anatomy-val">${htmlEscape(res.domain.subdomain)}</div>
          </div>
          <div class="anatomy-cell anatomy-highlight">
            <div class="anatomy-label" style="color: var(--accent);">Registrable Domain</div>
            <div class="anatomy-val" style="color: var(--accent); font-weight: 700;">${htmlEscape(res.domain.registrableDomain)}</div>
          </div>
          <div class="anatomy-cell">
            <div class="anatomy-label">Port</div>
            <div class="anatomy-val">${htmlEscape(res.domain.port)}</div>
          </div>
          <div class="anatomy-cell">
            <div class="anatomy-label">Path</div>
            <div class="anatomy-val">${htmlEscape(res.domain.path)}</div>
          </div>
        </div>
      </section>

      <div class="dashboard-grid-12">
        <section class="col-span-7 card-editorial section-pad">
          <div class="section-header">
            <div>
              <h2 class="section-title">Heuristic Threat Assessment</h2>
              <p class="meta-mono">${htmlEscape(res.domain.hostname)}</p>
            </div>
            <span class="badge-finding">${res.indicators.length} Finding${res.indicators.length === 1 ? '' : 's'}</span>
          </div>

          <div class="score-hero-row">
            <div class="d3-gauge-card" aria-label="D3 Threat Level Gauge">
              <div id="d3-threat-gauge" class="d3-gauge-mount" data-score="${res.riskScore}" data-level="${threatTier}">
                <svg viewBox="0 0 220 135" class="d3-gauge-svg" role="img" aria-label="Threat Level: ${threatTier} (${res.riskScore} out of 100)">
                  <g transform="translate(110, 108)">
                    <path d="M -84 0 A 84 84 0 0 1 -57.5 -61.2 L -45.2 -48.1 A 66 66 0 0 0 -66 0 Z" fill="#059669" opacity="0.88" />
                    <path d="M -55.5 -63.0 A 84 84 0 0 1 -13.1 -83.0 L -10.3 -65.2 A 66 66 0 0 0 -43.6 -49.5 Z" fill="#D97706" opacity="0.88" />
                    <path d="M -10.5 -83.3 A 84 84 0 0 1 84 0 L 66 0 A 66 66 0 0 0 -8.2 -65.5 Z" fill="#DC2626" opacity="0.88" />
                    <text x="-88" y="16" text-anchor="start" font-size="9.5" font-weight="700" fill="#047857" font-family="JetBrains Mono, monospace">LOW</text>
                    <text x="0" y="-92" text-anchor="middle" font-size="9.5" font-weight="700" fill="#B45309" font-family="JetBrains Mono, monospace">MEDIUM</text>
                    <text x="88" y="16" text-anchor="end" font-size="9.5" font-weight="700" fill="#B91C1C" font-family="JetBrains Mono, monospace">HIGH</text>
                    <g class="d3-needle" transform="rotate(${needleDeg.toFixed(1)})">
                      <path d="M -3.5 0 L 0 -72 L 3.5 0 Z" fill="#1C1917" />
                      <circle cx="0" cy="0" r="6.5" fill="#1C1917" />
                      <circle cx="0" cy="0" r="2.5" fill="#FFFFFF" />
                    </g>
                  </g>
                </svg>
              </div>
              <div class="d3-gauge-readout">
                <div>
                  <span data-testid="risk-score-value" class="gauge-big-num ${theme.textClass}">${res.riskScore}</span>
                  <span class="meta-mono">/ 100</span>
                </div>
                <div data-testid="threat-level-tier" class="threat-level-tier-badge" style="background: ${theme.badgeBg}; border: 1px solid ${theme.badgeBorder}; color: ${theme.strokeHex};">
                  Threat Level: ${threatTier}
                </div>
              </div>
            </div>

            <div style="flex: 1; min-width: 240px;">
              <div>
                <span data-testid="risk-classification-label" class="classification-pill" style="background: ${theme.badgeBg}; border: 1px solid ${theme.badgeBorder}; color: ${theme.strokeHex};">${htmlEscape(res.classification)}</span>
              </div>
              <p class="summary-prose">${htmlEscape(res.summaryExplanation)}</p>
              <div class="linear-meter-block">
                <div style="display: flex; justify-content: space-between;" class="meta-mono">
                  <span>Composite Risk Score</span>
                  <span>${res.riskScore} / 100</span>
                </div>
                <div class="meter-track">
                  <div class="meter-fill ${theme.barClass}" style="width: ${Math.max(4, res.riskScore)}%;"></div>
                </div>
                <div class="meter-ticks">
                  <span>0 Low</span><span>20 Medium</span><span>45+ High</span>
                </div>
              </div>
            </div>
          </div>

          <div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border-soft); font-size: 0.75rem; color: var(--text-muted);">
            <p>${htmlEscape(res.disclaimer)}</p>
          </div>
        </section>

        <section class="col-span-5 card-editorial section-pad">
          <div class="section-header">
            <div>
              <h2 class="section-title">Recommended Safety Actions</h2>
              <p class="meta-quiet">${htmlEscape(res.guidance.headline)}</p>
            </div>
          </div>
          <div class="primary-advice ${theme.textClass}">
            ${htmlEscape(res.guidance.primaryAdvice)}
          </div>
          <ul class="guidance-list">
            ${res.guidance.universalRules.map((r, i) => `<li><span class="rule-num">0${i + 1}.</span><span>${htmlEscape(r)}</span></li>`).join('')}
          </ul>
          <div class="action-bar-footer">
            <a href="/" class="btn-primary">Scan Another URL</a>
            <a href="/export?url=${encodeURIComponent(res.domain.redactedUrl)}&format=txt" class="btn-secondary" download>Download TXT</a>
            <a href="/export?url=${encodeURIComponent(res.domain.redactedUrl)}&format=json" class="btn-secondary" download>Download JSON</a>
          </div>
        </section>
      </div>

      <div class="dashboard-grid-12">
        <section class="col-span-7 card-editorial section-pad">
          <div class="section-header">
            <div>
              <h2 class="section-title">Detected URL Indicators</h2>
              <p class="meta-quiet">Security signals identified in this URL</p>
            </div>
            <span class="badge-finding">${res.indicators.length} Triggered</span>
          </div>

          ${res.indicators.length === 0 ? `
            <div style="padding: 2.5rem 1rem; text-align: center;">
              <strong class="tone-emerald">No Suspicious URL Heuristics Triggered</strong>
              <p class="meta-quiet" style="margin-top: 0.35rem;">This URL uses HTTPS, a standard domain structure, and did not match known deceptive patterns. Verify sender context before entering credentials.</p>
            </div>
          ` : `
            <div>
              ${res.indicators.map((ind, i) => `
                <article class="indicator-article">
                  <div class="indicator-top">
                    <h3 class="indicator-title"><span class="rule-num">0${i + 1}.</span> ${htmlEscape(ind.name)}</h3>
                    <div class="meta-mono">
                      <span>Severity: <strong>${htmlEscape(ind.severity)}</strong></span>
                      <span>·</span>
                      <span>+${ind.weight} pts</span>
                    </div>
                  </div>
                  <p class="indicator-exp">${htmlEscape(ind.explanation)}</p>
                  <div class="indicator-comp">Matched Component: <code>${htmlEscape(ind.component)}</code></div>
                  <p class="indicator-why"><strong>Why this matters:</strong> ${htmlEscape(ind.reasonItMatters)}</p>
                </article>
              `).join('')}
            </div>
          `}
        </section>

        <section class="col-span-5 card-editorial section-pad">
          <div class="section-header">
            <div>
              <h2 class="section-title">Extracted Domain Details</h2>
              <p class="meta-quiet">Verified URL Components</p>
            </div>
          </div>
          <dl class="domain-dl">
            <div class="dl-row"><dt>Hostname</dt><dd class="meta-mono">${htmlEscape(res.domain.hostname)}</dd></div>
            <div class="dl-row"><dt>Registrable Domain</dt><dd class="meta-mono tone-terracotta" style="font-weight: 700;">${htmlEscape(res.domain.registrableDomain)}</dd></div>
            <div class="dl-row"><dt>Subdomain</dt><dd class="meta-mono">${htmlEscape(res.domain.subdomain)}</dd></div>
            <div class="dl-row"><dt>Top-Level Domain</dt><dd class="meta-mono">.${htmlEscape(res.domain.tld)}</dd></div>
            <div class="dl-row"><dt>Protocol</dt><dd class="meta-mono">${htmlEscape(res.domain.protocol)}</dd></div>
            <div class="dl-row"><dt>Port</dt><dd class="meta-mono">${htmlEscape(res.domain.port)}</dd></div>
            <div class="dl-row"><dt>Path</dt><dd class="meta-mono">${htmlEscape(res.domain.path)}</dd></div>
            ${res.domain.queryParamCount > 0 ? `<div class="dl-row"><dt>Query Parameters</dt><dd class="meta-mono">${res.domain.queryParamCount} (Redacted)</dd></div>` : ''}
            <div style="padding-top: 0.75rem; border-top: 1px solid var(--border-soft);">
              <dt style="font-size: 0.75rem; color: var(--text-muted);">Sanitized URL</dt>
              <dd class="meta-mono" style="word-break: break-all; margin-top: 0.25rem;">${htmlEscape(res.domain.redactedUrl)}</dd>
            </div>
          </dl>
        </section>
      </div>
    </div>
  </main>
  `;
  return renderHtmlPage(`Scan Report: ${res.domain.hostname} (${res.riskScore}/100) — CyberShield AI`, body);
}

// Express Routes
app.get('/', (req: Request, res: Response) => {
  const urlParam = req.query.url as string;
  if (urlParam) {
    const outcome = analyzeUrlStructured(urlParam);
    if (outcome.valid && outcome.result) {
      return res.send(renderResultsPage(outcome.result));
    } else {
      return res.send(renderScannerPage(urlParam, outcome.errorReason));
    }
  }
  return res.send(renderScannerPage(''));
});

app.get('/scan', (req: Request, res: Response) => {
  const urlParam = req.query.url as string;
  if (!urlParam) return res.redirect('/');
  const outcome = analyzeUrlStructured(urlParam);
  if (outcome.valid && outcome.result) {
    return res.send(renderResultsPage(outcome.result));
  }
  return res.send(renderScannerPage(urlParam, outcome.errorReason));
});

app.post('/scan', (req: Request, res: Response) => {
  const targetUrl = req.body.url as string;
  if (!targetUrl || !targetUrl.trim()) {
    return res.send(renderScannerPage('', 'Please enter a URL to scan.'));
  }
  const outcome = analyzeUrlStructured(targetUrl);
  if (outcome.valid && outcome.result) {
    return res.redirect(`/scan?url=${encodeURIComponent(outcome.result.domain.redactedUrl)}`);
  }
  return res.send(renderScannerPage(targetUrl, outcome.errorReason));
});

app.post('/clear-history', (_req: Request, res: Response) => {
  historyStore.clear();
  return res.redirect('/');
});

app.get('/export', (req: Request, res: Response) => {
  const urlParam = req.query.url as string;
  const format = (req.query.format as string) || 'txt';
  if (!urlParam) return res.redirect('/');

  const outcome = analyzeUrlStructured(urlParam);
  if (!outcome.valid || !outcome.result) {
    return res.status(400).send('Invalid URL for export');
  }

  const hostname = outcome.result.domain.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  if (format.toLowerCase() === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="cybershield_report_${hostname}.json"`);
    return res.send(JSON.stringify(outcome.result, null, 2));
  } else {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="cybershield_report_${hostname}.txt"`);
    return res.send(formatTxtReport(outcome.result));
  }
});

// JSON API: Analyze URL
app.post('/api/analyze', (req: Request, res: Response) => {
  const rawUrl = req.body.url;
  const outcome = analyzeUrlStructured(rawUrl);
  if (!outcome.valid) {
    return res.status(400).json({ valid: false, error: outcome.errorReason });
  }
  return res.json({ valid: true, result: outcome.result });
});

// JSON API: History
app.get('/api/history', (_req: Request, res: Response) => {
  return res.json({ history: historyStore.getRecent() });
});

app.delete('/api/history', (_req: Request, res: Response) => {
  historyStore.clear();
  return res.json({ success: true });
});

// JSON API: Multi-Turn AI Advisor Chat
app.post('/api/chat', async (req: Request, res: Response) => {
  const message = (req.body.message || '').toString().trim();
  const rolePreset = (req.body.rolePreset || 'threat-analyst').toString();
  const scanContext = (req.body.scanContext || '').toString();

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    // Deterministic fallback response when no key is configured
    return res.json({
      reply: 'Always inspect the registrable domain before submitting sensitive information. Attackers frequently use deceptive subdomains, character substitutions, and urgent penalty threats to trick users.'
    });
  }

  let rolePrompt = 'You are a cybersecurity expert specializing in URL analysis, antiphishing, and fraud detection. Keep advice actionable, direct, and under 3 sentences.';
  if (rolePreset === 'scam-educator') {
    rolePrompt = 'You are a patient cyber safety educator explaining scams and phishing. Emphasize universal defensive habits. Keep under 3 sentences.';
  } else if (rolePreset === 'incident-advisor') {
    rolePrompt = 'You are an incident response advisor helping someone who may have clicked a malicious link. Give immediate first steps (disconnect, change password, alert bank). Keep under 3 sentences.';
  }

  try {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(apiKey)}`;
    const promptText = `${rolePrompt}\n${scanContext ? 'Context: ' + scanContext : ''}\nUser question: ${message}`;
    const apiRes = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: promptText }] }],
        generationConfig: { maxOutputTokens: 300, temperature: 0.2 }
      })
    });

    if (!apiRes.ok) {
      throw new Error('Gemini API call failed with status ' + apiRes.status);
    }

    const data = await apiRes.json() as any;
    const candidateText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    return res.json({
      reply: candidateText || 'Check the domain name carefully before taking any action or submitting credentials.'
    });
  } catch {
    return res.json({
      reply: 'CyberShield Advisor: Never enter passwords or financial information on unverified domains reached through unsolicited messages.'
    });
  }
});

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', engine: 'CyberShield-FullStack-v2' });
});

app.get('/favicon.ico', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='#C2410C'><path d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z'/></svg>");
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[CyberShield AI] Server active and listening on http://0.0.0.0:${PORT}`);
});
