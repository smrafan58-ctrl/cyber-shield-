import {
  DetectedIndicator,
  ExampleFixture,
  ExternalReputationReport,
  RecommendedGuidance,
  RiskClassification,
  URLAnalysisResult,
} from '../types/scanner';
import { detectBrandImpersonation, PROTECTED_BRANDS } from './brandDetector';
import { validateAndNormalizeUrl } from './urlValidator';

export const MANDATORY_DISCLAIMER =
  'Risk scores are based on observable URL patterns and available reputation data. They do not guarantee that a website is safe or malicious.';

export const UNIVERSAL_SAFETY_RULES = [
  'Do not enter passwords on suspicious sites.',
  'Never share OTPs or banking credentials.',
  "Do not pay fines or transfer money based solely on a link's claims.",
  'Access official services through independently verified websites or applications.',
];

/**
 * Documented heuristic weight table.
 * Can be adjusted centrally while maintaining deterministic reproducibility.
 */
export const HEURISTIC_WEIGHTS = {
  HTTP_PROTOCOL: 8,
  IP_HOSTNAME: 18,
  EXCESSIVE_SUBDOMAINS: 10,
  BRAND_IMPERSONATION: 25,
  TYPOSQUATTING: 25,
  AUTHORITY_DECEPTION: 25,
  LONG_HOSTNAME: 8,
  LONG_URL: 5,
  EXCESSIVE_PARAMS: 5,
  SUSPICIOUS_ENCODING: 8,
  EXCESSIVE_HYPHENS: 8,
  PUNYCODE_IDN: 8,
  URL_SHORTENER: 8,
  UNUSUAL_PORT: 8,
  SUSPICIOUS_TLD: 8,
  OPEN_REDIRECT_PATTERN: 12,
  HIGH_RISK_PATH_COMBO: 15,
  GOV_DIGITAL_ARREST_PATTERN: 20,
} as const;

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'rb.gy',
  'tiny.cc',
  'shorturl.at',
  'v.gd',
  'bit.do',
  'bl.ink',
]);

const FREQUENTLY_ABUSED_TLDS = new Set([
  'xyz',
  'top',
  'click',
  'loan',
  'work',
  'gq',
  'tk',
  'ml',
  'cf',
  'ga',
  'zip',
  'mov',
  'icu',
  'buzz',
  'monster',
  'rest',
  'support',
]);

const REDIRECT_PARAM_NAMES = new Set([
  'redirect',
  'redirect_uri',
  'redirect_url',
  'return',
  'returnurl',
  'return_to',
  'next',
  'url',
  'target',
  'dest',
  'destination',
  'continue',
  'goto',
  'out',
  'view',
]);

export function classifyRiskScore(score: number): RiskClassification {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  if (clamped <= 19) return 'LOW RISK INDICATORS';
  if (clamped <= 39) return 'MILD SUSPICION';
  if (clamped <= 59) return 'MODERATE RISK';
  if (clamped <= 79) return 'HIGH RISK';
  return 'VERY HIGH RISK';
}

export function buildRecommendedGuidance(
  classification: RiskClassification
): RecommendedGuidance {
  switch (classification) {
    case 'LOW RISK INDICATORS':
      return {
        headline: 'Exercise Standard Caution',
        primaryAdvice:
          'Continue to exercise normal caution. This scan does not establish that the site is safe.',
        universalRules: UNIVERSAL_SAFETY_RULES,
      };
    case 'MILD SUSPICION':
      return {
        headline: 'Inspect Destination Carefully',
        primaryAdvice:
          'This link has minor structural warning signs. Confirm you recognize the domain before interacting with forms or downloads.',
        universalRules: UNIVERSAL_SAFETY_RULES,
      };
    case 'MODERATE RISK':
      return {
        headline: 'Independent Verification Recommended',
        primaryAdvice:
          'Verify the domain independently before entering personal or financial information.',
        universalRules: UNIVERSAL_SAFETY_RULES,
      };
    case 'HIGH RISK':
      return {
        headline: 'High Caution — Do Not Submit Sensitive Data',
        primaryAdvice:
          'Do not enter passwords, payment information, or identity documents until the destination has been independently verified.',
        universalRules: UNIVERSAL_SAFETY_RULES,
      };
    case 'VERY HIGH RISK':
      return {
        headline: 'Critical Warning — Avoid Visiting This Link',
        primaryAdvice:
          'Avoid opening this link unless you can independently establish that it is legitimate.',
        universalRules: UNIVERSAL_SAFETY_RULES,
      };
  }
}

function isKnownOfficialBrandDomain(registrableDomain: string): boolean {
  const lower = registrableDomain.toLowerCase();
  return PROTECTED_BRANDS.some((b) => b.officialDomains.includes(lower));
}

function isOfficialGovOrLawDomain(registrableDomain: string, tld: string): boolean {
  const lowerTld = tld.toLowerCase();
  return (
    lowerTld === 'gov' ||
    lowerTld === 'gov.in' ||
    lowerTld === 'nic.in' ||
    lowerTld === 'gov.uk' ||
    lowerTld === 'gov.au' ||
    lowerTld === 'mil' ||
    lowerTld === 'mil.in' ||
    registrableDomain.endsWith('.gov') ||
    registrableDomain.endsWith('.gov.in') ||
    registrableDomain.endsWith('.nic.in')
  );
}

/**
 * Deterministic URL Threat Analysis Engine.
 * Evaluates 16+ structural, lexical, and contextual indicators without arbitrary AI scoring.
 */
export function analyzeUrl(
  rawInput: string,
  externalReputation?: ExternalReputationReport
): { valid: true; result: URLAnalysisResult } | { valid: false; errorTitle: string; error: string } {
  const validation = validateAndNormalizeUrl(rawInput);
  if (!validation.valid || !validation.domainDetails || !validation.parsedUrl) {
    return {
      valid: false,
      errorTitle: validation.errorTitle || 'Invalid URL',
      error: validation.error || 'The submitted input is not a valid HTTP or HTTPS URL.',
    };
  }

  const domain = validation.domainDetails;
  const parsed = validation.parsedUrl;
  const indicators: DetectedIndicator[] = [];

  const isOfficialBrand = isKnownOfficialBrandDomain(domain.registrableDomain);
  const isOfficialGov = isOfficialGovOrLawDomain(domain.registrableDomain, domain.tld);

  // 1. Check HTTP instead of HTTPS (+8)
  if (domain.protocol === 'HTTP') {
    indicators.push({
      id: 'http-protocol',
      name: 'Unencrypted HTTP Protocol',
      severity: 'Low',
      weight: HEURISTIC_WEIGHTS.HTTP_PROTOCOL,
      explanation: 'This URL uses unencrypted HTTP rather than HTTPS.',
      component: `Protocol: http://`,
      reasonItMatters:
        'Data transmitted over plain HTTP is not encrypted in transit and can be intercepted or modified on untrusted networks.',
    });
  }

  // 2. Hostname is an IP address (+18)
  if (domain.isIpAddress) {
    indicators.push({
      id: 'ip-hostname',
      name: 'IP Address Used as Hostname',
      severity: 'Medium',
      weight: HEURISTIC_WEIGHTS.IP_HOSTNAME,
      explanation: `The URL points directly to a numeric IP address (${domain.hostname}) instead of a registered domain name.`,
      component: domain.hostname,
      reasonItMatters:
        'Legitimate banking, retail, and government portals rarely ask users to log in via raw IP addresses. Phishing kits often use raw IPs to bypass domain takedowns.',
    });
  }

  // 3. Suspicious URL authority structure (@ symbol / embedded credentials) (+25)
  if (domain.hasCredentialsInAuthority) {
    indicators.push({
      id: 'authority-deception',
      name: 'Deceptive URL Authority Structure (@ Symbol)',
      severity: 'Critical',
      weight: HEURISTIC_WEIGHTS.AUTHORITY_DECEPTION,
      explanation:
        'The URL contains an "@" symbol in the authority section, which can disguise the real destination host.',
      component: validation.rawAuthorityPrefix
        ? `${validation.rawAuthorityPrefix}@${domain.hostname}`
        : `@${domain.hostname}`,
      reasonItMatters:
        'Everything before "@" in a URL authority is treated as a username, while the browser actually navigates to the hostname after "@". Attackers abuse this to make links look like trusted sites.',
    });
  }

  // 4 & 5. Brand Impersonation (+25) and Strong Typosquatting Signal (+25)
  // Avoid double-counting: if both occur on the same URL, count the primary match at full weight.
  const brandMatches = detectBrandImpersonation(domain, validation.rawAuthorityPrefix);
  const typosquatMatch = brandMatches.find((m) => m.type === 'typosquatting');
  const impersonationMatch = brandMatches.find((m) => m.type === 'impersonation');

  if (typosquatMatch) {
    indicators.push({
      id: 'typosquatting-signal',
      name: `Strong Typosquatting Signal (${typosquatMatch.brandName})`,
      severity: 'High',
      weight: HEURISTIC_WEIGHTS.TYPOSQUATTING,
      explanation: typosquatMatch.explanation,
      component: typosquatMatch.matchedString,
      reasonItMatters:
        'Attackers register lookalike domains using character substitutions (such as "1" for "l" or "0" for "o") to trick users who glance quickly at the address bar.',
    });
  } else if (impersonationMatch) {
    indicators.push({
      id: 'brand-impersonation',
      name: `Possible Brand Impersonation (${impersonationMatch.brandName})`,
      severity: 'High',
      weight: HEURISTIC_WEIGHTS.BRAND_IMPERSONATION,
      explanation: impersonationMatch.explanation,
      component: impersonationMatch.matchedString,
      reasonItMatters:
        'Placing a trusted brand name in a subdomain or hyphenated prefix does not mean the website belongs to that brand. Only the registrable domain indicates who controls the server.',
    });
  }

  // 6. Excessive Subdomains (+10)
  if (!domain.isIpAddress && domain.subdomain !== 'None') {
    const subParts = domain.subdomain.split('.').filter(Boolean);
    // 3 or more subdomain levels (i.e. 5+ total labels) or 2+ subdomain levels with deceptive security words
    const hasSecurityWordsInSub = /(security|verify|login|signin|account|update|secure|auth|confirm|banking)/i.test(
      domain.subdomain
    );
    if (subParts.length >= 3 || (subParts.length >= 2 && hasSecurityWordsInSub && !isOfficialBrand)) {
      indicators.push({
        id: 'excessive-subdomains',
        name: 'Excessive or Chained Subdomains',
        severity: 'Medium',
        weight: HEURISTIC_WEIGHTS.EXCESSIVE_SUBDOMAINS,
        explanation: `The hostname chains ${subParts.length} subdomain levels ("${domain.subdomain}") before the actual registrable domain "${domain.registrableDomain}".`,
        component: domain.hostname,
        reasonItMatters:
          'Deeply nested subdomains are frequently used to push the real registrable domain out of view on mobile screens.',
      });
    }
  }

  // 7. Suspiciously long hostname (+8)
  if (domain.hostnameLength > 42) {
    indicators.push({
      id: 'long-hostname',
      name: 'Suspiciously Long Hostname',
      severity: 'Low',
      weight: HEURISTIC_WEIGHTS.LONG_HOSTNAME,
      explanation: `The hostname is ${domain.hostnameLength} characters long, exceeding typical domain lengths.`,
      component: domain.hostname,
      reasonItMatters:
        'Unusually long hostnames often stuff keywords like "-security-check-account-login" to appear legitimate and hide the true domain.',
    });
  }

  // 8. Unusual overall URL length (+5)
  if (domain.urlLength > 120) {
    indicators.push({
      id: 'unusual-url-length',
      name: 'Unusually Long URL',
      severity: 'Informational',
      weight: HEURISTIC_WEIGHTS.LONG_URL,
      explanation: `The full URL is ${domain.urlLength} characters long.`,
      component: `Length: ${domain.urlLength} chars`,
      reasonItMatters:
        'While many legitimate articles and tracking links are long, phishing URLs also use long paths and query strings to obscure redirect targets or session tracking.',
    });
  }

  // 9. Excessive URL parameters (+5)
  if (domain.queryParamCount >= 5) {
    indicators.push({
      id: 'excessive-parameters',
      name: 'Excessive Query Parameters',
      severity: 'Informational',
      weight: HEURISTIC_WEIGHTS.EXCESSIVE_PARAMS,
      explanation: `The URL contains ${domain.queryParamCount} query parameters.`,
      component: `Parameters (${domain.queryParamCount}): ${domain.queryParamKeys.slice(0, 5).join(', ')}`,
      reasonItMatters:
        'Complex query strings can carry encoded tracking identifiers, pre-filled victim data, or hidden redirect instructions.',
    });
  }

  // 10. Suspicious URL encoding (+8)
  const rawPathAndQuery = `${parsed.pathname}${parsed.search}`;
  const encodedMatches = rawPathAndQuery.match(/%[0-9a-fA-F]{2}/g) || [];
  const hasDoubleEncoding = /%25[0-9a-fA-F]{2}/.test(rawPathAndQuery);
  const hasEncodedSlashesOrAt = /%(2f|2F|40|3a|3A)/.test(parsed.pathname);
  if (encodedMatches.length >= 4 || hasDoubleEncoding || hasEncodedSlashesOrAt) {
    indicators.push({
      id: 'suspicious-encoding',
      name: 'Obfuscated or Heavy URL Encoding',
      severity: 'Medium',
      weight: HEURISTIC_WEIGHTS.SUSPICIOUS_ENCODING,
      explanation:
        'The URL contains percent-encoded characters that may obscure paths, slashes, or embedded destination URLs.',
      component: encodedMatches.slice(0, 6).join(' '),
      reasonItMatters:
        'Attackers use percent-encoding (such as %2F for "/" or %40 for "@") to evade simple text filters and hide malicious redirect targets.',
    });
  }

  // 11. Suspiciously many hyphens in hostname (+8)
  const hyphenCount = (domain.hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    indicators.push({
      id: 'excessive-hyphens',
      name: 'Multiple Hyphens in Hostname',
      severity: 'Medium',
      weight: HEURISTIC_WEIGHTS.EXCESSIVE_HYPHENS,
      explanation: `The hostname contains ${hyphenCount} hyphens ("${domain.hostname}").`,
      component: domain.hostname,
      reasonItMatters:
        'Deceptive domains frequently string together multiple hyphenated words (for example, "secure-login-verify-account.com") to imitate official portals.',
    });
  }

  // 12. Punycode / IDN domain (+8)
  if (domain.isPunycode) {
    indicators.push({
      id: 'punycode-idn',
      name: 'Internationalized Domain Name (Punycode xn--)',
      severity: 'Medium',
      weight: HEURISTIC_WEIGHTS.PUNYCODE_IDN,
      explanation:
        'The hostname uses Punycode ("xn--") encoding to represent non-ASCII international characters.',
      component: domain.hostname,
      reasonItMatters:
        'While legitimate non-English websites use IDNs, attackers can use lookalike Cyrillic or Greek characters (IDN homograph attacks) to visually impersonate well-known Latin domains.',
    });
  }

  // 13. URL shortener hiding destination (+8)
  if (URL_SHORTENERS.has(domain.registrableDomain)) {
    indicators.push({
      id: 'url-shortener',
      name: 'Shortened Link Hiding Final Destination',
      severity: 'Medium',
      weight: HEURISTIC_WEIGHTS.URL_SHORTENER,
      explanation: `The domain "${domain.registrableDomain}" is a URL shortening service that redirects to another undisclosed web address.`,
      component: domain.registrableDomain,
      reasonItMatters:
        'Shortened links conceal the real destination domain until you click them, making it impossible to verify the target site from the link text alone.',
    });
  }

  // 14. Unusual port (+8)
  if (domain.port !== 'Default' && domain.port !== '80' && domain.port !== '443') {
    indicators.push({
      id: 'unusual-port',
      name: 'Non-Standard Network Port',
      severity: 'Medium',
      weight: HEURISTIC_WEIGHTS.UNUSUAL_PORT,
      explanation: `The URL connects to non-standard TCP port ${domain.port}.`,
      component: `Port: ${domain.port}`,
      reasonItMatters:
        'Standard consumer websites use port 443 (HTTPS) or port 80 (HTTP). Unusual ports often indicate temporary servers, exposed admin panels, or makeshift phishing hosts.',
    });
  }

  // 15. Suspicious hostname suffix (+8)
  if (FREQUENTLY_ABUSED_TLDS.has(domain.tld) && !isOfficialBrand) {
    indicators.push({
      id: 'suspicious-tld',
      name: 'High-Risk or Frequently Abused Top-Level Domain',
      severity: 'Low',
      weight: HEURISTIC_WEIGHTS.SUSPICIOUS_TLD,
      explanation: `The domain uses the ".${domain.tld}" top-level suffix.`,
      component: `.${domain.tld}`,
      reasonItMatters:
        'While legitimate projects can use low-cost new TLDs, suffixes like .xyz, .top, .click, and .zip (which resembles a file extension) see disproportionately high abuse in bulk phishing campaigns.',
    });
  }

  // 16. Suspicious redirect pattern (+12)
  let detectedRedirectParam = '';
  for (const [key, value] of parsed.searchParams.entries()) {
    const lowerKey = key.toLowerCase();
    const lowerVal = value.toLowerCase();
    if (
      REDIRECT_PARAM_NAMES.has(lowerKey) ||
      lowerVal.startsWith('http://') ||
      lowerVal.startsWith('https://') ||
      lowerVal.startsWith('//')
    ) {
      detectedRedirectParam = `${key}=[EXTERNAL_TARGET]`;
      break;
    }
  }
  if (detectedRedirectParam) {
    indicators.push({
      id: 'suspicious-redirect',
      name: 'External Redirect Parameter Detected',
      severity: 'Medium',
      weight: HEURISTIC_WEIGHTS.OPEN_REDIRECT_PATTERN,
      explanation:
        'The URL query string includes a redirect parameter that may forward the browser to a different website after clicking.',
      component: detectedRedirectParam,
      reasonItMatters:
        'Attackers exploit open redirects on legitimate or intermediary websites so the initial link looks trustworthy before silently forwarding you to a phishing page.',
    });
  }

  // 17. High-risk path & lexical combinations:
  // A) Digital arrest, law enforcement, or urgent fine / customs / tax impersonation on non-gov domains
  const fullLexicalTarget = `${domain.hostname}${domain.path}`.toLowerCase();
  const govScamPattern =
    /(digital-?arrest|cyber-?crime|cbi-?notice|ed-?summon|narcotics|customs-?seizure|arrest-?warrant|fir-?copy|supreme-?court|police-?verification|echallan|challan-?pay|income-?tax-?refund|kyc-?block|pan-?suspend)/i;
  const govScamMatch = fullLexicalTarget.match(govScamPattern);

  if (govScamMatch && !isOfficialGov) {
    indicators.push({
      id: 'gov-impersonation-pattern',
      name: 'Government, Law-Enforcement, or Urgent Fine Pattern on Non-Official Domain',
      severity: 'High',
      weight: HEURISTIC_WEIGHTS.GOV_DIGITAL_ARREST_PATTERN,
      explanation: `The URL references "${govScamMatch[0]}" on "${domain.registrableDomain}", which is not an official government (.gov / .gov.in / .nic.in) domain.`,
      component: govScamMatch[0],
      reasonItMatters:
        'Digital arrest scams, fake traffic e-challans, and KYC suspension links use urgent law-enforcement or regulatory terms on private domains to coerce victims into immediate compliance or payment.',
    });
  }

  // B) Sensitive authentication, verification, banking, or payment paths on non-official or suspicious domains
  const sensitivePathPattern =
    /\/(login|signin|sign-in|verify|verification|account|secure|update|password|reset|confirm|wallet|banking|payment|kyc|auth|unlock|suspend)(\/|$|-|\.)/i;
  const sensitiveHostPattern =
    /(login|signin|verify|verification|secure|account|update|banking|payment|kyc|auth|unlock|suspend)/i;

  const pathMatch = domain.path.match(sensitivePathPattern);
  const hostSensitiveMatch = !isOfficialBrand && domain.hostname.match(sensitiveHostPattern);

  if ((pathMatch || hostSensitiveMatch) && !isOfficialBrand && !isOfficialGov) {
    const matchedToken = pathMatch ? pathMatch[0] : hostSensitiveMatch?.[0] || domain.path;
    const hasCompoundingRisk =
      brandMatches.length > 0 ||
      domain.isIpAddress ||
      domain.protocol === 'HTTP' ||
      hyphenCount >= 2 ||
      FREQUENTLY_ABUSED_TLDS.has(domain.tld);

    indicators.push({
      id: 'sensitive-login-payment-combo',
      name: hasCompoundingRisk
        ? 'High-Risk Login or Account Verification Pattern'
        : 'Account Login or Verification Route',
      severity: hasCompoundingRisk ? 'High' : 'Low',
      weight: HEURISTIC_WEIGHTS.HIGH_RISK_PATH_COMBO,
      explanation: hasCompoundingRisk
        ? `The URL combines a sensitive authentication/verification route ("${matchedToken}") with other deceptive domain signals on "${domain.registrableDomain}".`
        : `The URL leads to an account login or verification path ("${matchedToken}") on "${domain.registrableDomain}".`,
      component: matchedToken,
      reasonItMatters:
        'Credential-harvesting pages routinely ask users to sign in, verify their identity, or resolve an account warning. Always confirm the registrable domain is official before entering credentials.',
    });
  }

  // Calculate total weighted score (capped at 0..100)
  let rawScore = indicators.reduce((sum, ind) => sum + ind.weight, 0);

  // If external reputation explicitly confirmed a match, elevate score to at least 85
  if (externalReputation?.checked && externalReputation.status === 'flagged') {
    rawScore = Math.max(rawScore, 85);
    indicators.unshift({
      id: 'external-reputation-match',
      name: `Confirmed Threat Intelligence Match (${externalReputation.providerName})`,
      severity: 'Critical',
      weight: 85,
      explanation:
        externalReputation.details ||
        `This URL was flagged as unsafe by ${externalReputation.providerName}.`,
      component: domain.normalizedUrl,
      reasonItMatters:
        'A confirmed match in an external threat intelligence database indicates that the URL or domain has been actively reported for phishing, malware, or social engineering.',
    });
  }

  const riskScore = Math.max(0, Math.min(100, rawScore));
  const classification = classifyRiskScore(riskScore);
  const guidance = buildRecommendedGuidance(classification);

  // Build concise one-sentence explanation
  let summaryExplanation = '';
  if (indicators.length === 0) {
    summaryExplanation =
      'No suspicious structural or lexical URL indicators were detected during heuristic analysis, though low risk indicators do not guarantee website safety.';
  } else if (indicators.length === 1) {
    summaryExplanation = `This URL triggered 1 heuristic indicator: ${indicators[0].name.toLowerCase()}.`;
  } else {
    const topTwo = [...indicators]
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 2)
      .map((i) => i.name.toLowerCase());
    summaryExplanation = `This URL contains ${indicators.length} suspicious characteristics, including ${topTwo.join(' and ')}.`;
  }

  const reputation: ExternalReputationReport = externalReputation || {
    checked: false,
    status: 'not_configured',
    summaryLabel: 'Local URL heuristic analysis — external reputation not checked.',
    providerName: 'Not checked',
    lastCheckedAt: null,
  };

  const result: URLAnalysisResult = {
    id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    riskScore,
    classification,
    summaryExplanation,
    disclaimer: MANDATORY_DISCLAIMER,
    domain,
    indicators,
    reputation,
    guidance,
  };

  return { valid: true, result };
}

/**
 * Curated test fixtures required by section 14 of the specification.
 * Demonstrates benign vs deceptive patterns deterministically.
 */
export const EXAMPLE_TEST_FIXTURES: ExampleFixture[] = [
  {
    label: 'wikipedia.org',
    url: 'https://www.wikipedia.org/',
    category: 'Benign Baseline',
    description: 'Standard HTTPS reference domain with clean hierarchy.',
  },
  {
    label: 'google.com',
    url: 'https://www.google.com/',
    category: 'Benign Baseline',
    description: 'Official Google registrable domain over HTTPS.',
  },
  {
    label: 'http://example.com',
    url: 'http://example.com/',
    category: 'HTTP Baseline',
    description: 'Unencrypted HTTP connection without deceptive brand terms.',
  },
  {
    label: 'Subdomain Brand Spoof',
    url: 'https://google.com.security-check.example.org/',
    category: 'Brand Subdomain Spoof',
    description: 'Places google.com in a subdomain while hosted on example.org.',
  },
  {
    label: 'Typosquatting Login',
    url: 'https://paypa1-example.com/login',
    category: 'Typosquatting Login',
    description: 'Uses "1" instead of "l" in "paypa1" combined with a /login path.',
  },
  {
    label: 'Account Verify Path',
    url: 'https://example.com/account/verify',
    category: 'Verification Route',
    description: 'Account verification route on a non-brand domain.',
  },
];
