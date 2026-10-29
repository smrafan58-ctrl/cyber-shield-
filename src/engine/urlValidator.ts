import { DomainDetails, ValidationResult } from '../types/scanner';

/**
 * Multi-part public suffixes commonly encountered in global and Indian domains.
 * Used for deterministic registrable domain extraction without external network calls.
 */
const MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'co.in',
  'gov.in',
  'nic.in',
  'org.in',
  'ac.in',
  'net.in',
  'res.in',
  'edu.in',
  'mil.in',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'co.jp',
  'ne.jp',
  'or.jp',
  'co.nz',
  'com.br',
  'com.sg',
  'edu.sg',
  'gov.sg',
  'co.za',
  'com.mx',
  'com.hk',
  'com.tr',
  'co.kr',
  'co.id',
  'com.my',
]);

const UNSUPPORTED_PROTOCOLS = new Set([
  'javascript:',
  'data:',
  'file:',
  'ftp:',
  'vbscript:',
  'mailto:',
  'tel:',
  'ws:',
  'wss:',
  'blob:',
  'about:',
  'chrome:',
]);

/**
 * Checks whether a hostname is an IPv4 or bracketed IPv6 literal.
 */
export function isIpHostname(hostname: string): boolean {
  const clean = hostname.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    return true;
  }
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(clean)) {
    const octets = clean.split('.').map(Number);
    return octets.every((n) => n >= 0 && n <= 255);
  }
  return false;
}

/**
 * Extracts registrable domain, subdomain, and TLD from a normalized hostname.
 */
export function parseHostnameParts(hostname: string): {
  registrableDomain: string;
  subdomain: string;
  tld: string;
} {
  const cleanHost = hostname.toLowerCase().replace(/\.$/, '');
  if (!cleanHost || isIpHostname(cleanHost)) {
    return {
      registrableDomain: cleanHost || 'Not available',
      subdomain: 'None',
      tld: isIpHostname(cleanHost) ? 'IP Literal' : 'None',
    };
  }

  const labels = cleanHost.split('.');
  if (labels.length === 1) {
    return {
      registrableDomain: cleanHost,
      subdomain: 'None',
      tld: 'None',
    };
  }

  const lastTwo = labels.slice(-2).join('.');
  let tldPartsCount = 1;
  if (labels.length >= 3 && MULTI_PART_TLDS.has(lastTwo)) {
    tldPartsCount = 2;
  }

  const tld = labels.slice(-tldPartsCount).join('.');
  const registrableStartIndex = Math.max(0, labels.length - (tldPartsCount + 1));
  const registrableDomain = labels.slice(registrableStartIndex).join('.');
  const subdomainLabels = labels.slice(0, registrableStartIndex);

  return {
    registrableDomain,
    subdomain: subdomainLabels.length > 0 ? subdomainLabels.join('.') : 'None',
    tld,
  };
}

/**
 * Builds a privacy-safe redacted representation of a URL.
 * Masks query parameter values so session tokens, OTPs, or PII are never persisted or exposed.
 */
export function redactSensitiveUrl(parsed: URL): string {
  const base = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  const params = Array.from(parsed.searchParams.keys());
  if (params.length === 0) {
    return base;
  }
  const maskedQuery = Array.from(new Set(params))
    .map((key) => `${encodeURIComponent(key)}=[REDACTED]`)
    .join('&');
  return `${base}?${maskedQuery}`;
}

/**
 * Validates and normalizes untrusted user input as a single HTTP/HTTPS URL.
 * Rejects empty input, multiple URLs, embedded whitespace, and dangerous schemes.
 */
export function validateAndNormalizeUrl(rawInput: string): ValidationResult {
  const trimmed = rawInput.trim();

  // 1. Reject empty input
  if (!trimmed) {
    return {
      valid: false,
      errorTitle: 'Empty URL Input',
      error: 'Please enter a single URL or domain name to analyze (for example, https://example.com).',
    };
  }

  // 2. Reject maximum excessive length (> 2048 chars) for safety
  if (trimmed.length > 2048) {
    return {
      valid: false,
      errorTitle: 'Input Exceeds Maximum Length',
      error: 'The submitted text is over 2,048 characters long. Please submit a single valid URL.',
    };
  }

  // 3. Reject embedded whitespace, line breaks, or paragraphs / multiple URLs
  if (/\s/.test(trimmed)) {
    const httpMatches = trimmed.match(/https?:\/\//gi);
    if (httpMatches && httpMatches.length > 1) {
      return {
        valid: false,
        errorTitle: 'Multiple URLs Detected',
        error: 'CyberShield AI analyzes one URL at a time. Please submit a single URL without extra text or spaces.',
      };
    }
    return {
      valid: false,
      errorTitle: 'Embedded Whitespace or Message Text Detected',
      error: 'This tool only scans single URLs, not text messages or paragraphs. Remove spaces and surrounding text before scanning.',
    };
  }

  // 4. Check explicit protocol if present
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:)/);
  let candidateInput = trimmed;

  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (UNSUPPORTED_PROTOCOLS.has(scheme) || (scheme !== 'http:' && scheme !== 'https:')) {
      // Allow case where schemeMatch is actually hostname:port (e.g. "example.com:8080/login")
      const afterColon = trimmed.slice(scheme.length);
      const looksLikeHostPort =
        scheme.includes('.') && /^\d{1,5}(\/|$)/.test(afterColon);

      if (!looksLikeHostPort) {
        return {
          valid: false,
          errorTitle: `Unsupported Protocol (${scheme})`,
          error: `Only standard web links (http:// and https://) can be analyzed. Links using "${scheme}" are blocked for security reasons.`,
        };
      }
      candidateInput = `https://${trimmed}`;
    }
  } else {
    // No scheme provided; normalize to https:// if it looks like a domain or IP
    if (trimmed.startsWith('//')) {
      candidateInput = `https:${trimmed}`;
    } else {
      candidateInput = `https://${trimmed}`;
    }
  }

  // Detect raw @ symbol in authority section before URL parser normalizes it
  const withoutScheme = candidateInput.replace(/^https?:\/\//i, '');
  const authorityPart = withoutScheme.split(/[/?#]/)[0] || '';
  const rawHadAuthorityAt = authorityPart.includes('@');
  const rawAuthorityPrefix = rawHadAuthorityAt
    ? authorityPart.slice(0, authorityPart.lastIndexOf('@'))
    : undefined;

  let parsed: URL;
  try {
    parsed = new URL(candidateInput);
  } catch {
    return {
      valid: false,
      errorTitle: 'Malformed URL Structure',
      error: 'The input could not be parsed as a valid web address. Check for typos in the domain name or protocol.',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      errorTitle: `Unsupported Protocol (${parsed.protocol})`,
      error: 'Only HTTP and HTTPS web addresses are supported by the URL threat analyzer.',
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return {
      valid: false,
      errorTitle: 'Missing Hostname',
      error: 'The URL does not contain a valid domain name or IP address.',
    };
  }

  // Validate hostname syntax: must either be a valid IP literal or have a dot with a valid TLD
  const ipLiteral = isIpHostname(hostname);
  if (!ipLiteral) {
    if (hostname.startsWith('.') || hostname.endsWith('.') || hostname.includes('..')) {
      return {
        valid: false,
        errorTitle: 'Invalid Domain Name',
        error: 'The domain name contains invalid dot placement. Please enter a complete domain such as example.com.',
      };
    }

    const labels = hostname.split('.');
    if (labels.length < 2) {
      return {
        valid: false,
        errorTitle: 'Incomplete Domain Name',
        error: `"${hostname}" does not include a top-level domain (such as .com, .org, or .in). Please enter a complete domain or URL.`,
      };
    }

    const tldLabel = labels[labels.length - 1];
    if (tldLabel.length < 2 || /^\d+$/.test(tldLabel)) {
      return {
        valid: false,
        errorTitle: 'Invalid Top-Level Domain',
        error: `The top-level domain ".${tldLabel}" is not a valid domain suffix.`,
      };
    }

    const validLabelRegex = /^[a-z0-9-_]+$/i;
    for (const label of labels) {
      if (!label || !validLabelRegex.test(label) || label.startsWith('-') || label.endsWith('-')) {
        return {
          valid: false,
          errorTitle: 'Invalid Characters in Domain',
          error: `The domain segment "${label}" contains invalid characters or leading/trailing hyphens.`,
        };
      }
    }
  }

  const { registrableDomain, subdomain, tld } = parseHostnameParts(hostname);
  const queryKeys = Array.from(parsed.searchParams.keys());
  const hasCredentials =
    rawHadAuthorityAt || Boolean(parsed.username) || Boolean(parsed.password);
  const isPunycode = hostname.includes('xn--');

  const domainDetails: DomainDetails = {
    originalInput: trimmed,
    normalizedUrl: parsed.href,
    redactedUrl: redactSensitiveUrl(parsed),
    protocol: parsed.protocol.replace(':', '').toUpperCase(),
    hostname,
    registrableDomain,
    subdomain,
    tld,
    port: parsed.port || 'Default',
    path: parsed.pathname || '/',
    urlLength: parsed.href.length,
    hostnameLength: hostname.length,
    queryParamCount: queryKeys.length,
    queryParamKeys: Array.from(new Set(queryKeys)),
    hasCredentialsInAuthority: hasCredentials,
    isIpAddress: ipLiteral,
    isPunycode,
  };

  return {
    valid: true,
    domainDetails,
    parsedUrl: parsed,
    rawHadAuthorityAt,
    rawAuthorityPrefix,
  };
}
