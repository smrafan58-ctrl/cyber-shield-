import { DomainDetails } from '../types/scanner';

export interface BrandRule {
  brandName: string;
  tokens: string[];
  officialDomains: string[];
  typosquatPatterns: RegExp[];
}

/**
 * Curated list of commonly impersonated global and Indian brands, banking institutions,
 * and payment/government portals.
 */
export const PROTECTED_BRANDS: BrandRule[] = [
  {
    brandName: 'Google',
    tokens: ['google', 'gmail', 'googlepay', 'gpay'],
    officialDomains: ['google.com', 'google.co.in', 'google.co.uk', 'gmail.com', 'withgoogle.com', 'youtube.com'],
    typosquatPatterns: [/g00gle/i, /goog1e/i, /g0ogle/i, /googie/i, /go0gle/i],
  },
  {
    brandName: 'Microsoft',
    tokens: ['microsoft', 'office365', 'onedrive', 'outlook', 'sharepoint'],
    officialDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'sharepoint.com', 'onedrive.com', 'microsoftonline.com'],
    typosquatPatterns: [/micr0soft/i, /mircosoft/i, /micros0ft/i, /rnicrosoft/i, /outl00k/i],
  },
  {
    brandName: 'Apple',
    tokens: ['apple', 'icloud', 'appleid'],
    officialDomains: ['apple.com', 'icloud.com', 'me.com'],
    typosquatPatterns: [/app1e/i, /ic1oud/i, /apple-id/i, /appIe/],
  },
  {
    brandName: 'Amazon',
    tokens: ['amazon', 'aws', 'primevideo'],
    officialDomains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com', 'primevideo.com'],
    typosquatPatterns: [/amaz0n/i, /arnazon/i, /amzon/i, /amazonn/i],
  },
  {
    brandName: 'PayPal',
    tokens: ['paypal'],
    officialDomains: ['paypal.com', 'paypal.me'],
    typosquatPatterns: [/paypa1/i, /paypai/i, /paypaI/, /paipal/i, /pay-pal/i],
  },
  {
    brandName: 'State Bank of India (SBI)',
    tokens: ['onlinesbi', 'sbicard', 'sbiyono', 'yonosbi'],
    officialDomains: ['onlinesbi.sbi', 'sbi.co.in', 'sbicard.com'],
    typosquatPatterns: [/on1inesbi/i, /sbi-kyc/i, /sbi-yono/i, /yono-sbi/i],
  },
  {
    brandName: 'HDFC Bank',
    tokens: ['hdfcbank', 'hdfcnetbanking'],
    officialDomains: ['hdfcbank.com', 'hdfc.com'],
    typosquatPatterns: [/hdfc-kyc/i, /hdfc-bank/i, /hdfcbnk/i],
  },
  {
    brandName: 'ICICI Bank',
    tokens: ['icicibank'],
    officialDomains: ['icicibank.com', 'icicidirect.com'],
    typosquatPatterns: [/ic1cibank/i, /icici-bank/i, /icici-kyc/i],
  },
  {
    brandName: 'Axis Bank',
    tokens: ['axisbank'],
    officialDomains: ['axisbank.com'],
    typosquatPatterns: [/axis-bank/i, /ax1sbank/i, /axis-kyc/i],
  },
  {
    brandName: 'Netflix',
    tokens: ['netflix'],
    officialDomains: ['netflix.com'],
    typosquatPatterns: [/netf1ix/i, /netfiix/i, /net-flix/i],
  },
  {
    brandName: 'Meta / Facebook / Instagram',
    tokens: ['facebook', 'instagram', 'whatsapp'],
    officialDomains: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'fb.com'],
    typosquatPatterns: [/faceb00k/i, /1nstagram/i, /instagrarn/i, /whatsap-/i],
  },
  {
    brandName: 'GitHub',
    tokens: ['github'],
    officialDomains: ['github.com', 'github.io', 'githubusercontent.com'],
    typosquatPatterns: [/g1thub/i, /git-hub/i],
  },
  {
    brandName: 'Chase Bank',
    tokens: ['jpmorganchase'],
    officialDomains: ['chase.com', 'jpmorganchase.com'],
    typosquatPatterns: [/chase-bank/i, /chase-verify/i, /chase-login/i],
  },
];

export interface BrandDetectionMatch {
  type: 'impersonation' | 'typosquatting';
  brandName: string;
  matchedString: string;
  location: 'subdomain' | 'registrable_domain' | 'authority';
  explanation: string;
}

/**
 * Normalizes common homoglyphs (1 -> l, 0 -> o, rn -> m, vv -> w) to detect lookalike tokens.
 */
function dehomoglyph(input: string): string {
  return input
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/!/g, 'i')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

/**
 * Computes Levenshtein edit distance between two strings.
 */
function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

/**
 * Conservatively evaluates whether a URL's hostname or authority exhibits brand impersonation
 * or typosquatting, while respecting official registrable domains.
 */
export function detectBrandImpersonation(
  domain: DomainDetails,
  rawAuthorityPrefix?: string
): BrandDetectionMatch[] {
  const matches: BrandDetectionMatch[] = [];
  if (domain.isIpAddress) {
    return matches;
  }

  const registrable = domain.registrableDomain.toLowerCase();
  const registrableBase = registrable.split('.')[0] || '';
  const subdomain = domain.subdomain === 'None' ? '' : domain.subdomain.toLowerCase();
  const fullHost = domain.hostname.toLowerCase();

  for (const brand of PROTECTED_BRANDS) {
    const isOfficial = brand.officialDomains.includes(registrable);
    if (isOfficial) {
      // Legitimate registrable domain for this brand (e.g. accounts.google.com -> google.com)
      continue;
    }

    // 1. Check explicit typosquatting patterns in hostname or registrable domain
    let foundTyposquat = false;
    for (const pattern of brand.typosquatPatterns) {
      const m = fullHost.match(pattern);
      if (m) {
        matches.push({
          type: 'typosquatting',
          brandName: brand.brandName,
          matchedString: m[0],
          location: registrable.match(pattern) ? 'registrable_domain' : 'subdomain',
          explanation: `The hostname contains the lookalike string "${m[0]}" resembling ${brand.brandName}, while the actual registrable domain is "${domain.registrableDomain}".`,
        });
        foundTyposquat = true;
        break;
      }
    }
    if (foundTyposquat) continue;

    // 2. Check homoglyph / edit-distance typosquatting on tokens in registrable domain segments
    const registrableSegments = registrableBase.split('-').filter(Boolean);
    for (const seg of registrableSegments) {
      for (const token of brand.tokens) {
        if (token.length < 5) continue;
        const normalizedSeg = dehomoglyph(seg);
        if (seg !== token && normalizedSeg === token) {
          matches.push({
            type: 'typosquatting',
            brandName: brand.brandName,
            matchedString: seg,
            location: 'registrable_domain',
            explanation: `The domain segment "${seg}" uses character substitution (homoglyphs) to mimic "${token}" (${brand.brandName}) on unrelated domain "${domain.registrableDomain}".`,
          });
          foundTyposquat = true;
          break;
        }
        // Check 1-character edit distance for longer brand names (e.g. "microsft", "paypall")
        if (
          token.length >= 6 &&
          Math.abs(seg.length - token.length) <= 1 &&
          seg !== token &&
          editDistance(seg, token) === 1
        ) {
          matches.push({
            type: 'typosquatting',
            brandName: brand.brandName,
            matchedString: seg,
            location: 'registrable_domain',
            explanation: `The domain segment "${seg}" is a 1-character near-match to "${token}" (${brand.brandName}) on unrelated domain "${domain.registrableDomain}".`,
          });
          foundTyposquat = true;
          break;
        }
      }
      if (foundTyposquat) break;
    }
    if (foundTyposquat) continue;

    // 3. Check exact brand token used deceptively in subdomain or hyphenated registrable domain
    for (const token of brand.tokens) {
      // Check if brand appears in authority prefix before @ (e.g. https://google.com@evil.org)
      if (rawAuthorityPrefix && rawAuthorityPrefix.toLowerCase().includes(token)) {
        matches.push({
          type: 'impersonation',
          brandName: brand.brandName,
          matchedString: rawAuthorityPrefix,
          location: 'authority',
          explanation: `The URL authority prefix before "@" references ${brand.brandName} ("${rawAuthorityPrefix}"), but the browser actually connects to "${domain.registrableDomain}".`,
        });
        break;
      }

      // Check if brand token or official domain appears in the subdomain of an unrelated registrable domain
      // e.g. google.com.security-check.example.org
      const subdomainTokens = subdomain.split(/[.-]/).filter(Boolean);
      if (subdomainTokens.includes(token)) {
        matches.push({
          type: 'impersonation',
          brandName: brand.brandName,
          matchedString: subdomain,
          location: 'subdomain',
          explanation: `The subdomain "${subdomain}" contains "${token}" (${brand.brandName}), but the actual registrable domain is "${domain.registrableDomain}".`,
        });
        break;
      }

      // Check if brand token is combined with hyphens or extra words in an unrelated registrable domain
      // e.g. microsoft-login.example.net or paypal-secure.com
      if (registrableSegments.includes(token) || (registrableBase.includes(token) && registrableBase !== token)) {
        matches.push({
          type: 'impersonation',
          brandName: brand.brandName,
          matchedString: domain.registrableDomain,
          location: 'registrable_domain',
          explanation: `The domain "${domain.registrableDomain}" embeds the brand name "${token}" (${brand.brandName}), but is not an official ${brand.brandName} registrable domain.`,
        });
        break;
      }
    }
  }

  return matches;
}
