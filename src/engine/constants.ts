import { ExampleFixture } from '../types/scanner';

export const MANDATORY_DISCLAIMER =
  'Risk scores are based on observable URL patterns and available reputation data. They do not guarantee that a website is safe or malicious.';

/**
 * Curated test fixtures demonstrating benign vs deceptive URL patterns.
 * Analysis is executed exclusively by the Java 17 backend engine (/api/analyze).
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
