import test from 'node:test';
import assert from 'node:assert/strict';
import { validateAndNormalizeUrl, parseHostnameParts } from './urlValidator';
import { analyzeUrl, classifyRiskScore } from './urlAnalyzer';

test('URL validation rejects empty input and embedded whitespace/multiple URLs', () => {
  const emptyRes = validateAndNormalizeUrl('   ');
  assert.equal(emptyRes.valid, false);
  assert.match(emptyRes.error || '', /enter a single URL/i);

  const multiRes = validateAndNormalizeUrl('https://example.com https://google.com');
  assert.equal(multiRes.valid, false);
  assert.match(multiRes.errorTitle || '', /Multiple URLs/i);

  const paragraphRes = validateAndNormalizeUrl('Dear customer click https://example.com urgently');
  assert.equal(paragraphRes.valid, false);
  assert.match(paragraphRes.errorTitle || '', /Whitespace|Message/i);
});

test('URL validation blocks dangerous protocols (javascript:, data:, file:, ftp:)', () => {
  for (const dangerous of [
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'file:///etc/passwd',
    'ftp://files.example.com/archive.zip',
  ]) {
    const res = validateAndNormalizeUrl(dangerous);
    assert.equal(res.valid, false, `Expected ${dangerous} to be rejected`);
    assert.match(res.errorTitle || '', /Unsupported Protocol/i);
  }
});

test('URL validation normalizes valid scheme-less domains to HTTPS and redacts query values', () => {
  const res = validateAndNormalizeUrl('example.com/path?token=secret123&session=abc');
  assert.equal(res.valid, true);
  assert.equal(res.domainDetails?.protocol, 'HTTPS');
  assert.equal(res.domainDetails?.hostname, 'example.com');
  assert.equal(res.domainDetails?.queryParamCount, 2);
  assert.equal(res.domainDetails?.redactedUrl.includes('secret123'), false);
  assert.equal(res.domainDetails?.redactedUrl.includes('[REDACTED]'), true);
});

test('Hostname extraction accurately separates subdomain, registrable domain, and multi-part TLDs', () => {
  const wiki = parseHostnameParts('www.wikipedia.org');
  assert.equal(wiki.registrableDomain, 'wikipedia.org');
  assert.equal(wiki.subdomain, 'www');
  assert.equal(wiki.tld, 'org');

  const spoof = parseHostnameParts('google.com.security-check.example.org');
  assert.equal(spoof.registrableDomain, 'example.org');
  assert.equal(spoof.subdomain, 'google.com.security-check');
  assert.equal(spoof.tld, 'org');

  const indiaGov = parseHostnameParts('portal.cybercrime.gov.in');
  assert.equal(indiaGov.registrableDomain, 'cybercrime.gov.in');
  assert.equal(indiaGov.subdomain, 'portal');
  assert.equal(indiaGov.tld, 'gov.in');
});

test('Risk classification boundaries map accurately across 0-100', () => {
  assert.equal(classifyRiskScore(0), 'LOW RISK INDICATORS');
  assert.equal(classifyRiskScore(19), 'LOW RISK INDICATORS');
  assert.equal(classifyRiskScore(20), 'MILD SUSPICION');
  assert.equal(classifyRiskScore(39), 'MILD SUSPICION');
  assert.equal(classifyRiskScore(40), 'MODERATE RISK');
  assert.equal(classifyRiskScore(59), 'MODERATE RISK');
  assert.equal(classifyRiskScore(60), 'HIGH RISK');
  assert.equal(classifyRiskScore(79), 'HIGH RISK');
  assert.equal(classifyRiskScore(80), 'VERY HIGH RISK');
  assert.equal(classifyRiskScore(100), 'VERY HIGH RISK');
});

test('Required test fixtures produce accurate, reproducible heuristic results', () => {
  // 1. https://www.wikipedia.org/ -> Benign
  const wiki = analyzeUrl('https://www.wikipedia.org/');
  assert.equal(wiki.valid, true);
  if (wiki.valid) {
    assert.equal(wiki.result.riskScore, 0);
    assert.equal(wiki.result.classification, 'LOW RISK INDICATORS');
    assert.equal(wiki.result.indicators.length, 0);
  }

  // 2. https://www.google.com/ -> Benign official brand
  const google = analyzeUrl('https://www.google.com/');
  assert.equal(google.valid, true);
  if (google.valid) {
    assert.equal(google.result.riskScore, 0);
    assert.equal(google.result.classification, 'LOW RISK INDICATORS');
  }

  // 3. Legitimate brand subdomain accounts.google.com -> Not flagged for brand impersonation
  const googleAccounts = analyzeUrl('https://accounts.google.com/ServiceLogin');
  assert.equal(googleAccounts.valid, true);
  if (googleAccounts.valid) {
    assert.equal(googleAccounts.result.riskScore, 0);
    assert.equal(googleAccounts.result.indicators.length, 0);
  }

  // 4. http://example.com/ -> Unencrypted HTTP (+8), Low Risk Indicators
  const httpEx = analyzeUrl('http://example.com/');
  assert.equal(httpEx.valid, true);
  if (httpEx.valid) {
    assert.equal(httpEx.result.riskScore, 8);
    assert.equal(httpEx.result.classification, 'LOW RISK INDICATORS');
    assert.equal(httpEx.result.indicators.some((i) => i.id === 'http-protocol'), true);
  }

  // 5. https://google.com.security-check.example.org/ -> Brand impersonation + excessive subdomains
  const brandSpoof = analyzeUrl('https://google.com.security-check.example.org/');
  assert.equal(brandSpoof.valid, true);
  if (brandSpoof.valid) {
    assert.ok(brandSpoof.result.riskScore >= 35, `Expected elevated score, got ${brandSpoof.result.riskScore}`);
    assert.equal(brandSpoof.result.indicators.some((i) => i.id === 'brand-impersonation'), true);
    assert.equal(brandSpoof.result.domain.registrableDomain, 'example.org');
  }

  // 6. https://paypa1-example.com/login -> Typosquatting (+25) + High-risk login combo (+15) = 40
  const typosquat = analyzeUrl('https://paypa1-example.com/login');
  assert.equal(typosquat.valid, true);
  if (typosquat.valid) {
    assert.equal(typosquat.result.riskScore, 40);
    assert.equal(typosquat.result.classification, 'MODERATE RISK');
    assert.equal(typosquat.result.indicators.some((i) => i.id === 'typosquatting-signal'), true);
    assert.equal(typosquat.result.indicators.some((i) => i.id === 'sensitive-login-payment-combo'), true);
  }

  // 7. https://example.com/account/verify -> Account verify route (+15)
  const verifyRoute = analyzeUrl('https://example.com/account/verify');
  assert.equal(verifyRoute.valid, true);
  if (verifyRoute.valid) {
    assert.equal(verifyRoute.result.riskScore, 15);
    assert.equal(verifyRoute.result.classification, 'LOW RISK INDICATORS');
    assert.equal(verifyRoute.result.indicators.some((i) => i.id === 'sensitive-login-payment-combo'), true);
  }

  // 8. Reproducibility check: running same URL twice gives identical score
  const runA = analyzeUrl('https://google.com.security-check.example.org/login?redirect=https://evil.xyz');
  const runB = analyzeUrl('https://google.com.security-check.example.org/login?redirect=https://evil.xyz');
  assert.equal(runA.valid && runB.valid, true);
  if (runA.valid && runB.valid) {
    assert.equal(runA.result.riskScore, runB.result.riskScore);
    assert.ok(runA.result.riskScore >= 60);
  }
});
