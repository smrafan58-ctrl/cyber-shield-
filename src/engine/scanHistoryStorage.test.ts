import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_SCAN_HISTORY_ITEMS,
  upsertScanHistoryList,
} from './scanHistoryStorage.ts';
import { URLAnalysisResult } from '../types/scanner.ts';

function makeMockResult(url: string, riskScore: number): URLAnalysisResult {
  const parsed = new URL(url);
  return {
    id: `scan-${url}`,
    timestamp: new Date().toISOString(),
    riskScore,
    classification:
      riskScore >= 60
        ? 'HIGH RISK'
        : riskScore >= 35
        ? 'MODERATE RISK'
        : 'LOW RISK INDICATORS',
    summaryExplanation: 'Test summary',
    disclaimer: 'Test disclaimer',
    domain: {
      originalInput: url,
      normalizedUrl: parsed.toString(),
      redactedUrl: parsed.toString(),
      protocol: 'HTTPS',
      hostname: parsed.hostname,
      registrableDomain: parsed.hostname,
      subdomain: 'None',
      tld: 'com',
      port: 'Default',
      path: parsed.pathname,
      queryParamCount: 0,
      queryParamKeys: [],
      urlLength: url.length,
      hostnameLength: parsed.hostname.length,
      hasCredentialsInAuthority: false,
      isIpAddress: false,
      isPunycode: false,
    },
    indicators: [],
    reputation: {
      checked: false,
      providerName: 'Local Heuristic Engine',
      status: 'not_configured',
      summaryLabel: 'Local URL heuristic analysis — external reputation not checked.',
      lastCheckedAt: null,
    },
    guidance: {
      headline: 'Safe',
      primaryAdvice: 'Verify domain',
      universalRules: [],
    },
  };
}

describe('scanHistoryStorage (Last 5 Analyzed URLs)', () => {
  it('caps the history list strictly at 5 analyzed URLs in newest-first order', () => {
    let history: URLAnalysisResult[] = [];
    for (let i = 1; i <= 7; i++) {
      history = upsertScanHistoryList(
        history,
        makeMockResult(`https://example-${i}.com/`, i * 10)
      );
    }

    assert.equal(history.length, MAX_SCAN_HISTORY_ITEMS);
    assert.equal(history.length, 5);
    assert.equal(history[0].domain.hostname, 'example-7.com');
    assert.equal(history[0].riskScore, 70);
    assert.equal(history[4].domain.hostname, 'example-3.com');
    assert.equal(history[4].riskScore, 30);
  });

  it('deduplicates re-scanned URLs and moves the latest scan to the top', () => {
    let history: URLAnalysisResult[] = [];
    history = upsertScanHistoryList(
      history,
      makeMockResult('https://first.example.com/', 10)
    );
    history = upsertScanHistoryList(
      history,
      makeMockResult('https://second.example.com/', 40)
    );
    history = upsertScanHistoryList(
      history,
      makeMockResult('https://first.example.com/', 15)
    );

    assert.equal(history.length, 2);
    assert.equal(history[0].domain.hostname, 'first.example.com');
    assert.equal(history[0].riskScore, 15);
    assert.equal(history[1].domain.hostname, 'second.example.com');
  });
});
