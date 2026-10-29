export type RiskClassification =
  | 'LOW RISK INDICATORS'
  | 'MILD SUSPICION'
  | 'MODERATE RISK'
  | 'HIGH RISK'
  | 'VERY HIGH RISK';

export type IndicatorSeverity =
  | 'Informational'
  | 'Low'
  | 'Medium'
  | 'High'
  | 'Critical';

export interface DetectedIndicator {
  id: string;
  name: string;
  severity: IndicatorSeverity;
  weight: number;
  explanation: string;
  component: string;
  reasonItMatters: string;
}

export interface DomainDetails {
  originalInput: string;
  normalizedUrl: string;
  redactedUrl: string;
  protocol: string;
  hostname: string;
  registrableDomain: string;
  subdomain: string;
  tld: string;
  port: string;
  path: string;
  urlLength: number;
  hostnameLength: number;
  queryParamCount: number;
  queryParamKeys: string[];
  hasCredentialsInAuthority: boolean;
  isIpAddress: boolean;
  isPunycode: boolean;
}

export interface ExternalReputationReport {
  checked: boolean;
  status: 'not_configured' | 'clean' | 'flagged' | 'unavailable';
  summaryLabel: string;
  providerName: string;
  lastCheckedAt: string | null;
  details?: string;
}

export interface RecommendedGuidance {
  headline: string;
  primaryAdvice: string;
  universalRules: string[];
}

export interface URLAnalysisResult {
  id: string;
  timestamp: string;
  riskScore: number;
  classification: RiskClassification;
  summaryExplanation: string;
  disclaimer: string;
  domain: DomainDetails;
  indicators: DetectedIndicator[];
  reputation: ExternalReputationReport;
  guidance: RecommendedGuidance;
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
  errorTitle?: string;
  domainDetails?: DomainDetails;
  parsedUrl?: URL;
  rawHadAuthorityAt?: boolean;
  rawAuthorityPrefix?: string;
}

export interface ScanHistoryEntry {
  id: string;
  timestamp: string;
  registrableDomain: string;
  hostname: string;
  redactedUrl: string;
  riskScore: number;
  classification: RiskClassification;
  indicatorCount: number;
  summaryExplanation: string;
  resultSnapshot: URLAnalysisResult;
}

export interface ExampleFixture {
  label: string;
  url: string;
  category: 'Benign Baseline' | 'HTTP Baseline' | 'Brand Subdomain Spoof' | 'Typosquatting Login' | 'Verification Route' | 'Urgent Scam Pattern';
  description: string;
}
