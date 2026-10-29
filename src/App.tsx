/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import { Shield } from 'lucide-react';
import { ActiveTab, Navbar } from './components/Navbar';
import { URLInputSection } from './components/URLInputSection';
import { ScanResultsDashboard } from './components/ScanResultsDashboard';
import { ScanHistorySection } from './components/ScanHistorySection';
import { SafetyGuideSection } from './components/SafetyGuideSection';
import { AboutSection } from './components/AboutSection';
import { ScannerEmptyOverview } from './components/ScannerEmptyOverview';
import { analyzeUrl, MANDATORY_DISCLAIMER } from './engine/urlAnalyzer';
import {
  ExternalReputationReport,
  ScanHistoryEntry,
  URLAnalysisResult,
} from './types/scanner';

const HISTORY_STORAGE_KEY = 'cybershield_scan_history_v1';
const HISTORY_ENABLED_KEY = 'cybershield_history_enabled_v1';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [urlInput, setUrlInput] = useState<string>('');
  const [validationError, setValidationError] = useState<{
    title: string;
    message: string;
  } | null>(null);
  const [currentResult, setCurrentResult] = useState<URLAnalysisResult | null>(
    null
  );
  const [isScanning, setIsScanning] = useState<boolean>(false);

  const [historyEnabled, setHistoryEnabled] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem(HISTORY_ENABLED_KEY);
      return saved === null ? true : saved === 'true';
    } catch {
      return true;
    }
  });

  const [history, setHistory] = useState<ScanHistoryEntry[]>(() => {
    try {
      const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  });

  const [reputationStatus, setReputationStatus] = useState<{
    configured: boolean;
    providers: string[];
    backendRuntime: string;
  }>({
    configured: false,
    providers: [],
    backendRuntime: 'Java 17 (OpenJDK HttpServer)',
  });

  const inputRef = useRef<HTMLInputElement | null>(null);

  // Check Java backend & optional server-side reputation status on mount
  useEffect(() => {
    let active = true;
    fetch('/api/reputation/status')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (active && data && typeof data.configured === 'boolean') {
          setReputationStatus({
            configured: data.configured,
            providers: Array.isArray(data.providers) ? data.providers : [],
            backendRuntime:
              typeof data.backendRuntime === 'string'
                ? data.backendRuntime
                : 'Java 17 (OpenJDK HttpServer)',
          });
        }
      })
      .catch(() => {
        // Optional backend status check failed gracefully; local heuristics continue unaffected
      });
    return () => {
      active = false;
    };
  }, []);

  // Sync history to localStorage when enabled
  useEffect(() => {
    try {
      if (historyEnabled) {
        localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
      }
    } catch {
      // Ignore storage quota errors
    }
  }, [history, historyEnabled]);

  const handleToggleHistoryEnabled = (enabled: boolean) => {
    setHistoryEnabled(enabled);
    try {
      localStorage.setItem(HISTORY_ENABLED_KEY, String(enabled));
      if (!enabled) {
        localStorage.removeItem(HISTORY_STORAGE_KEY);
        setHistory([]);
      }
    } catch {
      // Ignore storage errors
    }
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_STORAGE_KEY);
    } catch {
      // Ignore storage errors
    }
  };

  const executeScan = async (overrideUrl?: string) => {
    const rawTarget = overrideUrl !== undefined ? overrideUrl : urlInput;
    setValidationError(null);

    // Run deterministic URL validation & heuristic analysis first for instant validation
    const initialAnalysis = analyzeUrl(rawTarget);
    if (!initialAnalysis.valid) {
      setValidationError({
        title: initialAnalysis.errorTitle,
        message: initialAnalysis.error,
      });
      setCurrentResult(null);
      return;
    }

    setIsScanning(true);
    let finalResult = initialAnalysis.result;

    // Query the Java 17 Backend /api/analyze endpoint (falls back to local deterministic result if offline)
    try {
      const apiRes = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawTarget }),
      });
      if (apiRes.ok) {
        const apiData = (await apiRes.json()) as {
          valid: boolean;
          result?: URLAnalysisResult;
          backendEngine?: string;
        };
        if (apiData.valid && apiData.result) {
          finalResult = apiData.result;
        }
      }
    } catch {
      // Graceful fallback to local deterministic heuristic result
    }

    setIsScanning(false);
    setCurrentResult(finalResult);

    if (activeTab !== 'scanner' && activeTab !== 'home') {
      setActiveTab('scanner');
    }

    if (historyEnabled) {
      const sanitizedSnapshot: URLAnalysisResult = {
        ...finalResult,
        domain: {
          ...finalResult.domain,
          originalInput: finalResult.domain.redactedUrl,
          normalizedUrl: finalResult.domain.redactedUrl,
        },
      };

      const newEntry: ScanHistoryEntry = {
        id: finalResult.id,
        timestamp: finalResult.timestamp,
        registrableDomain: finalResult.domain.registrableDomain,
        hostname: finalResult.domain.hostname,
        redactedUrl: finalResult.domain.redactedUrl,
        riskScore: finalResult.riskScore,
        classification: finalResult.classification,
        indicatorCount: finalResult.indicators.length,
        summaryExplanation: finalResult.summaryExplanation,
        resultSnapshot: sanitizedSnapshot,
      };

      setHistory((prev) => [newEntry, ...prev.slice(0, 49)]);
    }
  };

  const handleClearScanner = () => {
    setUrlInput('');
    setValidationError(null);
    setCurrentResult(null);
    inputRef.current?.focus();
  };

  const handleQuickNewScan = () => {
    setActiveTab('scanner');
    setUrlInput('');
    setValidationError(null);
    setCurrentResult(null);
    setTimeout(() => {
      inputRef.current?.focus();
    }, 50);
  };

  const handleSelectHistoryEntry = (entry: ScanHistoryEntry) => {
    setUrlInput(entry.redactedUrl);
    setValidationError(null);
    setCurrentResult(entry.resultSnapshot);
    setActiveTab('scanner');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleNavigateFromGuide = (sampleUrl?: string) => {
    setActiveTab('scanner');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    if (sampleUrl) {
      setUrlInput(sampleUrl);
      executeScan(sampleUrl);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0B1120] text-slate-100">
      <Navbar
        activeTab={activeTab}
        onNavigate={(tab) => {
          setActiveTab(tab);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
        onQuickNewScan={handleQuickNewScan}
        historyCount={history.length}
      />

      <main className="flex-1">
        {(activeTab === 'home' || activeTab === 'scanner') && (
          <>
            <URLInputSection
              urlInput={urlInput}
              onUrlInputChange={setUrlInput}
              onScanSubmit={executeScan}
              onClear={handleClearScanner}
              validationError={validationError}
              isScanning={isScanning}
              inputRef={inputRef}
            />

            {currentResult ? (
              <ScanResultsDashboard
                result={currentResult}
                onScanAnother={handleQuickNewScan}
                onOpenSafetyGuide={() => {
                  setActiveTab('guide');
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }}
              />
            ) : (
              <ScannerEmptyOverview
                onSelectFixtureUrl={(fixtureUrl) => {
                  setUrlInput(fixtureUrl);
                  executeScan(fixtureUrl);
                }}
                onOpenSafetyGuide={() => {
                  setActiveTab('guide');
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }}
              />
            )}
          </>
        )}

        {activeTab === 'history' && (
          <ScanHistorySection
            history={history}
            historyEnabled={historyEnabled}
            onToggleHistoryEnabled={handleToggleHistoryEnabled}
            onClearHistory={handleClearHistory}
            onSelectHistoryEntry={handleSelectHistoryEntry}
            onNavigateToScanner={() => setActiveTab('scanner')}
          />
        )}

        {activeTab === 'guide' && (
          <SafetyGuideSection onNavigateToScanner={handleNavigateFromGuide} />
        )}

        {activeTab === 'about' && (
          <AboutSection
            reputationConfigured={reputationStatus.configured}
            reputationProviders={reputationStatus.providers}
            backendRuntime={reputationStatus.backendRuntime}
            onNavigateToScanner={() => setActiveTab('scanner')}
          />
        )}
      </main>

      <footer className="border-t border-slate-800/80 bg-[#0B1120] py-8 mt-12">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-sky-400 shrink-0" aria-hidden="true" />
            <span className="font-semibold text-slate-200">CyberShield AI</span>
            <span aria-hidden="true">·</span>
            <span>Analyze suspicious URLs and understand the risks before you click.</span>
          </div>
          <p className="max-w-xl sm:text-right text-slate-400">
            {MANDATORY_DISCLAIMER}
          </p>
        </div>
      </footer>
    </div>
  );
}
