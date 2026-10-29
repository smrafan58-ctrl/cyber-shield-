/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef, useState } from 'react';
import { Shield } from 'lucide-react';
import { Navbar } from './components/Navbar';
import { URLInputSection } from './components/URLInputSection';
import { ScanResultsDashboard } from './components/ScanResultsDashboard';
import { CyberShieldChatbot } from './components/CyberShieldChatbot';
import { MANDATORY_DISCLAIMER } from './engine/constants';
import {
  clearScanHistoryFromStorage,
  loadScanHistoryFromStorage,
  saveScanHistoryToStorage,
  upsertScanHistoryList,
} from './engine/scanHistoryStorage';
import { URLAnalysisResult } from './types/scanner';

export default function App() {
  const [urlInput, setUrlInput] = useState<string>('');
  const [validationError, setValidationError] = useState<{
    title: string;
    message: string;
  } | null>(null);
  const [currentResult, setCurrentResult] = useState<URLAnalysisResult | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanHistory, setScanHistory] = useState<URLAnalysisResult[]>(() =>
    loadScanHistoryFromStorage()
  );
  const [isChatOpen, setIsChatOpen] = useState<boolean>(false);

  const inputRef = useRef<HTMLInputElement | null>(null);

  const handleResetToScanner = () => {
    setUrlInput('');
    setValidationError(null);
    setCurrentResult(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => {
      inputRef.current?.focus();
    }, 50);
  };

  const handleClearInput = () => {
    setUrlInput('');
    setValidationError(null);
    inputRef.current?.focus();
  };

  const handleSelectHistoryItem = (item: URLAnalysisResult) => {
    setValidationError(null);
    setUrlInput(item.domain.redactedUrl);
    setCurrentResult(item);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleClearHistory = () => {
    clearScanHistoryFromStorage();
    setScanHistory([]);
  };

  const executeScan = async (overrideUrl?: string) => {
    const rawTarget = overrideUrl !== undefined ? overrideUrl : urlInput;
    setValidationError(null);
    setIsScanning(true);

    try {
      const apiRes = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawTarget }),
      });

      const apiData = (await apiRes.json()) as {
        valid: boolean;
        errorTitle?: string;
        error?: string;
        result?: URLAnalysisResult;
      };

      if (!apiData.valid) {
        setValidationError({
          title: apiData.errorTitle || 'Invalid URL Input',
          message:
            apiData.error ||
            'Please enter a single valid HTTP or HTTPS URL (for example, https://example.com).',
        });
        setIsScanning(false);
        return;
      }

      if (apiData.result) {
        const result = apiData.result;
        setCurrentResult(result);
        setScanHistory((prev) => {
          const updated = upsertScanHistoryList(prev, result);
          saveScanHistoryToStorage(updated);
          return updated;
        });
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    } catch {
      setValidationError({
        title: 'Backend Connection Error',
        message:
          'Unable to reach the Java URL threat analysis backend service. Please try again in a moment.',
      });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0B1120] text-slate-100">
      <Navbar
        onNewScan={handleResetToScanner}
        hasResult={Boolean(currentResult)}
        isChatOpen={isChatOpen}
        onToggleChat={() => setIsChatOpen((prev) => !prev)}
      />

      <main className="flex-1">
        {/* Strictly Two Views: URL Pasting Page & Risk Showing Page */}
        {!currentResult ? (
          /* 1. URL Pasting Page (with Local Storage Last-5 Scan History below input) */
          <URLInputSection
            urlInput={urlInput}
            onUrlInputChange={setUrlInput}
            onScanSubmit={executeScan}
            onClear={handleClearInput}
            validationError={validationError}
            isScanning={isScanning}
            inputRef={inputRef}
            scanHistory={scanHistory}
            onSelectHistoryItem={handleSelectHistoryItem}
            onClearHistory={handleClearHistory}
          />
        ) : (
          /* 2. Risk Showing Page */
          <ScanResultsDashboard
            result={currentResult}
            onScanAnother={handleResetToScanner}
          />
        )}
      </main>

      {/* Multi-Turn Gemini Cybersecurity Chatbot */}
      <CyberShieldChatbot
        isOpen={isChatOpen}
        onToggleOpen={() => setIsChatOpen((prev) => !prev)}
        activeScanResult={currentResult}
      />

      <footer className="border-t border-slate-800/80 bg-[#0B1120] py-6 mt-12">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-sky-400 shrink-0" aria-hidden="true" />
            <span className="font-semibold text-slate-200">CyberShield AI</span>
            <span aria-hidden="true">·</span>
            <span>URL Threat Detection (Java 17 Backend)</span>
          </div>
          <p className="max-w-xl text-center sm:text-right text-slate-400">
            {MANDATORY_DISCLAIMER}
          </p>
        </div>
      </footer>
    </div>
  );
}
