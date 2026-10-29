/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import { Shield } from 'lucide-react';
import { onAuthStateChanged, User } from 'firebase/auth';
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
import {
  analyzeUrlViaJavaBackend,
  clearScanHistoryOnJavaBackend,
  fetchScanHistoryFromJavaBackend,
} from './api/javaBackendClient';
import {
  auth,
  deleteAllUserScansFromFirestore,
  ensureUserProfileDocument,
  saveScanToFirestore,
  signInWithGooglePopup,
  signOutUser,
  subscribeToUserScans,
} from './firebase';
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
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isAuthReady, setIsAuthReady] = useState<boolean>(false);
  const [authStatusMessage, setAuthStatusMessage] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement | null>(null);

  // Track Firebase Authentication state
  useEffect(() => {
    const unsubscribeAuth = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      setIsAuthReady(true);
      if (user) {
        setAuthStatusMessage(null);
        ensureUserProfileDocument(user).catch(() => {
          // Handled via handleFirestoreError in firebase.ts
        });
      }
    });
    return () => unsubscribeAuth();
  }, []);

  // Attach Firestore real-time listener only when auth is ready and user is authenticated
  useEffect(() => {
    if (!isAuthReady || !currentUser) return;

    // Backfill any local storage scans into the user's Firestore collection
    const localItems = loadScanHistoryFromStorage();
    for (const item of localItems) {
      saveScanToFirestore(currentUser, item).catch(() => {
        // Handled via handleFirestoreError
      });
    }

    const unsubscribeScans = subscribeToUserScans(
      currentUser,
      (cloudScans) => {
        if (cloudScans.length > 0) {
          setScanHistory((prev) => {
            let merged = [...prev];
            for (let i = cloudScans.length - 1; i >= 0; i--) {
              merged = upsertScanHistoryList(merged, cloudScans[i]);
            }
            saveScanHistoryToStorage(merged);
            return merged;
          });
        }
      },
      (err) => {
        if (err.message.includes('Quota exceeded')) {
          setAuthStatusMessage(
            'Firestore daily free-tier quota exceeded. Local scan history remains active and cloud quota resets tomorrow.'
          );
        }
      }
    );

    return () => unsubscribeScans();
  }, [isAuthReady, currentUser]);

  // Initial fallback load from Java backend when unauthenticated and local storage is empty
  useEffect(() => {
    const localItems = loadScanHistoryFromStorage();
    if (localItems.length === 0) {
      fetchScanHistoryFromJavaBackend().then((javaItems) => {
        if (javaItems.length > 0) {
          setScanHistory(javaItems.slice(0, 5));
          saveScanHistoryToStorage(javaItems.slice(0, 5));
        }
      });
    }
  }, []);

  const handleGoogleSignIn = async () => {
    setAuthStatusMessage(null);
    try {
      await signInWithGooglePopup();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes('auth/popup-closed-by-user')) {
        setAuthStatusMessage(
          'Google Sign-In could not be completed in this window. Please ensure popups are allowed and try again.'
        );
      }
    }
  };

  const handleSignOut = async () => {
    setAuthStatusMessage(null);
    try {
      await signOutUser();
    } catch {
      setAuthStatusMessage('Unable to sign out right now. Please try again.');
    }
  };

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

  const handleSelectHistoryItem = async (item: URLAnalysisResult) => {
    setValidationError(null);
    setUrlInput(item.domain.redactedUrl);
    setCurrentResult(item);
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // If item was hydrated from Firestore summary, refresh full deterministic indicator breakdown from Java backend
    if (item.indicators.some((ind) => ind.id.startsWith('cloud-ind-'))) {
      try {
        const apiData = await analyzeUrlViaJavaBackend(item.domain.redactedUrl);
        if (apiData.valid && apiData.result) {
          setCurrentResult(apiData.result);
        }
      } catch {
        // Keep hydrated result on screen
      }
    }
  };

  const handleClearHistory = () => {
    clearScanHistoryFromStorage();
    clearScanHistoryOnJavaBackend();
    setScanHistory([]);
    if (currentUser) {
      deleteAllUserScansFromFirestore(currentUser).catch(() => {
        // Handled via handleFirestoreError
      });
    }
  };

  const executeScan = async (overrideUrl?: string) => {
    const rawTarget = overrideUrl !== undefined ? overrideUrl : urlInput;
    setValidationError(null);
    setIsScanning(true);

    try {
      const apiData = await analyzeUrlViaJavaBackend(rawTarget);

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
        if (currentUser) {
          saveScanToFirestore(currentUser, result).catch(() => {
            // Handled via handleFirestoreError
          });
        }
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
    <div
      data-preferred-theme="light"
      className="min-h-screen flex flex-col text-[#231710]"
    >
      <Navbar
        onNewScan={handleResetToScanner}
        hasResult={Boolean(currentResult)}
        isChatOpen={isChatOpen}
        onToggleChat={() => setIsChatOpen((prev) => !prev)}
        currentUser={currentUser}
        isAuthReady={isAuthReady}
        onGoogleSignIn={handleGoogleSignIn}
        onSignOut={handleSignOut}
      />

      <main className="flex-1">
        {/* Strictly Two Views: URL Pasting Page & Risk Showing Page */}
        {!currentResult ? (
          /* 1. URL Pasting Page (with Local Storage + Firestore Last-5 Scan History below input) */
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
            isAuthenticated={Boolean(currentUser)}
            onGoogleSignIn={handleGoogleSignIn}
            authStatusMessage={authStatusMessage}
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

      <footer className="border-t border-[#EEDBC8] bg-[#FFFDF9] py-7 mt-12">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#7A5C49]">
          <div className="flex items-center gap-2.5">
            <Shield className="h-4 w-4 text-[#C85A32] shrink-0" aria-hidden="true" />
            <span className="font-display font-bold text-sm text-[#231710]">
              CyberShield AI
            </span>
            <span aria-hidden="true">·</span>
            <span>URL Threat Detection (Java 17 Backend · Firebase Cloud Sync)</span>
          </div>
          <p className="max-w-xl text-center sm:text-right text-[#7A5C49] leading-relaxed">
            {MANDATORY_DISCLAIMER}
          </p>
        </div>
      </footer>
    </div>
  );
}

