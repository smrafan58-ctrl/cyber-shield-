import { URLAnalysisResult } from '../types/scanner';

export const SCAN_HISTORY_STORAGE_KEY = 'cybershield_scan_history_v1';
export const MAX_SCAN_HISTORY_ITEMS = 5;

/**
 * Pure helper that inserts or updates a scan result at the top of the history list,
 * deduplicating by normalized URL and capping the list at MAX_SCAN_HISTORY_ITEMS (5).
 */
export function upsertScanHistoryList(
  existing: URLAnalysisResult[],
  incoming: URLAnalysisResult,
  maxItems: number = MAX_SCAN_HISTORY_ITEMS
): URLAnalysisResult[] {
  const incomingKey =
    incoming.domain?.normalizedUrl ||
    incoming.domain?.redactedUrl ||
    incoming.id;

  const filtered = existing.filter((item) => {
    const itemKey =
      item.domain?.normalizedUrl || item.domain?.redactedUrl || item.id;
    return itemKey !== incomingKey;
  });

  return [incoming, ...filtered].slice(0, Math.max(1, maxItems));
}

/**
 * Loads the last 5 analyzed URLs from browser localStorage safely.
 */
export function loadScanHistoryFromStorage(): URLAnalysisResult[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(SCAN_HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    return parsed
      .filter(
        (item): item is URLAnalysisResult =>
          Boolean(
            item &&
              typeof item === 'object' &&
              typeof item.riskScore === 'number' &&
              typeof item.classification === 'string' &&
              item.domain &&
              typeof item.domain.hostname === 'string' &&
              typeof item.domain.redactedUrl === 'string'
          )
      )
      .slice(0, MAX_SCAN_HISTORY_ITEMS);
  } catch {
    return [];
  }
}

/**
 * Persists up to the last 5 analyzed URLs to browser localStorage.
 */
export function saveScanHistoryToStorage(items: URLAnalysisResult[]): void {
  if (typeof window === 'undefined' || !window.localStorage) {
    return;
  }

  try {
    const capped = items.slice(0, MAX_SCAN_HISTORY_ITEMS);
    window.localStorage.setItem(
      SCAN_HISTORY_STORAGE_KEY,
      JSON.stringify(capped)
    );
  } catch {
    // Ignore storage quota or private browsing errors
  }
}

/**
 * Clears the stored scan history from browser localStorage.
 */
export function clearScanHistoryFromStorage(): void {
  if (typeof window === 'undefined' || !window.localStorage) {
    return;
  }

  try {
    window.localStorage.removeItem(SCAN_HISTORY_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}
