/**
 * Pure JavaScript Fetch Client for the CyberShield AI Java 17 Backend.
 * Communicates with CyberShieldServer.java endpoints (/api/analyze, /api/history, /api/chat, /api/transcribe).
 */

export async function analyzeUrlViaJavaBackend(url) {
  const response = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  return response.json();
}

export async function fetchScanHistoryFromJavaBackend() {
  try {
    const response = await fetch('/api/history', {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return [];
    const data = await response.json();
    return Array.isArray(data.history) ? data.history : [];
  } catch {
    return [];
  }
}

export async function clearScanHistoryOnJavaBackend() {
  try {
    await fetch('/api/history', { method: 'DELETE' });
  } catch {
    // Ignore network errors when clearing history
  }
}

export async function sendChatToJavaBackend(payload) {
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  return { ok: response.ok, data };
}

export async function transcribeAudioViaJavaBackend(payload) {
  const response = await fetch('/api/transcribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  return { ok: response.ok, data };
}
