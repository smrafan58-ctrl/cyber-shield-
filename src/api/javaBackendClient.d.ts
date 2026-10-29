import { URLAnalysisResult } from '../types/scanner';

export function analyzeUrlViaJavaBackend(url: string): Promise<{
  valid: boolean;
  errorTitle?: string;
  error?: string;
  result?: URLAnalysisResult;
}>;

export function fetchScanHistoryFromJavaBackend(): Promise<URLAnalysisResult[]>;

export function clearScanHistoryOnJavaBackend(): Promise<void>;

export function sendChatToJavaBackend(payload: {
  model: string;
  rolePreset: string;
  scanContext: string;
  messages: Array<{ role: 'user' | 'model'; text: string }>;
}): Promise<{
  ok: boolean;
  data: {
    reply?: string;
    model?: string;
    error?: string;
  };
}>;

export function transcribeAudioViaJavaBackend(payload: {
  audioData: string;
  mimeType: string;
  mode: 'url' | 'chat';
}): Promise<{
  ok: boolean;
  data: {
    transcript?: string;
    model?: string;
    error?: string;
  };
}>;
