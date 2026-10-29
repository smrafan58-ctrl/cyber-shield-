import { GoogleGenAI, GenerateContentResponse } from '@google/genai';

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

export type SupportedGeminiModel =
  | 'gemini-4-argon'
  | 'gemini-3.8-flash'
  | 'gemini-3.1-flash-lite';

export interface MultiTurnMessage {
  role: 'user' | 'model';
  text: string;
}

export async function runCyberShieldMultiTurnChat(params: {
  model: SupportedGeminiModel;
  systemInstruction: string;
  history: MultiTurnMessage[];
  message: string;
}): Promise<string> {
  const formattedHistory = params.history.map((turn) => ({
    role: turn.role,
    parts: [{ text: turn.text }],
  }));

  const chat = ai.chats.create({
    model: params.model,
    history: formattedHistory,
    config: {
      systemInstruction: params.systemInstruction,
    },
  });

  const response: GenerateContentResponse = await chat.sendMessage({
    message: params.message,
  });

  return response.text || '';
}

export const GEMINI_TRANSCRIBE_MODEL = 'gemini-3.5-transcribe' as const;

export async function transcribeAudioWithGemini(params: {
  base64Audio: string;
  mimeType: string;
  prompt?: string;
}): Promise<string> {
  const audioPart = {
    inlineData: {
      mimeType: params.mimeType || 'audio/webm',
      data: params.base64Audio,
    },
  };

  const textPart = {
    text: params.prompt || 'Transcribe this audio.',
  };

  const response: GenerateContentResponse = await ai.models.generateContent({
    model: GEMINI_TRANSCRIBE_MODEL,
    contents: { parts: [audioPart, textPart] },
  });

  return response.text || '';
}

