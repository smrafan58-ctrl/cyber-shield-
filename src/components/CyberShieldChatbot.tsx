import React, { useEffect, useRef, useState } from 'react';
import {
  MessageSquare,
  Send,
  X,
  RotateCcw,
  Shield,
  Bot,
  User,
  Zap,
  Cpu,
  AlertCircle,
} from 'lucide-react';
import { URLAnalysisResult } from '../types/scanner';

import { AudioTranscribeButton } from './AudioTranscribeButton';
import { sendChatToJavaBackend } from '../api/javaBackendClient';

export type GeminiModelOption =
  | 'gemini-3.8-flash'
  | 'gemini-3.1-flash-lite'
  | 'gemini-4-argon';

export type ChatbotRolePreset =
  | 'threat-analyst'
  | 'scam-educator'
  | 'incident-advisor';

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  text: string;
  timestamp: string;
  modelUsed?: string;
}

interface CyberShieldChatbotProps {
  isOpen: boolean;
  onToggleOpen: () => void;
  activeScanResult: URLAnalysisResult | null;
}

const ROLE_PRESETS: Array<{
  id: ChatbotRolePreset;
  label: string;
  shortDesc: string;
  welcomeText: string;
}> = [
  {
    id: 'threat-analyst',
    label: 'URL Threat Analyst',
    shortDesc: 'Explains domain structure, subdomains, typosquatting & heuristic indicators.',
    welcomeText:
      'Hello! I am the CyberShield AI URL Threat Analyst. Ask me about any scanned URL, suspicious subdomain, lookalike domain, or security indicator.',
  },
  {
    id: 'scam-educator',
    label: 'Scam & Phishing Educator',
    shortDesc: 'Explains fake banking portals, digital arrest scams & social engineering.',
    welcomeText:
      'Hello! I am the CyberShield AI Scam & Phishing Educator. Ask me how to spot phishing links, fake payment portals, or government impersonation scams.',
  },
  {
    id: 'incident-advisor',
    label: 'Incident Safety Advisor',
    shortDesc: 'Step-by-step protective actions if you clicked a suspicious link.',
    welcomeText:
      'Hello! I am the CyberShield AI Incident Safety Advisor. Tell me if you clicked a suspicious link or entered credentials, and I will walk you through immediate safety steps.',
  },
];

const MODEL_OPTIONS: Array<{
  id: GeminiModelOption;
  label: string;
  taskTier: string;
}> = [
  {
    id: 'gemini-3.8-flash',
    label: 'Gemini 3.8 Flash',
    taskTier: 'General Tasks (Balanced)',
  },
  {
    id: 'gemini-3.1-flash-lite',
    label: 'Gemini 3.1 Flash Lite',
    taskTier: 'Fast Tasks (Low Latency)',
  },
  {
    id: 'gemini-4-argon',
    label: 'Gemini 4 Argon',
    taskTier: 'Complex Tasks (Deep Analysis)',
  },
];

function formatActiveScanContext(result: URLAnalysisResult | null): string {
  if (!result) return '';
  const indicatorNames =
    result.indicators.length > 0
      ? result.indicators
          .map((i) => `${i.name} (${i.severity}, +${i.weight} pts): ${i.explanation}`)
          .join('; ')
      : 'None triggered';
  return [
    `Sanitized URL: ${result.domain.redactedUrl}`,
    `Hostname: ${result.domain.hostname}`,
    `Registrable Domain: ${result.domain.registrableDomain}`,
    `Subdomain: ${result.domain.subdomain}`,
    `Protocol: ${result.domain.protocol}`,
    `Risk Score: ${result.riskScore}/100 (${result.classification})`,
    `Triggered Indicators: ${indicatorNames}`,
  ].join('\n');
}

export const CyberShieldChatbot: React.FC<CyberShieldChatbotProps> = ({
  isOpen,
  onToggleOpen,
  activeScanResult,
}) => {
  const [rolePreset, setRolePreset] = useState<ChatbotRolePreset>('threat-analyst');
  const [selectedModel, setSelectedModel] =
    useState<GeminiModelOption>('gemini-3.8-flash');
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome-initial',
      role: 'model',
      text: ROLE_PRESETS[0].welcomeText,
      timestamp: new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      }),
    },
  ]);
  const [inputValue, setInputValue] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const threadEndRef = useRef<HTMLDivElement | null>(null);
  const inputFieldRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (isOpen) {
      threadEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      setTimeout(() => {
        inputFieldRef.current?.focus();
      }, 80);
    }
  }, [isOpen, messages.length, isLoading]);

  const handleRoleChange = (newRole: ChatbotRolePreset) => {
    setRolePreset(newRole);
    setErrorMessage(null);
    const presetInfo =
      ROLE_PRESETS.find((r) => r.id === newRole) || ROLE_PRESETS[0];
    setMessages((prev) => [
      ...prev,
      {
        id: `role-switch-${Date.now()}`,
        role: 'model',
        text: presetInfo.welcomeText,
        timestamp: new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        }),
      },
    ]);
  };

  const handleResetChat = () => {
    const presetInfo =
      ROLE_PRESETS.find((r) => r.id === rolePreset) || ROLE_PRESETS[0];
    setErrorMessage(null);
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: 'model',
        text: presetInfo.welcomeText,
        timestamp: new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        }),
      },
    ]);
  };

  const sendMessage = async (textOverride?: string) => {
    const trimmed = (
      textOverride !== undefined ? textOverride : inputValue
    ).trim();
    if (!trimmed || isLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      text: trimmed,
      timestamp: new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      }),
    };

    const updatedHistory = [...messages, userMsg];
    setMessages(updatedHistory);
    if (textOverride === undefined) {
      setInputValue('');
    }
    setErrorMessage(null);
    setIsLoading(true);

    try {
      const apiMessages = updatedHistory.map((m) => ({
        role: m.role,
        text: m.text,
      }));

      const { ok, data } = await sendChatToJavaBackend({
        model: selectedModel,
        rolePreset,
        scanContext: formatActiveScanContext(activeScanResult),
        messages: apiMessages,
      });

      if (!ok || !data.reply) {
        setErrorMessage(
          data.error ||
            'Unable to reach the Gemini cybersecurity assistant right now. Please try again.'
        );
      } else {
        const modelReply: ChatMessage = {
          id: `model-${Date.now()}`,
          role: 'model',
          text: data.reply,
          modelUsed: data.model || selectedModel,
          timestamp: new Date().toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
          }),
        };
        setMessages((prev) => [...prev, modelReply]);
      }
    } catch {
      setErrorMessage(
        'Network error while communicating with the Java Gemini chat service.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const currentRoleObj =
    ROLE_PRESETS.find((r) => r.id === rolePreset) || ROLE_PRESETS[0];

  const quickPrompts = activeScanResult
    ? [
        `Explain why ${activeScanResult.domain.hostname} scored ${activeScanResult.riskScore}/100`,
        'Is the registrable domain trustworthy?',
        'What safety steps should I follow for this link?',
      ]
    : [
        'How do attackers use subdomains to spoof brands?',
        'What is a digital arrest scam link?',
        'I clicked a suspicious link—what should I do first?',
      ];

  return (
    <>
      {/* Floating Chat Launcher Button */}
      {!isOpen && (
        <div className="fixed bottom-5 right-5 z-50">
          <button
            type="button"
            data-testid="chatbot-toggle-button"
            onClick={onToggleOpen}
            aria-label="Open CyberShield Gemini Security Chatbot"
            className="inline-flex items-center gap-3 rounded-xl border border-[#E6C9AE] bg-[#FFFDF9] px-4 py-3 text-xs sm:text-sm font-semibold text-[#231710] shadow-editorial-lg hover:border-[#C85A32] hover:bg-[#FDF5EB] transition-all cursor-pointer"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-warm-cta text-white">
              <MessageSquare className="h-4 w-4" aria-hidden="true" />
            </span>
            <div className="text-left">
              <div className="font-display font-bold text-sm text-[#231710]">
                AI Security Advisor
              </div>
              <div className="text-[11px] font-normal text-[#7A5C49]">
                Multi-turn Gemini Assistant
              </div>
            </div>
          </button>
        </div>
      )}

      {/* Slide-Up / Docked Multi-Turn Chat Window */}
      {isOpen && (
        <aside
          data-testid="chatbot-drawer"
          aria-label="CyberShield AI Multi-Turn Gemini Chatbot"
          className="fixed bottom-4 right-4 z-50 w-[calc(100vw-2rem)] sm:w-[440px] max-h-[calc(100vh-5rem)] flex flex-col rounded-2xl border border-[#E6C9AE] bg-[#FFFDF9] shadow-editorial-lg overflow-hidden"
        >
          {/* Chat Header */}
          <div className="flex items-center justify-between gap-3 border-b border-[#E6C9AE] bg-[#FDECD8] px-4 py-3.5">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[#FFFDF9] border border-[#E6C9AE] text-[#C85A32]">
                <Shield className="h-4 w-4" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <h2 className="font-display text-sm font-bold text-[#231710] truncate">
                  CyberShield Security Advisor
                </h2>
                <p className="text-[11px] text-[#7A5C49] truncate">
                  {currentRoleObj.label}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                onClick={handleResetChat}
                title="Reset conversation thread"
                className="inline-flex items-center gap-1 rounded-lg border border-[#E6C9AE] bg-[#FFFDF9] px-2.5 py-1.5 text-xs font-medium text-[#4A3528] hover:bg-[#FDF5EB] hover:text-[#231710] transition-colors cursor-pointer"
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Reset</span>
              </button>
              <button
                type="button"
                onClick={onToggleOpen}
                aria-label="Close Gemini Chatbot"
                className="inline-flex items-center justify-center rounded-lg border border-[#E6C9AE] bg-[#FFFDF9] p-1.5 text-[#4A3528] hover:bg-[#FDF5EB] hover:text-[#231710] transition-colors cursor-pointer"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          </div>

          {/* Role (System Instruction) & Model Controls */}
          <div className="border-b border-[#EEDBC8] bg-[#FDF5EB] px-4 py-2.5 space-y-2">
            {/* System Role Selector */}
            <div className="flex items-center justify-between gap-2">
              <label
                htmlFor="chatbot-role-select"
                className="text-[11px] font-medium text-[#7A5C49] shrink-0"
              >
                Analyst Role:
              </label>
              <select
                id="chatbot-role-select"
                data-testid="chatbot-role-select"
                value={rolePreset}
                onChange={(e) =>
                  handleRoleChange(e.target.value as ChatbotRolePreset)
                }
                className="min-w-0 flex-1 rounded-md border border-[#E6C9AE] bg-[#FFFDF9] px-2.5 py-1 text-xs text-[#231710] focus:border-[#C85A32] focus:outline-none truncate"
              >
                {ROLE_PRESETS.map((preset) => (
                  <option key={preset.id} value={preset.id}>
                    {preset.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Gemini Model Tier Selector */}
            <div className="flex items-center justify-between gap-2">
              <label
                htmlFor="chatbot-model-select"
                className="text-[11px] font-medium text-[#7A5C49] shrink-0 flex items-center gap-1"
              >
                <Cpu className="h-3 w-3 text-[#C85A32]" aria-hidden="true" />
                <span>Gemini Model:</span>
              </label>
              <select
                id="chatbot-model-select"
                data-testid="chatbot-model-select"
                value={selectedModel}
                onChange={(e) =>
                  setSelectedModel(e.target.value as GeminiModelOption)
                }
                className="min-w-0 flex-1 rounded-md border border-[#E6C9AE] bg-[#FFFDF9] px-2.5 py-1 text-xs font-mono text-[#231710] focus:border-[#C85A32] focus:outline-none truncate"
              >
                {MODEL_OPTIONS.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label} ({m.taskTier})
                  </option>
                ))}
              </select>
            </div>

            {/* Active Scan Context Indicator */}
            {activeScanResult && (
              <div className="flex items-center justify-between gap-2 pt-1 border-t border-[#EEDBC8] text-[11px] text-[#A94622] font-mono truncate">
                <span className="truncate">
                  Context: {activeScanResult.domain.hostname} (
                  {activeScanResult.riskScore}/100)
                </span>
                <Zap className="h-3 w-3 shrink-0 text-[#C85A32]" aria-hidden="true" />
              </div>
            )}
          </div>

          {/* Scrollable Conversation Thread */}
          <div
            data-testid="gemini-chat-thread"
            className="flex-1 overflow-y-auto px-4 py-3 space-y-3 min-h-[260px] max-h-[340px] bg-[#FFFDF9]"
          >
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex items-start gap-2.5 ${
                  msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'
                }`}
              >
                <div
                  className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md border text-xs ${
                    msg.role === 'user'
                      ? 'border-[#C85A32]/40 bg-[#FDECD8] text-[#C85A32]'
                      : 'border-[#EEDBC8] bg-[#FDF5EB] text-[#231710]'
                  }`}
                >
                  {msg.role === 'user' ? (
                    <User className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <Bot className="h-3.5 w-3.5 text-[#C85A32]" aria-hidden="true" />
                  )}
                </div>

                <div
                  className={`max-w-[82%] rounded-xl px-3.5 py-2.5 text-xs leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-warm-cta text-white font-medium'
                      : 'border border-[#EEDBC8] bg-[#FDF5EB] text-[#231710]'
                  }`}
                >
                  <div className="whitespace-pre-wrap break-words">
                    {msg.text}
                  </div>
                  <div
                    className={`mt-1 flex items-center gap-1.5 text-[10px] ${
                      msg.role === 'user'
                        ? 'text-white/85 justify-end'
                        : 'text-[#7A5C49]'
                    }`}
                  >
                    <span>{msg.timestamp}</span>
                    {msg.modelUsed && (
                      <>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono">{msg.modelUsed}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {isLoading && (
              <div className="flex items-start gap-2.5">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-[#EEDBC8] bg-[#FDF5EB] text-[#C85A32]">
                  <Bot className="h-3.5 w-3.5" aria-hidden="true" />
                </div>
                <div className="rounded-xl border border-[#EEDBC8] bg-[#FDF5EB] px-3.5 py-2 text-xs text-[#7A5C49]">
                  Analyzing with {selectedModel}...
                </div>
              </div>
            )}

            {errorMessage && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-lg border border-amber-300 bg-amber-50 p-2.5 text-xs text-amber-900"
              >
                <AlertCircle className="h-4 w-4 text-amber-700 shrink-0 mt-0.5" />
                <span>{errorMessage}</span>
              </div>
            )}

            <div ref={threadEndRef} />
          </div>

          {/* Starter Prompts */}
          <div className="border-t border-[#EEDBC8] bg-[#FDF5EB] px-3 py-2">
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
              {quickPrompts.map((prompt) => (
                <button
                  key={prompt}
                  type="button"
                  disabled={isLoading}
                  onClick={() => sendMessage(prompt)}
                  className="shrink-0 rounded-md border border-[#EEDBC8] bg-[#FFFDF9] px-2.5 py-1 text-[11px] text-[#4A3528] hover:border-[#C85A32] hover:bg-[#FDECD8] hover:text-[#231710] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>

          {/* Message Input Form */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              sendMessage();
            }}
            className="border-t border-[#EEDBC8] bg-[#FFFDF9] p-3 flex items-center gap-2"
          >
            <input
              ref={inputFieldRef}
              data-testid="chatbot-input"
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Ask or use Voice (gemini-3.5-transcribe)..."
              aria-label="Chat message input"
              className="min-w-0 flex-1 rounded-lg border border-[#E6C9AE] bg-[#FDF5EB] px-3 py-2 text-xs text-[#231710] placeholder:text-[#9C7D68] focus:border-[#C85A32] focus:bg-[#FFFDF9] focus:outline-none"
            />
            <AudioTranscribeButton
              mode="chat"
              compact
              disabled={isLoading}
              onStatusMessage={(msg) => setErrorMessage(msg)}
              onTranscribed={(transcript) => {
                setErrorMessage(null);
                setInputValue((prev) =>
                  prev.trim() ? `${prev.trim()} ${transcript}` : transcript
                );
                inputFieldRef.current?.focus();
              }}
            />
            <button
              type="submit"
              data-testid="chatbot-send-button"
              disabled={isLoading || !inputValue.trim()}
              aria-label="Send chat message"
              className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-warm-cta px-3.5 py-2 text-xs font-semibold text-white disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer shrink-0"
            >
              <Send className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Send</span>
            </button>
          </form>
        </aside>
      )}
    </>
  );
};

