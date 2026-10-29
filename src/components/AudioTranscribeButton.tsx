import React, { useEffect, useRef, useState } from 'react';
import { Mic, Square, Loader2 } from 'lucide-react';
import { transcribeAudioViaJavaBackend } from '../api/javaBackendClient';

interface AudioTranscribeButtonProps {
  mode: 'url' | 'chat';
  onTranscribed: (transcript: string) => void;
  onStatusMessage?: (message: string | null) => void;
  disabled?: boolean;
  compact?: boolean;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export const AudioTranscribeButton: React.FC<AudioTranscribeButtonProps> = ({
  mode,
  onTranscribed,
  onStatusMessage,
  disabled = false,
  compact = false,
}) => {
  const [isRecording, setIsRecording] = useState(false);
  const [isTranscribing, setIsTranscribing] = useState(false);

  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<Blob[]>([]);

  useEffect(() => {
    return () => {
      if (streamRef.current) {
        streamRef.current.getTracks().forEach((t) => t.stop());
      }
    };
  }, []);

  const stopStreamTracks = () => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
  };

  const sendAudioForTranscription = async (base64Audio: string, mimeType: string) => {
    setIsTranscribing(true);
    onStatusMessage?.('Transcribing audio with gemini-3.5-transcribe...');

    try {
      const { ok, data } = await transcribeAudioViaJavaBackend({
        audioData: base64Audio,
        mimeType,
        mode,
      });

      if (!ok || !data.transcript) {
        onStatusMessage?.(
          data.error || 'Could not transcribe audio. Please try speaking again.'
        );
        return;
      }

      onStatusMessage?.(null);
      onTranscribed(data.transcript.trim());
    } catch {
      onStatusMessage?.(
        'Network error while communicating with the Gemini audio transcription service.'
      );
    } finally {
      setIsTranscribing(false);
    }
  };

  const handleToggleRecording = async () => {
    if (isTranscribing || disabled) return;

    if (isRecording) {
      if (
        mediaRecorderRef.current &&
        mediaRecorderRef.current.state !== 'inactive'
      ) {
        mediaRecorderRef.current.stop();
      }
      setIsRecording(false);
      return;
    }

    onStatusMessage?.(null);

    if (
      typeof navigator === 'undefined' ||
      !navigator.mediaDevices ||
      !navigator.mediaDevices.getUserMedia
    ) {
      onStatusMessage?.(
        'Microphone recording is not supported in this browser environment.'
      );
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;
      chunksRef.current = [];

      const preferredMime =
        typeof MediaRecorder !== 'undefined' &&
        MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
          ? 'audio/webm;codecs=opus'
          : typeof MediaRecorder !== 'undefined' &&
            MediaRecorder.isTypeSupported('audio/webm')
          ? 'audio/webm'
          : 'audio/mp4';

      const recorder = new MediaRecorder(stream);
      mediaRecorderRef.current = recorder;

      recorder.ondataavailable = (event: BlobEvent) => {
        if (event.data && event.data.size > 0) {
          chunksRef.current.push(event.data);
        }
      };

      recorder.onstop = async () => {
        stopStreamTracks();
        const blobMime = recorder.mimeType || preferredMime || 'audio/webm';
        const audioBlob = new Blob(chunksRef.current, { type: blobMime });
        chunksRef.current = [];

        if (audioBlob.size === 0) {
          onStatusMessage?.('No audio was captured. Please try again.');
          return;
        }

        const buffer = await audioBlob.arrayBuffer();
        const base64Audio = arrayBufferToBase64(buffer);
        await sendAudioForTranscription(
          base64Audio,
          blobMime.split(';')[0] || 'audio/webm'
        );
      };

      recorder.start();
      setIsRecording(true);
      onStatusMessage?.(
        mode === 'url'
          ? 'Listening... Speak a domain or URL, then click Stop to transcribe with gemini-3.5-transcribe.'
          : 'Listening... Speak your security question, then click Stop to transcribe.'
      );
    } catch {
      stopStreamTracks();
      setIsRecording(false);
      onStatusMessage?.(
        'Microphone access was blocked or no audio input device was found. Please allow microphone permissions in your browser.'
      );
    }
  };

  if (compact) {
    return (
      <button
        type="button"
        data-testid={`audio-transcribe-btn-${mode}`}
        onClick={handleToggleRecording}
        disabled={disabled || isTranscribing}
        aria-label={
          isRecording
            ? 'Stop microphone recording and transcribe'
            : 'Record voice input with Gemini 3.5 Transcribe'
        }
        title={
          isRecording
            ? 'Stop recording & transcribe audio (gemini-3.5-transcribe)'
            : 'Transcribe voice with microphone (gemini-3.5-transcribe)'
        }
        className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors shrink-0 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
          isRecording
            ? 'border-rose-400 bg-rose-50 text-rose-700 hover:bg-rose-100'
            : 'border-[#EEDBC8] bg-[#FDF5EB] text-[#231710] hover:border-[#C85A32] hover:bg-[#FDECD8]'
        }`}
      >
        {isTranscribing ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin text-[#C85A32]" aria-hidden="true" />
        ) : isRecording ? (
          <Square className="h-3.5 w-3.5 text-rose-600 fill-rose-600" aria-hidden="true" />
        ) : (
          <Mic className="h-3.5 w-3.5 text-[#C85A32]" aria-hidden="true" />
        )}
        <span className="sr-only sm:not-sr-only">
          {isTranscribing ? 'Transcribing' : isRecording ? 'Stop' : 'Voice'}
        </span>
      </button>
    );
  }

  return (
    <button
      type="button"
      data-testid={`audio-transcribe-btn-${mode}`}
      onClick={handleToggleRecording}
      disabled={disabled || isTranscribing}
      aria-label={
        isRecording
          ? 'Stop recording and transcribe voice URL'
          : 'Transcribe voice input using Gemini 3.5 Transcribe'
      }
      title={
        isRecording
          ? 'Stop recording & transcribe audio (gemini-3.5-transcribe)'
          : 'Voice URL dictation powered by gemini-3.5-transcribe'
      }
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-3.5 py-3.5 text-xs sm:text-sm font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ${
        isRecording
          ? 'border-rose-400 bg-rose-50 text-rose-700 hover:bg-rose-100'
          : 'border-[#EEDBC8] bg-[#FDF5EB] text-[#231710] hover:border-[#C85A32] hover:bg-[#FDECD8]'
      }`}
    >
      {isTranscribing ? (
        <Loader2 className="h-4 w-4 shrink-0 animate-spin text-[#C85A32]" aria-hidden="true" />
      ) : isRecording ? (
        <Square className="h-4 w-4 shrink-0 text-rose-600 fill-rose-600" aria-hidden="true" />
      ) : (
        <Mic className="h-4 w-4 shrink-0 text-[#C85A32]" aria-hidden="true" />
      )}
      <span>
        {isTranscribing
          ? 'Transcribing...'
          : isRecording
          ? 'Stop Audio'
          : 'Voice'}
      </span>
    </button>
  );
};


