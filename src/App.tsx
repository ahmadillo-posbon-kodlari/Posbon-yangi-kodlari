import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Upload,
  FileText,
  Image as ImageIcon,
  Video,
  Globe,
  Search,
  Loader2,
  Sparkles,
  FileCode,
  HelpCircle,
  PackageSearch,
  BadgeCheck,
  Sun,
  Moon,
  Bot,
  History,
  Send,
  Paperclip,
  X,
  ExternalLink,
  FileWarning,
  Link2Off,
  FileCheck2,
  ArrowLeft,
  Mic,
  MicOff,
  Volume2,
  VolumeX,
  PhoneCall,
  PhoneOff,
  Trash2,
  Lock,
  Users,
  Database,
  RefreshCw,
  Calendar,
} from "lucide-react";
import { AlertExplainer, ExplainerTarget } from "./components/AlertExplainer.tsx";
import { TelegramConnect, TelegramThreatEventClient } from "./components/TelegramConnect.tsx";
import { useAmbientSound } from "./hooks/use-ambient.ts";

type ActiveTab = "scanner" | "telegram" | "ai" | "history" | "guide";
type ScannerCategory = "file" | "image" | "video" | "document" | "url";
type GuideSection = "scanner" | "telegram" | "ai" | "history" | "test";

interface ScanResultItem {
  id: string;
  targetName: string;
  targetType: ScannerCategory | "audio" | string;
  mimeType?: string;
  detectedFormat?: string;
  extensionMatchesBinary?: boolean;
  fileSize?: number;
  sha256?: string;
  verdict: "safe" | "suspicious" | "malicious";
  isCompletelySafe?: boolean;
  safetyPercentage?: number;
  riskScore: number;
  trustScore?: number;
  threatCategory: string;
  whatIsInside?: string;
  authenticityVerdict?: string;
  politeSummary: string;
  technicalDetails: string[];
  recommendations: string[];
  indicators?: {
    label: string;
    status: "pass" | "warn" | "fail";
    detail: string;
  }[];
  analyzedAt: string;
  source?: "web" | "telegram";
  senderName?: string;
}

interface AIChatMessage {
  id: string;
  role: "user" | "ai";
  text: string;
  attachmentName?: string;
  analysis?: ScanResultItem;
  timestamp: string;
}

interface AdminLinkedUserRecord {
  chatId: string;
  userId: number;
  username?: string;
  firstName: string;
  lastName?: string;
  linkedAt: string;
  linkedAtFormatted: string;
  lastActiveFormatted?: string;
  isActive: boolean;
  stats: {
    totalScanned: number;
    threatsDeleted: number;
    safePassed: number;
  };
}

interface AdminDeletedFileRecord {
  id: string;
  chatId: string;
  targetName: string;
  targetType: string;
  senderName: string;
  senderUsername?: string;
  riskScore: number;
  safetyPercentage: number;
  threatCategory: string;
  whatIsInside: string;
  timestamp: string;
  timestampFormatted: string;
}

export default function App() {
  const [isDark, setIsDark] = useState<boolean>(() => {
    const saved = localStorage.getItem("posbon_theme");
    return saved ? saved === "dark" : true;
  });

  // 5 Main Sections: SKAYNER | TELEGRAM | AI | TARIX | QO'LLANMA
  const [activeTab, setActiveTab] = useState<ActiveTab>("scanner");

  // Scanner state — Result is hidden until user scans
  const [scanCategory, setScanCategory] = useState<ScannerCategory>("file");
  const [urlInput, setUrlInput] = useState<string>("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePreviewUrl, setFilePreviewUrl] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<ScanResultItem | null>(null);

  // History state — Detail is hidden until user clicks an item
  const [webHistory, setWebHistory] = useState<ScanResultItem[]>([]);
  const [telegramEvents, setTelegramEvents] = useState<TelegramThreatEventClient[]>([]);
  const [historyFilter, setHistoryFilter] = useState<"all" | "malicious" | "safe">("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedHistoryItem, setSelectedHistoryItem] = useState<ScanResultItem | null>(null);

  // Telegram status state
  const [telegramLinked, setTelegramLinked] = useState<boolean>(false);
  const [telegramChatId, setTelegramChatId] = useState<string | undefined>(undefined);

  // Guide state (Divided into clear parts)
  const [guideSection, setGuideSection] = useState<GuideSection>("telegram");
  const [testLoading, setTestLoading] = useState<string | null>(null);
  const [testNotice, setTestNotice] = useState<string | null>(null);

  // AI Chat & Online Voice state
  const [aiMessages, setAiMessages] = useState<AIChatMessage[]>([
    {
      id: "welcome-ai",
      role: "ai",
      text: "Assalomu alaykum! Men POSBON AI yordamchisiman. Menga savol yozishingiz, mikrofonni bosib ovoz orqali gaplashishingiz yoki fayl, rasm va havola yuborib tekshirtirishingiz mumkin.",
      timestamp: new Date().toISOString(),
    },
  ]);
  const [aiInput, setAiInput] = useState<string>("");
  const [aiFile, setAiFile] = useState<File | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [isRecordingVoice, setIsRecordingVoice] = useState<boolean>(false);
  const [voiceStatusText, setVoiceStatusText] = useState<string | null>(null);
  const [speechLang, setSpeechLang] = useState<"uz-UZ" | "ru-RU" | "en-US">("uz-UZ");
  const [onlineVoiceMode, setOnlineVoiceMode] = useState<boolean>(false);
  const [autoSpeakAi, setAutoSpeakAi] = useState<boolean>(false);
  const [isAiSpeaking, setIsAiSpeaking] = useState<boolean>(false);
  const [speakingMsgId, setSpeakingMsgId] = useState<string | null>(null);

  // Modal explainer
  const [explainerTarget, setExplainerTarget] = useState<ExplainerTarget | null>(null);

  // Secret Admin Panel (Opens on 3 rapid clicks on "POSBON AI" logo, Password: 0513)
  const [showAdminModal, setShowAdminModal] = useState<boolean>(false);
  const [adminUnlocked, setAdminUnlocked] = useState<boolean>(false);
  const [adminPassword, setAdminPassword] = useState<string>("");
  const [adminError, setAdminError] = useState<string | null>(null);
  const [adminLoading, setAdminLoading] = useState<boolean>(false);
  const [adminTab, setAdminTab] = useState<"users" | "deleted">("users");
  const [adminUsers, setAdminUsers] = useState<AdminLinkedUserRecord[]>([]);
  const [adminDeletedFiles, setAdminDeletedFiles] = useState<AdminDeletedFileRecord[]>([]);
  const [adminStats, setAdminStats] = useState<{
    totalUsers: number;
    totalDeleted: number;
    totalScanned: number;
  }>({ totalUsers: 0, totalDeleted: 0, totalScanned: 0 });
  const logoClickTimesRef = useRef<number[]>([]);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const aiFileInputRef = useRef<HTMLInputElement | null>(null);
  const aiInputRef = useRef<HTMLInputElement | null>(null);
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const speechRecognitionRef = useRef<any>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const baseInputBeforeVoiceRef = useRef<string>("");
  const latestTranscriptRef = useRef<string>("");
  const silenceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onlineVoiceModeRef = useRef<boolean>(false);
  const currentAudioPlayerRef = useRef<HTMLAudioElement | null>(null);
  const { playTone } = useAmbientSound();

  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add("dark");
      localStorage.setItem("posbon_theme", "dark");
    } else {
      root.classList.remove("dark");
      localStorage.setItem("posbon_theme", "light");
    }
  }, [isDark]);

  const refreshAllData = useCallback(() => {
    fetch("/api/history")
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data.history)) {
          setWebHistory(data.history);
        }
      })
      .catch(() => {});

    const savedSession = localStorage.getItem("posbon_tg_session") || "";
    const savedChatId = localStorage.getItem("posbon_tg_chat_id") || "";
    fetch(
      `/api/telegram/status?sessionId=${encodeURIComponent(savedSession)}&chatId=${encodeURIComponent(savedChatId)}`
    )
      .then((r) => r.json())
      .then((data) => {
        if (data.linked && data.user) {
          setTelegramLinked(true);
          setTelegramChatId(data.user.chatId);
        } else {
          setTelegramLinked(false);
          setTelegramChatId(undefined);
        }
        if (Array.isArray(data.events)) {
          setTelegramEvents(data.events);
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshAllData();
    const interval = setInterval(refreshAllData, 4000);
    return () => clearInterval(interval);
  }, [refreshAllData]);

  useEffect(() => {
    if (activeTab === "ai") {
      chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [aiMessages, activeTab]);

  const fileToBase64 = (file: File): Promise<{ base64: string; textSnippet?: string }> => {
    return new Promise((resolve, reject) => {
      // For very large files (>18MB), read the first 6MB so binary header, manifest, and internal strings are always analyzed by AI
      const blobToRead = file.size > 18 * 1024 * 1024 ? file.slice(0, 6 * 1024 * 1024) : file;
      const reader = new FileReader();
      reader.onload = () => {
        const resultStr = String(reader.result || "");
        const base64 = resultStr.includes(",") ? resultStr.split(",")[1] : resultStr;

        if (file.size < 2 * 1024 * 1024) {
          const textReader = new FileReader();
          textReader.onload = () => {
            resolve({
              base64,
              textSnippet: String(textReader.result || "").slice(0, 4000),
            });
          };
          textReader.onerror = () => resolve({ base64 });
          textReader.readAsText(file);
        } else {
          resolve({ base64 });
        }
      };
      reader.onerror = (err) => reject(err);
      reader.readAsDataURL(blobToRead);
    });
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    setScanError(null);

    if (file.type.startsWith("image/")) {
      setScanCategory("image");
      setFilePreviewUrl(URL.createObjectURL(file));
    } else if (file.type.startsWith("video/") || file.type.startsWith("audio/")) {
      setScanCategory("video");
      setFilePreviewUrl(null);
    } else if (/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv|rtf)$/i.test(file.name)) {
      setScanCategory("document");
      setFilePreviewUrl(null);
    } else {
      setScanCategory("file");
      setFilePreviewUrl(null);
    }
  };

  const handleRunScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setScanError(null);

    if (scanCategory === "url") {
      if (!urlInput.trim()) {
        setScanError("Havolani (URL) kiriting.");
        return;
      }
    } else {
      if (!selectedFile) {
        setScanError("Fayl tanlang.");
        return;
      }
    }

    setIsScanning(true);
    playTone("scan");

    try {
      let payload: Record<string, unknown> = {};
      if (scanCategory === "url") {
        const cleanUrl = urlInput.trim();
        payload = {
          targetName: cleanUrl,
          targetType: "url",
          url: cleanUrl,
          mimeType: "text/uri-list",
        };
      } else if (selectedFile) {
        const encoded = await fileToBase64(selectedFile);
        const base64Data = encoded.base64;
        const textContent = encoded.textSnippet;
        payload = {
          targetName: selectedFile.name,
          targetType: scanCategory,
          mimeType: selectedFile.type || "application/octet-stream",
          fileSize: selectedFile.size,
          base64Data,
          textContent,
        };
      }

      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        setScanError(data.error || "Tahlil xatoligi yuz berdi.");
      } else {
        setCurrentResult(data);
        setWebHistory((prev) => [data, ...prev]);
        playTone(data.verdict === "safe" ? "safe" : "threat");
      }
    } catch {
      setScanError("Bog'lanishda xatolik yuz berdi.");
    } finally {
      setIsScanning(false);
    }
  };

  // Stop any ongoing AI speech playback
  const stopAiSpeech = useCallback(() => {
    if (currentAudioPlayerRef.current) {
      currentAudioPlayerRef.current.pause();
      currentAudioPlayerRef.current = null;
    }
    if (typeof window !== "undefined" && "speechSynthesis" in window) {
      window.speechSynthesis.cancel();
    }
    setIsAiSpeaking(false);
    setSpeakingMsgId(null);
  }, []);

  // Speak AI text out loud via Gemini TTS or Web Speech Synthesis fallback
  const speakAiResponse = useCallback(
    async (text: string, msgId?: string, onEndedCallback?: () => void) => {
      if (!text.trim()) {
        onEndedCallback?.();
        return;
      }
      stopAiSpeech();
      setIsAiSpeaking(true);
      if (msgId) setSpeakingMsgId(msgId);

      const cleanForSpeech = text
        .replace(/[*#_`~•🔍📦🛡️💡✅⚠️🚨📎]/g, "")
        .replace(/https?:\/\/[^\s]+/g, "havola")
        .trim();

      const speakWithBrowserFallback = () => {
        if (typeof window !== "undefined" && "speechSynthesis" in window) {
          window.speechSynthesis.cancel();
          const utterance = new SpeechSynthesisUtterance(cleanForSpeech);
          utterance.lang = speechLang;
          utterance.rate = 1.02;
          utterance.onend = () => {
            setIsAiSpeaking(false);
            setSpeakingMsgId(null);
            onEndedCallback?.();
          };
          utterance.onerror = () => {
            setIsAiSpeaking(false);
            setSpeakingMsgId(null);
            onEndedCallback?.();
          };
          window.speechSynthesis.speak(utterance);
        } else {
          setIsAiSpeaking(false);
          setSpeakingMsgId(null);
          onEndedCallback?.();
        }
      };

      try {
        const res = await fetch("/api/ai-tts", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: cleanForSpeech }),
        });
        const data = await res.json();
        if (data.audioBase64) {
          const audio = new Audio(`data:audio/wav;base64,${data.audioBase64}`);
          currentAudioPlayerRef.current = audio;
          audio.onended = () => {
            setIsAiSpeaking(false);
            setSpeakingMsgId(null);
            currentAudioPlayerRef.current = null;
            onEndedCallback?.();
          };
          audio.onerror = () => {
            currentAudioPlayerRef.current = null;
            speakWithBrowserFallback();
          };
          await audio.play();
          return;
        }
      } catch {
        // Fallback to browser speechSynthesis
      }
      speakWithBrowserFallback();
    },
    [speechLang, stopAiSpeech]
  );

  // Stop voice recording (Web Speech API + MediaRecorder fallback)
  const stopVoiceRecording = useCallback(() => {
    if (silenceTimerRef.current) {
      clearTimeout(silenceTimerRef.current);
      silenceTimerRef.current = null;
    }
    if (speechRecognitionRef.current) {
      try {
        speechRecognitionRef.current.onend = null;
        speechRecognitionRef.current.stop();
      } catch {
        // ignore
      }
      speechRecognitionRef.current = null;
    }
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== "inactive") {
      try {
        mediaRecorderRef.current.stop();
      } catch {
        // ignore
      }
    }
    setIsRecordingVoice(false);
    setVoiceStatusText(null);
  }, []);

  // Send message / file in AI section (accepts optional overrideText for voice auto-send)
  const handleSendAiMessage = async (e?: React.FormEvent, overrideText?: string) => {
    if (e) e.preventDefault();
    const textToSend = (overrideText !== undefined ? overrideText : aiInput).trim();
    if (!textToSend && !aiFile) return;

    if (isRecordingVoice && !onlineVoiceModeRef.current) {
      stopVoiceRecording();
    }

    const currentFile = aiFile;
    const userMsg: AIChatMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      text: textToSend || (currentFile ? `${currentFile.name}` : ""),
      attachmentName: currentFile?.name,
      timestamp: new Date().toISOString(),
    };

    const historySnapshot = aiMessages.slice(-8).map((m) => ({
      role: m.role,
      text: m.text,
    }));

    setAiMessages((prev) => [...prev, userMsg]);
    setAiInput("");
    baseInputBeforeVoiceRef.current = "";
    latestTranscriptRef.current = "";
    setAiFile(null);
    setAiLoading(true);
    playTone("scan");

    try {
      let base64Data: string | undefined;
      let textContent: string | undefined;
      if (currentFile) {
        const encoded = await fileToBase64(currentFile);
        base64Data = encoded.base64;
        textContent = encoded.textSnippet;
      }

      const res = await fetch("/api/ai-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: textToSend,
          history: historySnapshot,
          fileName: currentFile?.name,
          mimeType: currentFile?.type,
          fileSize: currentFile?.size,
          base64Data,
          textContent,
        }),
      });

      const data = await res.json();
      const replyText = data.reply || "Savolingiz bo'yicha javob tayyor.";
      const aiMsgId = `ai-${Date.now()}`;
      const aiMsg: AIChatMessage = {
        id: aiMsgId,
        role: "ai",
        text: replyText,
        analysis: data.analysis,
        timestamp: new Date().toISOString(),
      };
      setAiMessages((prev) => [...prev, aiMsg]);
      if (data.analysis) {
        setWebHistory((prev) => [data.analysis, ...prev]);
        playTone(data.analysis.verdict === "safe" ? "safe" : "threat");
      } else {
        playTone("safe");
      }

      // Speak response aloud if Online Voice Mode or Auto-Speak is active
      if (onlineVoiceModeRef.current || autoSpeakAi) {
        await speakAiResponse(replyText, aiMsgId, () => {
          if (onlineVoiceModeRef.current) {
            startVoiceRecording(true);
          }
        });
      }
    } catch {
      setAiMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: "ai",
          text: "Savolingiz qabul qilindi. Iltimos, xabaringizni yana bir bor yuboring.",
          timestamp: new Date().toISOString(),
        },
      ]);
    } finally {
      setAiLoading(false);
    }
  };

  // Start Web Speech API voice recording and automatically insert transcript into aiInput field
  const startVoiceRecording = useCallback(
    async (isContinuousOnlineCall = false) => {
      stopAiSpeech();

      const SpeechRecognitionAPI =
        typeof window !== "undefined"
          ? (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition
          : null;

      if (SpeechRecognitionAPI) {
        try {
          if (speechRecognitionRef.current) {
            speechRecognitionRef.current.onend = null;
            speechRecognitionRef.current.stop();
          }

          const recognition = new SpeechRecognitionAPI();
          recognition.lang = speechLang;
          recognition.continuous = true;
          recognition.interimResults = true;
          recognition.maxAlternatives = 1;

          baseInputBeforeVoiceRef.current = isContinuousOnlineCall
            ? ""
            : aiInput.trim()
            ? `${aiInput.trim()} `
            : "";
          latestTranscriptRef.current = "";

          recognition.onstart = () => {
            setIsRecordingVoice(true);
            setVoiceStatusText(
              isContinuousOnlineCall
                ? "Jonli suhbat: Gapiring, POSBON AI sizni eshitmoqda..."
                : "Ovoz yozilmoqda... Gapiring, matn yozuv maydoniga avtomatik tushadi"
            );
          };

          recognition.onresult = (event: any) => {
            let finalSegment = "";
            let interimSegment = "";

            for (let i = 0; i < event.results.length; i++) {
              const transcriptPiece = event.results[i][0]?.transcript || "";
              if (event.results[i].isFinal) {
                finalSegment += transcriptPiece + " ";
              } else {
                interimSegment += transcriptPiece;
              }
            }

            const combinedTranscript = `${baseInputBeforeVoiceRef.current}${finalSegment}${interimSegment}`.trim();
            latestTranscriptRef.current = combinedTranscript;

            // Automatically insert the live transcript directly into the chat input field!
            setAiInput(combinedTranscript);

            // In Online Voice Call mode, auto-send after user pauses speaking for 1.5 seconds
            if (onlineVoiceModeRef.current && combinedTranscript.length > 1) {
              if (silenceTimerRef.current) clearTimeout(silenceTimerRef.current);
              silenceTimerRef.current = setTimeout(() => {
                const textReady = latestTranscriptRef.current.trim();
                if (textReady && onlineVoiceModeRef.current) {
                  stopVoiceRecording();
                  handleSendAiMessage(undefined, textReady);
                }
              }, 1500);
            }
          };

          recognition.onerror = (event: any) => {
            if (event.error === "not-allowed") {
              setVoiceStatusText("Mikrofonga ruxsat berilmadi. Brauzerda mikrofon ruxsatini yoqing.");
              setIsRecordingVoice(false);
            } else if (event.error !== "aborted") {
              setIsRecordingVoice(false);
              setVoiceStatusText(null);
            }
          };

          recognition.onend = () => {
            setIsRecordingVoice(false);
            setVoiceStatusText(null);
            // Focus the chat input field so the user can immediately review/edit/send the inserted transcript
            if (!onlineVoiceModeRef.current) {
              aiInputRef.current?.focus();
            }
          };

          speechRecognitionRef.current = recognition;
          recognition.start();
          return;
        } catch {
          // Fall through to MediaRecorder fallback if SpeechRecognition fails to start
        }
      }

      // Fallback: MediaRecorder + server-side Gemini audio transcription (/api/ai-transcribe)
      if (typeof navigator !== "undefined" && navigator.mediaDevices?.getUserMedia) {
        try {
          const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
          const recorder = new MediaRecorder(stream);
          audioChunksRef.current = [];

          recorder.ondataavailable = (ev) => {
            if (ev.data.size > 0) audioChunksRef.current.push(ev.data);
          };

          recorder.onstop = async () => {
            stream.getTracks().forEach((track) => track.stop());
            const audioBlob = new Blob(audioChunksRef.current, {
              type: recorder.mimeType || "audio/webm",
            });
            if (audioBlob.size === 0) return;

            setVoiceStatusText("Ovoz matnga aylantirilmoqda...");
            const reader = new FileReader();
            reader.onloadend = async () => {
              const base64Str = String(reader.result || "").split(",")[1] || "";
              try {
                const res = await fetch("/api/ai-transcribe", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({
                    base64Audio: base64Str,
                    mimeType: recorder.mimeType || "audio/webm",
                  }),
                });
                const data = await res.json();
                if (data.transcript) {
                  const newText = aiInput.trim()
                    ? `${aiInput.trim()} ${data.transcript}`
                    : data.transcript;
                  // Automatically insert transcript into the chat input field
                  setAiInput(newText);
                  aiInputRef.current?.focus();
                  if (onlineVoiceModeRef.current) {
                    handleSendAiMessage(undefined, newText);
                  }
                }
              } catch {
                // ignore
              } finally {
                setVoiceStatusText(null);
                setIsRecordingVoice(false);
              }
            };
            reader.readAsDataURL(audioBlob);
          };

          mediaRecorderRef.current = recorder;
          recorder.start();
          setIsRecordingVoice(true);
          setVoiceStatusText("Ovoz yozilmoqda... Tugatgach mikrofon tugmasini bosing");
        } catch {
          setVoiceStatusText("Mikrofonga ulanish imkoni bo'lmadi.");
        }
      } else {
        setVoiceStatusText("Brauzeringiz ovoz yozishni qo'llab-quvvatlamaydi.");
      }
    },
    [aiInput, speechLang, stopAiSpeech, stopVoiceRecording]
  );

  // Toggle microphone recording on/off
  const handleToggleVoiceRecording = () => {
    if (isRecordingVoice) {
      stopVoiceRecording();
    } else {
      startVoiceRecording(onlineVoiceModeRef.current);
    }
  };

  // Toggle Online Voice Call Mode
  const handleToggleOnlineVoiceMode = () => {
    const nextMode = !onlineVoiceMode;
    setOnlineVoiceMode(nextMode);
    onlineVoiceModeRef.current = nextMode;
    if (nextMode) {
      setAutoSpeakAi(true);
      startVoiceRecording(true);
    } else {
      stopVoiceRecording();
      stopAiSpeech();
    }
  };

  // Secret Admin Panel: Detect 3 rapid clicks on top "POSBON AI" logo
  const handleLogoSecretClick = (e: React.MouseEvent) => {
    e.preventDefault();
    const now = Date.now();
    const recentClicks = logoClickTimesRef.current.filter((t) => now - t < 900);
    recentClicks.push(now);
    logoClickTimesRef.current = recentClicks;

    if (recentClicks.length >= 3) {
      logoClickTimesRef.current = [];
      setShowAdminModal(true);
      setAdminError(null);
      if (adminUnlocked) {
        fetchAdminDatabase("0513");
      }
    } else {
      setActiveTab("scanner");
    }
  };

  const fetchAdminDatabase = async (pwd: string) => {
    setAdminLoading(true);
    setAdminError(null);
    try {
      const res = await fetch("/api/admin/database", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pwd.trim() }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setAdminError(data.error || "Parol noto'g'ri! Qaytadan urinib ko'ring.");
        setAdminUnlocked(false);
      } else {
        setAdminUnlocked(true);
        setAdminUsers(Array.isArray(data.users) ? data.users : []);
        setAdminDeletedFiles(Array.isArray(data.deletedFiles) ? data.deletedFiles : []);
        setAdminStats({
          totalUsers: data.totalUsers || 0,
          totalDeleted: data.totalDeleted || 0,
          totalScanned: data.totalScanned || 0,
        });
      }
    } catch {
      setAdminError("Server bilan bog'lanishda xatolik yuz berdi.");
    } finally {
      setAdminLoading(false);
    }
  };

  const handleAdminLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAdminDatabase(adminPassword);
  };

  // Test buttons inside Guide section
  const handleGuideTest = async (testType: "virus_file" | "phishing_url" | "safe_doc") => {
    setTestLoading(testType);
    setTestNotice(null);
    playTone("scan");

    try {
      if (telegramLinked && telegramChatId) {
        const res = await fetch("/api/telegram/test-protection", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chatId: telegramChatId,
            testType,
            customSenderName: "Sinov (@test_uz)",
          }),
        });
        const data = await res.json();
        if (data.event) {
          setTelegramEvents((prev) => [data.event, ...prev]);
          playTone(data.event.verdict === "safe" ? "safe" : "threat");
          setTestNotice(
            data.event.verdict === "safe"
              ? `✅ Telegramingizga (${telegramChatId}) toza hujjat tahlili (${data.event.safetyPercentage}% xavfsiz) yuborildi!`
              : `🛡️ Telegramda xavfli xabar avtomatik o'chirildi va @PosbonXBot dan sizga ogohlantirish xabari bordi!`
          );
        }
      } else {
        let payload: Record<string, unknown> = {};
        if (testType === "virus_file") {
          payload = {
            targetName: "Jarima_Qaror_2026.pdf.exe",
            targetType: "file",
            mimeType: "application/x-msdownload",
            fileSize: 1840200,
            textContent: "MZ EICAR-STANDARD-ANTIVIRUS-TEST-FILE powershell -e cmd.exe /c",
          };
        } else if (testType === "phishing_url") {
          payload = {
            targetName: "http://uzcard-bonus-yutuq.xyz/login",
            targetType: "url",
            url: "http://uzcard-bonus-yutuq.xyz/login",
            mimeType: "text/uri-list",
          };
        } else {
          payload = {
            targetName: "Rasmiy_Shartnoma_2026.pdf",
            targetType: "document",
            mimeType: "application/pdf",
            fileSize: 210400,
            textContent: "%PDF-1.7 Rasmiy tasdiqlangan shartnoma matni.",
          };
        }

        const res = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (res.ok && !data.error) {
          setCurrentResult(data);
          setWebHistory((prev) => [data, ...prev]);
          playTone(data.verdict === "safe" ? "safe" : "threat");
          setTestNotice(
            `Sinov bajarildi: "${data.targetName}" — ${data.safetyPercentage}% xavfsiz (${data.threatCategory}).`
          );
        }
      }
    } catch {
      setTestNotice("Sinov vaqtida xatolik yuz berdi.");
    } finally {
      setTestLoading(null);
    }
  };

  // Unified History (Web + Telegram)
  const unifiedHistory: ScanResultItem[] = [
    ...telegramEvents.map((ev) => ({
      id: ev.id,
      targetName: ev.targetName,
      targetType: ev.targetType,
      detectedFormat: ev.analysisResult?.detectedFormat || ev.targetType,
      verdict: ev.verdict,
      isCompletelySafe: ev.isCompletelySafe,
      safetyPercentage:
        typeof ev.safetyPercentage === "number"
          ? ev.safetyPercentage
          : Math.max(0, 100 - ev.riskScore),
      riskScore: ev.riskScore,
      trustScore:
        typeof ev.trustScore === "number"
          ? ev.trustScore
          : Math.max(0, 100 - ev.riskScore),
      threatCategory: ev.threatCategory,
      whatIsInside: ev.whatIsInside,
      authenticityVerdict: ev.authenticityVerdict,
      politeSummary: ev.politeSummary,
      technicalDetails: ev.analysisResult?.technicalDetails || [],
      recommendations: ev.analysisResult?.recommendations || [],
      analyzedAt: ev.timestamp,
      source: "telegram" as const,
      senderName: ev.senderName,
    })),
    ...webHistory,
  ].sort((a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime());

  const filteredHistory = unifiedHistory.filter((item) => {
    if (historyFilter === "malicious" && item.verdict === "safe") return false;
    if (historyFilter === "safe" && item.verdict !== "safe") return false;
    if (
      searchQuery.trim() &&
      !item.targetName.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !item.threatCategory.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const acceptByCategory: Record<ScannerCategory, string> = {
    file: "*/*",
    document: ".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.rtf,.docm,.xlsm",
    image: "image/*",
    video: "video/*,audio/*",
    url: "",
  };

  const currentSafetyPct = currentResult
    ? typeof currentResult.safetyPercentage === "number"
      ? currentResult.safetyPercentage
      : Math.max(0, 100 - currentResult.riskScore)
    : 0;
  const currentTrustPct = currentResult
    ? typeof currentResult.trustScore === "number"
      ? currentResult.trustScore
      : currentSafetyPct
    : 0;

  const showScannerResult = isScanning || Boolean(currentResult);

  return (
    <div className="h-[100dvh] w-full overflow-hidden bg-slate-100 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col transition-colors">
      {/* Top Bar — Strict 3-Zone Contract */}
      <header className="flex items-center justify-between gap-4 sm:gap-8 px-4 sm:px-8 h-14 shrink-0 border-b border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900">
        {/* Zone 1: Brand Wordmark (Triple-click opens Secret Admin Panel) */}
        <a
          href="#scanner"
          onClick={handleLogoSecretClick}
          className="text-base sm:text-lg font-bold tracking-tight text-slate-900 dark:text-white whitespace-nowrap shrink-0 select-none cursor-pointer"
        >
          POSBON AI
        </a>

        {/* Zone 2: Desktop Nav Links */}
        <nav className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-600 dark:text-slate-400">
          <a
            href="#scanner"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab("scanner");
            }}
            className={`hover:text-slate-900 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeTab === "scanner"
                ? "text-emerald-600 dark:text-emerald-400 font-bold underline underline-offset-8 decoration-2"
                : ""
            }`}
          >
            Skayner
          </a>
          <a
            href="#telegram"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab("telegram");
            }}
            className={`hover:text-slate-900 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeTab === "telegram"
                ? "text-sky-600 dark:text-sky-400 font-bold underline underline-offset-8 decoration-2"
                : ""
            }`}
          >
            Telegram
          </a>
          <a
            href="#ai"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab("ai");
            }}
            className={`hover:text-slate-900 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeTab === "ai"
                ? "text-emerald-600 dark:text-emerald-400 font-bold underline underline-offset-8 decoration-2"
                : ""
            }`}
          >
            AI
          </a>
          <a
            href="#history"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab("history");
            }}
            className={`hover:text-slate-900 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeTab === "history"
                ? "text-emerald-600 dark:text-emerald-400 font-bold underline underline-offset-8 decoration-2"
                : ""
            }`}
          >
            Tarix
          </a>
          <a
            href="#guide"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab("guide");
            }}
            className={`hover:text-slate-900 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 ${
              activeTab === "guide"
                ? "text-emerald-600 dark:text-emerald-400 font-bold underline underline-offset-8 decoration-2"
                : ""
            }`}
          >
            Qo'llanma
          </a>
        </nav>

        {/* Zone 3: Theme Toggle + Telegram Action */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setIsDark(!isDark)}
            aria-label="Tun va kun rejimi"
            className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
          >
            {isDark ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4" />}
          </button>

          <button
            onClick={() => setActiveTab("telegram")}
            className="px-3 py-2 text-xs font-semibold text-white dark:text-slate-950 bg-emerald-600 dark:bg-emerald-400 rounded-xl hover:bg-emerald-500 dark:hover:bg-emerald-300 transition-colors whitespace-nowrap shrink-0"
          >
            {telegramLinked ? "Ulangan" : "Telegram Ulash"}
          </button>
        </div>
      </header>

      {/* Main Viewport — Single Window on Mobile, Wide Centered on Desktop */}
      <main className="mx-auto w-full max-w-[1320px] flex-1 overflow-y-auto px-3 sm:px-8 py-3 sm:py-6 flex flex-col justify-center">
        {/* =========================================================
            1. SKAYNER — Only shows Scanner until user scans!
               On mobile: Single window (either Scanner OR Result)
        ========================================================= */}
        {activeTab === "scanner" && (
          <div
            className={
              showScannerResult
                ? "grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch w-full"
                : "mx-auto w-full max-w-xl"
            }
          >
            {/* Scanner Input Card (Hidden on mobile when result is open so mobile has only 1 window!) */}
            <div
              className={`${
                showScannerResult ? "hidden lg:flex lg:col-span-6" : "flex w-full"
              } rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-6 shadow-sm flex-col justify-between space-y-5`}
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h1 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white">
                    Xavfsizlik Skayneri
                  </h1>
                  <Shield className="h-5 w-5 text-emerald-500 shrink-0" />
                </div>

                {/* 5 Clean Category Buttons */}
                <div className="grid grid-cols-5 gap-1 p-1 bg-slate-100 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800">
                  <button
                    type="button"
                    onClick={() => {
                      setScanCategory("file");
                      setScanError(null);
                    }}
                    className={`flex flex-col sm:flex-row items-center justify-center gap-1 py-2 px-1 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                      scanCategory === "file"
                        ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                        : "text-slate-600 dark:text-slate-400"
                    }`}
                  >
                    <FileCode className="h-4 w-4 shrink-0" />
                    <span>Fayl</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setScanCategory("document");
                      setScanError(null);
                    }}
                    className={`flex flex-col sm:flex-row items-center justify-center gap-1 py-2 px-1 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                      scanCategory === "document"
                        ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                        : "text-slate-600 dark:text-slate-400"
                    }`}
                  >
                    <FileText className="h-4 w-4 shrink-0" />
                    <span>Hujjat</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setScanCategory("image");
                      setScanError(null);
                    }}
                    className={`flex flex-col sm:flex-row items-center justify-center gap-1 py-2 px-1 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                      scanCategory === "image"
                        ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                        : "text-slate-600 dark:text-slate-400"
                    }`}
                  >
                    <ImageIcon className="h-4 w-4 shrink-0" />
                    <span>Rasm</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setScanCategory("video");
                      setScanError(null);
                    }}
                    className={`flex flex-col sm:flex-row items-center justify-center gap-1 py-2 px-1 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                      scanCategory === "video"
                        ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                        : "text-slate-600 dark:text-slate-400"
                    }`}
                  >
                    <Video className="h-4 w-4 shrink-0" />
                    <span>Video</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setScanCategory("url");
                      setScanError(null);
                    }}
                    className={`flex flex-col sm:flex-row items-center justify-center gap-1 py-2 px-1 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                      scanCategory === "url"
                        ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                        : "text-slate-600 dark:text-slate-400"
                    }`}
                  >
                    <Globe className="h-4 w-4 shrink-0" />
                    <span>Havola</span>
                  </button>
                </div>

                {/* Input Area */}
                {scanCategory === "url" ? (
                  <form onSubmit={handleRunScan} className="space-y-3 pt-1">
                    <input
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="https://..."
                      className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-4 py-3.5 text-sm font-mono text-slate-900 dark:text-white placeholder:text-slate-400 focus:border-emerald-500 focus:outline-none"
                    />
                    <button
                      type="submit"
                      disabled={isScanning}
                      className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 dark:bg-emerald-500 px-5 py-3.5 text-sm font-semibold text-white dark:text-slate-950 hover:bg-emerald-500 dark:hover:bg-emerald-400 disabled:opacity-50 transition-colors"
                    >
                      <Search className="h-4 w-4" />
                      <span>Tekshirish</span>
                    </button>
                  </form>
                ) : (
                  <div className="space-y-3 pt-1">
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept={acceptByCategory[scanCategory]}
                      onChange={handleFileChange}
                      className="hidden"
                    />

                    <div
                      onClick={() => fileInputRef.current?.click()}
                      onDragOver={(e) => e.preventDefault()}
                      onDrop={(e) => {
                        e.preventDefault();
                        const dropped = e.dataTransfer.files?.[0];
                        if (dropped) {
                          setSelectedFile(dropped);
                          setScanError(null);
                        }
                      }}
                      className="cursor-pointer rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950/60 p-7 text-center hover:border-emerald-500 transition-colors"
                    >
                      {selectedFile ? (
                        <div className="space-y-1.5">
                          {filePreviewUrl && (
                            <img
                              src={filePreviewUrl}
                              alt="Tanlangan rasm"
                              referrerPolicy="no-referrer"
                              className="mx-auto h-16 w-16 rounded-lg object-cover border border-slate-200 dark:border-slate-800"
                            />
                          )}
                          <div className="text-sm font-semibold text-emerald-600 dark:text-emerald-400 font-mono truncate max-w-xs mx-auto">
                            {selectedFile.name}
                          </div>
                          <div className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                            {(selectedFile.size / 1024).toFixed(1)} KB
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-2 py-2">
                          <Upload className="mx-auto h-7 w-7 text-emerald-500" />
                          <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                            Fayl tanlash
                          </div>
                        </div>
                      )}
                    </div>

                    <button
                      type="button"
                      onClick={() => handleRunScan()}
                      disabled={isScanning || !selectedFile}
                      className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 dark:bg-emerald-500 px-5 py-3.5 text-sm font-semibold text-white dark:text-slate-950 hover:bg-emerald-500 dark:hover:bg-emerald-400 disabled:opacity-50 transition-colors"
                    >
                      <Shield className="h-4 w-4" />
                      <span>Tekshirish</span>
                    </button>
                  </div>
                )}

                {scanError && (
                  <div className="rounded-xl border border-rose-500/40 bg-rose-50 dark:bg-rose-950/30 p-3 text-xs text-rose-600 dark:text-rose-300">
                    {scanError}
                  </div>
                )}
              </div>
            </div>

            {/* Result Card — ONLY rendered when scanning or when currentResult exists! */}
            {showScannerResult && (
              <div className="lg:col-span-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-6 shadow-sm flex flex-col justify-between">
                {isScanning ? (
                  <div className="my-auto py-14 text-center space-y-3">
                    <Loader2 className="mx-auto h-9 w-9 text-emerald-500 animate-spin" />
                    <div className="text-sm font-semibold text-slate-800 dark:text-white">
                      Tekshirilmoqda...
                    </div>
                  </div>
                ) : currentResult ? (
                  <div className="space-y-4 flex-1 flex flex-col justify-between">
                    <div className="space-y-3.5">
                      <div className="flex items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
                        <div className="flex items-center gap-2.5 min-w-0">
                          {currentResult.verdict === "malicious" ? (
                            <ShieldAlert className="h-7 w-7 text-rose-500 shrink-0" />
                          ) : currentResult.verdict === "suspicious" ? (
                            <AlertTriangle className="h-7 w-7 text-amber-500 shrink-0" />
                          ) : (
                            <ShieldCheck className="h-7 w-7 text-emerald-500 shrink-0" />
                          )}
                          <div className="min-w-0">
                            <div
                              className={`text-base font-bold truncate ${
                                currentResult.verdict === "malicious"
                                  ? "text-rose-600 dark:text-rose-400"
                                  : currentResult.verdict === "suspicious"
                                  ? "text-amber-600 dark:text-amber-400"
                                  : "text-emerald-600 dark:text-emerald-400"
                              }`}
                            >
                              {currentResult.threatCategory}
                            </div>
                            <div className="text-xs text-slate-500 dark:text-slate-400 font-mono truncate">
                              {currentResult.targetName}
                            </div>
                          </div>
                        </div>

                        <button
                          type="button"
                          onClick={() => setCurrentResult(null)}
                          className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-white transition-colors"
                          title="Yopish"
                        >
                          <X className="h-5 w-5" />
                        </button>
                      </div>

                      {/* 3 Simple Numbers */}
                      <div className="grid grid-cols-3 gap-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3 font-mono tabular-nums text-xs text-center">
                        <div>
                          <div className="text-[10px] text-slate-400">Holati</div>
                          <div
                            className={`font-bold mt-0.5 text-sm ${
                              currentResult.verdict === "safe"
                                ? "text-emerald-600 dark:text-emerald-400"
                                : currentResult.verdict === "suspicious"
                                ? "text-amber-600 dark:text-amber-400"
                                : "text-rose-600 dark:text-rose-400"
                            }`}
                          >
                            {currentResult.verdict === "safe"
                              ? "XAVFSIZ"
                              : currentResult.verdict === "suspicious"
                              ? "SHUBHALI"
                              : "XAVFLI!"}
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-400">Xavfsizlik</div>
                          <div className="font-bold text-emerald-600 dark:text-emerald-400 mt-0.5 text-sm">
                            {currentSafetyPct}%
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-400">Ishonchlilik</div>
                          <div className="font-bold text-sky-600 dark:text-sky-400 mt-0.5 text-sm">
                            {currentTrustPct}%
                          </div>
                        </div>
                      </div>

                      {currentResult.whatIsInside && (
                        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3">
                          <div className="flex items-center gap-1.5 text-xs font-semibold text-sky-600 dark:text-sky-400 mb-1">
                            <PackageSearch className="h-4 w-4" />
                            <span>AI Tahlili (Ichida nima bor?)</span>
                          </div>
                          <p className="text-xs italic leading-relaxed text-slate-700 dark:text-slate-200 line-clamp-3">
                            «{currentResult.whatIsInside}»
                          </p>
                        </div>
                      )}

                      {currentResult.authenticityVerdict && (
                        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3">
                          <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400 mb-1">
                            <BadgeCheck className="h-4 w-4" />
                            <span>Haqiqiyligi</span>
                          </div>
                          <p className="text-xs italic leading-relaxed text-slate-700 dark:text-slate-200 line-clamp-2">
                            «{currentResult.authenticityVerdict}»
                          </p>
                        </div>
                      )}
                    </div>

                    <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setCurrentResult(null);
                          setSelectedFile(null);
                        }}
                        className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 hover:underline"
                      >
                        <ArrowLeft className="h-3.5 w-3.5" />
                        <span>Yangi tekshiruv</span>
                      </button>

                      <button
                        type="button"
                        onClick={() =>
                          setExplainerTarget({
                            targetName: currentResult.targetName,
                            threatCategory: currentResult.threatCategory,
                            verdict: currentResult.verdict,
                            isCompletelySafe: currentResult.isCompletelySafe,
                            safetyPercentage: currentSafetyPct,
                            riskScore: currentResult.riskScore,
                            trustScore: currentTrustPct,
                            detectedFormat: currentResult.detectedFormat,
                            whatIsInside: currentResult.whatIsInside,
                            authenticityVerdict: currentResult.authenticityVerdict,
                            politeSummary: currentResult.politeSummary,
                            technicalDetails: currentResult.technicalDetails,
                            recommendations: currentResult.recommendations,
                          })
                        }
                        className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500/10 px-3.5 py-2 text-xs font-semibold text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 transition-colors"
                      >
                        <Sparkles className="h-3.5 w-3.5" />
                        <span>Batafsil</span>
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        )}

        {/* =========================================================
            2. TELEGRAM — Single Clean Authorization Window
        ========================================================= */}
        {activeTab === "telegram" && (
          <TelegramConnect
            onStatusChange={(linked, chatId, events) => {
              setTelegramLinked(linked);
              setTelegramChatId(chatId);
              if (events) setTelegramEvents(events);
            }}
            onPlaySound={playTone}
          />
        )}

        {/* =========================================================
            3. AI — Full Conversational AI + Web Speech API + Online Voice Mode + File Check
        ========================================================= */}
        {activeTab === "ai" && (
          <div className="mx-auto w-full max-w-3xl rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm flex flex-col h-[calc(100dvh-9.5rem)] max-h-[580px] overflow-hidden">
            {/* AI Header Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 px-4 sm:px-5 py-3 bg-slate-50/60 dark:bg-slate-900">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                  <Sparkles className="h-4 w-4" />
                </div>
                <div>
                  <h2 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white leading-tight">
                    POSBON AI Yordamchi
                  </h2>
                  <div className="flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span>Online · Matn, Fayl va Ovozli Suhbat</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                {/* Speech Recognition Language Selector */}
                <select
                  value={speechLang}
                  onChange={(e) => setSpeechLang(e.target.value as "uz-UZ" | "ru-RU" | "en-US")}
                  aria-label="Ovoz tili"
                  className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-2 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300 focus:outline-none"
                >
                  <option value="uz-UZ">🇺🇿 O'zbek</option>
                  <option value="ru-RU">🇷🇺 Русский</option>
                  <option value="en-US">🇬🇧 English</option>
                </select>

                {/* Auto-Speak Toggle */}
                <button
                  type="button"
                  onClick={() => {
                    if (isAiSpeaking) stopAiSpeech();
                    setAutoSpeakAi(!autoSpeakAi);
                  }}
                  title={autoSpeakAi ? "Ovozli o'qish yoqilgan" : "Javoblarni ovozda o'qish"}
                  className={`flex h-8 w-8 items-center justify-center rounded-lg border transition-colors ${
                    autoSpeakAi
                      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                      : "border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-500"
                  }`}
                >
                  {autoSpeakAi ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
                </button>

                {/* Online Live Voice Call Mode Button */}
                <button
                  type="button"
                  onClick={handleToggleOnlineVoiceMode}
                  className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                    onlineVoiceMode
                      ? "bg-rose-600 text-white hover:bg-rose-500"
                      : "bg-emerald-600 dark:bg-emerald-500 text-white dark:text-slate-950 hover:bg-emerald-500 dark:hover:bg-emerald-400"
                  }`}
                >
                  {onlineVoiceMode ? (
                    <>
                      <PhoneOff className="h-3.5 w-3.5" />
                      <span>Ovozni Yopish</span>
                    </>
                  ) : (
                    <>
                      <PhoneCall className="h-3.5 w-3.5" />
                      <span>Online Ovoz</span>
                    </>
                  )}
                </button>

                {/* Clear Chat */}
                {aiMessages.length > 1 && (
                  <button
                    type="button"
                    onClick={() => {
                      stopAiSpeech();
                      setAiMessages([
                        {
                          id: "welcome-ai",
                          role: "ai",
                          text: "Assalomu alaykum! Men POSBON AI yordamchisiman. Menga savol yozishingiz, mikrofonni bosib ovoz orqali gaplashishingiz yoki fayl, rasm va havola yuborib tekshirtirishingiz mumkin.",
                          timestamp: new Date().toISOString(),
                        },
                      ]);
                    }}
                    title="Suhbatni tozalash"
                    className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-400 hover:text-rose-500 transition-colors"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            </div>

            {/* Online Live Voice Call Banner (Active when Online Voice Mode is turned on) */}
            {onlineVoiceMode && (
              <div className="border-b border-emerald-500/20 bg-emerald-500/5 px-4 py-3 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <button
                    type="button"
                    onClick={handleToggleVoiceRecording}
                    className={`flex h-11 w-11 items-center justify-center rounded-full shrink-0 transition-transform ${
                      isRecordingVoice
                        ? "bg-rose-500 text-white ring-4 ring-rose-500/25 scale-105"
                        : isAiSpeaking
                        ? "bg-sky-500 text-white ring-4 ring-sky-500/25"
                        : "bg-emerald-500 text-slate-950"
                    }`}
                  >
                    {isRecordingVoice ? (
                      <Mic className="h-5 w-5 animate-pulse" />
                    ) : isAiSpeaking ? (
                      <Volume2 className="h-5 w-5 animate-bounce" />
                    ) : (
                      <MicOff className="h-5 w-5" />
                    )}
                  </button>
                  <div className="min-w-0">
                    <div className="text-xs font-bold text-slate-900 dark:text-white">
                      {isAiSpeaking
                        ? "POSBON AI ovozda javob bermoqda..."
                        : isRecordingVoice
                        ? "Online Ovozli Suhbat — Gapiring, sizni eshityapman..."
                        : aiLoading
                        ? "POSBON AI javob tayyorlamoqda..."
                        : "Gapirish uchun mikrofon ustiga bosing"}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                      {aiInput
                        ? `Yozib olinmoqda: "${aiInput}"`
                        : "Aytgan so'zlaringiz avtomatik pastdagi yozuv maydoniga tushadi va yuboriladi"}
                    </div>
                  </div>
                </div>

                {isAiSpeaking && (
                  <button
                    type="button"
                    onClick={stopAiSpeech}
                    className="rounded-lg border border-slate-300 dark:border-slate-700 px-2.5 py-1 text-xs font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 shrink-0"
                  >
                    To'xtatish
                  </button>
                )}
              </div>
            )}

            {/* Messages Scroll Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3.5">
              {aiMessages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex flex-col ${
                    msg.role === "user" ? "items-end" : "items-start"
                  }`}
                >
                  <div
                    className={`max-w-[88%] sm:max-w-[82%] rounded-2xl px-4 py-3 text-xs sm:text-sm leading-relaxed ${
                      msg.role === "user"
                        ? "bg-emerald-600 text-white"
                        : "bg-slate-100 dark:bg-slate-800/90 text-slate-800 dark:text-slate-100 border border-slate-200/70 dark:border-slate-700/60"
                    }`}
                  >
                    {msg.attachmentName && (
                      <div className="mb-1.5 flex items-center gap-1.5 rounded-lg bg-black/15 px-2.5 py-1 text-xs font-mono">
                        <Paperclip className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate">{msg.attachmentName}</span>
                      </div>
                    )}
                    <p className={`whitespace-pre-line ${msg.analysis ? "italic" : ""}`}>{msg.text}</p>

                    {msg.analysis && (
                      <div className="mt-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 text-slate-900 dark:text-slate-100 space-y-1.5">
                        <div className="flex items-center justify-between gap-2 font-mono text-xs">
                          <span className="font-bold text-emerald-600 dark:text-emerald-400">
                            Xavfsizlik: {msg.analysis.safetyPercentage ?? Math.max(0, 100 - msg.analysis.riskScore)}%
                          </span>
                          <span className="font-semibold text-sky-600 dark:text-sky-400">
                            Ishonchlilik: {msg.analysis.trustScore ?? 90}%
                          </span>
                        </div>
                        {msg.analysis.whatIsInside && (
                          <p className="text-xs italic text-slate-600 dark:text-slate-300">
                            «{msg.analysis.whatIsInside}»
                          </p>
                        )}
                      </div>
                    )}

                    {/* Listen / Stop Voice button for each AI message */}
                    {msg.role === "ai" && (
                      <div className="mt-2 pt-1.5 border-t border-slate-200/60 dark:border-slate-700/50 flex items-center justify-end">
                        <button
                          type="button"
                          onClick={() => {
                            if (speakingMsgId === msg.id && isAiSpeaking) {
                              stopAiSpeech();
                            } else {
                              speakAiResponse(msg.text, msg.id);
                            }
                          }}
                          className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 hover:underline"
                        >
                          {speakingMsgId === msg.id && isAiSpeaking ? (
                            <>
                              <VolumeX className="h-3.5 w-3.5" />
                              <span>Ovozni to'xtatish</span>
                            </>
                          ) : (
                            <>
                              <Volume2 className="h-3.5 w-3.5" />
                              <span>Ovozda eshitish</span>
                            </>
                          )}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {/* Quick Starter Prompts when conversation is fresh */}
              {aiMessages.length === 1 && !aiLoading && (
                <div className="pt-2 flex flex-wrap gap-1.5">
                  {[
                    "Salom, imkoniyatlaring qanday?",
                    "Telegram botni qanday ulayman?",
                    "Fishing havolani qanday aniqlash mumkin?",
                    "Noma'lum .apk fayl xavflimi?",
                  ].map((promptText) => (
                    <button
                      key={promptText}
                      type="button"
                      onClick={() => handleSendAiMessage(undefined, promptText)}
                      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 hover:border-emerald-500/50 hover:text-emerald-600 dark:hover:text-emerald-400 transition-colors"
                    >
                      {promptText}
                    </button>
                  ))}
                </div>
              )}

              {aiLoading && (
                <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 pl-2">
                  <Loader2 className="h-4 w-4 animate-spin text-emerald-500" />
                  <span>POSBON AI javob yozmoqda...</span>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Active Web Speech API Recording Status Banner */}
            {voiceStatusText && !onlineVoiceMode && (
              <div className="mx-4 mb-2 flex items-center justify-between gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-300">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="h-2 w-2 rounded-full bg-rose-500 animate-ping shrink-0" />
                  <span className="truncate font-medium">{voiceStatusText}</span>
                </div>
                <button
                  type="button"
                  onClick={stopVoiceRecording}
                  className="font-semibold underline shrink-0"
                >
                  To'xtatish
                </button>
              </div>
            )}

            {/* Attached File Chip */}
            {aiFile && (
              <div className="mx-4 mb-2 flex items-center justify-between rounded-xl border border-emerald-500/30 bg-emerald-50 dark:bg-emerald-950/30 px-3 py-1.5 text-xs">
                <div className="flex items-center gap-2 truncate font-mono text-emerald-700 dark:text-emerald-300">
                  <Paperclip className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate">{aiFile.name}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setAiFile(null)}
                  className="text-slate-500 hover:text-rose-500"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}

            {/* Chat Input Bar with Web Speech API Voice-to-Input Button */}
            <form
              onSubmit={(e) => handleSendAiMessage(e)}
              className="border-t border-slate-200 dark:border-slate-800 p-3 flex items-center gap-2 bg-white dark:bg-slate-900"
            >
              <input
                ref={aiFileInputRef}
                type="file"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) setAiFile(f);
                }}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => aiFileInputRef.current?.click()}
                title="Fayl yoki rasm yuborish"
                className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shrink-0"
              >
                <Paperclip className="h-4 w-4" />
              </button>

              {/* Web Speech API Voice Recording Button (Inserts transcript automatically into input) */}
              <button
                type="button"
                onClick={handleToggleVoiceRecording}
                title={
                  isRecordingVoice
                    ? "Ovoz yozishni to'xtatish"
                    : "Ovoz orqali yozish (Web Speech API)"
                }
                aria-label="Ovoz orqali yozish"
                className={`flex h-10 w-10 items-center justify-center rounded-xl border transition-all shrink-0 ${
                  isRecordingVoice
                    ? "border-rose-500 bg-rose-500 text-white ring-4 ring-rose-500/20 animate-pulse"
                    : "border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-300 hover:border-emerald-500/50 hover:text-emerald-600 dark:hover:text-emerald-400"
                }`}
              >
                {isRecordingVoice ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
              </button>

              <input
                ref={aiInputRef}
                type="text"
                value={aiInput}
                onChange={(e) => {
                  setAiInput(e.target.value);
                  latestTranscriptRef.current = e.target.value;
                }}
                placeholder={
                  isRecordingVoice
                    ? "Gapiring... so'zlaringiz shu yerga tushadi"
                    : "Savol yozing, mikrofonni bosing yoki fayl yuboring..."
                }
                className="flex-1 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-3.5 py-2.5 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:border-emerald-500 focus:outline-none"
              />

              <button
                type="submit"
                disabled={aiLoading || (!aiInput.trim() && !aiFile)}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-emerald-600 dark:bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-white dark:text-slate-950 hover:bg-emerald-500 dark:hover:bg-emerald-400 disabled:opacity-50 transition-colors shrink-0"
              >
                <Send className="h-4 w-4" />
              </button>
            </form>
          </div>
        )}

        {/* =========================================================
            4. TARIX — Detail is hidden until user clicks an item!
               On mobile: Single Window (either List OR Selected Detail)
        ========================================================= */}
        {activeTab === "history" && (
          <div
            className={
              selectedHistoryItem
                ? "grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch w-full"
                : "mx-auto w-full max-w-2xl"
            }
          >
            {/* History List (Hidden on mobile when an item is selected so mobile has only 1 window!) */}
            <div
              className={`${
                selectedHistoryItem ? "hidden lg:flex lg:col-span-5" : "flex w-full"
              } rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm flex-col h-[calc(100dvh-9.5rem)] max-h-[520px] overflow-hidden`}
            >
              <div className="border-b border-slate-200 dark:border-slate-800 p-4 space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <h2 className="text-base font-bold text-slate-900 dark:text-white">
                    Tarix
                  </h2>
                  <span className="text-xs font-mono text-slate-400">
                    {filteredHistory.length} ta
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Qidirish..."
                    className="flex-1 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 text-xs text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none"
                  />

                  <div className="flex items-center gap-1 p-0.5 bg-slate-100 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                    <button
                      onClick={() => setHistoryFilter("all")}
                      className={`px-2 py-1 text-[11px] font-medium rounded-md ${
                        historyFilter === "all"
                          ? "bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-sm"
                          : "text-slate-500"
                      }`}
                    >
                      Barchasi
                    </button>
                    <button
                      onClick={() => setHistoryFilter("malicious")}
                      className={`px-2 py-1 text-[11px] font-medium rounded-md ${
                        historyFilter === "malicious"
                          ? "bg-rose-500/20 text-rose-600 dark:text-rose-300"
                          : "text-slate-500"
                      }`}
                    >
                      Xavfli
                    </button>
                    <button
                      onClick={() => setHistoryFilter("safe")}
                      className={`px-2 py-1 text-[11px] font-medium rounded-md ${
                        historyFilter === "safe"
                          ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-300"
                          : "text-slate-500"
                      }`}
                    >
                      Toza
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto divide-y divide-slate-200 dark:divide-slate-800">
                {filteredHistory.length === 0 ? (
                  <div className="p-10 text-center space-y-2">
                    <History className="h-7 w-7 text-slate-400 mx-auto" />
                    <div className="text-xs font-medium text-slate-500">
                      Tarix bo'sh
                    </div>
                  </div>
                ) : (
                  filteredHistory.map((item) => {
                    const safetyPct =
                      typeof item.safetyPercentage === "number"
                        ? item.safetyPercentage
                        : Math.max(0, 100 - item.riskScore);
                    const isSelected = selectedHistoryItem?.id === item.id;

                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setSelectedHistoryItem(item)}
                        className={`w-full text-left p-3.5 flex items-center justify-between gap-3 transition-colors ${
                          isSelected
                            ? "bg-emerald-500/10 dark:bg-emerald-500/10"
                            : "hover:bg-slate-50 dark:hover:bg-slate-800/40"
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          {item.verdict === "malicious" ? (
                            <ShieldAlert className="h-4 w-4 text-rose-500 shrink-0" />
                          ) : item.verdict === "suspicious" ? (
                            <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0" />
                          ) : (
                            <ShieldCheck className="h-4 w-4 text-emerald-500 shrink-0" />
                          )}
                          <div className="min-w-0">
                            <div className="font-mono text-xs font-semibold text-slate-900 dark:text-white truncate">
                              {item.targetName}
                            </div>
                            <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                              {item.threatCategory}
                            </div>
                          </div>
                        </div>

                        <div className="text-right font-mono tabular-nums text-xs shrink-0">
                          <span
                            className={`font-bold ${
                              safetyPct >= 75
                                ? "text-emerald-600 dark:text-emerald-400"
                                : safetyPct >= 40
                                ? "text-amber-600 dark:text-amber-400"
                                : "text-rose-600 dark:text-rose-400"
                            }`}
                          >
                            {safetyPct}%
                          </span>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </div>

            {/* Selected History Item Analysis — ONLY rendered after user selects an item! */}
            {selectedHistoryItem && (
              <div className="lg:col-span-7 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-6 shadow-sm flex flex-col justify-between h-[calc(100dvh-9.5rem)] max-h-[520px] overflow-y-auto">
                <div className="space-y-3.5">
                  <div className="flex items-start justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                    <div className="space-y-0.5 min-w-0">
                      <div className="text-xs text-slate-400">
                        {selectedHistoryItem.source === "telegram"
                          ? `Telegram orqali (${selectedHistoryItem.senderName || "-"})`
                          : "Skayner orqali"}
                      </div>
                      <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono truncate">
                        {selectedHistoryItem.targetName}
                      </h3>
                      <div
                        className={`text-xs font-semibold ${
                          selectedHistoryItem.verdict === "malicious"
                            ? "text-rose-600 dark:text-rose-400"
                            : selectedHistoryItem.verdict === "suspicious"
                            ? "text-amber-600 dark:text-amber-400"
                            : "text-emerald-600 dark:text-emerald-400"
                        }`}
                      >
                        {selectedHistoryItem.threatCategory}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => setSelectedHistoryItem(null)}
                      className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-white transition-colors shrink-0"
                      title="Yopish"
                    >
                      <X className="h-5 w-5" />
                    </button>
                  </div>

                  <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3 font-mono tabular-nums text-center">
                    <div>
                      <div className="text-[10px] text-slate-400">Xavfsizlik</div>
                      <div className="text-lg font-bold text-emerald-600 dark:text-emerald-400">
                        {selectedHistoryItem.safetyPercentage ??
                          Math.max(0, 100 - selectedHistoryItem.riskScore)}
                        %
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-400">Ishonchlilik</div>
                      <div className="text-lg font-bold text-sky-600 dark:text-sky-400">
                        {selectedHistoryItem.trustScore ??
                          Math.max(0, 100 - selectedHistoryItem.riskScore)}
                        %
                      </div>
                    </div>
                  </div>

                  {selectedHistoryItem.whatIsInside && (
                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-sky-600 dark:text-sky-400 mb-1">
                        <PackageSearch className="h-4 w-4" />
                        <span>AI Tahlili (Ichida nima bor?)</span>
                      </div>
                      <p className="text-xs italic leading-relaxed text-slate-700 dark:text-slate-200">
                        «{selectedHistoryItem.whatIsInside}»
                      </p>
                    </div>
                  )}

                  {selectedHistoryItem.authenticityVerdict && (
                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400 mb-1">
                        <BadgeCheck className="h-4 w-4" />
                        <span>Haqiqiyligi</span>
                      </div>
                      <p className="text-xs italic leading-relaxed text-slate-700 dark:text-slate-200">
                        «{selectedHistoryItem.authenticityVerdict}»
                      </p>
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
                  <button
                    type="button"
                    onClick={() => setSelectedHistoryItem(null)}
                    className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 hover:underline"
                  >
                    <ArrowLeft className="h-3.5 w-3.5" />
                    <span>Ro'yxatga qaytish</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* =========================================================
            5. QO'LLANMA — Divided into 5 Super-Simple Parts
               ("Hatto 1-sinf o'quvchisi ham tushunadigan tilda")
        ========================================================= */}
        {activeTab === "guide" && (
          <div className="mx-auto w-full max-w-3xl rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 sm:p-6 shadow-sm flex flex-col justify-between h-[calc(100dvh-9.5rem)] max-h-[540px] overflow-y-auto space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <HelpCircle className="h-5 w-5 text-emerald-500" />
                  <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
                    Sodda Qo'llanma (Bo'limlar bo'yicha)
                  </h2>
                </div>
              </div>

              {/* 5 Segmented Guide Sections */}
              <div className="grid grid-cols-5 gap-1 p-1 bg-slate-100 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-semibold">
                <button
                  type="button"
                  onClick={() => setGuideSection("telegram")}
                  className={`py-2 px-1 rounded-lg transition-colors truncate ${
                    guideSection === "telegram"
                      ? "bg-white dark:bg-sky-500 text-slate-900 dark:text-slate-950 shadow-sm"
                      : "text-slate-600 dark:text-slate-400"
                  }`}
                >
                  1. Telegram
                </button>
                <button
                  type="button"
                  onClick={() => setGuideSection("scanner")}
                  className={`py-2 px-1 rounded-lg transition-colors truncate ${
                    guideSection === "scanner"
                      ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                      : "text-slate-600 dark:text-slate-400"
                  }`}
                >
                  2. Skayner
                </button>
                <button
                  type="button"
                  onClick={() => setGuideSection("ai")}
                  className={`py-2 px-1 rounded-lg transition-colors truncate ${
                    guideSection === "ai"
                      ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                      : "text-slate-600 dark:text-slate-400"
                  }`}
                >
                  3. AI
                </button>
                <button
                  type="button"
                  onClick={() => setGuideSection("history")}
                  className={`py-2 px-1 rounded-lg transition-colors truncate ${
                    guideSection === "history"
                      ? "bg-white dark:bg-emerald-500 text-slate-900 dark:text-slate-950 shadow-sm"
                      : "text-slate-600 dark:text-slate-400"
                  }`}
                >
                  4. Tarix
                </button>
                <button
                  type="button"
                  onClick={() => setGuideSection("test")}
                  className={`py-2 px-1 rounded-lg transition-colors truncate ${
                    guideSection === "test"
                      ? "bg-white dark:bg-rose-500 text-slate-900 dark:text-white shadow-sm"
                      : "text-slate-600 dark:text-slate-400"
                  }`}
                >
                  5. Sinash
                </button>
              </div>

              {/* Section 1: Telegram Ulash va Avtorizatsiya */}
              {guideSection === "telegram" && (
                <div className="space-y-3 pt-1 text-xs sm:text-sm">
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-sky-600 dark:text-sky-400">
                      1-Qadam: "Telegram" menyusiga kiring
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Pastdagi menyudan <strong>TELEGRAM</strong> tugmasini bosing va yashil{" "}
                      <strong>"Telegram Orqali Ulash"</strong> tugmasini bosing.
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-emerald-600 dark:text-emerald-400">
                      2-Qadam: Botga START bosing
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Telegramda <strong>@PosbonXBot</strong> ochiladi. Pastdagi{" "}
                      <strong>START (Boshlash)</strong> tugmasini bosing — sayt sizning{" "}
                      <strong>Chat ID</strong> raqamingizni o'zi avtomatik oladi! (Yoki Chat ID raqamingizni qo'lda yozib "Ulash" tugmasini bosishingiz ham mumkin).
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-amber-600 dark:text-amber-400">
                      3-Qadam: Avtomatik himoyani yoqish
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Telegram sozlamalaridan (Telegram Business → Chatbots) <strong>@PosbonXBot</strong> ni qo'shing yoki guruhingizga Admin qiling. Shunda sizga kelgan har bir fayl tekshiriladi va xavfli fayl yoki fishing havola bo'lsa o'zi o'chirib yuboradi (rasm, video va ovozli xabarlar o'chirilmaydi, faqat ogohlantirish keladi)!
                    </p>
                  </div>

                  {/* New Guide Information about /start and /Deleted commands */}
                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-3.5 space-y-2">
                    <div className="font-bold text-emerald-600 dark:text-emerald-400">
                      4-Qadam: Botdagi maxsus buyruqlar (/start va /Deleted)
                    </div>
                    <div className="space-y-1.5 text-slate-700 dark:text-slate-300">
                      <p>
                        • <code className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono font-bold text-emerald-600 dark:text-emerald-400">/start</code> — Botni ishga tushiradi, Telegram akkauntingizni himoya tizimiga ulaydi va shaxsiy <strong>Chat ID</strong> raqamingizni chiqarib beradi.
                      </p>
                      <p>
                        • <code className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono font-bold text-rose-600 dark:text-rose-400">/Deleted</code> — Botga <strong>/Deleted</strong> (yoki <strong>/deleted</strong>) deb yozsangiz, bot avval o'chirib tashlagan barcha <strong>xavfli fayllar, hujjatlar va xavfli havolalar ro'yxatini</strong> (aniq <strong>sanasi va vaqti</strong> hamda <em>kursiv shriftdagi AI tahlili</em> bilan) chiqarib beradi!
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <a
                      href="https://t.me/PosbonXBot"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-xl bg-sky-500 px-4 py-2.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 transition-colors"
                    >
                      <Bot className="h-4 w-4" />
                      <span>@PosbonXBot ga O'tish</span>
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                    <button
                      type="button"
                      onClick={() => setActiveTab("telegram")}
                      className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 hover:underline"
                    >
                      Telegram bo'limini ochish →
                    </button>
                  </div>
                </div>
              )}

              {/* Section 2: Skayner */}
              {guideSection === "scanner" && (
                <div className="space-y-3 pt-1 text-xs sm:text-sm">
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-emerald-600 dark:text-emerald-400">
                      1-Qadam: Nima tekshirishni tanlang
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      <strong>SKAYNER</strong> bo'limida <strong>Fayl</strong>, <strong>Hujjat</strong>, <strong>Rasm</strong>, <strong>Video</strong> yoki <strong>Havola</strong> tugmasidan birini bosing.
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-sky-600 dark:text-sky-400">
                      2-Qadam: Faylni yuklang va "Tekshirish" ni bosing
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      O'rtadagi katakchani bosib telefoningiz yoki kompyuteringizdan faylni tanlang, so'ng yashil <strong>"Tekshirish"</strong> tugmasini bosing.
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-amber-600 dark:text-amber-400">
                      3-Qadam: Natijani ko'ring
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Ekranda fayl <strong>necha foiz xavfsiz (0%–100%)</strong> ekani, ichida nima borligi va haqiqiyligi oddiy so'zlar bilan chiqadi.
                    </p>
                  </div>
                </div>
              )}

              {/* Section 3: AI Yordamchi */}
              {guideSection === "ai" && (
                <div className="space-y-3 pt-1 text-xs sm:text-sm">
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-emerald-600 dark:text-emerald-400">
                      1. Oddiy savol-javob
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Pastki menyuning o'rtasidagi <strong>AI</strong> tugmasini bosing. Unga xuddi oddiy suhbatdoshdek istalgan savolingizni yozishingiz mumkin.
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-sky-600 dark:text-sky-400">
                      2. AI ichida fayl va rasm tekshirtirish
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Yozish oynasining chap tomonidagi <strong>qisqich (📎)</strong> tugmasini bosib, rasm, chek yoki fayl yuboring — AI uni tekshirib, ichida nima borligini aytib beradi.
                    </p>
                  </div>
                </div>
              )}

              {/* Section 4: Tarix */}
              {guideSection === "history" && (
                <div className="space-y-3 pt-1 text-xs sm:text-sm">
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-emerald-600 dark:text-emerald-400">
                      1. Barcha tekshiruvlar ro'yxati
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      <strong>TARIX</strong> bo'limida saytda va Telegramda tekshirilgan barcha fayllar ro'yxati turadi.
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 space-y-1">
                    <div className="font-bold text-sky-600 dark:text-sky-400">
                      2. Ustiga bosib tahlilni ochish
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Ro'yxatdagi istalgan faylning ustiga bossangiz, uning kimdan kelgani, necha foiz xavfsiz ekani va ichida nima borligi (<em>kursiv/talik shriftda</em>) ochiladi.
                    </p>
                  </div>

                  <div className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-3.5 space-y-1">
                    <div className="font-bold text-rose-600 dark:text-rose-400">
                      3. Telegramda o'chirilgan xavflar ro'yxati (/Deleted)
                    </div>
                    <p className="text-slate-700 dark:text-slate-300">
                      Telegram botga kirib <code className="rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 font-mono font-bold">/Deleted</code> buyrug'ini yozsangiz, bot avval o'chirib tashlagan barcha xavfli fayllar, rasmlar va hujjatlar ro'yxatini <strong>sanasi va vaqti</strong> bilan ko'rsatadi.
                    </p>
                  </div>
                </div>
              )}

              {/* Section 5: Tizim va Botni Sinash Tugmalari */}
              {guideSection === "test" && (
                <div className="space-y-3 pt-1">
                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    Quyidagi tugmalardan birini bosib, POSBON AI va{" "}
                    <strong>@PosbonXBot</strong> qanday ishlashini hoziroq tekshirib ko'ring:
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                    <button
                      type="button"
                      disabled={testLoading !== null}
                      onClick={() => handleGuideTest("virus_file")}
                      className="flex items-center justify-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3.5 text-xs font-semibold text-rose-600 dark:text-rose-300 hover:bg-rose-500/20 disabled:opacity-50 transition-colors"
                    >
                      <FileWarning className="h-4 w-4 shrink-0" />
                      <span>
                        {testLoading === "virus_file" ? "Tekshirilmoqda..." : "Virusli Fayl Sinovi"}
                      </span>
                    </button>

                    <button
                      type="button"
                      disabled={testLoading !== null}
                      onClick={() => handleGuideTest("phishing_url")}
                      className="flex items-center justify-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3.5 text-xs font-semibold text-amber-600 dark:text-amber-300 hover:bg-amber-500/20 disabled:opacity-50 transition-colors"
                    >
                      <Link2Off className="h-4 w-4 shrink-0" />
                      <span>
                        {testLoading === "phishing_url" ? "Tekshirilmoqda..." : "Fishing Havola Sinovi"}
                      </span>
                    </button>

                    <button
                      type="button"
                      disabled={testLoading !== null}
                      onClick={() => handleGuideTest("safe_doc")}
                      className="flex items-center justify-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3.5 text-xs font-semibold text-emerald-600 dark:text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50 transition-colors"
                    >
                      <FileCheck2 className="h-4 w-4 shrink-0" />
                      <span>
                        {testLoading === "safe_doc" ? "Tekshirilmoqda..." : "Toza Hujjat Sinovi"}
                      </span>
                    </button>
                  </div>

                  {testNotice && (
                    <div className="rounded-xl border border-emerald-500/30 bg-emerald-50 dark:bg-emerald-950/30 p-3 text-xs text-emerald-700 dark:text-emerald-300">
                      {testNotice}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Bottom Dock Menu — Exact Order: SKAYNER | TELEGRAM | AI | TARIX | QO'LLANMA */}
      <nav className="shrink-0 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
        <div className="mx-auto max-w-xl grid grid-cols-5 items-center px-2 py-1.5">
          {/* 1. SKAYNER */}
          <button
            type="button"
            onClick={() => setActiveTab("scanner")}
            className={`flex flex-col items-center justify-center py-1 rounded-xl text-[11px] font-semibold transition-colors ${
              activeTab === "scanner"
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-slate-500 dark:text-slate-400"
            }`}
          >
            <Shield className="h-5 w-5 mb-0.5" />
            <span>SKAYNER</span>
          </button>

          {/* 2. TELEGRAM */}
          <button
            type="button"
            onClick={() => setActiveTab("telegram")}
            className={`flex flex-col items-center justify-center py-1 rounded-xl text-[11px] font-semibold transition-colors ${
              activeTab === "telegram"
                ? "text-sky-600 dark:text-sky-400"
                : "text-slate-500 dark:text-slate-400"
            }`}
          >
            <Bot className="h-5 w-5 mb-0.5" />
            <span>TELEGRAM</span>
          </button>

          {/* 3. AI (Center) */}
          <button
            type="button"
            onClick={() => setActiveTab("ai")}
            className="flex flex-col items-center justify-center -mt-2.5"
          >
            <div
              className={`flex h-10 w-10 items-center justify-center rounded-2xl shadow-md transition-transform ${
                activeTab === "ai"
                  ? "bg-emerald-500 text-slate-950 scale-105"
                  : "bg-slate-900 dark:bg-emerald-600 text-white"
              }`}
            >
              <Sparkles className="h-5 w-5" />
            </div>
            <span
              className={`mt-0.5 text-[11px] font-bold ${
                activeTab === "ai"
                  ? "text-emerald-600 dark:text-emerald-400"
                  : "text-slate-600 dark:text-slate-300"
              }`}
            >
              AI
            </span>
          </button>

          {/* 4. TARIX */}
          <button
            type="button"
            onClick={() => setActiveTab("history")}
            className={`flex flex-col items-center justify-center py-1 rounded-xl text-[11px] font-semibold transition-colors ${
              activeTab === "history"
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-slate-500 dark:text-slate-400"
            }`}
          >
            <History className="h-5 w-5 mb-0.5" />
            <span>TARIX</span>
          </button>

          {/* 5. QO'LLANMA */}
          <button
            type="button"
            onClick={() => setActiveTab("guide")}
            className={`flex flex-col items-center justify-center py-1 rounded-xl text-[11px] font-semibold transition-colors ${
              activeTab === "guide"
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-slate-500 dark:text-slate-400"
            }`}
          >
            <HelpCircle className="h-5 w-5 mb-0.5" />
            <span>QO'LLANMA</span>
          </button>
        </div>
      </nav>

      <AlertExplainer target={explainerTarget} onClose={() => setExplainerTarget(null)} />

      {/* =========================================================
          SECRET ADMIN PANEL MODAL (Triggered by 3 rapid clicks on POSBON AI logo)
          Password: 0513
      ========================================================= */}
      {showAdminModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-3 sm:p-6 backdrop-blur-sm">
          <div className="relative w-full max-w-4xl rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden flex flex-col max-h-[88dvh]">
            {/* Modal Header */}
            <div className="flex items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 px-5 py-4 bg-slate-50 dark:bg-slate-950/60">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                  <Database className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white">
                    POSBON AI — Maxfiy Admin Panel va Ma'lumotlar Bazasi
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {adminUnlocked
                      ? "Telegram akkauntini ulagan foydalanuvchilar va o'chirilgan xavfli fayllar bazasi"
                      : "Boshqaruv paneliga kirish uchun maxfiy parolni kiriting"}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {adminUnlocked && (
                  <button
                    type="button"
                    onClick={() => fetchAdminDatabase("0513")}
                    disabled={adminLoading}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${adminLoading ? "animate-spin" : ""}`} />
                    <span>Yangilash</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    setShowAdminModal(false);
                    setAdminError(null);
                  }}
                  className="rounded-xl p-2 text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-white transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            {!adminUnlocked ? (
              <form onSubmit={handleAdminLoginSubmit} className="p-6 sm:p-8 max-w-md mx-auto w-full space-y-4">
                <div className="text-center space-y-1.5">
                  <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                    <Lock className="h-6 w-6" />
                  </div>
                  <h4 className="text-base font-bold text-slate-900 dark:text-white">
                    Maxfiy Admin Paroli
                  </h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Ma'lumotlar bazasini ko'rish uchun 4 xonali maxfiy kodni kiriting:
                  </p>
                </div>

                <input
                  type="password"
                  value={adminPassword}
                  onChange={(e) => setAdminPassword(e.target.value)}
                  placeholder="••••"
                  autoFocus
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-4 py-3 text-center text-lg font-mono tracking-widest text-slate-900 dark:text-white focus:border-emerald-500 focus:outline-none"
                />

                {adminError && (
                  <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-center text-xs font-medium text-rose-600 dark:text-rose-300">
                    {adminError}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={adminLoading || !adminPassword.trim()}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 dark:bg-emerald-500 px-5 py-3 text-sm font-semibold text-white dark:text-slate-950 hover:bg-emerald-500 dark:hover:bg-emerald-400 disabled:opacity-50 transition-colors"
                >
                  {adminLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
                  <span>Bazani Ochish</span>
                </button>
              </form>
            ) : (
              <div className="p-4 sm:p-6 space-y-4 overflow-y-auto flex-1">
                {/* Summary Stats Strip */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 text-center">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Ulangan Foydalanuvchilar
                    </div>
                    <div className="mt-1 text-xl font-bold font-mono text-emerald-600 dark:text-emerald-400">
                      {adminStats.totalUsers} ta
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 text-center">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      O'chirilgan Xavflar (/Deleted)
                    </div>
                    <div className="mt-1 text-xl font-bold font-mono text-rose-600 dark:text-rose-400">
                      {adminStats.totalDeleted} ta
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3.5 text-center">
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      Jami Tekshiruvlar
                    </div>
                    <div className="mt-1 text-xl font-bold font-mono text-sky-600 dark:text-sky-400">
                      {adminStats.totalScanned} ta
                    </div>
                  </div>
                </div>

                {/* Switch between Linked Users DB and Deleted Files DB */}
                <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
                  <button
                    type="button"
                    onClick={() => setAdminTab("users")}
                    className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition-colors ${
                      adminTab === "users"
                        ? "bg-emerald-600 text-white dark:bg-emerald-500 dark:text-slate-950"
                        : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
                    }`}
                  >
                    <Users className="h-4 w-4" />
                    <span>Ulangan Foydalanuvchilar ({adminUsers.length})</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setAdminTab("deleted")}
                    className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition-colors ${
                      adminTab === "deleted"
                        ? "bg-rose-600 text-white"
                        : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
                    }`}
                  >
                    <Trash2 className="h-4 w-4" />
                    <span>O'chirilgan Xavfli Fayllar (/Deleted) ({adminDeletedFiles.length})</span>
                  </button>
                </div>

                {/* Tab 1: Linked Telegram Users List with ID and Date/Time */}
                {adminTab === "users" && (
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    {adminUsers.length === 0 ? (
                      <div className="p-8 text-center text-xs text-slate-500">
                        Hozircha Telegram akkauntini ulagan foydalanuvchilar yo'q.
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse text-xs">
                          <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 font-semibold">
                              <th className="py-3 px-3.5">#</th>
                              <th className="py-3 px-3.5">Foydalanuvchi</th>
                              <th className="py-3 px-3.5">Telegram ID (Chat ID)</th>
                              <th className="py-3 px-3.5">Ulangan Sanasi va Vaqti</th>
                              <th className="py-3 px-3.5 text-center">Tekshirildi / O'chirildi</th>
                              <th className="py-3 px-3.5 text-right">Holati</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                            {adminUsers.map((u, idx) => (
                              <tr
                                key={u.chatId}
                                className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                              >
                                <td className="py-3 px-3.5 font-mono text-slate-400">{idx + 1}</td>
                                <td className="py-3 px-3.5">
                                  <div className="font-bold text-slate-900 dark:text-white">
                                    {[u.firstName, u.lastName].filter(Boolean).join(" ")}
                                  </div>
                                  {u.username && (
                                    <div className="text-[11px] font-mono text-sky-600 dark:text-sky-400">
                                      @{u.username}
                                    </div>
                                  )}
                                </td>
                                <td className="py-3 px-3.5">
                                  <span className="inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-950 px-2.5 py-1 font-mono font-bold text-slate-800 dark:text-emerald-400">
                                    {u.chatId}
                                  </span>
                                </td>
                                <td className="py-3 px-3.5 font-mono text-slate-700 dark:text-slate-300">
                                  <div className="inline-flex items-center gap-1.5">
                                    <Calendar className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                                    <span>{u.linkedAtFormatted}</span>
                                  </div>
                                </td>
                                <td className="py-3 px-3.5 text-center font-mono">
                                  <span className="text-emerald-600 dark:text-emerald-400 font-bold">
                                    {u.stats?.totalScanned ?? 0}
                                  </span>
                                  {" / "}
                                  <span className="text-rose-600 dark:text-rose-400 font-bold">
                                    {u.stats?.threatsDeleted ?? 0}
                                  </span>
                                </td>
                                <td className="py-3 px-3.5 text-right">
                                  <span
                                    className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-bold ${
                                      u.isActive
                                        ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                                        : "bg-slate-500/15 text-slate-500"
                                    }`}
                                  >
                                    {u.isActive ? "Faol" : "O'chiq"}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}

                {/* Tab 2: Deleted Dangerous Files (/Deleted) with Date & Time and Italic AI Result */}
                {adminTab === "deleted" && (
                  <div className="space-y-2.5">
                    {adminDeletedFiles.length === 0 ? (
                      <div className="rounded-xl border border-slate-200 dark:border-slate-800 p-8 text-center text-xs text-slate-500">
                        Hozircha o'chirilgan xavfli fayllar yo'q.
                      </div>
                    ) : (
                      adminDeletedFiles.map((item, idx) => (
                        <div
                          key={item.id}
                          className="rounded-xl border border-rose-500/25 bg-rose-500/5 p-3.5 space-y-1.5 text-xs"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="font-mono font-bold text-slate-900 dark:text-white">
                              {idx + 1}. {item.targetName}{" "}
                              <span className="text-rose-600 dark:text-rose-400">
                                ({item.threatCategory} — Xavf: {item.riskScore}%)
                              </span>
                            </div>
                            <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              📅 {item.timestampFormatted}
                            </div>
                          </div>
                          <div className="text-slate-600 dark:text-slate-300">
                            Kimdan: <strong>{item.senderName}</strong> (Chat ID:{" "}
                            <code className="font-mono">{item.chatId}</code>)
                          </div>
                          <div className="italic text-slate-700 dark:text-slate-200">
                            AI Tahlili: «{item.whatIsInside}»
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
