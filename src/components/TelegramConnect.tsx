import React, { useState, useEffect, useCallback } from "react";
import {
  Bot,
  CheckCircle2,
  ExternalLink,
  RefreshCw,
  Copy,
  Check,
  UserCheck,
  LogOut,
  ShieldCheck,
} from "lucide-react";

export interface LinkedUserClient {
  chatId: string;
  userId: number;
  username?: string;
  firstName: string;
  lastName?: string;
  linkedAt: string;
  isActive: boolean;
  autoDeleteThreats: boolean;
  notifyOnSafe: boolean;
  businessConnectionId?: string;
  stats: {
    totalScanned: number;
    threatsDeleted: number;
    safePassed: number;
  };
}

export interface TelegramThreatEventClient {
  id: string;
  chatId: string;
  chatTitle?: string;
  messageId: number;
  senderName: string;
  senderUsername?: string;
  targetName: string;
  targetType: string;
  verdict: "safe" | "suspicious" | "malicious";
  isCompletelySafe?: boolean;
  safetyPercentage?: number;
  riskScore: number;
  trustScore?: number;
  threatCategory: string;
  whatIsInside?: string;
  authenticityVerdict?: string;
  politeSummary: string;
  deletedAutomatically: boolean;
  botNotified: boolean;
  timestamp: string;
  analysisResult: {
    detectedFormat?: string;
    technicalDetails: string[];
    recommendations: string[];
  };
}

interface TelegramConnectProps {
  onStatusChange?: (
    linked: boolean,
    chatId?: string,
    events?: TelegramThreatEventClient[]
  ) => void;
  onPlaySound?: (type: "scan" | "safe" | "threat" | "linked") => void;
}

export const TelegramConnect: React.FC<TelegramConnectProps> = ({
  onStatusChange,
  onPlaySound,
}) => {
  const [sessionId, setSessionId] = useState<string>(() => {
    return localStorage.getItem("posbon_tg_session") || "";
  });
  const [authUrl, setAuthUrl] = useState<string>("https://t.me/PosbonXBot");
  const [botUsername, setBotUsername] = useState<string>("PosbonXBot");
  const [linkedUser, setLinkedUser] = useState<LinkedUserClient | null>(null);
  const [isWaitingForStart, setIsWaitingForStart] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);
  const [manualChatId, setManualChatId] = useState<string>("");
  const [manualError, setManualError] = useState<string | null>(null);
  const [manualLoading, setManualLoading] = useState<boolean>(false);

  const initAuthSession = useCallback(async () => {
    try {
      const res = await fetch("/api/telegram/session", { method: "POST" });
      const data = await res.json();
      if (data.sessionId) {
        setSessionId(data.sessionId);
        localStorage.setItem("posbon_tg_session", data.sessionId);
      }
      if (data.authUrl) setAuthUrl(data.authUrl);
      if (data.botUsername) setBotUsername(data.botUsername);
    } catch {
      // ignore
    }
  }, []);

  const fetchTelegramStatus = useCallback(async () => {
    try {
      const savedChatId = localStorage.getItem("posbon_tg_chat_id") || "";
      const res = await fetch(
        `/api/telegram/status?sessionId=${encodeURIComponent(sessionId)}&chatId=${encodeURIComponent(savedChatId)}`
      );
      const data = await res.json();
      if (data.botProfile?.username) {
        setBotUsername(data.botProfile.username);
      }
      if (data.linked && data.user) {
        const wasUnlinked = !linkedUser;
        setLinkedUser(data.user);
        localStorage.setItem("posbon_tg_chat_id", data.user.chatId);
        setIsWaitingForStart(false);
        if (wasUnlinked && onPlaySound) {
          onPlaySound("linked");
        }
        if (onStatusChange) {
          onStatusChange(true, data.user.chatId, data.events || []);
        }
      } else {
        setLinkedUser(null);
        if (onStatusChange) {
          onStatusChange(false, undefined, data.events || []);
        }
      }
    } catch {
      // ignore
    }
  }, [sessionId, linkedUser, onPlaySound, onStatusChange]);

  useEffect(() => {
    if (!sessionId) {
      initAuthSession();
    } else {
      setAuthUrl(`https://t.me/${botUsername}?start=auth_${sessionId}`);
    }
  }, [sessionId, botUsername, initAuthSession]);

  useEffect(() => {
    fetchTelegramStatus();
    const interval = setInterval(fetchTelegramStatus, 2500);
    return () => clearInterval(interval);
  }, [fetchTelegramStatus]);

  const handleCopyStartCmd = () => {
    const cmd = sessionId ? `/start auth_${sessionId}` : "/start";
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleManualLink = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualChatId.trim()) return;
    setManualLoading(true);
    setManualError(null);
    try {
      const res = await fetch("/api/telegram/manual-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chatId: manualChatId.trim() }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setManualError(data.error || "Ulashda xatolik");
      } else if (data.user) {
        setLinkedUser(data.user);
        localStorage.setItem("posbon_tg_chat_id", data.user.chatId);
        setManualChatId("");
        if (onPlaySound) onPlaySound("linked");
      }
    } catch {
      setManualError("Xatolik yuz berdi.");
    } finally {
      setManualLoading(false);
    }
  };

  const handleToggleSetting = async (field: "isActive" | "autoDeleteThreats", value: boolean) => {
    if (!linkedUser) return;
    try {
      const res = await fetch("/api/telegram/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chatId: linkedUser.chatId,
          [field]: value,
        }),
      });
      const data = await res.json();
      if (data.user) {
        setLinkedUser(data.user);
      }
    } catch {
      // ignore
    }
  };

  const handleUnlink = async () => {
    if (!linkedUser) return;
    await fetch("/api/telegram/unlink", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chatId: linkedUser.chatId }),
    });
    localStorage.removeItem("posbon_tg_chat_id");
    setLinkedUser(null);
    initAuthSession();
  };

  return (
    <div className="mx-auto w-full max-w-xl">
      {!linkedUser ? (
        /* Single Clean Window for Authorization — Zero extra helper text */
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-7 shadow-sm space-y-5">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400">
                <Bot className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
                  Telegram Avtorizatsiya
                </h2>
                <span className="text-xs font-mono text-sky-600 dark:text-sky-400">
                  @{botUsername}
                </span>
              </div>
            </div>

            <RefreshCw
              className={`h-4 w-4 text-sky-500 ${isWaitingForStart ? "animate-spin" : ""}`}
            />
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
            <a
              href={authUrl}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => setIsWaitingForStart(true)}
              className="flex-1 inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 dark:bg-emerald-500 px-5 py-3.5 text-sm font-semibold text-white dark:text-slate-950 hover:bg-emerald-500 dark:hover:bg-emerald-400 transition-colors whitespace-nowrap shrink-0"
            >
              <UserCheck className="h-4 w-4" />
              <span>Telegram Orqali Ulash</span>
              <ExternalLink className="h-4 w-4" />
            </a>

            <button
              type="button"
              onClick={handleCopyStartCmd}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-4 py-3.5 text-xs font-mono text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              {copiedCmd ? (
                <Check className="h-4 w-4 text-emerald-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
              <span>{copiedCmd ? "Nusxalandi" : "Kod"}</span>
            </button>
          </div>

          <form
            onSubmit={handleManualLink}
            className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-2"
          >
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={manualChatId}
                onChange={(e) => setManualChatId(e.target.value)}
                placeholder="Chat ID kiriting"
                className="flex-1 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-3.5 py-3 text-sm font-mono text-slate-900 dark:text-white placeholder:text-slate-400 focus:border-sky-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={manualLoading || !manualChatId.trim()}
                className="rounded-xl bg-slate-900 dark:bg-slate-800 px-5 py-3 text-xs font-semibold text-white hover:bg-slate-800 dark:hover:bg-slate-700 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0"
              >
                {manualLoading ? "..." : "Ulash"}
              </button>
            </div>
            {manualError && <p className="text-xs text-rose-500">{manualError}</p>}
          </form>
        </div>
      ) : (
        /* Single Clean Connected Window */
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-7 shadow-sm space-y-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 text-xs font-semibold">
                <CheckCircle2 className="h-4 w-4" />
                <span>Ulangan</span>
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white mt-0.5">
                {linkedUser.firstName} {linkedUser.lastName || ""}
              </h3>
              <div className="text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                ID: {linkedUser.chatId}
                {linkedUser.username ? ` · @${linkedUser.username}` : ""}
              </div>
            </div>

            <button
              onClick={handleUnlink}
              className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 dark:border-slate-800 px-3 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-rose-500 transition-colors whitespace-nowrap shrink-0"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Uzish</span>
            </button>
          </div>

          <div className="grid grid-cols-3 gap-2 border-y border-slate-200 dark:border-slate-800 py-3.5 text-center font-mono tabular-nums">
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Tekshirildi</div>
              <div className="text-lg font-bold text-slate-900 dark:text-white">
                {linkedUser.stats.totalScanned}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">O'chirildi</div>
              <div className="text-lg font-bold text-rose-500">
                {linkedUser.stats.threatsDeleted}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Xavfsiz</div>
              <div className="text-lg font-bold text-emerald-500">
                {linkedUser.stats.safePassed}
              </div>
            </div>
          </div>

          <div className="space-y-2.5">
            <label className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-3.5 py-3 cursor-pointer">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-500" />
                <span className="text-xs sm:text-sm font-semibold text-slate-800 dark:text-slate-200">
                  Avtomatik Fayl Tahlili
                </span>
              </div>
              <input
                type="checkbox"
                checked={linkedUser.isActive}
                onChange={(e) => handleToggleSetting("isActive", e.target.checked)}
                className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 text-emerald-600"
              />
            </label>

            <label className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-3.5 py-3 cursor-pointer">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-rose-500" />
                <span className="text-xs sm:text-sm font-semibold text-slate-800 dark:text-slate-200">
                  Xavflilarni Avto-O'chirish
                </span>
              </div>
              <input
                type="checkbox"
                checked={linkedUser.autoDeleteThreats}
                onChange={(e) => handleToggleSetting("autoDeleteThreats", e.target.checked)}
                className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 text-emerald-600"
              />
            </label>
          </div>

          <a
            href={`https://t.me/${botUsername}`}
            target="_blank"
            rel="noopener noreferrer"
            className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-3 text-xs sm:text-sm font-semibold text-slate-950 hover:bg-sky-400 transition-colors"
          >
            <Bot className="h-4 w-4" />
            <span>@{botUsername} ga o'tish</span>
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
      )}
    </div>
  );
};
