import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Send,
  Loader2,
  X,
  PackageSearch,
  BadgeCheck,
} from "lucide-react";

export interface ExplainerTarget {
  targetName: string;
  threatCategory: string;
  verdict: "safe" | "suspicious" | "malicious";
  isCompletelySafe?: boolean;
  safetyPercentage?: number;
  riskScore: number;
  trustScore?: number;
  detectedFormat?: string;
  whatIsInside?: string;
  authenticityVerdict?: string;
  politeSummary: string;
  technicalDetails: string[];
  recommendations: string[];
  senderName?: string;
}

interface AlertExplainerProps {
  target: ExplainerTarget | null;
  onClose: () => void;
}

export const AlertExplainer: React.FC<AlertExplainerProps> = ({ target, onClose }) => {
  const [question, setQuestion] = useState("");
  const [aiReply, setAiReply] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!target) return null;

  const safetyPct =
    typeof target.safetyPercentage === "number"
      ? target.safetyPercentage
      : Math.max(0, 100 - target.riskScore);
  const trustPct =
    typeof target.trustScore === "number" ? target.trustScore : safetyPct;

  const handleAskExplanation = async (customQuestion?: string) => {
    const q = customQuestion ?? question;
    setLoading(true);
    try {
      const res = await fetch("/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetName: target.targetName,
          threatCategory: target.threatCategory,
          verdict: target.verdict,
          technicalDetails: target.technicalDetails,
          userQuestion: q || undefined,
        }),
      });
      const data = await res.json();
      if (data.explanation) {
        setAiReply(data.explanation);
      }
      if (!customQuestion) setQuestion("");
    } catch {
      setAiReply("Tarmoq xatoligi. Yuqoridagi xavfsizlik xulosasiga amal qiling.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-slate-950/70 p-0 sm:p-4 backdrop-blur-sm">
      <div className="relative w-full max-w-xl rounded-t-2xl sm:rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3.5">
          <div className="flex items-center gap-2.5 min-w-0">
            {target.verdict === "malicious" ? (
              <ShieldAlert className="h-6 w-6 text-rose-500 shrink-0" />
            ) : target.verdict === "suspicious" ? (
              <AlertTriangle className="h-6 w-6 text-amber-500 shrink-0" />
            ) : (
              <ShieldCheck className="h-6 w-6 text-emerald-500 shrink-0" />
            )}
            <div className="min-w-0">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 truncate">
                {target.threatCategory}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono truncate">
                {target.targetName}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 dark:text-slate-400 transition-colors"
            aria-label="Yopish"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="mt-4 space-y-3.5 max-h-[70vh] overflow-y-auto pr-1">
          {/* Compact 3-Metric Strip */}
          <div className="grid grid-cols-3 gap-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-3 font-mono tabular-nums text-center">
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Holati</div>
              <div
                className={`mt-0.5 text-xs sm:text-sm font-bold ${
                  target.verdict === "safe"
                    ? "text-emerald-600 dark:text-emerald-400"
                    : target.verdict === "suspicious"
                    ? "text-amber-600 dark:text-amber-400"
                    : "text-rose-600 dark:text-rose-400"
                }`}
              >
                {target.verdict === "safe"
                  ? "XAVFSIZ"
                  : target.verdict === "suspicious"
                  ? "SHUBHALI"
                  : "XAVFLI"}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Xavfsizlik</div>
              <div className="mt-0.5 text-base font-bold text-emerald-600 dark:text-emerald-400">
                {safetyPct}%
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">Ishonchlilik</div>
              <div className="mt-0.5 text-base font-bold text-sky-600 dark:text-sky-400">
                {trustPct}%
              </div>
            </div>
          </div>

          {target.whatIsInside && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-sky-600 dark:text-sky-400 mb-1">
                <PackageSearch className="h-4 w-4" />
                <span>AI Tahlili (Ichida nima bor?)</span>
              </div>
              <p className="text-xs sm:text-sm italic leading-relaxed text-slate-700 dark:text-slate-200">
                «{target.whatIsInside}»
              </p>
            </div>
          )}

          {target.authenticityVerdict && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-3.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400 mb-1">
                <BadgeCheck className="h-4 w-4" />
                <span>Haqiqiyligi</span>
              </div>
              <p className="text-xs sm:text-sm italic leading-relaxed text-slate-700 dark:text-slate-200">
                «{target.authenticityVerdict}»
              </p>
            </div>
          )}

          {aiReply && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-50 dark:bg-emerald-950/20 p-3.5">
              <div className="text-xs font-semibold text-emerald-700 dark:text-emerald-300 mb-1">
                AI Javobi:
              </div>
              <p className="text-xs sm:text-sm italic leading-relaxed text-slate-800 dark:text-slate-200 whitespace-pre-line">
                {aiReply}
              </p>
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleAskExplanation("Ichida qanday xavf bor?")}
              disabled={loading}
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950 px-3 py-1.5 text-xs text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              Ichida qanday xavf bor?
            </button>
            <button
              onClick={() => handleAskExplanation("Ma'lumotlar haqiqiymi?")}
              disabled={loading}
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-950 px-3 py-1.5 text-xs text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              Ma'lumotlar haqiqiymi?
            </button>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (question.trim()) handleAskExplanation();
            }}
            className="flex items-center gap-2 pt-1"
          >
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="AI ga savol yozing..."
              className="flex-1 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 px-3.5 py-2.5 text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:border-emerald-500 focus:outline-none"
            />
            <button
              type="submit"
              disabled={loading || !question.trim()}
              className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              <span>So'rash</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
