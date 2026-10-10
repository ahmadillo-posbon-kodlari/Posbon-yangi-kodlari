import React from "react";
import { ShieldCheck, Bot } from "lucide-react";

interface CreditsBannerProps {
  totalScans: number;
  threatsBlocked: number;
  telegramLinked: boolean;
  telegramChatId?: string;
  onOpenTelegram: () => void;
}

export const CreditsBanner: React.FC<CreditsBannerProps> = ({
  totalScans,
  threatsBlocked,
  telegramLinked,
  telegramChatId,
  onOpenTelegram,
}) => {
  return (
    <div className="border-b border-slate-800/80 bg-slate-900/60 px-6 py-3">
      <div className="mx-auto flex max-w-[1280px] flex-wrap items-center justify-between gap-4 text-xs text-slate-400">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" />
          <span className="text-slate-200 font-medium">
            Assalomu alaykum, xush kelibsiz! POSBON AI xavfsizligingiz xizmatida
          </span>
          <span aria-hidden="true">·</span>
          <span className="font-mono tabular-nums">
            Tekshiruvlar: <strong className="text-slate-200">{totalScans}</strong>
          </span>
          <span aria-hidden="true">·</span>
          <span className="font-mono tabular-nums">
            To'xtatilgan xavflar: <strong className="text-rose-400">{threatsBlocked}</strong>
          </span>
        </div>

        <div className="flex items-center gap-3">
          {telegramLinked ? (
            <button
              onClick={onOpenTelegram}
              className="flex items-center gap-2 text-emerald-400 hover:text-emerald-300 transition-colors font-medium whitespace-nowrap shrink-0"
            >
              <Bot className="h-3.5 w-3.5" />
              <span>@POSBON_RO_BOT Ulangan</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums text-slate-300">ID: {telegramChatId}</span>
            </button>
          ) : (
            <button
              onClick={onOpenTelegram}
              className="flex items-center gap-1.5 text-sky-400 hover:text-sky-300 transition-colors font-medium whitespace-nowrap shrink-0"
            >
              <Bot className="h-3.5 w-3.5" />
              <span>Telegram akkauntni ulash (@POSBON_RO_BOT)</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
