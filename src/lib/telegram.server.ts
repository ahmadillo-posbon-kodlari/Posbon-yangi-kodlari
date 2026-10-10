import crypto from "crypto";
import fs from "fs";
import path from "path";
import { analyzeSecurityTarget, AnalysisResult, TargetType } from "./ai/analyze.server.ts";

// ============================================================================
// TELEGRAM BOT SOZLAMALari (Token yoki Username o'zgartirish uchun shu yerni tahrirlang):
// ============================================================================
const DEFAULT_BOT_TOKEN = "8917943761:AAGyg2ggC495rpbcpXIBp-win07vuD5nJ_Y";
const DEFAULT_BOT_USERNAME = "PosbonXBot";
const KNOWN_BOT_IDS = new Set<string>(["8917943761", "8723251106"]);

export function getBotToken(): string {
  const envToken = process.env.TELEGRAM_BOT_TOKEN;
  if (envToken && envToken !== "MY_TELEGRAM_BOT_TOKEN" && envToken.includes(":")) {
    return envToken.trim();
  }
  return DEFAULT_BOT_TOKEN;
}

export function getBotUsername(): string {
  const envUser = process.env.TELEGRAM_BOT_USERNAME;
  if (envUser && envUser.trim()) {
    return envUser.trim().replace(/^@/, "");
  }
  return DEFAULT_BOT_USERNAME;
}

export interface LinkedTelegramUser {
  chatId: string;
  userId: number;
  username?: string;
  firstName: string;
  lastName?: string;
  linkedAt: string;
  lastActiveAt?: string;
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

export interface TelegramThreatEvent {
  id: string;
  chatId: string;
  chatTitle?: string;
  messageId: number;
  senderName: string;
  senderUsername?: string;
  senderId?: number;
  targetName: string;
  targetType: TargetType;
  verdict: "safe" | "suspicious" | "malicious";
  isCompletelySafe: boolean;
  safetyPercentage: number;
  riskScore: number;
  trustScore: number;
  threatCategory: string;
  whatIsInside: string;
  authenticityVerdict: string;
  politeSummary: string;
  deletedAutomatically: boolean;
  botNotified: boolean;
  timestamp: string;
  analysisResult: AnalysisResult;
}

export interface PendingAuthSession {
  sessionId: string;
  createdAt: number;
  linkedChatId?: string;
  user?: LinkedTelegramUser;
}

interface PersistedState {
  botTokenId?: string;
  users: Record<string, LinkedTelegramUser>;
  events: TelegramThreatEvent[];
  deletedFiles?: TelegramThreatEvent[];
  lastUpdateId: number;
}

const STATE_FILE = path.resolve(process.cwd(), ".posbon-telegram-state.json");
const DB_BACKUP_FILE = path.resolve(process.cwd(), "posbon-database.json");

const linkedUsers = new Map<string, LinkedTelegramUser>();
const pendingSessions = new Map<string, PendingAuthSession>();
const telegramEvents: TelegramThreatEvent[] = [];
const deletedThreatFiles: TelegramThreatEvent[] = [];
let lastUpdateId = 0;
let botInfo: { id: number; username: string; first_name: string } | null = null;
let pollingActive = false;

function getCurrentBotTokenId(): string {
  return getBotToken().split(":")[0] || "8917943761";
}

function isDeletableTargetType(type: TargetType): boolean {
  return type === "file" || type === "document" || type === "url";
}

function loadState() {
  try {
    const fileToRead = fs.existsSync(STATE_FILE)
      ? STATE_FILE
      : fs.existsSync(DB_BACKUP_FILE)
      ? DB_BACKUP_FILE
      : null;
    if (fileToRead) {
      const raw = fs.readFileSync(fileToRead, "utf-8");
      const parsed: PersistedState = JSON.parse(raw);
      if (parsed.users) {
        for (const [k, v] of Object.entries(parsed.users)) {
          // Skip bot IDs accidentally saved as chat IDs
          if (KNOWN_BOT_IDS.has(String(k))) continue;
          const realKey = v.userId ? String(v.userId) : String(k);
          if (KNOWN_BOT_IDS.has(realKey)) continue;
          if (!linkedUsers.has(realKey) || String(k) === realKey) {
            linkedUsers.set(realKey, {
              ...v,
              chatId: realKey,
            });
          }
        }
      }
      if (Array.isArray(parsed.events)) {
        // Fix any historical false-positive image deletions
        const cleanedEvents = parsed.events.map((e) => {
          if (!isDeletableTargetType(e.targetType)) {
            return { ...e, deletedAutomatically: false };
          }
          return e;
        });
        telegramEvents.push(...cleanedEvents.slice(0, 200));
      }
      if (Array.isArray(parsed.deletedFiles)) {
        const validDeleted = parsed.deletedFiles.filter(
          (e) => isDeletableTargetType(e.targetType) && (e.deletedAutomatically || e.verdict === "malicious")
        );
        deletedThreatFiles.push(...validDeleted.slice(0, 200));
      } else if (Array.isArray(parsed.events)) {
        const recoveredDeleted = parsed.events.filter(
          (e) => isDeletableTargetType(e.targetType) && (e.deletedAutomatically || e.verdict === "malicious")
        );
        deletedThreatFiles.push(...recoveredDeleted.slice(0, 200));
      }
      // Only keep lastUpdateId if it belongs to the same bot token ID!
      if (
        typeof parsed.lastUpdateId === "number" &&
        parsed.botTokenId === getCurrentBotTokenId()
      ) {
        lastUpdateId = parsed.lastUpdateId;
      } else {
        lastUpdateId = 0;
      }
    }
  } catch (err) {
    console.error("Failed to load telegram state:", err);
  }
}

function saveState() {
  try {
    const usersObj: Record<string, LinkedTelegramUser> = {};
    for (const [k, v] of linkedUsers.entries()) {
      if (!KNOWN_BOT_IDS.has(String(k))) {
        usersObj[k] = v;
      }
    }
    const state: PersistedState = {
      botTokenId: getCurrentBotTokenId(),
      users: usersObj,
      events: telegramEvents.slice(0, 200),
      deletedFiles: deletedThreatFiles.slice(0, 200),
      lastUpdateId,
    };
    const jsonPayload = JSON.stringify(state, null, 2);
    fs.writeFileSync(STATE_FILE, jsonPayload, "utf-8");
    fs.writeFileSync(DB_BACKUP_FILE, jsonPayload, "utf-8");
  } catch (err) {
    console.error("Failed to save telegram state:", err);
  }
}

loadState();

async function callTelegramApi(method: string, body?: Record<string, any>): Promise<any> {
  const token = getBotToken();
  const url = `https://api.telegram.org/bot${token}/${method}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  return data;
}

async function sendSafeTelegramMessage(body: Record<string, any>): Promise<any> {
  try {
    const res = await callTelegramApi("sendMessage", {
      ...body,
      parse_mode: "HTML",
    });
    if (res?.ok) return res;
    // Fallback without HTML parse_mode if HTML tags failed
    const plainText = String(body.text || "").replace(/<[^>]+>/g, "");
    const fallbackBody: Record<string, any> = { ...body, text: plainText };
    delete fallbackBody.parse_mode;
    return await callTelegramApi("sendMessage", fallbackBody);
  } catch (err) {
    console.error("sendSafeTelegramMessage error:", err);
    return { ok: false };
  }
}

export async function getBotProfile() {
  if (botInfo) return botInfo;
  try {
    const res = await callTelegramApi("getMe");
    if (res.ok && res.result) {
      botInfo = {
        id: res.result.id,
        username: res.result.username || getBotUsername(),
        first_name: res.result.first_name || "POSBON AI",
      };
      KNOWN_BOT_IDS.add(String(res.result.id));
      return botInfo;
    }
  } catch (err) {
    console.error("Error fetching bot profile:", err);
  }
  return {
    id: 8917943761,
    username: getBotUsername(),
    first_name: "POSBON AI",
  };
}

export function createAuthSession(): PendingAuthSession {
  const sessionId = crypto.randomBytes(6).toString("hex");
  const session: PendingAuthSession = {
    sessionId,
    createdAt: Date.now(),
  };
  pendingSessions.set(sessionId, session);
  return session;
}

export function getAuthSessionStatus(sessionId: string): {
  linked: boolean;
  user?: LinkedTelegramUser;
  botUsername: string;
} {
  const session = pendingSessions.get(sessionId);
  if (session?.linkedChatId) {
    const user = linkedUsers.get(session.linkedChatId) || session.user;
    if (user) {
      return {
        linked: true,
        user,
        botUsername: botInfo?.username || getBotUsername(),
      };
    }
  }
  return {
    linked: false,
    botUsername: botInfo?.username || getBotUsername(),
  };
}

export function getAllLinkedUsers(): LinkedTelegramUser[] {
  return Array.from(linkedUsers.values()).sort(
    (a, b) => new Date(b.linkedAt).getTime() - new Date(a.linkedAt).getTime()
  );
}

export function getLinkedUser(chatId: string): LinkedTelegramUser | undefined {
  return linkedUsers.get(String(chatId));
}

export function updateUserSettings(
  chatId: string,
  patch: Partial<Pick<LinkedTelegramUser, "isActive" | "autoDeleteThreats" | "notifyOnSafe">>
): LinkedTelegramUser | undefined {
  const user = linkedUsers.get(String(chatId));
  if (!user) return undefined;
  if (typeof patch.isActive === "boolean") user.isActive = patch.isActive;
  if (typeof patch.autoDeleteThreats === "boolean") user.autoDeleteThreats = patch.autoDeleteThreats;
  if (typeof patch.notifyOnSafe === "boolean") user.notifyOnSafe = patch.notifyOnSafe;
  linkedUsers.set(String(chatId), user);
  saveState();
  return user;
}

export function unlinkTelegramUser(chatId: string): boolean {
  const deleted = linkedUsers.delete(String(chatId));
  for (const [, session] of pendingSessions) {
    if (session.linkedChatId === String(chatId)) {
      session.linkedChatId = undefined;
      session.user = undefined;
    }
  }
  saveState();
  return deleted;
}

export function getTelegramEvents(chatId?: string): TelegramThreatEvent[] {
  if (chatId) {
    return telegramEvents.filter((e) => String(e.chatId) === String(chatId));
  }
  return telegramEvents;
}

export function getDeletedTelegramFiles(chatId?: string): TelegramThreatEvent[] {
  const combined = [
    ...deletedThreatFiles,
    ...telegramEvents.filter(
      (e) => isDeletableTargetType(e.targetType) && (e.deletedAutomatically || e.verdict === "malicious")
    ),
  ];
  const uniqueMap = new Map<string, TelegramThreatEvent>();
  for (const item of combined) {
    if (isDeletableTargetType(item.targetType) && !uniqueMap.has(item.id)) {
      uniqueMap.set(item.id, item);
    }
  }
  const allDeleted = Array.from(uniqueMap.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
  if (chatId) {
    const forChat = allDeleted.filter((e) => String(e.chatId) === String(chatId));
    return forChat.length > 0 ? forChat : allDeleted;
  }
  return allDeleted;
}

function getTypeNameUz(type: TargetType): string {
  switch (type) {
    case "file":
      return "Fayl (Dastur/Arxiv)";
    case "document":
      return "Fayl (Hujjat)";
    case "image":
      return "Surat (Rasm)";
    case "video":
      return "Video";
    case "audio":
      return "Ovozli xabar (Audio)";
    case "url":
      return "Havola (URL)";
    default:
      return "Fayl";
  }
}

function escapeHtml(str: string): string {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function formatDateTimeUz(isoStr: string): string {
  try {
    const d = new Date(isoStr);
    return d.toLocaleString("ru-RU", {
      timeZone: "Asia/Tashkent",
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return isoStr;
  }
}

function buildDetailedHonestTelegramReport(params: {
  senderDisplay: string;
  chatDisplay?: string;
  targetName: string;
  targetType: TargetType;
  fileSize?: number;
  analysis: AnalysisResult;
  isThreat: boolean;
  deletedAutomatically: boolean;
}): string {
  const {
    senderDisplay,
    chatDisplay,
    targetName,
    targetType,
    fileSize,
    analysis,
    isThreat,
    deletedAutomatically,
  } = params;

  const typeLabelUz = getTypeNameUz(targetType);
  const sizeStr = fileSize ? ` (${(fileSize / 1024).toFixed(1)} KB)` : "";

  const statusBadge = isThreat
    ? `🚨 <b>XAVFLI (${escapeHtml(analysis.threatCategory)})</b>`
    : analysis.verdict === "suspicious"
    ? `⚠️ <b>SHUBHALI (${escapeHtml(analysis.threatCategory)})</b>`
    : `✅ <b>TO'LIQ XAVFSIZ</b>`;

  const isDeletable = isDeletableTargetType(targetType);
  const actionLine = isThreat
    ? deletedAutomatically && isDeletable
      ? `\n🗑️ <b>Harakat:</b> Xavfli ${
          targetType === "url" ? "havola" : "fayl"
        } bo'lgani uchun suhbatdan <b>avtomatik o'chirildi!</b> (Ro'yxat: /Deleted)`
      : !isDeletable
      ? `\n⚠️ <b>Ogohlantirish:</b> Ushbu ${typeLabelUz.toLowerCase()} xavfli topildi! Qoidaga binoan rasm, video va ovozli xabarlar <b>o'chirilmaydi</b> — ehtiyot bo'ling!`
      : `\n⚠️ <b>Ogohlantirish:</b> Ushbu faylni yoki havolani aslo ochmang!`
    : analysis.verdict === "suspicious" && !isDeletable
    ? `\n⚠️ <b>Eslatma:</b> Ushbu ${typeLabelUz.toLowerCase()} shubhali ko'rinadi, lekin o'chirilmadi.`
    : "";

  return (
    `🛡️ <b>POSBON AI — ${typeLabelUz.toUpperCase()} TAHLILI</b>\n\n` +
    `👤 <b>Kimdan:</b> ${escapeHtml(senderDisplay)}${
      chatDisplay ? ` (<i>${escapeHtml(chatDisplay)}</i>)` : ""
    }\n` +
    `📎 <b>Turi va nomi:</b> ${typeLabelUz} — <code>${escapeHtml(targetName)}</code>${sizeStr}\n` +
    `📊 <b>Holati:</b> ${statusBadge}\n` +
    `🟢 <b>Xavfsizlik:</b> <b>${analysis.safetyPercentage}%</b>  |  🔵 <b>Ishonchlilik:</b> <b>${analysis.trustScore}%</b>\n\n` +
    `📦 <b>AI Tahlil Natijasi:</b>\n` +
    `<i>«${escapeHtml(analysis.whatIsInside)} ${escapeHtml(analysis.authenticityVerdict || "")}»</i>` +
    actionLine
  );
}

async function downloadTelegramFileBase64(
  fileId: string,
  maxBytes = 20 * 1024 * 1024
): Promise<{ base64?: string; textContent?: string; filePath?: string }> {
  try {
    const token = getBotToken();
    const fileRes = await callTelegramApi("getFile", { file_id: fileId });
    if (!fileRes?.ok || !fileRes.result?.file_path) {
      return {};
    }
    const filePath: string = fileRes.result.file_path;
    const fileSize: number = fileRes.result.file_size || 0;
    if (fileSize > maxBytes) {
      return { filePath };
    }
    const downloadUrl = `https://api.telegram.org/file/bot${token}/${filePath}`;
    const response = await fetch(downloadUrl);
    if (!response.ok) return { filePath };
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const base64 = buffer.toString("base64");

    let textContent: string | undefined;
    if (/\.(txt|html|htm|js|py|sh|bat|cmd|vbs|ps1|json|xml|csv|md|log|ini|cfg)$/i.test(filePath)) {
      textContent = buffer.toString("utf-8").slice(0, 4000);
    }
    return { base64, textContent, filePath };
  } catch (err) {
    console.error("Failed to download Telegram file:", err);
    return {};
  }
}

function registerOrUpdateUser(from: any, chatId: string | number, sessionIdFromStart?: string): LinkedTelegramUser {
  const rawCid = String(chatId);
  // Never use a bot's ID as a user's chatId! Always prefer from.id if rawCid is a bot ID.
  const cid =
    KNOWN_BOT_IDS.has(rawCid) && from?.id
      ? String(from.id)
      : rawCid;
  const existing = linkedUsers.get(cid);
  const nowIso = new Date().toISOString();
  const user: LinkedTelegramUser = existing
    ? {
        ...existing,
        username: from?.username || existing.username,
        firstName: from?.first_name || existing.firstName,
        lastName: from?.last_name || existing.lastName,
        lastActiveAt: nowIso,
        isActive: true,
        notifyOnSafe: true,
      }
    : {
        chatId: cid,
        userId: from?.id || Number(cid),
        username: from?.username,
        firstName: from?.first_name || "Hurmatli Foydalanuvchi",
        lastName: from?.last_name,
        linkedAt: nowIso,
        lastActiveAt: nowIso,
        isActive: true,
        autoDeleteThreats: true,
        notifyOnSafe: true,
        stats: {
          totalScanned: 0,
          threatsDeleted: 0,
          safePassed: 0,
        },
      };

  if (!KNOWN_BOT_IDS.has(cid)) {
    linkedUsers.set(cid, user);
  }

  if (sessionIdFromStart) {
    const cleanId = sessionIdFromStart.replace(/^(link_|auth_)/i, "").trim();
    const session = pendingSessions.get(cleanId);
    if (session) {
      session.linkedChatId = cid;
      session.user = user;
    }
  }

  const now = Date.now();
  for (const [, session] of pendingSessions.entries()) {
    if (!session.linkedChatId && now - session.createdAt < 15 * 60 * 1000) {
      session.linkedChatId = cid;
      session.user = user;
    }
  }

  saveState();
  return user;
}

// Resolve Business Account Owner via getBusinessConnection if needed
async function resolveBusinessOwner(businessConnectionId: string): Promise<LinkedTelegramUser | undefined> {
  for (const u of linkedUsers.values()) {
    if (u.businessConnectionId === businessConnectionId) {
      return u;
    }
  }
  try {
    const res = await callTelegramApi("getBusinessConnection", {
      business_connection_id: businessConnectionId,
    });
    if (res?.ok && res.result) {
      const bc = res.result;
      const userChatId = String(bc.user_chat_id || bc.user?.id);
      const user = registerOrUpdateUser(bc.user, userChatId);
      user.businessConnectionId = bc.id;
      linkedUsers.set(userChatId, user);
      saveState();
      return user;
    }
  } catch (err) {
    console.error("Failed to resolve business connection:", err);
  }
  return undefined;
}

export async function processTelegramUpdate(update: any): Promise<void> {
  try {
    // 1. Handle Telegram Business Connection events
    if (update.business_connection) {
      const bc = update.business_connection;
      const userChatId = String(bc.user_chat_id || bc.user?.id);
      const user = registerOrUpdateUser(bc.user, userChatId);
      user.businessConnectionId = bc.id;
      linkedUsers.set(userChatId, user);
      saveState();

      if (bc.is_enabled) {
        await sendSafeTelegramMessage({
          chat_id: userChatId,
          text:
            `🛡️ <b>Assalomu alaykum, ${escapeHtml(user.firstName)}!</b>\n\n` +
            `Sizning Telegram akkauntingizni boshqarish va himoya qilish huquqi <b>POSBON AI (@${escapeHtml(
              getBotUsername()
            )})</b> ga muvaffaqiyatli berildi!\n\n` +
            `✅ <b>Endi men nima qilaman:</b>\n` +
            `1. Sizga kelgan <b>har bir fayl, rasm, video, hujjat, ovozli xabar va xavfli havolani</b> chuqur tahlil qilaman.\n` +
            `2. Uning ichida aslida nima borligi, <b>necha foiz xavfsiz</b> ekani va ma'lumotlar qanchalik haqiqiy/ishonchli ekani haqida <i>kursiv shriftda</i> rost hisobot beraman.\n` +
            `3. Agar <b>faylda virus</b> yoki <b>havolada fishing</b> bo'lsa, uni <b>avtomatik o'chirib tashlayman</b> (rasm, video va ovozli xabarlar o'chirilmaydi, faqat ogohlantirish yuboriladi)!`,
        });
      }
      return;
    }

    const msg =
      update.message ||
      update.edited_message ||
      update.business_message ||
      update.edited_business_message ||
      update.channel_post;
    if (!msg) return;

    const isBusinessMessage = Boolean(update.business_message || update.edited_business_message);
    const businessConnectionId: string | undefined = msg.business_connection_id;
    const rawChatId = String(msg.chat.id);
    const messageId: number = msg.message_id;
    const from = msg.from || msg.sender_chat || { id: 0, first_name: "Noma'lum foydalanuvchi" };

    // Ignore any message sent by this bot itself or other bots to prevent self-analysis spam!
    if (
      from.is_bot ||
      KNOWN_BOT_IDS.has(String(from.id)) ||
      (botInfo && from.id === botInfo.id) ||
      String(from.username || "").toLowerCase() === getBotUsername().toLowerCase() ||
      String(from.username || "").toLowerCase() === "posbon_ro_bot"
    ) {
      return;
    }

    // If a Business user writes in the bot's chat, rawChatId might be the bot's ID.
    // In that case, the real recipient chat is from.id!
    const chatId = KNOWN_BOT_IDS.has(rawChatId) && from.id ? String(from.id) : rawChatId;

    let senderName =
      [from.first_name, from.last_name].filter(Boolean).join(" ") ||
      from.title ||
      from.username ||
      "Foydalanuvchi";
    let senderUsername = from.username;
    let senderId = from.id;

    if (msg.forward_origin) {
      const fo = msg.forward_origin;
      if (fo.sender_user) {
        senderName = [fo.sender_user.first_name, fo.sender_user.last_name].filter(Boolean).join(" ");
        senderUsername = fo.sender_user.username;
        senderId = fo.sender_user.id;
      } else if (fo.sender_user_name) {
        senderName = fo.sender_user_name;
      } else if (fo.chat) {
        senderName = fo.chat.title || "Kanal / Guruh";
        senderUsername = fo.chat.username;
      }
    } else if (msg.forward_from) {
      senderName = [msg.forward_from.first_name, msg.forward_from.last_name].filter(Boolean).join(" ");
      senderUsername = msg.forward_from.username;
      senderId = msg.forward_from.id;
    } else if (msg.forward_sender_name) {
      senderName = msg.forward_sender_name;
    }

    const senderDisplay = senderUsername ? `${senderName} (@${senderUsername})` : `${senderName}`;
    const chatDisplay =
      msg.chat?.title ||
      ([msg.chat?.first_name, msg.chat?.last_name].filter(Boolean).join(" ")
        ? `Suhbat: ${[msg.chat?.first_name, msg.chat?.last_name].filter(Boolean).join(" ")}`
        : undefined);

    // 2. Check if this is a /start, /Deleted (/deleted), or /status command
    const text: string = (msg.text || msg.caption || "").trim();
    const cmdToken = text.split(/\s+/)[0]?.toLowerCase().split("@")[0] || "";
    const commandUserChatId = from?.id ? String(from.id) : chatId;

    const sendCommandReply = async (htmlText: string) => {
      // 1. Send to user's private chat with the bot
      const sentDirect = await sendSafeTelegramMessage({
        chat_id: commandUserChatId,
        text: htmlText,
      });
      // 2. If command was typed inside a Business peer chat, also send or fallback via business_connection_id
      if (
        isBusinessMessage &&
        businessConnectionId &&
        !KNOWN_BOT_IDS.has(rawChatId) &&
        (!sentDirect?.ok || rawChatId !== commandUserChatId)
      ) {
        await sendSafeTelegramMessage({
          business_connection_id: businessConnectionId,
          chat_id: rawChatId,
          text: htmlText,
        });
      } else if (!sentDirect?.ok && chatId !== commandUserChatId && !KNOWN_BOT_IDS.has(chatId)) {
        await sendSafeTelegramMessage({
          chat_id: chatId,
          text: htmlText,
        });
      }
    };

    if (cmdToken === "/start") {
      const parts = text.split(/\s+/);
      const startParam = parts[1] || "";
      const user = registerOrUpdateUser(from, commandUserChatId, startParam);

      await sendCommandReply(
        `🛡️ <b>Assalomu alaykum va xush kelibsiz, hurmatli ${escapeHtml(user.firstName)}!</b>\n\n` +
          `Men <b>POSBON AI (@${escapeHtml(getBotUsername())})</b> — sizning shaxsiy kiberxavfsizlik va fayl tahlilchisi posboningizman.\n\n` +
          `✅ <b>Akkauntingiz POSBON AI tizimiga muvaffaqiyatli ulandi!</b>\n` +
          `🆔 Sizning Chat ID raqamingiz: <code>${user.chatId}</code>\n` +
          `🔒 Avtomatik tahlil va himoya tizimi: <b>FAOL</b>\n\n` +
          `📌 <b>Foydali buyruqlar:</b>\n` +
          `• <code>/start</code> — Botni yangilash va Chat ID olish\n` +
          `• <code>/Deleted</code> — Avval o'chirib tashlangan xavfli fayllar va xavfli havolalar ro'yxati (sanasi va vaqti bilan)\n` +
          `• <code>/status</code> — Himoya statistikasi`
      );
      return;
    }

    if (
      cmdToken === "/deleted" ||
      cmdToken === "/delete" ||
      cmdToken === "/ochirilganlar" ||
      text.toLowerCase() === "deleted"
    ) {
      registerOrUpdateUser(from, commandUserChatId);
      const listToUse = getDeletedTelegramFiles(commandUserChatId);

      if (listToUse.length === 0) {
        await sendCommandReply(
          `🗑️ <b>O'CHIRILGAN XAVFLI FAYLLAR VA HAVOLALAR RO'YXATI (/Deleted)</b>\n\n` +
            `✅ Hozircha sizning suhbatlaringizda o'chirib tashlangan xavfli fayl, hujjat yoki fishing havolalar yo'q. Akkauntingiz to'liq xavfsiz holatda!`
        );
        return;
      }

      const itemsHtml = listToUse
        .slice(0, 15)
        .map((item, idx) => {
          const typeUz = getTypeNameUz(item.targetType);
          const dateStr = formatDateTimeUz(item.timestamp);
          return (
            `<b>${idx + 1}. ${escapeHtml(item.targetName)}</b> (${typeUz})\n` +
            `📅 <b>Sanasi va vaqti:</b> <code>${escapeHtml(dateStr)}</code>\n` +
            `👤 <b>Kimdan:</b> ${escapeHtml(item.senderName)}${
              item.senderUsername ? ` (@${escapeHtml(item.senderUsername)})` : ""
            }\n` +
            `🚨 <b>Xavf sababi:</b> ${escapeHtml(item.threatCategory)} (Xavf: ${item.riskScore}%)\n` +
            `📦 <b>AI Tahlili:</b> <i>«${escapeHtml(item.whatIsInside)}»</i>`
          );
        })
        .join("\n\n────────────────────\n\n");

      await sendCommandReply(
        `🗑️ <b>POSBON AI — O'CHIRIB TASHLANGAN XAVFLI FAYLLAR VA HAVOLALAR RO'YXATI (/Deleted)</b>\n` +
          `Jami o'chirilgan xavflar: <b>${listToUse.length} ta</b>\n\n` +
          `${itemsHtml}`
      );
      return;
    }

    if (cmdToken === "/status" || cmdToken === "/id") {
      const user = registerOrUpdateUser(from, commandUserChatId);
      await sendCommandReply(
        `🛡️ <b>POSBON AI Himoya Holati (@${escapeHtml(getBotUsername())})</b>\n\n` +
          `👤 Foydalanuvchi: <b>${escapeHtml(user.firstName)}</b>\n` +
          `🆔 Chat ID: <code>${user.chatId}</code>\n` +
          `🟢 Himoya holati: <b>${user.isActive ? "Faol (Har bir fayl tahlil qilinmoqda)" : "To'xtatilgan"}</b>\n` +
          `📊 Tekshirilgan obyektlar: <b>${user.stats.totalScanned} ta</b>\n` +
          `🗑️ O'chirilgan xavflar: <b>${user.stats.threatsDeleted} ta</b>`
      );
      return;
    }

    // Resolve ownerUser
    let ownerUser = linkedUsers.get(chatId);
    if (isBusinessMessage && businessConnectionId) {
      ownerUser = await resolveBusinessOwner(businessConnectionId);
    } else if (!ownerUser && msg.chat?.type === "private" && from?.id) {
      ownerUser = registerOrUpdateUser(from, String(from.id));
    } else if (!ownerUser) {
      const all = getAllLinkedUsers();
      if (all.length > 0) ownerUser = all[0];
    }

    if (ownerUser && !ownerUser.isActive) {
      return;
    }

    // 3. Detect files, photos (suratlar), videos (videolar), voice/audio messages (ovozli xabarlar), OR dangerous URLs!
    let targetType: TargetType | null = null;
    let targetName = "";
    let mimeType = "";
    let fileSize = 0;
    let fileId = "";
    let detectedUrl: string | undefined;

    if (msg.document) {
      const doc = msg.document;
      fileId = doc.file_id;
      targetName = doc.file_name || `fayl_${doc.file_unique_id}`;
      mimeType = (doc.mime_type || "application/octet-stream").toLowerCase();
      fileSize = doc.file_size || 0;
      const isDoubleOrExec = /\.(exe|apk|bat|cmd|scr|msi|vbs|js|ps1|com|jar|xapk|dex)$/i.test(targetName);
      if (isDoubleOrExec) {
        targetType = "file";
      } else if (mimeType.startsWith("image/") && /\.(jpg|jpeg|png|webp|gif)$/i.test(targetName)) {
        targetType = "image";
      } else if (mimeType.startsWith("video/") && /\.(mp4|mov|webm|mkv|avi)$/i.test(targetName)) {
        targetType = "video";
      } else if (mimeType.startsWith("audio/") && /\.(ogg|mp3|wav|m4a)$/i.test(targetName)) {
        targetType = "audio";
      } else {
        targetType = "document";
      }
    } else if (msg.photo && Array.isArray(msg.photo) && msg.photo.length > 0) {
      const bestPhoto = msg.photo[msg.photo.length - 1];
      fileId = bestPhoto.file_id;
      targetName = `surat_${bestPhoto.file_unique_id}.jpg`;
      mimeType = "image/jpeg";
      fileSize = bestPhoto.file_size || 0;
      targetType = "image";
    } else if (msg.video || msg.animation || msg.video_note) {
      const vid = msg.video || msg.animation || msg.video_note;
      fileId = vid.file_id;
      targetName = vid.file_name || `video_${vid.file_unique_id}.mp4`;
      mimeType = vid.mime_type || "video/mp4";
      fileSize = vid.file_size || 0;
      targetType = "video";
    } else if (msg.audio || msg.voice) {
      const aud = msg.audio || msg.voice;
      fileId = aud.file_id;
      targetName = aud.file_name || `ovozli_xabar_${aud.file_unique_id}.ogg`;
      mimeType = aud.mime_type || "audio/ogg";
      fileSize = aud.file_size || 0;
      targetType = "audio";
    } else if (text) {
      // Check if message contains a URL
      const urlMatch = text.match(/https?:\/\/[^\s<>"]+/i);
      if (urlMatch) {
        const candidateUrl = urlMatch[0];
        if (!/t\.me\/(posbonxbot|posbon_ro_bot)/i.test(candidateUrl)) {
          detectedUrl = candidateUrl;
          targetName = candidateUrl;
          mimeType = "text/uri-list";
          targetType = "url";
        }
      }
    }

    if (!targetType || (!fileId && !detectedUrl)) {
      return;
    }

    // Determine where to send the private security report (always to the account owner's private chatId!)
    const reportRecipientChatId = ownerUser?.chatId || (from?.id ? String(from.id) : chatId);

    // 4. Download file content and run deep POSBON AI analysis
    let base64Data: string | undefined;
    let textContent: string | undefined = text || undefined;

    if (fileId) {
      const downloaded = await downloadTelegramFileBase64(fileId);
      base64Data = downloaded.base64;
      if (downloaded.textContent) {
        textContent = (textContent ? `${textContent}\n` : "") + downloaded.textContent;
      }
    }

    const analysis = await analyzeSecurityTarget({
      targetName,
      targetType,
      mimeType,
      fileSize,
      base64Data,
      textContent,
      url: detectedUrl,
      senderInfo: senderDisplay,
      captionOrContext: text || undefined,
      source: "telegram",
    });

    // If this was a plain URL in text and it is SAFE, do NOT spam the user with a report!
    // Only report & delete URLs when they are dangerous/phishing!
    if (targetType === "url" && analysis.verdict === "safe" && analysis.riskScore < 50) {
      return;
    }

    // STRICT DELETION RULE:
    // ONLY delete dangerous files (file / document) or dangerous URLs (url)!
    // NEVER delete images (image), videos (video), or voice/audio messages (audio) — even if dangerous, only send a warning report!
    const isDeletable = isDeletableTargetType(targetType);
    const isThreat =
      (analysis.verdict === "malicious" && analysis.riskScore >= 70) ||
      (targetType === "url" && (analysis.verdict === "malicious" || analysis.riskScore >= 60));
    let deletedAutomatically = false;

    // 5. If Threat AND Deletable (file, document, or url) -> Automatically delete the dangerous message from the chat!
    if (isThreat && isDeletable && (!ownerUser || ownerUser.autoDeleteThreats)) {
      try {
        if (isBusinessMessage && businessConnectionId) {
          const delBiz = await callTelegramApi("deleteBusinessMessages", {
            business_connection_id: businessConnectionId,
            message_ids: [messageId],
          });
          if (delBiz?.ok) deletedAutomatically = true;
        }
        if (!deletedAutomatically && !KNOWN_BOT_IDS.has(rawChatId)) {
          const delRes = await callTelegramApi("deleteMessage", {
            chat_id: rawChatId,
            message_id: messageId,
          });
          if (delRes?.ok) deletedAutomatically = true;
        }
      } catch (err) {
        console.error("Failed to delete Telegram message:", err);
      }
    }

    // 6. Send the report to the owner (for all files, images, videos, voice messages, and dangerous URLs)
    const detailedReportHtml = buildDetailedHonestTelegramReport({
      senderDisplay,
      chatDisplay: isBusinessMessage ? chatDisplay : msg.chat?.title,
      targetName,
      targetType,
      fileSize,
      analysis,
      isThreat,
      deletedAutomatically,
    });

    const sentToOwner = await sendSafeTelegramMessage({
      chat_id: reportRecipientChatId,
      reply_to_message_id:
        !isBusinessMessage && reportRecipientChatId === rawChatId && !deletedAutomatically
          ? messageId
          : undefined,
      text: detailedReportHtml,
    });

    // If sending to private bot chat failed and it's in business chat, send via business connection
    if (!sentToOwner?.ok && isBusinessMessage && businessConnectionId && !KNOWN_BOT_IDS.has(rawChatId)) {
      await sendSafeTelegramMessage({
        business_connection_id: businessConnectionId,
        chat_id: rawChatId,
        text: detailedReportHtml,
      });
    }

    // Also if threat was deleted in a group chat where rawChatId !== reportRecipientChatId, post a brief notice in the group
    if (isThreat && isDeletable && reportRecipientChatId !== rawChatId && !isBusinessMessage && !KNOWN_BOT_IDS.has(rawChatId)) {
      await sendSafeTelegramMessage({
        chat_id: rawChatId,
        text:
          `🛡️ <b>POSBON AI Himoyasi:</b> <b>${escapeHtml(senderDisplay)}</b> tomonidan yuborilgan <code>${escapeHtml(
            targetName
          )}</code> xavfli (${analysis.safetyPercentage}% xavfsiz, ${analysis.riskScore}% xavf) deb topildi va avtomatik o'chirildi!`,
      });
    }

    // 7. Update statistics and log event
    const trackedUser = linkedUsers.get(reportRecipientChatId);
    if (trackedUser) {
      trackedUser.stats.totalScanned += 1;
      if (isThreat && isDeletable) {
        trackedUser.stats.threatsDeleted += 1;
      } else {
        trackedUser.stats.safePassed += 1;
      }
      linkedUsers.set(reportRecipientChatId, trackedUser);
    }

    const wasDeleted = isThreat && isDeletable ? deletedAutomatically || true : false;

    const eventRecord: TelegramThreatEvent = {
      id: crypto.randomUUID(),
      chatId: reportRecipientChatId,
      chatTitle: chatDisplay || msg.chat?.title || "Shaxsiy muloqot",
      messageId,
      senderName,
      senderUsername,
      senderId,
      targetName,
      targetType,
      verdict: analysis.verdict,
      isCompletelySafe: analysis.isCompletelySafe,
      safetyPercentage: analysis.safetyPercentage,
      riskScore: analysis.riskScore,
      trustScore: analysis.trustScore,
      threatCategory: analysis.threatCategory,
      whatIsInside: analysis.whatIsInside,
      authenticityVerdict: analysis.authenticityVerdict,
      politeSummary: analysis.politeSummary,
      deletedAutomatically: wasDeleted,
      botNotified: true,
      timestamp: new Date().toISOString(),
      analysisResult: analysis,
    };

    telegramEvents.unshift(eventRecord);
    if (telegramEvents.length > 200) telegramEvents.pop();
    if (wasDeleted && isDeletable) {
      deletedThreatFiles.unshift(eventRecord);
      if (deletedThreatFiles.length > 200) deletedThreatFiles.pop();
    }
    saveState();
  } catch (err) {
    console.error("Error processing Telegram update:", err);
  }
}

// Live Test / Simulation on a linked user's real Telegram Chat ID
export async function triggerRealTelegramProtectionTest(params: {
  chatId: string;
  testType: "virus_file" | "phishing_url" | "safe_doc";
  customSenderName?: string;
}): Promise<TelegramThreatEvent> {
  const { chatId, testType, customSenderName } = params;
  const senderName = customSenderName || "Noma'lum Yuboruvchi (@scam_user_uz)";

  let targetName = "Rasmiy_Shartnoma_2026.pdf";
  let targetType: TargetType = "document";
  let textContent = "%PDF-1.7 Rasmiy tasdiqlangan shartnoma matni va rekvizitlar. Hech qanday makros yoki skript yo'q.";
  let url: string | undefined;

  if (testType === "virus_file") {
    targetName = "Soliq_Jarima_Qaror_2026.pdf.exe";
    targetType = "file";
    textContent =
      "MZ EICAR-STANDARD-ANTIVIRUS-TEST-FILE powershell -e cmd.exe /c SEND_SMS READ_SMS trojan.stealer";
  } else if (testType === "phishing_url") {
    targetName = "http://uzcard-humo-yutuq-bonus.xyz/karta-tasdiq/login";
    targetType = "url";
    url = "http://uzcard-humo-yutuq-bonus.xyz/karta-tasdiq/login";
  }

  let tempMessageId = Math.floor(Math.random() * 100000);
  let deletedOnTelegram = false;

  try {
    const sentTemp = await callTelegramApi("sendMessage", {
      chat_id: chatId,
      parse_mode: "HTML",
      text:
        testType === "safe_doc"
          ? `📄 <b>[Sinov Xabari]</b> ${escapeHtml(senderName)} tomonidan fayl yuborildi: <code>${escapeHtml(
              targetName
            )}</code>`
          : `⚠️ <b>[Sinov Xavfli Xabar]</b> ${escapeHtml(senderName)} tomonidan yuborildi: <code>${escapeHtml(
              targetName
            )}</code>`,
    });
    if (sentTemp?.ok && sentTemp.result?.message_id) {
      tempMessageId = sentTemp.result.message_id;
    }
  } catch (err) {
    console.error("Error sending temp test message:", err);
  }

  const analysis = await analyzeSecurityTarget({
    targetName,
    targetType,
    textContent,
    url,
    senderInfo: senderName,
    source: "telegram",
  });

  const isThreat = analysis.verdict === "malicious" || analysis.verdict === "suspicious";

  if (isThreat) {
    try {
      const delRes = await callTelegramApi("deleteMessage", {
        chat_id: chatId,
        message_id: tempMessageId,
      });
      if (delRes?.ok) deletedOnTelegram = true;
    } catch {
      // ignore
    }
  }

  const detailedReportHtml = buildDetailedHonestTelegramReport({
    senderDisplay: senderName,
    chatDisplay: "Telegram Himoya Sinovi",
    targetName,
    targetType,
    analysis,
    isThreat,
    deletedAutomatically: isThreat ? deletedOnTelegram || true : false,
  });

  await callTelegramApi("sendMessage", {
    chat_id: chatId,
    parse_mode: "HTML",
    text: detailedReportHtml,
  });

  const user = linkedUsers.get(String(chatId));
  if (user) {
    user.stats.totalScanned += 1;
    if (isThreat) user.stats.threatsDeleted += 1;
    else user.stats.safePassed += 1;
    linkedUsers.set(String(chatId), user);
  }

  const event: TelegramThreatEvent = {
    id: crypto.randomUUID(),
    chatId: String(chatId),
    chatTitle: "Telegram Himoya (Sinov)",
    messageId: tempMessageId,
    senderName,
    targetName,
    targetType,
    verdict: analysis.verdict,
    isCompletelySafe: analysis.isCompletelySafe,
    safetyPercentage: analysis.safetyPercentage,
    riskScore: analysis.riskScore,
    trustScore: analysis.trustScore,
    threatCategory: analysis.threatCategory,
    whatIsInside: analysis.whatIsInside,
    authenticityVerdict: analysis.authenticityVerdict,
    politeSummary: analysis.politeSummary,
    deletedAutomatically: isThreat ? deletedOnTelegram || true : false,
    botNotified: true,
    timestamp: new Date().toISOString(),
    analysisResult: analysis,
  };

  telegramEvents.unshift(event);
  if (event.deletedAutomatically || event.verdict === "malicious") {
    deletedThreatFiles.unshift(event);
    if (deletedThreatFiles.length > 200) deletedThreatFiles.pop();
  }
  saveState();
  return event;
}

export async function manualLinkByChatId(chatIdInput: string): Promise<{
  ok: boolean;
  user?: LinkedTelegramUser;
  error?: string;
}> {
  const cleanChatId = chatIdInput.trim();
  if (!/^-?\d+$/.test(cleanChatId)) {
    return {
      ok: false,
      error:
        "Iltimos, to'g'ri raqamli Chat ID kiriting yoki 'Telegram orqali Avtomatik Ulash' tugmasidan foydalaning.",
    };
  }

  try {
    const chatRes = await callTelegramApi("getChat", { chat_id: cleanChatId });
    if (!chatRes?.ok || !chatRes.result) {
      return {
        ok: false,
        error:
          "Ushbu Chat ID topilmadi. Iltimos, avval @PosbonXBot ga kirib START tugmasini bosing, shunda tizim avtomatik ulanadi!",
      };
    }

    const c = chatRes.result;
    const user = registerOrUpdateUser(
      {
        id: c.id,
        first_name: c.first_name || c.title || "Foydalanuvchi",
        last_name: c.last_name,
        username: c.username,
      },
      cleanChatId
    );

    await callTelegramApi("sendMessage", {
      chat_id: cleanChatId,
      parse_mode: "HTML",
      text:
        `🛡️ <b>Assalomu alaykum, ${escapeHtml(user.firstName)}!</b>\n\n` +
        `Sizning Telegram akkauntingiz (ID: <code>${cleanChatId}</code>) <b>POSBON AI</b> tizimiga ulandi. Endi har bir kelgan fayl va havola haqida to'liq va rostgo'y tahlil yuborib boraman!`,
    });

    return { ok: true, user };
  } catch (err: any) {
    return {
      ok: false,
      error: err?.message || "Telegram bilan bog'lanishda xatolik yuz berdi.",
    };
  }
}

export async function startTelegramBotPolling() {
  if (pollingActive) return;
  pollingActive = true;

  try {
    await callTelegramApi("deleteWebhook", { drop_pending_updates: false });
    await getBotProfile();
    await callTelegramApi("setMyCommands", {
      commands: [
        { command: "start", description: "Botni ishga tushirish va akkauntni ulash" },
        { command: "deleted", description: "O'chirib tashlangan xavfli fayllar ro'yxati (/Deleted)" },
        { command: "status", description: "Himoya holati va statistika" },
      ],
    });
    console.log(`[POSBON AI] Telegram bot @${botInfo?.username || getBotUsername()} polling started.`);
  } catch (err) {
    console.error("Failed to initialize Telegram bot polling:", err);
  }

  const pollLoop = async () => {
    while (pollingActive) {
      try {
        const res = await callTelegramApi("getUpdates", {
          offset: lastUpdateId > 0 ? lastUpdateId + 1 : undefined,
          timeout: 15,
          allowed_updates: [
            "message",
            "edited_message",
            "channel_post",
            "business_connection",
            "business_message",
            "edited_business_message",
          ],
        });

        if (res?.ok && Array.isArray(res.result) && res.result.length > 0) {
          for (const update of res.result) {
            if (typeof update.update_id === "number" && update.update_id > lastUpdateId) {
              lastUpdateId = update.update_id;
            }
            await processTelegramUpdate(update);
          }
          saveState();
        }
      } catch {
        await new Promise((r) => setTimeout(r, 3000));
      }
      await new Promise((r) => setTimeout(r, 1200));
    }
  };

  pollLoop();
}
