import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import {
  analyzeSecurityTarget,
  explainSecurityAlertPolite,
  chatWithPosbonAI,
  generatePosbonSpeech,
  transcribePosbonAudio,
  AnalysisResult,
} from "./src/lib/ai/analyze.server.ts";
import {
  createAuthSession,
  formatDateTimeUz,
  getAllLinkedUsers,
  getAuthSessionStatus,
  getBotProfile,
  getDeletedTelegramFiles,
  getLinkedUser,
  getTelegramEvents,
  manualLinkByChatId,
  processTelegramUpdate,
  startTelegramBotPolling,
  triggerRealTelegramProtectionTest,
  unlinkTelegramUser,
  updateUserSettings,
} from "./src/lib/telegram.server.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const webScanHistory: AnalysisResult[] = [];

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Increase payload limit to 50MB for real file, APK, image, video, and document scanning
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ extended: true, limit: "50mb" }));

  // 1. Analyze File / Image / Video / Document / URL
  app.post("/api/analyze", async (req, res) => {
    try {
      const { targetName, targetType, mimeType, fileSize, base64Data, textContent, url } = req.body;
      if (!targetName && !url) {
        res.status(400).json({
          error: "Hurmatli foydalanuvchi, iltimos tekshirish uchun fayl yoki URL manzil kiriting.",
        });
        return;
      }

      const result = await analyzeSecurityTarget({
        targetName: targetName || url,
        targetType: targetType || (url ? "url" : "file"),
        mimeType,
        fileSize,
        base64Data,
        textContent,
        url,
        source: "web",
      });

      webScanHistory.unshift(result);
      if (webScanHistory.length > 50) webScanHistory.pop();

      res.json(result);
    } catch (err: any) {
      console.error("Analyze API error:", err);
      res.status(500).json({
        error:
          err?.message ||
          "Kechirasiz, tahlil jarayonida kutilmagan xatolik yuz berdi. Iltimos, qaytadan urinib ko'ring.",
      });
    }
  });

  // 2. Get recent web scan history
  app.get("/api/history", (_req, res) => {
    res.json({ history: webScanHistory });
  });

  // 3. Polite Alert Explainer
  app.post("/api/explain", async (req, res) => {
    try {
      const { targetName, threatCategory, verdict, technicalDetails, userQuestion } = req.body;
      const explanation = await explainSecurityAlertPolite({
        targetName: targetName || "Noma'lum obyekt",
        threatCategory: threatCategory || "Xavfsizlik tekshiruvi",
        verdict: verdict || "suspicious",
        technicalDetails: Array.isArray(technicalDetails) ? technicalDetails : [],
        userQuestion,
      });
      res.json({ explanation });
    } catch (err: any) {
      res.status(500).json({
        error: err?.message || "Izoh olishda xatolik yuz berdi.",
      });
    }
  });

  // 3b. Interactive POSBON AI Chat & File/Image Analyzer
  app.post("/api/ai-chat", async (req, res) => {
    try {
      const { message, history, fileName, mimeType, fileSize, base64Data, textContent } = req.body;
      const result = await chatWithPosbonAI({
        message: message || "",
        history: Array.isArray(history) ? history : [],
        fileName,
        mimeType,
        fileSize,
        base64Data,
        textContent,
      });
      if (result.analysis) {
        webScanHistory.unshift(result.analysis);
        if (webScanHistory.length > 50) webScanHistory.pop();
      }
      res.json(result);
    } catch (err: any) {
      res.status(500).json({
        error: err?.message || "AI bilan bog'lanishda xatolik yuz berdi.",
      });
    }
  });

  // 3c. POSBON AI Text-to-Speech (TTS)
  app.post("/api/ai-tts", async (req, res) => {
    try {
      const { text } = req.body;
      const result = await generatePosbonSpeech(String(text || ""));
      res.json(result);
    } catch {
      res.json({});
    }
  });

  // 3d. POSBON AI Audio Transcription
  app.post("/api/ai-transcribe", async (req, res) => {
    try {
      const { base64Audio, mimeType } = req.body;
      const result = await transcribePosbonAudio({
        base64Audio: String(base64Audio || ""),
        mimeType: mimeType || "audio/webm",
      });
      res.json(result);
    } catch {
      res.json({ transcript: "" });
    }
  });

  // 4. Create Telegram Auth Session for seamless 1-click linking
  app.post("/api/telegram/session", async (_req, res) => {
    try {
      const session = createAuthSession();
      const bot = await getBotProfile();
      res.json({
        sessionId: session.sessionId,
        botUsername: bot.username,
        botFirstName: bot.first_name,
        authUrl: `https://t.me/${bot.username}?start=auth_${session.sessionId}`,
        directBotUrl: `https://t.me/${bot.username}`,
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Sessiya yaratishda xatolik" });
    }
  });

  // 5. Poll Telegram Auth & Protection Status (automatically detects chat_id once user clicks Start)
  app.get("/api/telegram/status", async (req, res) => {
    try {
      const sessionId = String(req.query.sessionId || "");
      const chatId = String(req.query.chatId || "");
      const bot = await getBotProfile();

      let activeUser = chatId ? getLinkedUser(chatId) : undefined;
      if (!activeUser && sessionId) {
        const sessStatus = getAuthSessionStatus(sessionId);
        if (sessStatus.linked && sessStatus.user) {
          activeUser = sessStatus.user;
        }
      }
      // If still no activeUser for this browser tab, check if a user just connected via /start recently
      const allUsers = getAllLinkedUsers();
      if (!activeUser && allUsers.length > 0) {
        activeUser = allUsers[0];
      }

      const events = getTelegramEvents(activeUser?.chatId);

      res.json({
        linked: Boolean(activeUser),
        user: activeUser || null,
        allUsers,
        botProfile: bot,
        events,
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Statusni olishda xatolik" });
    }
  });

  // 6. Manual link by Chat ID
  app.post("/api/telegram/manual-link", async (req, res) => {
    try {
      const { chatId } = req.body;
      const result = await manualLinkByChatId(String(chatId || ""));
      if (!result.ok) {
        res.status(400).json({ error: result.error });
        return;
      }
      res.json({ linked: true, user: result.user });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Ulashda xatolik" });
    }
  });

  // 7. Update Telegram protection settings
  app.post("/api/telegram/settings", (req, res) => {
    const { chatId, isActive, autoDeleteThreats, notifyOnSafe } = req.body;
    const updated = updateUserSettings(String(chatId), {
      isActive,
      autoDeleteThreats,
      notifyOnSafe,
    });
    if (!updated) {
      res.status(404).json({ error: "Foydalanuvchi topilmadi" });
      return;
    }
    res.json({ user: updated });
  });

  // 8. Unlink Telegram account
  app.post("/api/telegram/unlink", (req, res) => {
    const { chatId } = req.body;
    unlinkTelegramUser(String(chatId));
    res.json({ ok: true });
  });

  // 9. Trigger Real Telegram Protection Test (Sends message, detects threat, deletes message, notifies user on Telegram)
  app.post("/api/telegram/test-protection", async (req, res) => {
    try {
      const { chatId, testType, customSenderName } = req.body;
      if (!chatId) {
        res.status(400).json({ error: "Avval Telegram akkauntingizni ulang." });
        return;
      }
      const event = await triggerRealTelegramProtectionTest({
        chatId: String(chatId),
        testType: testType || "virus_file",
        customSenderName,
      });
      res.json({ event, user: getLinkedUser(String(chatId)) });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Sinov xabarini yuborishda xatolik" });
    }
  });

  // 10. Public Telegram Webhook endpoint
  app.post("/api/public/telegram/webhook", async (req, res) => {
    try {
      await processTelegramUpdate(req.body);
      res.status(200).json({ ok: true });
    } catch (err) {
      console.error("Webhook error:", err);
      res.status(200).json({ ok: true });
    }
  });

  // 11. Secret Admin Panel Database API (Password: 0513)
  app.post("/api/admin/database", async (req, res) => {
    try {
      const { password } = req.body;
      if (String(password || "").trim() !== "0513") {
        res.status(403).json({
          ok: false,
          error: "Maxfiy parol noto'g'ri! Kirish rad etildi.",
        });
        return;
      }

      const users = getAllLinkedUsers().map((u) => ({
        ...u,
        linkedAtFormatted: formatDateTimeUz(u.linkedAt),
        lastActiveFormatted: u.lastActiveAt ? formatDateTimeUz(u.lastActiveAt) : formatDateTimeUz(u.linkedAt),
      }));

      const deletedFiles = getDeletedTelegramFiles().map((d) => ({
        id: d.id,
        chatId: d.chatId,
        targetName: d.targetName,
        targetType: d.targetType,
        senderName: d.senderName,
        senderUsername: d.senderUsername,
        riskScore: d.riskScore,
        safetyPercentage: d.safetyPercentage,
        threatCategory: d.threatCategory,
        whatIsInside: d.whatIsInside,
        timestamp: d.timestamp,
        timestampFormatted: formatDateTimeUz(d.timestamp),
      }));

      const allEvents = getTelegramEvents();
      const bot = await getBotProfile();

      res.json({
        ok: true,
        botProfile: bot,
        users,
        deletedFiles,
        totalUsers: users.length,
        totalDeleted: deletedFiles.length,
        totalScanned: allEvents.length + webScanHistory.length,
      });
    } catch (err: any) {
      res.status(500).json({
        ok: false,
        error: err?.message || "Ma'lumotlar bazasini o'qishda xatolik",
      });
    }
  });

  // Start Telegram Bot long-polling in background so @POSBON_RO_BOT works immediately
  startTelegramBotPolling();

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[POSBON AI] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
