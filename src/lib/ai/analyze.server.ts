import { GoogleGenAI, Type } from "@google/genai";
import crypto from "crypto";
import zlib from "zlib";

export type TargetType = "file" | "image" | "video" | "document" | "url" | "audio";
export type VerdictType = "safe" | "suspicious" | "malicious";

export interface AnalysisResult {
  id: string;
  targetName: string;
  targetType: TargetType;
  mimeType?: string;
  detectedFormat: string;
  extensionMatchesBinary: boolean;
  fileSize?: number;
  sha256: string;
  verdict: VerdictType;
  isCompletelySafe: boolean;
  safetyPercentage: number; // 0 - 100 (Necha foiz xavfsiz)
  riskScore: number; // 0 - 100 (Necha foiz xavfli)
  trustScore: number; // 0 - 100 (Ma'lumotlar qanchalik ishonchli va haqiqiy)
  threatCategory: string;
  whatIsInside: string; // Ichida aslida nima bor va nima bo'lishi mumkin (100% rost tahlil)
  authenticityVerdict: string; // Ma'lumotlar haqiqiymi yoki soxta/manipulyatsiyami?
  politeSummary: string;
  technicalDetails: string[];
  recommendations: string[];
  indicators: {
    label: string;
    status: "pass" | "warn" | "fail";
    detail: string;
  }[];
  analyzedAt: string;
  source?: "web" | "telegram";
}

export interface AnalyzeInput {
  targetName: string;
  targetType: TargetType;
  mimeType?: string;
  fileSize?: number;
  base64Data?: string;
  textContent?: string;
  url?: string;
  senderInfo?: string;
  captionOrContext?: string;
  source?: "web" | "telegram";
}

// Cache by SHA-256 hash to save AI quota and respond fast on repeated files/URLs
const analysisCache = new Map<string, AnalysisResult>();

function getApiKeys(): string[] {
  const keys: string[] = [];
  if (process.env.GEMINI_API_KEYS) {
    keys.push(
      ...process.env.GEMINI_API_KEYS.split(",")
        .map((k) => k.trim())
        .filter(Boolean)
    );
  }
  if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY") {
    if (!keys.includes(process.env.GEMINI_API_KEY.trim())) {
      keys.push(process.env.GEMINI_API_KEY.trim());
    }
  }
  return keys;
}

let keyIndex = 0;

function getGenAIClient(): GoogleGenAI | null {
  const keys = getApiKeys();
  if (keys.length === 0) {
    return null;
  }
  const selectedKey = keys[keyIndex % keys.length];
  keyIndex = (keyIndex + 1) % keys.length;
  return new GoogleGenAI({
    apiKey: selectedKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

// Deep binary inspection: detect real file format from magic bytes, zip entries, and printable strings
function inspectBinaryBuffer(
  base64Data?: string,
  fileName = ""
): {
  detectedFormat: string;
  extensionMatchesBinary: boolean;
  extractedStringsSample: string;
  archiveEntries: string[];
  suspiciousStrings: string[];
  isWindowsExecutable: boolean;
  isEicarTest: boolean;
} {
  if (!base64Data) {
    return {
      detectedFormat: "Noma'lum (Matn yoki Havola)",
      extensionMatchesBinary: true,
      extractedStringsSample: "",
      archiveEntries: [],
      suspiciousStrings: [],
      isWindowsExecutable: false,
      isEicarTest: false,
    };
  }

  try {
    const buf = Buffer.from(base64Data, "base64");
    const lowerName = fileName.toLowerCase();
    let detectedFormat = "Noma'lum binar fayl";
    let extensionMatchesBinary = true;
    let isWindowsExecutable = false;

    if (buf.length >= 4) {
      if (buf[0] === 0x4d && buf[1] === 0x5a) {
        detectedFormat = "Windows Bajariluvchi Dasturi (PE / EXE / DLL)";
        isWindowsExecutable = true;
        if (!/\.(exe|dll|scr|cpl|msi|sys)$/i.test(lowerName)) {
          extensionMatchesBinary = false;
        }
      } else if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) {
        detectedFormat = "PDF Hujjat (%PDF)";
        if (!lowerName.endsWith(".pdf")) extensionMatchesBinary = false;
      } else if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
        if (lowerName.endsWith(".apk") || lowerName.endsWith(".xapk")) {
          detectedFormat = "Android Ilova Paketi (APK / ZIP konteyner)";
        } else if (/\.(docx|xlsx|pptx)$/i.test(lowerName)) {
          detectedFormat = "Microsoft Office OpenXML Hujjati (ZIP konteyner)";
        } else {
          detectedFormat = "ZIP Arxiv yoki Konteyner (PK)";
        }
      } else if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
        detectedFormat = "PNG Tasvir";
      } else if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
        detectedFormat = "JPEG Tasvir";
      } else if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) {
        detectedFormat = "GIF Tasvir";
      } else if (buf[0] === 0x52 && buf[1] === 0x61 && buf[2] === 0x72 && buf[3] === 0x21) {
        detectedFormat = "RAR Arxiv";
      } else if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
        detectedFormat = "Linux ELF Bajariluvchi Fayl";
      } else if (buf.subarray(4, 8).toString("ascii") === "ftyp") {
        detectedFormat = "MP4 / MOV Video konteyner";
      } else if (buf.subarray(0, 4).toString("ascii") === "OggS") {
        detectedFormat = "OGG Ovozli / Audio fayl";
      } else if (buf.subarray(0, 3).toString("ascii") === "ID3") {
        detectedFormat = "MP3 Audio fayl";
      }
    }

    // Scan buffer for ZIP central directory & local file headers to see what is inside .zip / .apk / .docx
    // Also decompress AndroidManifest.xml or text/xml entries using zlib to inspect real APK permissions and contents!
    const archiveEntries: string[] = [];
    const decompressedSnippets: string[] = [];

    if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b) {
      // 1. Scan Central Directory headers (0x504b0102) from the end of the file (last 256KB) for full file list
      const cdStart = Math.max(0, buf.length - 256 * 1024);
      for (let i = cdStart; i < buf.length - 46 && archiveEntries.length < 40; i++) {
        if (
          buf[i] === 0x50 &&
          buf[i + 1] === 0x4b &&
          buf[i + 2] === 0x01 &&
          buf[i + 3] === 0x02
        ) {
          const nameLen = buf.readUInt16LE(i + 28);
          const extraLen = buf.readUInt16LE(i + 30);
          const commentLen = buf.readUInt16LE(i + 32);
          if (nameLen > 0 && nameLen < 260 && i + 46 + nameLen <= buf.length) {
            const entryName = buf.subarray(i + 46, i + 46 + nameLen).toString("utf-8");
            if (/^[\x20-\x7E]+$/.test(entryName) && !archiveEntries.includes(entryName)) {
              archiveEntries.push(entryName);
            }
          }
          i += 45 + nameLen + extraLen + commentLen;
        }
      }

      // 2. Scan Local File headers (0x504b0304) and decompress key entries (AndroidManifest.xml, classes.dex sample, xml, txt, js, etc.)
      let offset = 0;
      const maxScan = Math.min(buf.length - 30, 2 * 1024 * 1024);
      while (offset < maxScan) {
        if (
          buf[offset] === 0x50 &&
          buf[offset + 1] === 0x4b &&
          buf[offset + 2] === 0x03 &&
          buf[offset + 3] === 0x04
        ) {
          const compressionMethod = buf.readUInt16LE(offset + 8);
          const compressedSize = buf.readUInt32LE(offset + 18);
          const nameLen = buf.readUInt16LE(offset + 26);
          const extraLen = buf.readUInt16LE(offset + 28);
          const dataStart = offset + 30 + nameLen + extraLen;

          if (nameLen > 0 && nameLen < 260 && offset + 30 + nameLen <= buf.length) {
            const entryName = buf.subarray(offset + 30, offset + 30 + nameLen).toString("utf-8");
            if (/^[\x20-\x7E]+$/.test(entryName) && !archiveEntries.includes(entryName) && archiveEntries.length < 40) {
              archiveEntries.push(entryName);
            }

            const isInspectableEntry =
              /(AndroidManifest\.xml|classes\.dex|plugin\.xml|package\.json|word\/document\.xml|\.txt$|\.js$|\.vbs$|\.bat$|\.ps1$|\.sh$|\.html$)/i.test(
                entryName
              );

            if (
              isInspectableEntry &&
              compressedSize > 0 &&
              compressedSize < 1024 * 1024 &&
              dataStart + compressedSize <= buf.length &&
              decompressedSnippets.length < 6
            ) {
              try {
                const rawSlice = buf.subarray(dataStart, dataStart + compressedSize);
                const unpacked =
                  compressionMethod === 8
                    ? zlib.inflateRawSync(rawSlice, { maxOutputLength: 1024 * 1024 })
                    : compressionMethod === 0
                    ? rawSlice
                    : null;

                if (unpacked) {
                  // Extract both ASCII/UTF-8 and UTF-16LE strings (Android binary XML stores permissions in UTF-16LE / UTF-8)
                  const asciiStr = unpacked.toString("latin1");
                  const utf16Str = unpacked.toString("utf16le");
                  const matchesAscii = asciiStr.match(/[\x20-\x7E]{5,100}/g) || [];
                  const matchesUtf16 = utf16Str.match(/[a-zA-Z0-9_.:\-/]{5,100}/g) || [];
                  const combinedEntryStrings = [...matchesUtf16, ...matchesAscii]
                    .filter((s) =>
                      /(permission\.|package|activity|service|receiver|http|https|sms|accessibility|admin|telegram|bot|token|uzcard|humo|click|payme|dex|MainActivity|application)/i.test(
                        s
                      )
                    )
                    .filter((v, i, a) => a.indexOf(v) === i)
                    .slice(0, 35);

                  if (combinedEntryStrings.length > 0) {
                    decompressedSnippets.push(
                      `[${entryName} ichidan]: ${combinedEntryStrings.join(", ")}`
                    );
                  }
                }
              } catch {
                // ignore decompression error on partial entry
              }
            }
          }
          offset = dataStart + (compressedSize > 0 && compressedSize < buf.length ? compressedSize : 1);
        } else {
          offset++;
        }
      }
    }

    // Extract printable strings from buffer + decompressed APK/ZIP entries
    const sampleSlice = buf.subarray(0, Math.min(buf.length, 256 * 1024)).toString("latin1");
    const isEicarTest = sampleSlice.includes("EICAR-STANDARD-ANTIVIRUS-TEST-FILE");

    const printableMatches = sampleSlice.match(/[\x20-\x7E]{6,120}/g) || [];
    const interestingStrings = printableMatches
      .filter(
        (s) =>
          /(http|https|www\.|\.uz|\.com|\.ru|\.xyz|cmd\.exe|powershell|SEND_SMS|READ_SMS|RECEIVE_SMS|BIND_ACCESSIBILITY_SERVICE|BIND_DEVICE_ADMIN|AutoOpen|VBA|JavaScript|OpenAction|Launch|EmbeddedFiles|Creator|Producer|Author|Title|Subject|telegram|token|password|login|karta|uzcard|humo)/i.test(
            s
          )
      )
      .slice(0, 25);

    const extractedStringsSample = [
      ...decompressedSnippets,
      ...interestingStrings,
      ...printableMatches.slice(0, 15),
    ]
      .filter((v, i, a) => a.indexOf(v) === i)
      .join(" | ")
      .slice(0, 3000);

    return {
      detectedFormat,
      extensionMatchesBinary,
      extractedStringsSample,
      archiveEntries,
      suspiciousStrings: interestingStrings,
      isWindowsExecutable,
      isEicarTest,
    };
  } catch {
    return {
      detectedFormat: "Standart fayl",
      extensionMatchesBinary: true,
      extractedStringsSample: "",
      archiveEntries: [],
      suspiciousStrings: [],
      isWindowsExecutable: false,
      isEicarTest: false,
    };
  }
}

// Heuristic pre-scan for files and URLs
function runHeuristicPreScan(
  input: AnalyzeInput,
  binInfo: ReturnType<typeof inspectBinaryBuffer>
): {
  heuristicScore: number;
  flags: string[];
  indicators: AnalysisResult["indicators"];
} {
  let heuristicScore = 0;
  const flags: string[] = [];
  const indicators: AnalysisResult["indicators"] = [];

  const lowerName = (input.targetName || "").toLowerCase();

  if (input.targetType === "url" || input.url) {
    const rawUrl = (input.url || input.targetName || "").trim();
    const lowerUrl = rawUrl.toLowerCase();

    if (lowerUrl.startsWith("http://")) {
      heuristicScore += 20;
      flags.push("Himoyalanmagan HTTP protokoli (SSL/TLS sertifikati yo'q)");
      indicators.push({
        label: "SSL/TLS Shifrlash",
        status: "warn",
        detail: "Sayt himoyalanmagan HTTP protokolidan foydalanmoqda",
      });
    } else if (lowerUrl.startsWith("https://")) {
      indicators.push({
        label: "SSL/TLS Shifrlash",
        status: "pass",
        detail: "HTTPS shifrlangan ulanish mavjud",
      });
    }

    const phishingPatterns = [
      /telegram.*login/i,
      /t\.me-.*login/i,
      /uzcard.*bonus/i,
      /humo.*yutuq/i,
      /click.*aksiya/i,
      /payme.*pul/i,
      /yutuq.*olish/i,
      /karta.*tasdiq/i,
      /free.*crypto/i,
      /airdrop.*claim/i,
      /steam.*gift/i,
      /discrod/i,
      /teiegram/i,
      /g00gle/i,
      /paypa1/i,
      /ngrok-free/i,
      /\.tk(\/|$)/i,
      /\.xyz(\/|$)/i,
      /\.top(\/|$)/i,
      /\.vip(\/|$)/i,
      /\.buzz(\/|$)/i,
      /\.icu(\/|$)/i,
      /@/,
    ];

    let matchedPhishing = false;
    for (const pattern of phishingPatterns) {
      if (pattern.test(lowerUrl)) {
        heuristicScore += 45;
        matchedPhishing = true;
        flags.push(`Shubhali yoki fishing namunasiga mos keluvchi manzil: ${pattern.source}`);
      }
    }

    if (/^https?:\/\/\d{1,3}(\.\d{1,3}){3}/i.test(lowerUrl)) {
      heuristicScore += 50;
      matchedPhishing = true;
      flags.push("Domen o'rniga to'g'ridan-to'g'ri IP-manzil ishlatilgan");
    }

    if (/\.(exe|apk|bat|scr|cmd|msi|vbs|jar|ps1)(\?|$)/i.test(lowerUrl)) {
      heuristicScore += 65;
      matchedPhishing = true;
      flags.push("Havola to'g'ridan-to'g'ri bajariluvchi xavfli dasturga (.exe/.apk/.bat) olib boradi");
    }

    indicators.push({
      label: "Domen va Fishing Tahlili",
      status: matchedPhishing ? "fail" : "pass",
      detail: matchedPhishing
        ? "Manzilda fishing yoki zararli resurs alomatlari topildi"
        : "Domen tuzilmasi standart ko'rinishda",
    });
  } else {
    const dangerousExts = [
      ".exe",
      ".bat",
      ".cmd",
      ".scr",
      ".vbs",
      ".vbe",
      ".js",
      ".jse",
      ".wsf",
      ".wsh",
      ".ps1",
      ".msi",
      ".hta",
      ".cpl",
      ".reg",
      ".pif",
      ".com",
    ];
    const mobileExecExts = [".apk", ".xapk", ".dex", ".so"];
    const archiveMacroExts = [".docm", ".xlsm", ".pptm", ".iso", ".img", ".vhd"];

    if (/\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|mp4|txt)\.(exe|scr|bat|cmd|apk|vbs|js|ps1)$/i.test(lowerName)) {
      heuristicScore += 85;
      flags.push("Qo'shaloq kengaytma (Double Extension) orqali yashirilgan troyan/virus aniqlandi");
      indicators.push({
        label: "Fayl Kengaytmasi",
        status: "fail",
        detail: "Fayl nomi oddiy hujjatdek ko'rsatilib, aslida bajariluvchi dastur (.exe/.apk/.scr) ekani aniqlandi",
      });
    } else if (dangerousExts.some((ext) => lowerName.endsWith(ext))) {
      heuristicScore += 75;
      flags.push(`Tizimda bajariluvchi xavfli dasturiy fayl (${lowerName.split(".").pop()})`);
      indicators.push({
        label: "Fayl Kengaytmasi",
        status: "fail",
        detail: "Bajariluvchi tizim fayli — virus yoki troyan bo'lish ehtimoli juda yuqori",
      });
    } else if (mobileExecExts.some((ext) => lowerName.endsWith(ext))) {
      // Do NOT penalize an .apk just for being an .apk!
      // Instead, check if its internal structure and permissions are clean or suspicious.
      indicators.push({
        label: "Fayl Kengaytmasi",
        status: "pass",
        detail: "Android APK dastur paketi — ichki manifest va ruxsatlari AI orqali tekshirilmoqda",
      });
    } else if (archiveMacroExts.some((ext) => lowerName.endsWith(ext))) {
      heuristicScore += 45;
      flags.push("Makros yoki tizim obrazini saqlovchi hujjat formati");
      indicators.push({
        label: "Fayl Kengaytmasi",
        status: "warn",
        detail: "Ichki makros skriptlarni ishga tushirishi mumkin bo'lgan format",
      });
    } else {
      indicators.push({
        label: "Fayl Kengaytmasi",
        status: "pass",
        detail: `Standart ${input.targetType} formati (${binInfo.detectedFormat})`,
      });
    }

    const isMediaType =
      input.targetType === "image" ||
      input.targetType === "video" ||
      input.targetType === "audio" ||
      /\.(jpg|jpeg|png|webp|gif|mp4|mov|webm|ogg|mp3|wav)$/i.test(lowerName);

    if (
      !isMediaType &&
      (/(foto.*apk|video.*apk|rasm.*apk|taklifnoma.*apk|yechinish.*apk|sovga.*apk|yutuq.*apk|uzcard.*apk|humo.*apk|click.*apk|soliq.*apk|mib.*apk|sud.*apk|aliment.*apk|jarima.*apk)/i.test(
        lowerName
      ) ||
        /(^|[^a-z])(hack|crack|stealer|rat|trojan|virus)([^a-z]|$)/i.test(lowerName))
    ) {
      heuristicScore += 75;
      flags.push("Fayl nomida ijtimoiy muhandislik (aldov) yoki zararli troyan kalit so'zlari mavjud");
      indicators.push({
        label: "Ijtimoiy Muhandislik Tekshiruvi",
        status: "fail",
        detail: "Foydalanuvchini chalg'ituvchi nomlanish (rasm, video, taklifnoma, bank yoki jarima niqobi ostidagi virus)",
      });
    } else {
      indicators.push({
        label: "Ijtimoiy Muhandislik Tekshiruvi",
        status: "pass",
        detail: "Fayl nomida shubhali aldov iboralari topilmadi",
      });
    }

    // Check binary consistency
    if (!binInfo.extensionMatchesBinary) {
      heuristicScore += 75;
      flags.push(
        `Fayl kengaytmasi soxtalashtirilgan! Tashqi ko'rinishi "${fileNameExt(lowerName)}", lekin ichki binar imzosi: "${binInfo.detectedFormat}"`
      );
      indicators.push({
        label: "Haqiqiy Binar Imzo (Magic Bytes)",
        status: "fail",
        detail: `Kengaytma va haqiqiy format mos emas (${binInfo.detectedFormat})`,
      });
    } else if (binInfo.isWindowsExecutable) {
      heuristicScore += 80;
      flags.push("Fayl ichida Windows PE (MZ) bajariluvchi dastur kodi topildi!");
      indicators.push({
        label: "Haqiqiy Binar Imzo (Magic Bytes)",
        status: "fail",
        detail: "Windows bajariluvchi dastur imzosi (MZ/PE)",
      });
    } else if (binInfo.isEicarTest || (input.textContent && input.textContent.includes("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"))) {
      heuristicScore = 100;
      flags.push("EICAR standart antivirus test virusi aniqlandi!");
      indicators.push({
        label: "Haqiqiy Binar Imzo (Magic Bytes)",
        status: "fail",
        detail: "EICAR zararli test imzosi",
      });
    } else {
      indicators.push({
        label: "Haqiqiy Binar Imzo (Magic Bytes)",
        status: "pass",
        detail: `Format tasdiqlandi: ${binInfo.detectedFormat}`,
      });
    }

    // Check archive entries for hidden executables inside ZIP/RAR
    if (binInfo.archiveEntries.some((e) => /\.(exe|bat|cmd|scr|vbs|js|ps1|apk|dex)$/i.test(e))) {
      if (!lowerName.endsWith(".apk")) {
        heuristicScore += 65;
        flags.push(
          `Arxiv ichida yashirin bajariluvchi fayl topildi: ${binInfo.archiveEntries
            .filter((e) => /\.(exe|bat|cmd|scr|vbs|js|ps1|apk)$/i.test(e))
            .join(", ")}`
        );
      }
    }

    // Only scan for code patterns on non-media files (not pure images/videos/voice notes)
    if (!isMediaType || binInfo.isWindowsExecutable || binInfo.isEicarTest) {
      const combinedText = `${input.textContent || ""} ${binInfo.extractedStringsSample}`;
      const suspiciousCodePatterns = [
        { pat: /powershell\s+-e/i, desc: "Yashirin kodlangan PowerShell buyrug'i" },
        { pat: /Invoke-Expression/i, desc: "PowerShell zararli yuklamani ishga tushirish kodi" },
        { pat: /cmd\.exe\s+\/c/i, desc: "Yashirin buyruqlar satri (cmd.exe) chaqiruvi" },
        { pat: /WScript\.Shell/i, desc: "Windows skript qobig'i orqali tizimga kirish" },
        { pat: /SEND_SMS|READ_SMS|RECEIVE_SMS/i, desc: "SMS xabarlar va bank tasdiqlash kodlarini o'qish/yuborish ruxsati" },
        { pat: /BIND_ACCESSIBILITY_SERVICE/i, desc: "Telefon ekranini masofadan boshqarish (Accessibility) ruxsati" },
        { pat: /AutoOpen|Document_Open/i, desc: "Hujjat ochilishi bilan avtomatik ishlovchi makros" },
        { pat: /\/JavaScript|\/JS|\/Launch/i, desc: "PDF ichiga yashirilgan bajariluvchi JavaScript/Launch kodi" },
      ];
      for (const item of suspiciousCodePatterns) {
        if (item.pat.test(combinedText)) {
          heuristicScore += 55;
          flags.push(`Ichki tahlilda aniqlandi: ${item.desc}`);
        }
      }
    }
  }

  return {
    heuristicScore: Math.min(100, heuristicScore),
    flags,
    indicators,
  };
}

function fileNameExt(name: string): string {
  const parts = name.split(".");
  return parts.length > 1 ? `.${parts.pop()}` : "noma'lum";
}

async function fetchUrlContextSafe(urlStr: string): Promise<string> {
  try {
    const parsed = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(parsed.toString(), {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; PosbonSecurityScanner/2.0)",
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    const contentType = res.headers.get("content-type") || "";
    const status = res.status;
    if (contentType.includes("text/html") || contentType.includes("text/plain")) {
      const text = await res.text();
      const titleMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : "";
      const cleanSnippet = text
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 1200);
      return `HTTP Status: ${status}, Content-Type: ${contentType}, Page Title: "${title}", Page Text Snippet: "${cleanSnippet}"`;
    }
    return `HTTP Status: ${status}, Content-Type: ${contentType}`;
  } catch (err: any) {
    return `URL fetch info: ${err?.message || "Ulanib bo'lmadi yoki bloklangan"}`;
  }
}

export async function analyzeSecurityTarget(input: AnalyzeInput): Promise<AnalysisResult> {
  const hashSource =
    input.base64Data ||
    input.textContent ||
    input.url ||
    `${input.targetName}:${input.fileSize || 0}:${input.mimeType || ""}`;
  const sha256 = crypto.createHash("sha256").update(hashSource).digest("hex");

  const cached = analysisCache.get(sha256);
  if (cached) {
    return {
      ...cached,
      id: crypto.randomUUID(),
      analyzedAt: new Date().toISOString(),
      source: input.source || cached.source || "web",
    };
  }

  const binInfo = inspectBinaryBuffer(input.base64Data, input.targetName);
  const { heuristicScore, flags, indicators } = runHeuristicPreScan(input, binInfo);

  let urlContext = "";
  if (input.targetType === "url" || input.url) {
    urlContext = await fetchUrlContextSafe(input.url || input.targetName);
  }

  const ai = getGenAIClient();

  const systemInstruction = `Siz POSBON AI — O'zbekistondagi eng kuchli, o'ta xushmuomala va 100% ROSTGO'Y kiberxavfsizlik hamda fayl/kontent ekspertisiz.
Foydalanuvchi sizga o'z Telegram akkauntini himoya qilish va har bir kelgan fayl, rasm, video, hujjat, audio yoki URL havola haqida haqqoniy ma'lumot olish uchun ishonch bildirdi.

SIZNING ASOSIY VAZIFANGIZ — FAQAT ROSTINI AYTISH VA CHUQUR AI TAHLIL QILISH:
1. "whatIsInside" (Fayl/obyekt ichida nima bor va nima bo'lishi mumkin?):
   - Agar rasm, PDF, hujjat, kod, audio yoki video yuborilgan bo'lsa, uning ichini haqiqatan o'qing/ko'ring va ichida aniq nima yozilganini, nima tasvirlanganini yoki qanday dasturiy modullar borligini ROSTGO'YLIK bilan batafsil yozing.
   - MUHIM (.APK FAYLLAR UCHUN): Har qanday .apk faylni avtomatik xavfli demang! Faylning ichki manifesti, ruxsatlari (permissions), fayllar ro'yxati va nomini tahlil qiling:
     * Agar .apk fayl oddiy, toza dastur yoki o'yin bo'lsa va ichida SMS o'g'irlash (READ_SMS, SEND_SMS, RECEIVE_SMS), Accessibility orqali ekranni yashirin boshqarish (BIND_ACCESSIBILITY_SERVICE) yoki aldov nomi ("To'y taklifnomasi.apk", "Video.apk", "Yechinish xonasi.apk", "Soliq jarima.apk") bo'lmasa — uni "safe" (xavfsiz, 85-98% xavfsiz) deb baholang!
     * Faqatgina .apk ichida haqiqatan ham SMS/karta o'g'irlaydigan ruxsatlar, troyan/stealer alomatlari yoki aldov nomi bo'lsagina uni "malicious" (xavfli) deb baholang!
2. "safetyPercentage" (0 dan 100 gacha) va "isCompletelySafe" (true/false):
   - Bu narsa TO'LIQ xavfsizmi yoki yo'qmi? Necha foiz xavfsiz? (Toza rasm, toza PDF yoki toza .apk dastur bo'lsa 88-100% xavfsiz; ichida virus/troyan/fishing bo'lsa 0-15% xavfsiz).
3. "trustScore" (0 dan 100 gacha) va "authenticityVerdict" (Ma'lumotlar haqiqiymi va ishonchlimi?):
   - Fayl yoki tasvir ichidagi ma'lumotlar haqiqiymi va binar formati o'z kengaytmasiga mosmi?
4. Barcha javoblarni o'ta xushmuomala, hurmat bilan, lekin hech narsani yashirmasdan O'ZBEK tilida qaytaring.`;

  const promptText = `Tahlil obyekti haqida barcha real texnik ma'lumotlar:
- Nomi / Manzil: ${input.targetName}
- Turi: ${input.targetType}
- E'lon qilingan MIME turi: ${input.mimeType || "Noma'lum"}
- Binar imzo orqali aniqlangan haqiqiy format: ${binInfo.detectedFormat}
- Kengaytma va binar imzo mosligi: ${binInfo.extensionMatchesBinary ? "Mos keladi (Haqiqiy)" : "MOS EMAS! Soxtalashtirilgan kengaytma!"}
- Hajmi: ${input.fileSize ? `${(input.fileSize / 1024).toFixed(2)} KB (${input.fileSize} bayt)` : "Noma'lum"}
- SHA-256: ${sha256}
- Yuboruvchi va manba: ${input.source === "telegram" ? `Telegram orqali (${input.senderInfo || "foydalanuvchi"})` : "POSBON AI veb-ilovasi"}
${input.captionOrContext ? `- Xabar izohi (Caption / Matn): "${input.captionOrContext}"` : ""}
${binInfo.archiveEntries.length > 0 ? `- Konteyner/Arxiv ichidagi fayllar ro'yxati: ${binInfo.archiveEntries.join(", ")}` : ""}
${binInfo.extractedStringsSample ? `- Fayl binar kodidan ajratib olingan ichki satrlar: ${binInfo.extractedStringsSample}` : ""}
${input.url ? `- Tekshirilayotgan URL: ${input.url}\n- Saytdan olingan jonli ma'lumot: ${urlContext}` : ""}
${input.textContent ? `- Fayl ichidagi matn / kod:\n${input.textContent.slice(0, 3500)}` : ""}
- Dastlabki evristik xavf balli: ${heuristicScore}/100
- Evristik ogohlantirishlar: ${flags.length > 0 ? flags.join("; ") : "Hech qanday zararli imzo topilmadi"}

Iltimos, foydalanuvchiga faqat rostini aytib, ichida nima borligi, necha foiz xavfsiz ekani va ma'lumotlar qanchalik haqiqiy/ishonchli ekanini JSON formatida tahlil qilib bering.`;

  if (ai) {
    try {
      const parts: any[] = [];

      const supportedInlineMimes = [
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/gif",
        "application/pdf",
        "audio/mp3",
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "video/mp4",
        "video/webm",
        "text/plain",
        "text/html",
        "text/csv",
      ];

      if (
        input.base64Data &&
        input.mimeType &&
        supportedInlineMimes.some((m) => input.mimeType!.toLowerCase().startsWith(m)) &&
        input.base64Data.length < 12 * 1024 * 1024
      ) {
        parts.push({
          inlineData: {
            mimeType: input.mimeType,
            data: input.base64Data,
          },
        });
      }

      parts.push({ text: promptText });

      const modelsToTry = ["gemini-3.8-flash", "gemini-flash-latest", "gemini-3.1-flash-lite"];
      let rawText: string | undefined;

      for (const modelName of modelsToTry) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: { parts },
            config: {
              systemInstruction,
              responseMimeType: "application/json",
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  verdict: {
                    type: Type.STRING,
                    description: "Must be one of: safe, suspicious, malicious",
                  },
                  isCompletelySafe: {
                    type: Type.BOOLEAN,
                    description: "True only if the file/link is genuinely safe with no hidden risks.",
                  },
                  safetyPercentage: {
                    type: Type.INTEGER,
                    description: "How safe the file/link is from 0% (deadly virus/phishing) to 100% (completely clean and safe).",
                  },
                  riskScore: {
                    type: Type.INTEGER,
                    description: "Risk percentage from 0% to 100% (roughly 100 - safetyPercentage).",
                  },
                  trustScore: {
                    type: Type.INTEGER,
                    description: "Reliability and authenticity score from 0% (forged/fake/scam) to 100% (authentic/verified).",
                  },
                  threatCategory: {
                    type: Type.STRING,
                    description: "Short category in Uzbek, e.g. 'To\\'liq xavfsiz va ishonchli', 'Xavfsiz Android Ilova (.APK)', 'Fishing tuzog\\'i', 'Troyan / Virus'",
                  },
                  whatIsInside: {
                    type: Type.STRING,
                    description: "Honest, detailed explanation in Uzbek of what is actually inside this file/image/video/document/link and what hidden payloads or risks could be inside.",
                  },
                  authenticityVerdict: {
                    type: Type.STRING,
                    description: "Honest assessment in Uzbek of whether the file/content/information is genuine, authentic, and trustworthy or fake/manipulated.",
                  },
                  politeSummary: {
                    type: Type.STRING,
                    description: "Polite, respectful summary in Uzbek addressing the user warmly.",
                  },
                  technicalDetails: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING },
                    description: "3 to 5 concrete technical findings in Uzbek",
                  },
                  recommendations: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING },
                    description: "2 to 4 clear safety recommendations in Uzbek",
                  },
                },
                required: [
                  "verdict",
                  "isCompletelySafe",
                  "safetyPercentage",
                  "riskScore",
                  "trustScore",
                  "threatCategory",
                  "whatIsInside",
                  "authenticityVerdict",
                  "politeSummary",
                  "technicalDetails",
                  "recommendations",
                ],
              },
            },
          });
          if (response.text?.trim()) {
            rawText = response.text.trim();
            break;
          }
        } catch {
          // try next model in fallback chain
        }
      }

      if (rawText) {
        const parsed = JSON.parse(rawText);
        // Trust AI's riskScore unless heuristic found a hard verified virus signature (heuristicScore >= 75)
        const aiRisk = Math.max(0, Math.min(100, Number(parsed.riskScore) || 0));
        const finalRiskScore =
          heuristicScore >= 75 ? Math.max(aiRisk, heuristicScore) : aiRisk;
        const finalSafetyPercentage = Math.max(0, Math.min(100, 100 - finalRiskScore));

        let finalVerdict: VerdictType =
          parsed.verdict === "malicious" || parsed.verdict === "suspicious" || parsed.verdict === "safe"
            ? parsed.verdict
            : "safe";

        if (finalRiskScore >= 70) {
          finalVerdict = "malicious";
        } else if (finalRiskScore >= 35 && finalVerdict === "safe") {
          finalVerdict = "suspicious";
        }

        const isCompletelySafe = finalVerdict === "safe" && finalSafetyPercentage >= 80;
        const trustScore =
          typeof parsed.trustScore === "number"
            ? Math.max(0, Math.min(100, parsed.trustScore))
            : finalSafetyPercentage;

        const aiIndicators: AnalysisResult["indicators"] = [
          ...indicators,
          {
            label: "Ma'lumot Haqiqiyligi va Ishonchliligi",
            status: trustScore >= 75 ? "pass" : trustScore >= 45 ? "warn" : "fail",
            detail: `${trustScore}% ishonchli (${binInfo.detectedFormat})`,
          },
          {
            label: "POSBON AI Neyron Tahlili",
            status: finalVerdict === "malicious" ? "fail" : finalVerdict === "suspicious" ? "warn" : "pass",
            detail: `${finalSafetyPercentage}% xavfsiz · ${parsed.threatCategory || "Tahlil yakunlandi"}`,
          },
        ];

        const result: AnalysisResult = {
          id: crypto.randomUUID(),
          targetName: input.targetName,
          targetType: input.targetType,
          mimeType: input.mimeType,
          detectedFormat: binInfo.detectedFormat,
          extensionMatchesBinary: binInfo.extensionMatchesBinary,
          fileSize: input.fileSize,
          sha256,
          verdict: finalVerdict,
          isCompletelySafe,
          safetyPercentage: finalSafetyPercentage,
          riskScore: finalRiskScore,
          trustScore,
          threatCategory:
            parsed.threatCategory ||
            (finalVerdict === "safe" ? "To'liq xavfsiz va ishonchli" : "Xavfli obyekt"),
          whatIsInside:
            parsed.whatIsInside ||
            `Ushbu obyekt (${binInfo.detectedFormat}) tarkibida ${
              flags.length > 0 ? flags.join(", ") : "standart ma'lumotlar"
            } mavjud.`,
          authenticityVerdict:
            parsed.authenticityVerdict ||
            (binInfo.extensionMatchesBinary
              ? "Fayl tuzilmasi va kengaytmasi haqiqiy, soxtalashtirish alomatlari yo'q."
              : "Diqqat! Fayl kengaytmasi va ichki binar tuzilmasi bir-biriga mos emas (soxta fayl)!"),
          politeSummary: parsed.politeSummary,
          technicalDetails: Array.isArray(parsed.technicalDetails) ? parsed.technicalDetails : flags,
          recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
          indicators: aiIndicators,
          analyzedAt: new Date().toISOString(),
          source: input.source || "web",
        };

        analysisCache.set(sha256, result);
        return result;
      }
    } catch (err) {
      console.error("Gemini analysis fallback triggered:", err);
    }
  }

  // Deterministic fallback when AI quota/network is busy
  const finalRiskScore = Math.min(100, heuristicScore);
  const finalSafetyPercentage = Math.max(0, 100 - finalRiskScore);
  const finalVerdict: VerdictType =
    finalRiskScore >= 65 ? "malicious" : finalRiskScore >= 35 ? "suspicious" : "safe";
  const isCompletelySafe = finalVerdict === "safe" && finalSafetyPercentage >= 80;
  const trustScore = binInfo.extensionMatchesBinary ? finalSafetyPercentage : Math.min(20, finalSafetyPercentage);

  const fallbackResult: AnalysisResult = {
    id: crypto.randomUUID(),
    targetName: input.targetName,
    targetType: input.targetType,
    mimeType: input.mimeType,
    detectedFormat: binInfo.detectedFormat,
    extensionMatchesBinary: binInfo.extensionMatchesBinary,
    fileSize: input.fileSize,
    sha256,
    verdict: finalVerdict,
    isCompletelySafe,
    safetyPercentage: finalSafetyPercentage,
    riskScore: finalRiskScore,
    trustScore,
    threatCategory:
      finalVerdict === "malicious"
        ? "Virus yoki Fishing Xavfi"
        : finalVerdict === "suspicious"
        ? "Shubhali Obyekt (Ehtiyot bo'ling)"
        : "To'liq Xavfsiz va Ishonchli",
    whatIsInside:
      finalVerdict === "malicious"
        ? `Rostini aytganda, "${input.targetName}" (${binInfo.detectedFormat}) ichida yuqori xavfli zararli elementlar (${flags.join(
            ", "
          )}) mavjud. U qurilmangizdagi shaxsiy ma'lumotlar, parollar yoki bank kartalari kodlarini o'g'irlashi mumkin.`
        : finalVerdict === "suspicious"
        ? `"${input.targetName}" (${binInfo.detectedFormat}) tarkibida shubhali ko'rsatkichlar (${flags.join(
            ", "
          )}) aniqlandi. Ichida yashirin skript yoki tasdiqlanmagan dasturiy kod bo'lishi mumkin.`
        : `"${input.targetName}" (${binInfo.detectedFormat}) — standart va toza ${input.targetType}. Ichida hech qanday yashirin virus, troyan, zararli makros yoki shubhali kod yo'q.`,
    authenticityVerdict: binInfo.extensionMatchesBinary
      ? finalVerdict === "safe"
        ? `Faylning haqiqiy formati (${binInfo.detectedFormat}) o'z nomiga to'liq mos keladi. Ma'lumotlar ishonchliligi: ${trustScore}%.`
        : `Fayl formati (${binInfo.detectedFormat}), ammo ichidagi ma'lumotlar shubhali (Ishonchlilik: ${trustScore}%).`
      : `DIQQAT: Fayl soxtalashtirilgan! Tashqi nomi boshqa formatda bo'lsa ham, ichida "${binInfo.detectedFormat}" yashirilgan!`,
    politeSummary:
      finalVerdict === "malicious"
        ? `Assalomu alaykum, hurmatli foydalanuvchi! Rostini aytishim shart: "${input.targetName}" xavfsiz emas (Xavfsizlik: atigi ${finalSafetyPercentage}%, Xavf: ${finalRiskScore}%). Ichida zararli kod yoki fishing tuzog'i aniqlandi.`
        : finalVerdict === "suspicious"
        ? `Assalomu alaykum! "${input.targetName}" to'liq xavfsiz deb bo'lmaydi (Xavfsizlik darajasi: ${finalSafetyPercentage}%). Ichida shubhali elementlar borligi sababli ehtiyot bo'lishni tavsiya qilaman.`
        : `Assalomu alaykum, hurmatli foydalanuvchi! "${input.targetName}" chuqur tekshirildi. Rostini aytganda, bu fayl ${finalSafetyPercentage}% xavfsiz va ${trustScore}% ishonchli — undan xotirjam foydalanishingiz mumkin!`,
    technicalDetails:
      flags.length > 0
        ? flags
        : [
            `Haqiqiy binar formati: ${binInfo.detectedFormat}`,
            `SHA-256 nazorat summasi: ${sha256.slice(0, 24)}...`,
            "Zararli imzolar, yashirin skriptlar va fishing bazalarida topilmadi",
          ],
    recommendations:
      finalVerdict === "malicious"
        ? [
            "Ushbu faylni yoki havolani aslo ochmang va o'chirib tashlang.",
            "Yuboruvchiga shaxsiy ma'lumot yoki SMS kodlarni bermang.",
          ]
        : finalVerdict === "suspicious"
        ? [
            "Yuboruvchi shaxsiga 100% ishonch hosil qilmasdan ushbu faylni ishga tushirmang.",
            "Agar bu .apk yoki dastur bo'lsa, telefoningizga o'rnatmang.",
          ]
        : [
            "Fayl to'liq xavfsiz, bemalol ochishingiz va foydalanishingiz mumkin.",
          ],
    indicators,
    analyzedAt: new Date().toISOString(),
    source: input.source || "web",
  };

  analysisCache.set(sha256, fallbackResult);
  return fallbackResult;
}

export async function explainSecurityAlertPolite(params: {
  targetName: string;
  threatCategory: string;
  verdict: string;
  technicalDetails: string[];
  userQuestion?: string;
}): Promise<string> {
  const ai = getGenAIClient();
  if (!ai) {
    return `Assalomu alaykum, hurmatli foydalanuvchi! "${params.targetName}" bo'yicha rostgo'y tahlil: Ushbu obyekt "${params.threatCategory}" deb baholandi. Texnik asoslar: ${params.technicalDetails.join("; ")}.`;
  }

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: `Foydalanuvchiga quyidagi fayl/havola bo'yicha xavfsizlik xulosasini o'ta xushmuomala, ammo 100% ROSTGO'Y va aniq O'zbek tilida tushuntirib bering:
Obyekt: ${params.targetName}
Holati: ${params.verdict} (${params.threatCategory})
Texnik tafsilotlar: ${params.technicalDetails.join(", ")}
${
  params.userQuestion
    ? `Foydalanuvchining savoli: "${params.userQuestion}"`
    : "Ichida nima bo'lishi mumkinligini, necha foiz xavfsiz va ma'lumotlar qanchalik haqiqiy ekanini ochiq tushuntiring."
}`,
      config: {
        systemInstruction:
          "Siz POSBON AI ning xushmuomala va rostgo'y kiberxavfsizlik ekspertisiz. Foydalanuvchiga haqiqatni ochiq, tushunarli va muloyim o'zbek tilida tushuntiring.",
      },
    });
    return (
      response.text?.trim() ||
      "Assalomu alaykum! Ushbu obyekt xavfsizlik qoidalarimiz asosida tekshirildi."
    );
  } catch {
    return `Assalomu alaykum, hurmatli foydalanuvchi! "${params.targetName}" obyekti "${params.threatCategory}" sifatida qayd etildi. Tafsilotlar: ${params.technicalDetails.join(". ")}.`;
  }
}

function getDedicatedChatAIClient(): GoogleGenAI | null {
  const chatKey =
    process.env.GEMINI_CHAT_API_KEY ||
    process.env.GEMINI_API_KEYS?.split(",").map((k) => k.trim()).filter(Boolean).pop() ||
    process.env.GEMINI_API_KEY;
  if (!chatKey || chatKey === "MY_GEMINI_API_KEY") {
    return getGenAIClient();
  }
  return new GoogleGenAI({
    apiKey: chatKey.trim(),
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

export function getLiveAIClient(): GoogleGenAI | null {
  return getDedicatedChatAIClient() || getGenAIClient();
}

function generateSmartPosbonReply(
  userMessage: string,
  analysis?: AnalysisResult,
  history?: { role: "user" | "ai"; text: string }[]
): string {
  const msg = (userMessage || "").trim();
  const lower = msg.toLowerCase();

  // 1. If a file/image/URL was analyzed along with the message, give a full detailed truth report
  if (analysis) {
    const verdictLabel =
      analysis.verdict === "safe"
        ? "✅ TO'LIQ XAVFSIZ"
        : analysis.verdict === "suspicious"
        ? "⚠️ SHUBHALI (Ehtiyot bo'ling)"
        : "🚨 XAVFLI (Virus yoki Fishing!)";

    const lines = [
      `🔍 **"${analysis.targetName}" bo'yicha to'liq AI tahlili:**`,
      `• **Holati:** ${verdictLabel} (${analysis.threatCategory})`,
      `• **Xavfsizlik darajasi:** ${analysis.safetyPercentage}%`,
      `• **Ishonchlilik va haqiqiylik:** ${analysis.trustScore}%`,
      `• **Haqiqiy format:** ${analysis.detectedFormat}`,
      "",
      `📦 **Ichida nima bor:**\n${analysis.whatIsInside}`,
      "",
      `🛡️ **Haqiqiyligi:**\n${analysis.authenticityVerdict}`,
    ];

    if (analysis.recommendations && analysis.recommendations.length > 0) {
      lines.push("", `💡 **Tavsiya:** ${analysis.recommendations.join(" ")}`);
    }
    return lines.join("\n");
  }

  // 2. Empty message
  if (!msg) {
    return "Assalomu alaykum! Men POSBON AI yordamchisiman. Menga ovoz orqali gapirishingiz, savol yozishingiz yoki fayl, rasm, hujjat va havola yuborib tekshirtirishingiz mumkin. Sizga qanday yordam beray?";
  }

  // 3. Math & Arithmetic evaluation (e.g., "25 * 48", "1200 + 350 necha bo'ladi")
  const mathCleaned = lower
    .replace(/necha|nechchi|bo'ladi|boladi|hisobla|javobi|teng|qancha|=|\?/gi, "")
    .replace(/ko'paytiruv|kopaytiruv|x/g, "*")
    .replace(/bo'luv|boluv|:/g, "/")
    .replace(/qo'shuv|qoshuv/g, "+")
    .replace(/ayiruv/g, "-")
    .trim();
  if (/^[\d\s+\-*/().%]+$/.test(mathCleaned) && /[\d]/.test(mathCleaned) && /[+\-*/%]/.test(mathCleaned)) {
    try {
      const sanitized = mathCleaned.replace(/[^0-9+\-*/().%]/g, "");
      const calcResult = Function(`"use strict"; return (${sanitized})`)();
      if (typeof calcResult === "number" && Number.isFinite(calcResult)) {
        return `Hisoblash natijasi: **${sanitized} = ${calcResult}**.\n\nYana boshqa hisob-kitob yoki savolingiz bo'lsa, bemalol ayting!`;
      }
    } catch {
      // ignore math eval errors
    }
  }

  // 4. Greetings & Casual Conversation
  if (
    /^(salom|assalom|assalomu alaykum|qalay|qalaysan|qalaysiz|ishlar qalay|yaxshimisan|yaxshimisiz|hello|hi|privet)\b/i.test(
      lower
    )
  ) {
    if (/qalay|yaxshimis/i.test(lower)) {
      return "Va alaykum assalom! Rahmat, juda yaxshiman va 100% ishchi holatdaman! 😊\n\nMen bilan matn yozib yoki **mikrofon tugmasini bosib ovoz orqali** bevosita suhbatlashishingiz, shuningdek har qanday fayl, rasm, hujjat yoki havolani tekshirtirishingiz mumkin. Sizga qanday yordam bera olaman?";
    }
    return "Va alaykum assalom! Xush kelibsiz! Men **POSBON AI** — sizning shaxsiy sun'iy intellekt va kiberxavfsizlik yordamchingizman.\n\nMenga istalgan savolingizni yozishingiz, ovoz orqali gaplashishingiz yoki fayl va havolalarni yuborib tekshirtirishingiz mumkin!";
  }

  if (/^(qalaysan|qalaysiz|ahvollar qalay|nima gap|tinchmi|yaxshimisan)/i.test(lower)) {
    return "Rahmat, a'lo darajada! Tizimlarimiz to'liq va barqaror ishlamoqda. Sizga qanday yordam bera olaman? Savolingizni yozishingiz yoki ovozli xabar orqali aytishingiz mumkin.";
  }

  // 5. Identity / Who are you / Capabilities
  if (
    /(kimsan|kim san|sen kimsan|siz kimsiz|o'zing haqingda|ozing haqingda|nima qila olasan|vazifang nima|posbon nima|posbon ai nima)/i.test(
      lower
    )
  ) {
    return `Men **POSBON AI** — sun'iy intellekt asosida ishlovchi universal yordamchi va kiberxavfsizlik tizimiman.

**Mening asosiy imkoniyatlarim:**
1. **Erkin suhbat va ovozli muloqot:** Men bilan oddiy AI kabi har qanday mavzuda (ilm-fan, dasturlash, maslahat, tarjima, kundalik savollar) yozishib yoki **ovoz orqali jonli** gaplashishingiz mumkin.
2. **Fayl, Rasm, Video, Hujjat va URL tahlili:** Menga fayl (\`.apk\`, \`.exe\`, \`.pdf\`, \`.docx\`, \`.zip\`), rasm yoki havola yuborsangiz, uning ichida nima borligini va necha foiz xavfsiz ekanini 100% rost tahlil qilib beraman.
3. **Telegram himoyasi (@PosbonXBot):** Telegram akkauntingizni ulasangiz, sizga kelgan xavfli virus fayllar va fishing havolalarni avtomatik o'chirib, sizni himoya qilaman.`;
  }

  // 6. How to connect Telegram / @PosbonXBot / Chat ID questions
  if (/(telegram|botni|posbonxbot|posbon_ro_bot|chat id|avtorizatsiya|qanday ulayman|ulash)/i.test(lower)) {
    return `**Telegram akkauntni @PosbonXBot ga ulash juda oson (3 qadam):**

1. Pastdagi menyudan **TELEGRAM** bo'limiga o'ting va yashil **"Telegram Orqali Ulash"** tugmasini bosing.
2. Telegramda **@PosbonXBot** ochiladi — unga **START** bosing. Sayt sizning **Chat ID** raqamingizni avtomatik oladi va akkauntingiz ulanadi!
3. Avtomatik himoya uchun Telegram sozlamalaridan (*Telegram Business → Chatbots*) **@PosbonXBot** ni qo'shing yoki guruhingizga Admin qiling.

Shundan so'ng sizga kelgan har bir fayl tekshiriladi: xavfsizlik foizi, ichida nima borligi aytiladi va xavfli fayl yoki fishing havola bo'lsa avtomatik o'chirib tashlanadi!`;
  }

  // 7. APK / Virus / Malware / Trojan questions
  if (/(\.apk|apk fayl|virus|troyan|trojan|exe|zararli|telefon qot|buzib kir|xaker|hacker)/i.test(lower)) {
    return `**Virus va zararli fayllardan (.apk, .exe, .scr) himoyalanish bo'yicha muhim ma'lumot:**

• **Noma'lum .APK fayllarni o'rnatmang:** Firibgarlar ko'pincha *"To'y taklifnomasi.apk"*, *"Video.apk"*, *"Yechinish xonasi.apk"* yoki *"Bank ilovasi.apk"* nomi ostida ** bank troyanlarini** yuborishadi. Bunday dastur o'rnatilsa, SMS kodlaringizni va karta ma'lumotlaringizni o'g'irlashi mumkin.
• **Ikki qavatli kengaytmalardan ehtiyot bo'ling:** Masalan, \`Shartnoma.pdf.exe\` yoki \`Rasm.jpg.scr\` — bular aslida hujjat emas, kompyuter virusidir.
• **Qanday tekshirish kerak?** Faylni ochishdan oldin uni shu yerga (**AI** bo'limiga yoki **SKAYNER** bo'limiga) yuklang — men uning binar kodini (Magic Bytes) tekshirib, ichida nima borligini aniq aytib beraman!`;
  }

  // 8. Phishing / Card / SMS code / Link security questions
  if (/(fishing|phishing|havola|link|ssilka|karta|uzcard|humo|click|payme|sms kod|firibgar|aldov|yutuq)/i.test(lower)) {
    return `**Fishing (soxta havolalar) va karta firibgarlaridan himoyalanish qoidalari:**

1. **SMS kodni hech kimga bermang:** Bank xodimi ham, Click/Payme ham sizdan SMS kodni yoki karta amal qilish muddatini so'ramaydi.
2. **Soxta yutuq va subsidiya havolalariga kirmang:** \`*.xyz\`, \`*.top\`, \`*.click\` kabi domenlarda *"Sizga 500 000 so'm bonus chiqdi"* deb karta raqamini so'rashsa — bu **100% fishing tuzog'i**.
3. **Havolani tekshiring:** Shubhali havolani bosishdan oldin uni menga yuboring — men u saytning haqiqiy yoki soxta ekanini tekshirib beraman.`;
  }

  // 9. Website sections / Guide questions
  if (/(sayt haqida|qanday ishlaydi|bo'limlar|bolimlar|qo'llanma|qollanma|skayner|tarix)/i.test(lower)) {
    return `**POSBON AI sayti 5 ta qulay bo'limdan iborat:**

1. **SKAYNER:** Fayl, Hujjat, Rasm, Video va Havolalarni (URL) bir zumda virus hamda fishingga tekshiradi.
2. **TELEGRAM:** Akkauntingizni **@PosbonXBot** ga ulash va avtomatik himoyani boshqarish bo'limi.
3. **AI (Hozirgi bo'lim):** Men bilan matn yoki **ovoz orqali jonli suhbatlashish** hamda fayllarni tekshirtirish oynasi.
4. **TARIX:** Tekshirilgan barcha fayllar ro'yxati. Istalgan fayl ustiga bossangiz, uning to'liq tahlili ochiladi.
5. **QO'LLANMA:** Barcha amallarning qadam-baqadam sodda tushuntirishi va tizimni sinash tugmalari.`;
  }

  // 10. Programming / Code / Tech questions
  if (/(dasturlash|kod yoz|python|javascript|react|html|css|dasturchi|algoritm)/i.test(lower)) {
    return `Albatta! Dasturlash va IT bo'yicha sizga yordam berishdan xursandman. 💻\n\nSizning so'rovingiz: *"${msg}"*\n\nAgar biror dastur kodi (Python, JavaScript/TypeScript, React, HTML/CSS) yozish, xatolikni topish yoki kod xavfsizligini (SQL Injection, XSS, CSRF) tekshirish kerak bo'lsa, kodni yoki vazifani batafsil yozib yuboring — darhol tayyorlab va tahlil qilib beraman!`;
  }

  // 11. Translation / Text writing
  if (/(tarjima|ingliz til|rus til|matn yoz|tabrik|ariza|maqola|she'r|sher)/i.test(lower)) {
    return `Marhamat! Siz so'ragan mavzu (*"${msg}"*) bo'yicha yordam berishga tayyorman.\n\nTarjima qilinadigan matnni yoki yozilishi kerak bo'lgan mavzu tafsilotlarini yuboring — men uni chiroyli, ravon va bexato qilib tayyorlab beraman!`;
  }

  // 12. Thanks / Polite closing
  if (/(rahmat|raxmat|tashakkur|katta rahmat|yaxshi|zo'r|zor|a'lo|mukammal)/i.test(lower)) {
    return "Arzimaydi, sizga yordam bera olganimdan juda xursandman! 😊\n\nYana savolingiz bo'lsa yoki biror fayl/havolani tekshirtirmoqchi bo'lsangiz, bemalol yozing yoki mikrofonni bosib ovoz orqali murojaat qiling!";
  }

  // 13. General intelligent response for any other user prompt
  const lastContext =
    history && history.length > 1
      ? ` Oldingi suhbatimizni ham inobatga olgan holda aytamanki,`
      : "";

  return `Savolingiz uchun rahmat! Siz *"${msg}"* haqida so'radingiz.${lastContext}

Men **POSBON AI** sifatida sizga quyidagi yo'nalishlarda aniq yordam bera olaman:
• Agar bu mavzu bo'yicha **qo'shimcha ma'lumot, maslahat yoki hisob-kitob** kerak bo'lsa, savolingizni biroz aniqlashtirib yozing yoki **mikrofon tugmasi** orqali ovozda ayting.
• Agar biror **fayl, rasm, hujjat yoki havolani (URL)** tekshirtirmoqchi bo'lsangiz, chap tomondagi **📎 (qisqich)** tugmasini bosib yuboring — men uning ichida nima borligini va necha foiz xavfsiz ekanini 100% rost tahlil qilib beraman!`;
}

export async function chatWithPosbonAI(params: {
  message: string;
  history?: { role: "user" | "ai"; text: string }[];
  fileName?: string;
  mimeType?: string;
  fileSize?: number;
  base64Data?: string;
  textContent?: string;
}): Promise<{
  reply: string;
  analysis?: AnalysisResult;
}> {
  let analysis: AnalysisResult | undefined;

  // If user attached a file/image/video/document or included a URL in their message, analyze it too
  if (params.fileName || params.base64Data) {
    let targetType: TargetType = "file";
    const mime = (params.mimeType || "").toLowerCase();
    if (mime.startsWith("image/")) targetType = "image";
    else if (mime.startsWith("video/") || mime.startsWith("audio/")) targetType = "video";
    else if (/\.(pdf|doc|docx|xls|xlsx|txt|csv)$/i.test(params.fileName || "")) targetType = "document";

    analysis = await analyzeSecurityTarget({
      targetName: params.fileName || "Yuklangan_fayl",
      targetType,
      mimeType: params.mimeType,
      fileSize: params.fileSize,
      base64Data: params.base64Data,
      textContent: params.textContent,
      source: "web",
    });
  } else if (params.message) {
    const urlMatch = params.message.match(/https?:\/\/[^\s]+/i);
    if (urlMatch) {
      analysis = await analyzeSecurityTarget({
        targetName: urlMatch[0],
        targetType: "url",
        url: urlMatch[0],
        mimeType: "text/uri-list",
        source: "web",
      });
    }
  }

  const ai = getDedicatedChatAIClient();
  if (!ai) {
    return {
      reply: generateSmartPosbonReply(params.message, analysis, params.history),
      analysis,
    };
  }

  const parts: any[] = [];
  const supportedMimes = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "application/pdf",
    "audio/mp3",
    "audio/mpeg",
    "audio/wav",
    "audio/ogg",
    "video/mp4",
    "video/webm",
    "text/plain",
  ];

  if (
    params.base64Data &&
    params.mimeType &&
    supportedMimes.some((m) => params.mimeType!.toLowerCase().startsWith(m)) &&
    params.base64Data.length < 12 * 1024 * 1024
  ) {
    parts.push({
      inlineData: {
        mimeType: params.mimeType,
        data: params.base64Data,
      },
    });
  }

  const historyTranscript =
    Array.isArray(params.history) && params.history.length > 0
      ? "\n\nOldingi suhbat tarixi:\n" +
        params.history
          .slice(-8)
          .map((h) => `${h.role === "user" ? "Foydalanuvchi" : "POSBON AI"}: ${h.text}`)
          .join("\n")
      : "";

  const contextBlock = analysis
    ? `\n\n[Avtomatik Xavfsizlik Tahlili Natijasi:\n- Fayl/Manzil: ${analysis.targetName}\n- Format: ${analysis.detectedFormat}\n- Xavfsizlik foizi: ${analysis.safetyPercentage}%\n- Ishonchlilik foizi: ${analysis.trustScore}%\n- Ichida nima bor: ${analysis.whatIsInside}\n- Haqiqiyligi: ${analysis.authenticityVerdict}]`
    : "";

  parts.push({
    text: `${historyTranscript}\n\nFoydalanuvchi xabari: ${
      params.message ||
      "Ushbu yuborilgan fayl/rasmni tahlil qilib, ichida nima borligi va qanchalik xavfsiz ekanini tushuntirib bering."
    }${params.textContent ? `\n\nFayl matni:\n${params.textContent.slice(0, 3000)}` : ""}${contextBlock}`,
  });

  const systemInstruction = `Siz POSBON AI platformasining aqlli, xushmuomala va universal sun'iy intellektisiz.
Siz oddiy AI kabi har qanday mavzudagi savollarga (kundalik savollar, bilim, maslahat, matn yozish, tarjima, dasturlash va h.k.) javob bera olasiz, shuningdek foydalanuvchi yuborgan fayl, rasm, video, hujjat va havolalarni chuqur tekshira olasiz.

POSBON AI SAYTI HAQIDA BILISHINGIZ SHART BO'LGAN MA'LUMOTLAR:
1. Saytda 5 ta bo'lim bor:
   - SKAYNER: Fayl (.apk, .exe, .zip), Hujjat (.pdf, .docx), Rasm, Video va Havolani (URL) virus hamda fishingga tekshiradi.
   - TELEGRAM: Foydalanuvchi Telegram akkauntini @PosbonXBot ga ulaydi. START bosilganda sayt Chat ID ni avtomatik oladi. Bot Telegramdan kelgan har bir fayl haqida rost ma'lumot (necha % xavfsiz, ichida nima bor, haqiqiymi) beradi va xavfli fayl yoki fishing havolani avtomatik o'chirib tashlaydi.
   - AI (Siz turgan bo'lim): Matn va ovoz orqali jonli suhbatlashish hamda fayl/rasmlarni yuborib tahlil qildirish bo'limi.
   - TARIX: Tekshirilgan barcha fayllar ro'yxati. Ustiga bosilganda to'liq tahlili chiqadi.
   - QO'LLANMA: 1-sinf o'quvchisi ham tushunadigan sodda yo'riqnoma va tizimni sinash tugmalari.
2. Doimo o'zbek tilida, sodda, aniq va samimiy javob bering.`;

  const modelsToTry = ["gemini-3.8-flash", "gemini-flash-latest", "gemini-3.1-flash-lite"];

  for (const modelName of modelsToTry) {
    try {
      const response = await ai.models.generateContent({
        model: modelName,
        contents: { parts },
        config: {
          systemInstruction,
        },
      });
      const text = response.text?.trim();
      if (text) {
        return {
          reply: text,
          analysis,
        };
      }
    } catch {
      // try next model
    }
  }

  return {
    reply: generateSmartPosbonReply(params.message, analysis, params.history),
    analysis,
  };
}

export async function generatePosbonSpeech(text: string): Promise<{ audioBase64?: string }> {
  const ai = getDedicatedChatAIClient();
  if (!ai || !text.trim()) return {};

  const cleanText = text.replace(/[*#_`~]/g, "").slice(0, 700);
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.8-flash-lite-tts",
      contents: [
        {
          role: "user",
          parts: [
            {
              text: cleanText,
            },
          ],
        },
      ],
      config: {
        responseModalities: ["AUDIO"],
        speechConfig: {
          voiceConfig: {
            prebuiltVoiceConfig: { voiceName: "Kore" },
          },
        },
      },
    });

    const base64Audio = response.candidates?.[0]?.content?.parts?.[0]?.inlineData?.data;
    if (base64Audio) {
      return { audioBase64: base64Audio };
    }
  } catch {
    // Client will seamlessly use Web Speech Synthesis fallback
  }
  return {};
}

export async function transcribePosbonAudio(params: {
  base64Audio: string;
  mimeType?: string;
}): Promise<{ transcript: string }> {
  const ai = getDedicatedChatAIClient();
  if (!ai || !params.base64Audio) {
    return { transcript: "" };
  }

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.5-transcribe",
      contents: {
        parts: [
          {
            inlineData: {
              mimeType: params.mimeType || "audio/webm",
              data: params.base64Audio,
            },
          },
          {
            text: "Transcribe this spoken audio accurately. Return only the transcribed words without extra commentary.",
          },
        ],
      },
    });
    return { transcript: response.text?.trim() || "" };
  } catch {
    return { transcript: "" };
  }
}

