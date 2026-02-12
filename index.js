// index.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";
import multer from "multer";
import crypto from "crypto";
import nodemailer from "nodemailer";

// ✅ ADDED
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

// ✅ ADDED
const ADMIN_KEY = process.env.ADMIN_KEY || "ozge123!";
// ✅ CHANGED: Render kalıcı disk (disk mount path /data olmalı)
const SHARE_FILE = "/data/shares.json";

// ✅ ADDED: foto upload klasörü (kalıcı)
const UPLOAD_DIR = "/data/uploads";


// ----------------- helpers -----------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const whereNotNull = (arr) => arr.filter((x) => x != null);

function maskEmail(email) {
  const [u, d] = String(email || "").split("@");
  if (!u || !d) return String(email || "");
  const head = u.slice(0, 2);
  return `${head}***@${d}`;
}

function nowIso() {
  return new Date().toISOString();
}

// ✅ ADDED (manifest share helpers)
function ensureShareDir() {
  try {
    const dir = path.dirname(SHARE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  } catch (e) {
    console.error("ensureShareDir error", e);
  }
}

// ✅ ADDED (upload dir)
function ensureUploadDir() {
  try {
    if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  } catch (e) {
    console.error("ensureUploadDir error", e);
  }
}
ensureUploadDir();
ensureShareDir();


// ✅ ADDED (static serve uploads)
app.use("/uploads", express.static(UPLOAD_DIR));

function readShares() {
  try {
    if (!fs.existsSync(SHARE_FILE)) return [];
    const raw = fs.readFileSync(SHARE_FILE, "utf-8");
    const data = JSON.parse(raw || "[]");
    return Array.isArray(data) ? data : [];
  } catch (e) {
    console.error("readShares error", e);
    return [];
  }
}

function writeShares(arr) {
  try {
    ensureShareDir(); // ✅ ADDED
    fs.writeFileSync(SHARE_FILE, JSON.stringify(arr, null, 2), "utf-8");
  } catch (e) {
    console.error("writeShares error", e);
  }
}

function requireAdmin(req, res, next) {
  const key = req.headers["x-admin-key"] || req.query.key;
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");
  next();
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ================== SECURE NOTE RESET (OTP) ==================
// auth resetTokens ile karışmasın diye ayrı store:
const secureNoteResetTokens = new Map(); // email -> { code, expiresAt, createdAt }

// ✅ Secure Note: OTP üret + mail gönder
app.post("/api/secure-note/request-reset", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  console.log(`🟨 [SECURE NOTE FORGOT] ${nowIso()} email=${maskEmail(email)}`);

  if (!email) return res.status(400).json({ error: "email zorunlu" });

  const code = genOtp();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 dk
  secureNoteResetTokens.set(email, { code, expiresAt, createdAt: Date.now() });

  console.log(
    `✅ [SECURE NOTE OTP SET] email=${maskEmail(email)} code=${code} exp=${new Date(expiresAt).toISOString()}`
  );

  if (mailer) {
    try {
      await mailer.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: "Kilitli Not Defteri - Şifre Sıfırlama Kodu",
        text: `Kilitli Not Defteri şifre sıfırlama kodun: ${code}\nKod 10 dakika geçerlidir.`,
      });
      console.log(`✅ [SECURE NOTE MAIL SENT] to=${maskEmail(email)}`);
    } catch (e) {
      console.error("❌ [SECURE NOTE MAIL FAILED]:", e);
      return res.status(500).json({ error: "Mail gönderilemedi" });
    }
  } else {
    console.log("📭 SMTP yok. Secure Note OTP (debug):", code);
  }

  return res.json({ ok: true });
});

// ✅ Secure Note: OTP doğrula (Flutter burada OK bekliyor)
app.post("/api/secure-note/confirm-reset", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "").trim();
  const newPin = String(req.body?.newPin || "").trim(); // sadece format kontrolü

  console.log(`🟧 [SECURE NOTE CONFIRM] ${nowIso()} email=${maskEmail(email)} code=${code}`);

  if (!email || !code || !newPin) {
    return res.status(400).json({ error: "email, code, newPin zorunlu" });
  }

  if (!/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: "Kod 6 haneli olmalı" });
  }

  if (!/^\d{4,6}$/.test(newPin)) {
    return res.status(400).json({ error: "PIN 4-6 haneli olmalı" });
  }

  const entry = secureNoteResetTokens.get(email);
  if (!entry) return res.status(400).json({ error: "Kod bulunamadı" });

  if (Date.now() > entry.expiresAt) {
    secureNoteResetTokens.delete(email);
    return res.status(400).json({ error: "Kod süresi doldu" });
  }

  if (String(entry.code).trim() !== code) {
    return res.status(400).json({ error: "Kod hatalı" });
  }

  // ✅ Kod doğru → backend sadece onay verir.
  // PIN zaten cihazda secure storage + hash olarak tutuluyor.
  secureNoteResetTokens.delete(email);

  return res.json({ ok: true });
});

// ----------------- AUTH (DEMO STORE) -----------------
// ⚠️ Demo: sunucu kapanınca silinir. Gerçekte DB bağlanmalı.
const users = new Map(); // email -> { email, passwordHash }
const resetTokens = new Map(); // email -> { code, expiresAt, createdAt }

function hashPassword(pw) {
  return crypto.createHash("sha256").update(String(pw)).digest("hex");
}

function genOtp() {
  // 6 haneli numeric
  return String(Math.floor(100000 + Math.random() * 900000));
}

function createMailer() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: false, // Gmail 587 STARTTLS
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

// Mailer’ı bir kez oluştur
const mailer = createMailer();

// Sunucu açılırken mailer bağlantısını test et (log için)
(async () => {
  if (!mailer) {
    console.log("📭 SMTP ayarlı değil. OTP maile gitmez, konsola basılır.");
    return;
  }
  try {
    await mailer.verify();
    console.log("✅ SMTP bağlantısı OK");
  } catch (e) {
    console.error("❌ SMTP verify hata:", e);
  }
})();

// ----------------- AUTH ENDPOINTS -----------------

// ✅ Register
app.post("/api/auth/register", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "").trim();

  console.log(`🟦 [REGISTER] ${nowIso()} email=${maskEmail(email)}`);

  if (!email || !password) {
    return res.status(400).json({ error: "email ve password zorunlu" });
  }
  if (users.has(email)) {
    return res.status(409).json({ error: "Bu e-posta zaten kayıtlı" });
  }

  users.set(email, { email, passwordHash: hashPassword(password) });

  if (mailer) {
    try {
      await mailer.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: "Mani Fal’a Hoş Geldin ✨",
        text: `Merhaba,

Mani Fal’a hoş geldin.

Artık sezgilerine kulak verebileceğin, kendinle baş başa kalabileceğin
küçük ama anlamlı anlar seni bekliyor.

Her gün:
• Günlük burç yorumunu okuyabilir
• Günün tarot kartını keşfedebilir
• Rüyalarının anlamlarını yorumlayabilir
• Fal ve ritüellerinle iç dünyana dokunabilirsin

Mani Fal, kesin kehanetler sunmaz;
sana sadece durup hissetmen için bir alan açar.

Keyifli keşifler dileriz.

Sevgiyle,
Mani Fal ✨`,
      });

      console.log(`✅ [WELCOME MAIL SENT] to=${maskEmail(email)}`);
    } catch (e) {
      console.error("❌ [WELCOME MAIL FAILED]:", e);
    }
  } else {
    console.log("📭 SMTP yok. Hoş geldin maili gönderilemedi (SMTP ayarlı değil).");
  }

  console.log(`✅ [REGISTER OK] users.size=${users.size}`);
  return res.status(201).json({ ok: true });
});

// ✅ Login
app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "").trim();

  console.log(`🟩 [LOGIN] ${nowIso()} email=${maskEmail(email)}`);

  if (!email || !password) {
    return res.status(400).json({ error: "email ve password zorunlu" });
  }

  const u = users.get(email);
  if (!u) return res.status(401).json({ error: "E-posta veya şifre hatalı" });

  const ok = u.passwordHash === hashPassword(password);
  if (!ok) return res.status(401).json({ error: "E-posta veya şifre hatalı" });

  return res.json({ ok: true });
});

// ✅ Forgot Password: OTP üret + mail gönder
app.post("/api/auth/forgot-password", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  console.log(`🟨 [FORGOT] ${nowIso()} email=${maskEmail(email)}`);

  if (!email) return res.status(400).json({ error: "email zorunlu" });

  const userExists = users.has(email);
  console.log(`ℹ️ [FORGOT] userExists=${userExists} users.size=${users.size}`);

  const code = genOtp();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 dk
  resetTokens.set(email, { code, expiresAt, createdAt: Date.now() });

  console.log(
    `✅ [FORGOT OTP SET] email=${maskEmail(email)} code=${code} exp=${new Date(expiresAt).toISOString()}`
  );

  if (mailer) {
    try {
      await mailer.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: "Şifre Sıfırlama Kodu",
        text: `Şifre sıfırlama kodun: ${code}\nKod 10 dakika geçerlidir.`,
      });
      console.log(`✅ [MAIL SENT] to=${maskEmail(email)}`);
    } catch (e) {
      console.error("❌ [MAIL FAILED]:", e);
    }
  } else {
    console.log("📭 SMTP yok. OTP (debug):", code);
  }

  return res.json({
    ok: true,
    message: "Eğer bu e-posta kayıtlıysa doğrulama kodu gönderildi.",
  });
});

// ✅ Verify Reset Code
app.post("/api/auth/verify-reset-code", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "").trim();

  console.log(`🟧 [VERIFY] ${nowIso()} email=${maskEmail(email)} code=${code}`);

  if (!email || !code) {
    return res.status(400).json({ error: "email ve code zorunlu" });
  }

  const entry = resetTokens.get(email);
  if (!entry) return res.status(400).json({ error: "Kod bulunamadı" });

  if (Date.now() > entry.expiresAt) {
    resetTokens.delete(email);
    return res.status(400).json({ error: "Kod süresi doldu" });
  }

  if (String(entry.code).trim() !== code) {
    return res.status(400).json({ error: "Kod hatalı" });
  }

  return res.json({ ok: true });
});

// ✅ Reset Password: email + code + newPassword
app.post("/api/auth/reset-password", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "").trim();
  const newPassword = String(req.body?.newPassword || "").trim();

  console.log(
    `🟥 [RESET] ${nowIso()} email=${maskEmail(email)} code=${code} newPwLen=${newPassword.length}`
  );

  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: "email, code, newPassword zorunlu" });
  }

  const entry = resetTokens.get(email);
  if (!entry) {
    console.log("❌ [RESET] entry yok (muhtemelen farklı server/IP veya restart)");
    return res.status(400).json({ error: "Kod bulunamadı" });
  }

  if (Date.now() > entry.expiresAt) {
    resetTokens.delete(email);
    return res.status(400).json({ error: "Kod süresi doldu" });
  }

  if (String(entry.code).trim() !== code) {
    console.log(`❌ [RESET] code mismatch expected=${entry.code} got=${code}`);
    return res.status(400).json({ error: "Kod hatalı" });
  }

  const existing = users.get(email);
  if (!existing) {
    console.log(`⚠️ [RESET] user yoktu, demo olarak oluşturuluyor: ${maskEmail(email)}`);
  }

  users.set(email, { email, passwordHash: hashPassword(newPassword) });
  resetTokens.delete(email);

  console.log(`✅ [RESET OK] ${maskEmail(email)}`);
  return res.json({ ok: true, message: "Şifre güncellendi" });
});

// ----------------- Gemini helpers (RETRY + BACKOFF) -----------------
async function callGemini(prompt, { retries = 5 } = {}) {
  if (!GEMINI_API_KEY) throw new Error("GEMINI_API_KEY tanımlı değil (.env)");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;

  let lastErr = null;

  for (let attempt = 1; attempt <= retries; attempt++) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.9, topP: 0.95, topK: 40 },
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (res.ok) {
      return data.candidates?.[0]?.content?.parts?.[0]?.text ?? "Fal metni üretilemedi.";
    }

    const code = data?.error?.code ?? res.status;
    const msg = data?.error?.message ?? res.statusText;

    if (code === 503 || code === 429) {
      const waitMs = Math.min(20000, 1500 * Math.pow(2, attempt - 1));
      console.error(`⏳ Gemini geçici hata ${code}: ${msg} | deneme ${attempt}/${retries} | ${waitMs}ms bekle`);
      await sleep(waitMs);
      lastErr = { code, msg };
      continue;
    }

    console.error("❌ Gemini API hatası:", res.status, JSON.stringify(data, null, 2));
    throw new Error(`Gemini API error: ${code} ${msg}`);
  }

  throw new Error(`Gemini geçici hata (retries bitti): ${JSON.stringify(lastErr)}`);
}

async function callGeminiVision(parts, { retries = 5 } = {}) {
  if (!GEMINI_API_KEY) throw new Error("GEMINI_API_KEY tanımlı değil (.env)");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;

  let lastErr = null;

  for (let attempt = 1; attempt <= retries; attempt++) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts }],
        generationConfig: { temperature: 0.9, topP: 0.95, topK: 40 },
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (res.ok) {
      return data.candidates?.[0]?.content?.parts?.[0]?.text ?? "Fal metni üretilemedi.";
    }

    const code = data?.error?.code ?? res.status;
    const msg = data?.error?.message ?? res.statusText;

    if (code === 503 || code === 429) {
      const waitMs = Math.min(20000, 1500 * Math.pow(2, attempt - 1));
      console.error(`⏳ Gemini Vision geçici hata ${code}: ${msg} | deneme ${attempt}/${retries} | ${waitMs}ms bekle`);
      await sleep(waitMs);
      lastErr = { code, msg };
      continue;
    }

    console.error("❌ Gemini Vision API hatası:", res.status, JSON.stringify(data, null, 2));
    throw new Error(`Gemini Vision error: ${code} ${msg}`);
  }

  throw new Error(`Gemini Vision geçici hata (retries bitti): ${JSON.stringify(lastErr)}`);
}

// ----------------- Upload (multer) -----------------
// ✅ AYNEN KALDI: kahve falı için memoryStorage
const upload = multer({ storage: multer.memoryStorage() });

// ✅ ADDED: manifest için disk storage (foto kaydı)
const manifestUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const ext = (file.originalname.split(".").pop() || "jpg")
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");
      cb(null, `${Date.now()}-${Math.random().toString(16).slice(2)}.${ext || "jpg"}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

// ----------------- 5dk Job Store -----------------
const fortuneJobs = new Map();
const DELAY_MS = 5 * 60 * 1000;

function genId() {
  return Date.now().toString() + Math.random().toString(16).slice(2);
}

// ✅ ADDED (manifest share endpoints)  ✅ UPDATED: photo optional
app.post("/api/manifest/share", manifestUpload.single("image"), (req, res) => {
  try {
    // JSON veya multipart ikisi de gelsin:
    const text = String(req.body?.text || req.body?.text === "" ? req.body.text : "").trim();
    let user = req.body?.user ?? null;

    // multipart'ta user JSON string gelebilir
    if (typeof user === "string") {
      try { user = JSON.parse(user); } catch (_) {}
    }

    if (!text || String(text).trim().length < 3) {
      return res.status(400).json({ error: "text required" });
    }

    const shares = readShares();

    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const item = {
      id: crypto.randomUUID?.() || String(Date.now()),
      text: String(text).trim(),
      user: user || null,
      imageUrl, // ✅ ADDED
      createdAt: new Date().toISOString(),
      ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || null,
    };

    shares.unshift(item);
    writeShares(shares);

    return res.json({ ok: true, id: item.id, imageUrl });
  } catch (e) {
    console.error("share save error", e);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/api/admin/manifest/shares", requireAdmin, (req, res) => {
  const shares = readShares();
  res.json({ ok: true, count: shares.length, shares });
});

app.get("/admin/shares", requireAdmin, (req, res) => {
  const shares = readShares();
  const key = req.query.key ? String(req.query.key) : "";

  const rows = shares
    .map(
      (s) => `
      <div style="padding:12px;border:1px solid #eee;border-radius:12px;margin:10px 0;">
        <div style="font-weight:700;">${new Date(s.createdAt).toLocaleString()}</div>
        <div style="white-space:pre-wrap;margin-top:6px;">${escapeHtml(s.text)}</div>

        ${
          s.imageUrl
            ? `<img src="${escapeHtml(s.imageUrl)}" style="max-width:100%;border-radius:12px;margin-top:10px;" />`
            : ""
        }

        <div style="opacity:.6;margin-top:8px;font-size:12px;">id: ${s.id} | ip: ${s.ip || "-"}</div>

        <a href="/admin/shares/${encodeURIComponent(s.id)}?key=${encodeURIComponent(key)}"
           style="display:inline-block;margin-top:8px;text-decoration:none;color:#E75480;font-weight:700;">
          Aç →
        </a>
      </div>
    `
    )
    .join("");

  res.send(`
    <html>
      <head><meta charset="utf-8"/><title>Manifest Paylaşımları</title></head>
      <body style="font-family:Arial;padding:18px;max-width:900px;margin:0 auto;">
        <h2>Manifest Paylaşımları (${shares.length})</h2>
        <p style="opacity:.7">Bu sayfayı açmak için key gerekli.</p>
        ${rows || "<p>Henüz paylaşım yok.</p>"}
      </body>
    </html>
  `);
});

// ✅ ADDED: detail page (✅ UPDATED: photo show)
app.get("/admin/shares/:id", requireAdmin, (req, res) => {
  const shares = readShares();
  const item = shares.find((x) => String(x.id) === String(req.params.id));

  if (!item) return res.status(404).send("Not found");

  const key = req.query.key ? String(req.query.key) : "";

  res.send(`
    <html>
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Paylaşım Detayı</title>
      </head>
      <body style="font-family:Arial;padding:18px;max-width:900px;margin:0 auto;">
        <a href="/admin/shares?key=${encodeURIComponent(key)}"
           style="display:inline-block;margin-bottom:12px;text-decoration:none;">
          ← Geri
        </a>

        <h2>Paylaşım Detayı</h2>

        <div style="opacity:.7;margin:8px 0 12px 0;">
          ${new Date(item.createdAt).toLocaleString()} • id: ${escapeHtml(item.id)}
        </div>

        <button onclick="copyText()"
          style="padding:10px 12px;border:1px solid #ddd;border-radius:10px;cursor:pointer;background:#fff;">
          Kopyala
        </button>

        <pre id="txt"
          style="white-space:pre-wrap;margin-top:12px;padding:12px;border:1px solid #eee;border-radius:12px;background:#fafafa;">
${escapeHtml(item.text)}
        </pre>

        ${
          item.imageUrl
            ? `<div style="margin-top:12px;">
                 <img src="${escapeHtml(item.imageUrl)}" style="max-width:100%;border-radius:12px;" />
               </div>`
            : ""
        }

        <div style="opacity:.6;margin-top:10px;font-size:12px;">
          ip: ${escapeHtml(item.ip || "-")}
        </div>

        <script>
          function copyText() {
            const t = document.getElementById("txt").innerText;
            navigator.clipboard.writeText(t);
            alert("Kopyalandı ✅");
          }
        </script>
      </body>
    </html>
  `);
});

// ----------------- Yükselen burç (Gemini + fallback) -----------------
app.post("/api/astrology/rising", async (req, res) => {
  const { birthDate, birthTime, birthPlace } = req.body || {};

  if (!birthDate || !birthTime || !birthPlace) {
    return res.status(400).json({
      error: "birthDate, birthTime ve birthPlace zorunlu",
    });
  }

  const allowed = [
    "aries","taurus","gemini","cancer","leo","virgo",
    "libra","scorpio","sagittarius","capricorn","aquarius","pisces",
  ];

  const prompt = `
Sen deneyimli bir astrologsun.

Görev:
Aşağıdaki doğum bilgilerine göre kullanıcının YÜKSELEN burcunu belirle.

Kurallar:
- SADECE aşağıdaki burç ID’lerinden BİR TANESİNİ seç:
${allowed.join(", ")}
- Cevap SADECE JSON olsun.
- Ek açıklama yazma.
- Format birebir şu olsun:
{"risingSignId":"aries"}

Doğum bilgileri:
- Tarih: ${birthDate}
- Saat: ${birthTime}
- Yer: ${birthPlace}
`.trim();

  let resultText;

  try {
    resultText = await callGemini(prompt);
  } catch (e) {
    console.error("⚠️ Gemini unavailable, fallback kullanılıyor");
    const hour = parseInt(String(birthTime).split(":")[0], 10);
    const idx = isNaN(hour) ? 0 : hour % 12;

    return res.json({
      risingSignId: allowed[idx],
      source: "fallback",
    });
  }

  let risingSignId = null;

  try {
    const parsed = JSON.parse(resultText);
    risingSignId = parsed?.risingSignId;
  } catch {
    const match = resultText.match(/"risingSignId"\s*:\s*"([^"]+)"/);
    risingSignId = match?.[1];
  }

  risingSignId = String(risingSignId || "").toLowerCase().trim();

  if (!allowed.includes(risingSignId)) {
    const hour = parseInt(String(birthTime).split(":")[0], 10);
    const idx = isNaN(hour) ? 0 : hour % 12;

    return res.json({
      risingSignId: allowed[idx],
      source: "fallback",
    });
  }

  return res.json({
    risingSignId,
    source: "gemini",
  });
});

// ----------------- Kahve falı endpoints -----------------
app.post(
  "/api/fortune/coffee",
  upload.fields([
    { name: "image_left", maxCount: 1 },
    { name: "image_center", maxCount: 1 },
    { name: "image_right", maxCount: 1 },
    { name: "image_saucer", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      if (!GEMINI_API_KEY) {
        return res.status(500).json({ error: "GEMINI_API_KEY tanımlı değil (.env)" });
      }

      const note = (req.body?.note || "").trim();

      let userProfile = null;
      try {
        userProfile = req.body?.userProfile ? JSON.parse(req.body.userProfile) : null;
      } catch (_) {
        userProfile = null;
      }

      const name = userProfile?.name || "kullanıcı";

      const files = req.files || {};
      const left = files["image_left"]?.[0];
      const center = files["image_center"]?.[0];
      const right = files["image_right"]?.[0];
      const saucer = files["image_saucer"]?.[0];

      if (!left || !center || !right || !saucer) {
        return res.status(400).json({
          error: "4 foto gerekli: image_left, image_center, image_right, image_saucer",
        });
      }

      const id = genId();
      fortuneJobs.set(id, {
        id,
        type: "coffee_photo",
        status: "pending",
        createdAt: new Date().toISOString(),
        resultText: null,
        error: null,
      });

      setTimeout(async () => {
        const current = fortuneJobs.get(id);
        if (!current) return;

        try {
          const prompt = `
Sen deneyimli bir Türk kahvesi falcısısın ve Türkçe konuşuyorsun.

Kullanıcı adı: ${name}
Kullanıcının notu / niyeti: "${note || "Genel fal"}"

Görev:
- Kullanıcı 4 foto gönderdi: fincan sol, fincan karşıdan (orta), fincan sağ, tabak.
- Bu 4 görseli BİRLİKTE değerlendir ve tutarlı tek bir fal yorumu üret.
- 4 başlık kullan: Genel Enerji, Aşk, Para/İş, Yakın Gelecek.
- 3–6 paragraf arası, akıcı ve empatik yaz.
- Korkutucu/tehditkâr dil kullanma; kesin kehanet verme.
- En sonda kısa bir kapanış cümlesi ekle.
`.trim();

          const parts = [
            { text: prompt },

            { text: "\n[1] Fincan - Sol taraf" },
            { inlineData: { mimeType: left.mimetype || "image/jpeg", data: left.buffer.toString("base64") } },

            { text: "\n[2] Fincan - Karşıdan / Orta" },
            { inlineData: { mimeType: center.mimetype || "image/jpeg", data: center.buffer.toString("base64") } },

            { text: "\n[3] Fincan - Sağ taraf" },
            { inlineData: { mimeType: right.mimetype || "image/jpeg", data: right.buffer.toString("base64") } },

            { text: "\n[4] Tabak" },
            { inlineData: { mimeType: saucer.mimetype || "image/jpeg", data: saucer.buffer.toString("base64") } },
          ];

          const resultText = await callGeminiVision(parts);

          fortuneJobs.set(id, { ...current, status: "ready", resultText: (resultText || "").trim(), error: null });
        } catch (e) {
          fortuneJobs.set(id, { ...current, status: "error", error: String(e) });
        }
      }, DELAY_MS);

      return res.json({ id, status: "pending" });
    } catch (err) {
      console.error("❌ /api/fortune/coffee hata:", err);
      return res.status(500).json({ error: "Kahve falı üretilemedi." });
    }
  }
);

app.post("/api/fortune/coffee/virtual", async (req, res) => {
  try {
    const { note, userProfile } = req.body || {};
    const name = userProfile?.name || "kullanıcı";

    const id = genId();
    fortuneJobs.set(id, {
      id,
      type: "coffee_virtual",
      status: "pending",
      createdAt: new Date().toISOString(),
      resultText: null,
      error: null,
    });

    setTimeout(async () => {
      const current = fortuneJobs.get(id);
      if (!current) return;

      try {
        const prompt = `
Sen deneyimli bir Türk kahvesi falcısısın ve Türkçe konuşuyorsun.

Kullanıcı adı: ${name}
Kullanıcının notu / niyeti: "${(note || "").trim() || "Genel fal"}"

Görev:
- Kullanıcı fotoğraf gönderemedi. Fincanı hayal ederek yorum yap.
- 4 başlık kullan: Genel Enerji, Aşk, Para/İş, Yakın Gelecek.
- 3–6 paragraf arası, akıcı ve empatik yaz.
- Korkutucu/tehditkâr dil kullanma; kesin kehanet verme.
- En sonda kısa bir kapanış cümlesi ekle.
`.trim();

        const resultText = await callGemini(prompt);
        fortuneJobs.set(id, { ...current, status: "ready", resultText: (resultText || "").trim(), error: null });
      } catch (e) {
        fortuneJobs.set(id, { ...current, status: "error", error: String(e) });
      }
    }, DELAY_MS);

    return res.json({ id, status: "pending" });
  } catch (e) {
    console.error("❌ /api/fortune/coffee/virtual hata:", e);
    return res.status(500).json({ error: "Virtual kahve falı oluşturulamadı." });
  }
});

app.get("/api/fortune/coffee/:id", (req, res) => {
  const id = req.params.id;
  const job = fortuneJobs.get(id);
  if (!job) return res.status(404).json({ error: "Fal bulunamadı." });
  return res.json(job);
});

// ----------------- Tarot yardımcıları -----------------
const tarotCardNames = {
  fool: "Deli (The Fool)",
  magician: "Büyücü (The Magician)",
  high_priestess: "Başrahibe (The High Priestess)",
  empress: "İmparatoriçe (The Empress)",
  emperor: "İmparator (The Emperor)",
  lovers: "Aşıklar (The Lovers)",
  wheel_of_fortune: "Kader Çarkı (Wheel of Fortune)",
  death: "Ölüm (Death)",
};

function buildPrompt(body) {
  const { type, userProfile, note, fortuneContext } = body || {};

  const name = userProfile?.name || "kullanıcı";
  const age = userProfile?.age;
  const gender = userProfile?.gender;

  const profileText = whereNotNull([
    `İsim: ${name}`,
    age ? `Yaş: ${age}` : null,
    gender ? `Cinsiyet: ${gender}` : null,
  ]).join(", ");

  if (type === "tarot_spread") {
    const tarot = fortuneContext?.tarot || {};
    const selectedIds = tarot.selectedCards || [];
    const questions = tarot.questions || [];

    const cardLines = selectedIds
      .map((id, i) => {
        const humanName = tarotCardNames[id] || id;
        return `${i + 1}. Kart: ${humanName} (id: ${id})`;
      })
      .join("\n");

    const questionLines = questions.map((q, i) => `${i + 1}. Soru: ${q}`).join("\n");

    return `
Sen deneyimli bir tarot yorumcususun ve Türkçe konuşuyorsun.
Görev: Seçilen kartlara göre kullanıcı için detaylı, akıcı ve empatik bir tarot açılımı yorumla.

Kullanıcı Profili:
${profileText || "Profil bilgisi sınırlı."}

Açılım tipi: 3 kartlı tarot açılımı.
Seçilen kartlar:
${cardLines || "(Kart bilgisi yok)"}

Kullanıcının soruları:
${questionLines || "(Soru belirtilmemiş)"}

Yönergeler:
- Tarot kartlarını tek tek açıklayıp, sonra genel bir özet ver.
- Cevabın tamamen Türkçe olsun.
- Kartların anlamlarını kullanıcıyı korkutmadan, yapıcı bir dille anlat.
- En sonunda kullanıcıya küçük bir kapanış cümlesi söyle.
`.trim();
  }

  return `
Sen empatik bir spiritüel rehbersin.
Aşağıdaki bağlama göre kullanıcıya sıcak, anlaşılır ve pozitif bir yorum yap.

Kullanıcı Profili:
${profileText || "Profil bilgisi sınırlı."}

Tip: ${type ?? "bilinmiyor"}
Not: ${note ?? "-"}

Fortune context JSON:
${JSON.stringify(fortuneContext, null, 2)}
`.trim();
}

// ----------------- Günlük burç endpoint’i -----------------
app.post("/api/fortune/horoscope", async (req, res) => {
  try {
    const { sign } = req.body;

    if (!sign) {
      return res.status(400).json({ error: "Burç ID gerekli (sign)" });
    }

    const prompt = `
Sen deneyimli bir astrologsun.
Görev: "${sign}" burcu için bugünün enerjisini
en fazla 2–3 cümlelik KISA, POZİTİF ve net bir günlük burç yorumu olarak yaz.

Kurallar:
- Sadece Türkçe yaz.
- Negatif / korkutucu / tehditkar ifadeler kullanma.
- Yorum günlük enerji tonunda olsun.
- Uzatma, kısa ve akıcı olsun.
`.trim();

    const resultText = await callGemini(prompt);
    res.json({ resultText: resultText.trim() });
  } catch (err) {
    console.error("❌ /api/fortune/horoscope hata:", err);
    res.status(500).json({ error: "Burç yorumu alınamadı.", detail: String(err) });
  }
});

// ----------------- Ana endpoint: /api/fortune/text -----------------
app.post("/api/fortune/text", async (req, res) => {
  const { type, userProfile } = req.body || {};

  if (type === "rabbit_fortune_short") {
    const name = userProfile?.name || "kullanıcı";

    const prompt = `
Sen pozitif, sevecen ve spiritüel bir rehbersin.
Görev: ${name} için TEK CÜMLELİK kısa bir motivasyon mesajı yaz.

Kurallar:
- Cümle 7–12 kelime arası olsun.
- En fazla 1 emoji kullanabilirsin.
- Mesaj sıcak, umut veren ve yumuşak olsun.
- Asla uzun paragraf yazma, sadece tek bir cümle döndür.
`.trim();

    try {
      const result = await callGemini(prompt);
      return res.json({ resultText: result.trim() });
    } catch (err) {
      console.error("🐰 Tavşan falı hata:", err);
      return res.json({
        resultText: "Bugün kalbin sana doğru yolu fısıldıyor ✨",
      });
    }
  }

  try {
    const prompt = buildPrompt(req.body);
    const resultText = await callGemini(prompt);
    res.json({ resultText });
  } catch (err) {
    console.error("❌ /api/fortune/text hata:", err);
    res.status(500).json({ error: "Fal metni üretilemedi." });
  }
});

// ----------------- Sunucu başlat -----------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Sunucu http://0.0.0.0:${PORT} üzerinde çalışıyor`);
});
