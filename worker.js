// ============================================================
// worker.js — API BACKEND MOOC IPWIJA (Cloudflare Worker + D1)
// VERSI TER-HARDENING — referensi pola: cms-api (piawai-api/worker.js),
// diadaptasi untuk domain MOOC (peran peserta/dosen/admin, kuis dengan
// kunci jawaban, sertifikat otomatis).
// ============================================================
// Ringkas perubahan keamanan dibanding versi sebelumnya (lihat
// SECURITY.md untuk daftar lengkap + penjelasan):
//
//  1. TIDAK ADA LAGI CRUD generik tanpa autentikasi. Versi lama
//     mengizinkan siapa pun (tanpa login) melakukan GET/POST/PATCH/
//     DELETE ke SEMUA tabel, termasuk `users` (password plaintext) dan
//     `quizzes` (kunci jawaban). Sekarang /api WAJIB token sesi, dan
//     tiap tabel punya aturan aksesnya sendiri (lihat handleApi).
//  2. Password di-hash PBKDF2-SHA256 (salt per-user, 100.000 iterasi —
//     batas maksimal WebCrypto Workers), bukan plaintext.
//  3. `users` TIDAK PERNAH bisa dibaca lewat /api generik. Login/
//     registrasi lewat /public?view=login|register; admin membuat akun
//     lewat /api?view=admin-create-account (khusus admin).
//  4. `quizzes.questions` (berisi kunci jawaban `ans`) HANYA bisa
//     diakses dosen/admin pengampu kursus (?view=quiz-admin). Peserta
//     mengambil soal lewat /public?view=quiz yang MEMBUANG field `ans`
//     sebelum dikirim — grading dilakukan di SERVER
//     (/public?view=quiz-submit), bukan di browser peserta.
//  5. Otorisasi kepemilikan kursus (dosen hanya boleh kelola kursusnya
//     sendiri) diverifikasi ULANG di server dari `instructorUsername`
//     vs `session.username` — TIDAK dari asumsi UI semata.
//  6. Captcha matematika + rate limiting nyata di D1 (tabel
//     `rate_limit`), sama pola dengan cms-api.
//  7. Nama kolom di INSERT/UPDATE di-allowlist per tabel
//     (WRITABLE_COLUMNS) — mencegah injeksi lewat nama kolom.
//  8. CORS tidak lagi `*`: hanya origin yang terdaftar (ALLOWED_ORIGINS).
//
// Secret/variable yang WAJIB di-set (lihat README.md):
//   wrangler secret put SESSION_SECRET
//   wrangler secret put RESEND_API_KEY      (opsional, utk email reset)
//   (opsional) vars ALLOWED_ORIGINS = "https://mooc.sismadi.com"
// ============================================================

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;     // 12 jam
// WebCrypto Cloudflare Workers membatasi PBKDF2 maksimal 100.000
// iterasi (di atas itu subtle.deriveBits melempar NotSupportedError).
const PBKDF2_ITERATIONS = 100_000;
const CAPTCHA_TTL_MS = 5 * 60 * 1000;

const USERNAME_RE = /^[a-z0-9._-]{3,40}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ROLES = new Set(['peserta', 'dosen', 'admin']);

const DEFAULT_ORIGINS = [
  'https://lms.piawai.id',
  'https://lms.piawai.pages.dev',
  'http://localhost:8080',
  'http://127.0.0.1:8080',
];

// Tabel yang TIDAK BOLEH disentuh lewat /api generik SAMA SEKALI.
//  - users          : kredensial; jalur resmi hanya /public (login/
//                      register) + /api?view=admin-* (admin only).
//  - passwordResets : murni state internal alur lupa-password.
//  - quizzes        : mengandung kunci jawaban; jalur resmi hanya
//                      /public?view=quiz (tanpa `ans`) & ?view=quiz-admin
//                      (dosen/admin pengampu, dengan `ans`).
//  - quizAttempts, certificates : HANYA ditulis server (quiz-submit);
//                      dibaca lewat ?view=my-attempts / my-certificates /
//                      participants, bukan tabel mentah.
const BLOCKED_TABLES = new Set(['users', 'passwordResets', 'quizzes', 'quizAttempts', 'certificates']);

// Kolom yang boleh ditulis klien lewat /api generik, per tabel. Di luar
// daftar ini dibuang diam-diam oleh pickColumns() — termasuk `id`,
// `instructorUsername`, `username`, yang SELALU ditentukan server.
const WRITABLE_COLUMNS = {
  courses: ['title', 'description', 'price', 'period', 'categories'],
  progress: ['viewed', 'lastId'],
};

function genId(prefix) {
  return prefix + '_' + Date.now().toString(36) + crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extraHeaders,
    },
  });
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0].trim()
    || 'unknown';
}

function corsHeaders(request, env) {
  const allowed = String(env.ALLOWED_ORIGINS || DEFAULT_ORIGINS.join(','))
    .split(',').map(s => s.trim()).filter(Boolean);
  const origin = request.headers.get('Origin') || '';
  const h = {
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
  if (origin && allowed.includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

// ------------------------------------------------------------
// Util dasar (base64url, perbandingan waktu-konstan)
// ------------------------------------------------------------
const enc = new TextEncoder();

function b64urlEncode(bytes) {
  let s = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ------------------------------------------------------------
// [KRITIS] Hashing password — PBKDF2-SHA256 lewat Web Crypto.
// ------------------------------------------------------------
async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$sha256$${PBKDF2_ITERATIONS}$${b64urlEncode(salt)}$${b64urlEncode(hash)}`;
}
async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 5 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[2], 10);
  if (!Number.isFinite(iterations) || iterations < 1000 || iterations > 100_000) return false;
  const salt = b64urlDecode(parts[3]);
  const expected = b64urlDecode(parts[4]);
  const actual = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(actual, expected);
}

// ------------------------------------------------------------
// [KRITIS] Token bertanda tangan server — HMAC-SHA256, generik.
// `typ` mencegah satu jenis token dipakai ulang sebagai jenis lain.
// ------------------------------------------------------------
async function hmacKey(env) {
  const secret = env.SESSION_SECRET || '';
  if (secret.length < 16) throw new HttpError(500, 'Server belum dikonfigurasi (SESSION_SECRET).');
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signToken(env, typ, payload, ttlMs) {
  const key = await hmacKey(env);
  const full = { ...payload, typ, iat: Date.now(), exp: Date.now() + ttlMs };
  const data = b64urlEncode(enc.encode(JSON.stringify(full)));
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return { token: `${data}.${b64urlEncode(sig)}`, payload: full };
}
async function verifyToken(env, typ, token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  let key;
  try { key = await hmacKey(env); } catch (e) { return null; }
  const valid = await crypto.subtle.verify('HMAC', key, b64urlDecode(sig), enc.encode(data)).catch(() => false);
  if (!valid) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(b64urlDecode(data))); } catch (e) { return null; }
  if (!payload?.exp || Date.now() > payload.exp) return null;
  if (payload.typ !== typ) return null;
  return payload;
}
async function signSession(env, payload) { return signToken(env, 'session', payload, SESSION_TTL_MS); }
async function verifySession(env, token) { return verifyToken(env, 'session', token); }

/** Ambil sesi dari header Authorization; lempar 401 kalau tidak sah. */
async function requireSession(request, env) {
  const raw = request.headers.get('Authorization') || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7).trim() : '';
  const session = await verifySession(env, token);
  if (!session) throw new HttpError(401, 'Sesi tidak valid atau sudah berakhir. Silakan masuk kembali.');
  return session;
}
function requireRole(session, ...roles) {
  if (!roles.includes(session.role)) throw new HttpError(403, 'Anda tidak berhak mengakses fitur ini.');
}

// ------------------------------------------------------------
// [TINGGI] Captcha matematika, diverifikasi di server (lihat cms-api
// untuk penjelasan trade-off lengkap: bukan pertahanan anti-bot
// canggih, cukup untuk menyaring spam form otomatis generik).
// ------------------------------------------------------------
async function generateMathCaptcha(env) {
  const a = 1 + Math.floor(Math.random() * 9);
  const b = 1 + Math.floor(Math.random() * 9);
  const { token } = await signToken(env, 'captcha', { a, b }, CAPTCHA_TTL_MS);
  return { challenge: `${a} + ${b} = ?`, token };
}
async function verifyMathCaptcha(env, db, token, answer, ip) {
  const key = `captcha:ip:${ip}`;
  await rateLimitCheck(db, key, { max: 10, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
  const payload = await verifyToken(env, 'captcha', token);
  const given = Number(answer);
  const correct = payload && Number.isFinite(given) && (payload.a + payload.b) === given;
  if (!correct) {
    await rateLimitHit(db, key);
    throw new HttpError(400, 'Jawaban captcha salah atau soal sudah kedaluwarsa. Muat ulang soal dan coba lagi.');
  }
}

// ------------------------------------------------------------
// [TINGGI] Rate limiting nyata di D1 — sama pola dengan cms-api.
// ------------------------------------------------------------
async function rateLimitCheck(db, key, { max, windowMs, blockMs }) {
  const now = Date.now();
  const row = await db.prepare(`SELECT * FROM rate_limit WHERE key = ?`).bind(key).first();
  if (row && row.blockedUntil > now) {
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((row.blockedUntil - now) / 1000)} detik.`);
  }
  if (!row || (now - row.windowStart) > windowMs) {
    await db.prepare(
      `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 0, ?, 0)
       ON CONFLICT(key) DO UPDATE SET count = 0, windowStart = ?, blockedUntil = 0`
    ).bind(key, now, now).run();
    return;
  }
  if (row.count >= max) {
    const until = now + blockMs;
    await db.prepare(`UPDATE rate_limit SET blockedUntil = ?, count = 0, windowStart = ? WHERE key = ?`)
      .bind(until, now, key).run();
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil(blockMs / 1000)} detik.`);
  }
}
async function rateLimitHit(db, key) {
  const now = Date.now();
  await db.prepare(
    `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 1, ?, 0)
     ON CONFLICT(key) DO UPDATE SET count = count + 1`
  ).bind(key, now).run();
}
async function rateLimitReset(db, key) {
  await db.prepare(`DELETE FROM rate_limit WHERE key = ?`).bind(key).run().catch(() => {});
}

// ------------------------------------------------------------
// Validasi teks & URL (server tidak pernah menyimpan HTML mentah di
// domain MOOC ini — semua field teks tampil sebagai teks polos di
// frontend, jadi cukup batasi panjang & buang karakter kontrol; skema
// URL tetap di-allowlist ketat karena dipakai sebagai href/src).
// ------------------------------------------------------------
function plainText(value, max) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}
function safeUrl(value) {
  const v = String(value || '').trim();
  if (!v) return '';
  const lowered = v.toLowerCase();
  if (/^(javascript|data|vbscript|file):/i.test(lowered)) return null;
  // ID video YouTube polos (mis. dQw4w9WgXcQ) diperbolehkan apa adanya —
  // itu bukan URL, cuma 11 karakter alfanumerik/-/_.
  if (/^[a-zA-Z0-9_-]{6,32}$/.test(v)) return v;
  if (/^https?:\/\//i.test(v)) return v.slice(0, 500);
  return null;
}

/** Validasi & bersihkan `courses.categories` (materi tambahan dosen). */
function normalizeCategories(input) {
  if (input === undefined) return undefined;
  let arr = input;
  if (typeof arr === 'string') {
    try { arr = JSON.parse(arr); } catch (e) { throw new HttpError(400, 'Format kategori materi tidak valid.'); }
  }
  if (!Array.isArray(arr)) throw new HttpError(400, 'Kategori materi harus berupa daftar.');
  if (arr.length > 30) throw new HttpError(400, 'Maksimal 30 kategori materi.');

  return arr.map(cat => {
    const name = plainText(cat?.name, 80) || 'Materi Tambahan';
    const items = Array.isArray(cat?.items) ? cat.items : [];
    if (items.length > 100) throw new HttpError(400, 'Maksimal 100 materi per kategori.');
    const cleanItems = items.map(item => {
      const title = plainText(item?.title, 150);
      if (!title) throw new HttpError(400, 'Judul materi wajib diisi.');
      const rawId = String(item?.id || '');
      const id = /^materi_[a-z0-9]+$/.test(rawId) ? rawId : genId('materi').replace(/[^a-z0-9_]/gi, '');
      const line = String((item?.lines || [])[0] || '');
      const isYoutube = line.startsWith('video:youtube:');
      const rawUrl = isYoutube ? line.slice('video:youtube:'.length) : line.replace(/^pdf:/, '');
      const url = safeUrl(rawUrl);
      if (url === null) throw new HttpError(400, `Tautan materi "${title}" tidak diperbolehkan.`);
      return { id, title, lines: [isYoutube ? `video:youtube:${url}` : `pdf:${url}`] };
    });
    return { name, items: cleanItems };
  });
}

/** Validasi & bersihkan `quizzes.questions` (dosen mengirim jawaban benar
 *  sebagai teks polos di field `correctAnswer` — server yang meng-encode
 *  ke `ans`, klien tidak pernah perlu tahu format penyimpanannya). */
function normalizeQuestions(input) {
  let arr = input;
  if (typeof arr === 'string') {
    try { arr = JSON.parse(arr); } catch (e) { throw new HttpError(400, 'Format soal tidak valid.'); }
  }
  if (!Array.isArray(arr)) throw new HttpError(400, 'Daftar soal harus berupa array.');
  if (arr.length > 200) throw new HttpError(400, 'Maksimal 200 soal per kuis.');

  return arr.map((raw, i) => {
    const q = plainText(raw?.q, 500);
    if (!q) throw new HttpError(400, `Soal #${i + 1}: pertanyaan wajib diisi.`);
    const options = (Array.isArray(raw?.options) ? raw.options : [])
      .map(o => plainText(o, 200)).filter(Boolean).slice(0, 10);
    if (options.length < 2) throw new HttpError(400, `Soal #${i + 1}: minimal 2 pilihan jawaban.`);

    // `ans` boleh datang dalam 2 bentuk: `correctAnswer` (teks polos,
    // dari form dosen) ATAU `ans` (base64, saat mem-PATCH ulang soal
    // yang sudah ada tanpa mengubah jawabannya — lihat dosenAction di
    // frontend, yang mengirim balik nilai `ans` apa adanya kalau field
    // jawaban tidak disentuh).
    let ansB64;
    if (typeof raw?.correctAnswer === 'string' && raw.correctAnswer !== '') {
      const correct = plainText(raw.correctAnswer, 200);
      if (!options.includes(correct)) {
        throw new HttpError(400, `Soal #${i + 1}: jawaban benar harus sama persis dengan salah satu pilihan.`);
      }
      ansB64 = btoa(unescape(encodeURIComponent(correct)));
    } else if (typeof raw?.ans === 'string' && raw.ans) {
      ansB64 = raw.ans; // dipertahankan apa adanya (sudah base64 dari penyimpanan sebelumnya)
    } else {
      throw new HttpError(400, `Soal #${i + 1}: jawaban benar wajib diisi.`);
    }
    return { q, options, ans: ansB64 };
  });
}

function b64decode(s) {
  try { return decodeURIComponent(escape(atob(s))); } catch (e) { return ''; }
}

// ------------------------------------------------------------
// Helper DB dengan kolom ter-allowlist
// ------------------------------------------------------------
function pickColumns(body, allowed) {
  const out = {};
  for (const col of allowed) if (body[col] !== undefined) out[col] = body[col];
  return out;
}
async function insertRow(db, table, record) {
  const cols = Object.keys(record);
  await db.prepare(`INSERT INTO ${table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`)
    .bind(...cols.map(c => record[c])).run();
  return record;
}
async function updateRow(db, table, id, patch) {
  const cols = Object.keys(patch);
  if (!cols.length) return;
  await db.prepare(`UPDATE ${table} SET ${cols.map(c => `${c} = ?`).join(', ')} WHERE id = ?`)
    .bind(...cols.map(c => patch[c]), id).run();
}
function serializeJsonCol(value) { return JSON.stringify(value ?? []); }
function parseJsonCol(value, fallback) {
  try { return JSON.parse(value); } catch (e) { return fallback; }
}

/** Baris kursus siap-tampil: `categories` sudah di-parse, tanpa field internal. */
function publicCourse(row) {
  if (!row) return row;
  return {
    id: row.id, slug: row.slug, title: row.title, description: row.description,
    price: row.price, instructor: row.instructor, instructorUsername: row.instructorUsername,
    period: row.period, categories: parseJsonCol(row.categories, []),
  };
}

// ============================================================
// /public — data publik + endpoint auth (tanpa sesi, KECUALI
// quiz-submit yang mewajibkan sesi peserta).
// ============================================================
async function handlePublic(request, env) {
  const url = new URL(request.url);
  const view = url.searchParams.get('view');
  const db = env.DB;

  if (view === 'captcha') return json(await generateMathCaptcha(env));

  // ---------- KATALOG KURSUS (override/tambahan dari dosen) ----------
  if (view === 'courses') {
    const { results } = await db.prepare(`SELECT * FROM courses WHERE deleted = 0 OR deleted IS NULL`).all();
    return json({ courses: results.map(publicCourse) });
  }

  // ---------- KUIS UNTUK PESERTA — TIDAK PERNAH mengandung `ans` -----
  if (view === 'quiz') {
    const slug = (url.searchParams.get('slug') || '').toLowerCase();
    const password = url.searchParams.get('password') || '';
    const quiz = await db.prepare(`SELECT * FROM quizzes WHERE slug = ?`).bind(slug).first();
    if (!quiz) throw new HttpError(404, 'Kursus ini belum memiliki kuis.');

    const locked = !!quiz.password;
    if (locked && password !== quiz.password) {
      const ip = clientIp(request);
      await rateLimitCheck(db, `quizpass:ip:${ip}:${slug}`, { max: 10, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
      if (password) await rateLimitHit(db, `quizpass:ip:${ip}:${slug}`);
      return json({ slug, title: quiz.title, passingGrade: quiz.passingGrade, locked: true, questions: null });
    }

    const questions = parseJsonCol(quiz.questions, []).map((q, qid) => ({ qid, q: q.q, options: q.options }));
    return json({ slug, title: quiz.title, passingGrade: quiz.passingGrade, locked: false, questions });
  }

  // ---------- SUBMIT KUIS — grading & sertifikat SELALU di server ----
  if (view === 'quiz-submit' && request.method === 'POST') {
    const session = await requireSession(request, env);
    const body = await request.json().catch(() => ({}));
    const slug = String(body.slug || '').toLowerCase();
    const answers = Array.isArray(body.answers) ? body.answers : [];

    await rateLimitCheck(db, `quizsubmit:${session.uid}:${slug}`, { max: 10, windowMs: 60 * 60_000, blockMs: 15 * 60_000 });

    const quiz = await db.prepare(`SELECT * FROM quizzes WHERE slug = ?`).bind(slug).first();
    if (!quiz) throw new HttpError(404, 'Kuis tidak ditemukan.');
    if (quiz.password && body.password !== quiz.password) {
      throw new HttpError(403, 'Kuis ini terproteksi sandi. Buka kuncinya terlebih dahulu.');
    }
    const questions = parseJsonCol(quiz.questions, []);
    if (!questions.length) throw new HttpError(400, 'Kuis ini belum memiliki soal.');

    const byQid = new Map(answers.map(a => [Number(a.qid), String(a.selected ?? '')]));
    let correct = 0;
    questions.forEach((q, i) => {
      const selected = byQid.get(i);
      if (selected !== undefined && selected === b64decode(q.ans)) correct++;
    });
    const finalScore = Number(((correct / questions.length) * 100).toFixed(2));
    await rateLimitHit(db, `quizsubmit:${session.uid}:${slug}`);

    await insertRow(db, 'quizAttempts', {
      id: genId('qa'), username: session.username, slug, score: finalScore,
      date: new Date().toISOString(),
    });

    const lulus = finalScore >= (quiz.passingGrade ?? 75);
    let certificateId = null;
    if (lulus) {
      const course = await db.prepare(`SELECT title FROM courses WHERE slug = ?`).bind(slug).first();
      certificateId = `SLS-KUIS-${slug}-${session.username}`.toUpperCase().replace(/[^A-Z0-9-]/g, '-');
      const record = {
        id: certificateId, username: session.username, name: session.name,
        slug, examTitle: quiz.title || course?.title || slug, score: finalScore,
        date: new Date().toLocaleDateString('id-ID', { day: 'numeric', month: 'long', year: 'numeric' }),
      };
      const existing = await db.prepare(`SELECT id FROM certificates WHERE id = ?`).bind(certificateId).first();
      if (existing) await updateRow(db, 'certificates', certificateId, record);
      else await insertRow(db, 'certificates', record);
    }

    return json({ score: finalScore, passingGrade: quiz.passingGrade ?? 75, lulus, certificateId });
  }

  // ---------- VERIFIKASI SERTIFIKAT (publik, tanpa login) ------------
  if (view === 'cert') {
    const id = url.searchParams.get('id') || '';
    const cert = await db.prepare(`SELECT * FROM certificates WHERE id = ?`).bind(id).first();
    if (!cert) throw new HttpError(404, 'Sertifikat tidak ditemukan.');
    return json({ certificate: cert });
  }

  // ---------- LOGIN ----------
  if (view === 'login' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    const ip = clientIp(request);

    await rateLimitCheck(db, `login:ip:${ip}`, { max: 20, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
    await rateLimitCheck(db, `login:acc:${username}`, { max: 5, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);
    if (!username || !password) throw new HttpError(400, 'Username dan password wajib diisi.');

    const user = await db.prepare(`SELECT * FROM users WHERE username = ?`).bind(username).first();
    // Verifikasi TETAP dijalankan (hash dummy) walau user tidak ada, supaya
    // waktu respons tidak membocorkan username mana yang terdaftar.
    const ok = await verifyPassword(password, user?.passwordHash || `pbkdf2$sha256$${PBKDF2_ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`);

    if (!user || !ok) {
      await rateLimitHit(db, `login:ip:${ip}`);
      await rateLimitHit(db, `login:acc:${username}`);
      throw new HttpError(401, 'Username atau password salah.');
    }
    await rateLimitReset(db, `login:acc:${username}`);

    const { token, payload } = await signSession(env, {
      uid: user.id, username: user.username, name: user.name, role: user.role,
    });
    return json({ token, expiresAt: payload.exp, user: sessionUserView(payload) });
  }

  // ---------- REGISTER (SELALU peran 'peserta') ----------
  if (view === 'register' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const ip = clientIp(request);
    await rateLimitCheck(db, `register:ip:${ip}`, { max: 5, windowMs: 60 * 60_000, blockMs: 60 * 60_000 });
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);
    await rateLimitHit(db, `register:ip:${ip}`);

    const username = String(body.username || '').trim().toLowerCase();
    const name = plainText(body.name, 80);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');

    if (!username || !name || !email || !password) throw new HttpError(400, 'Semua field wajib diisi.');
    if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Username 3-40 karakter: huruf kecil, angka, titik, garis bawah, atau strip.');
    if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Format email tidak valid.');
    if (password.length < 8) throw new HttpError(400, 'Password minimal 8 karakter.');

    const existing = await db.prepare(`SELECT id FROM users WHERE username = ? OR email = ?`).bind(username, email).first();
    if (existing) throw new HttpError(409, 'Username atau email sudah dipakai.');

    const record = {
      id: genId('usr'), username, passwordHash: await hashPassword(password),
      name, role: 'peserta', email,
    };
    await insertRow(db, 'users', record);

    const { token, payload } = await signSession(env, { uid: record.id, username, name, role: 'peserta' });
    return json({ token, expiresAt: payload.exp, user: sessionUserView(payload) }, 201);
  }

  // ---------- LUPA PASSWORD ----------
  if (view === 'forgot-password' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const ip = clientIp(request);
    await rateLimitCheck(db, `forgot:ip:${ip}`, { max: 5, windowMs: 60 * 60_000, blockMs: 60 * 60_000 });
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);
    await rateLimitHit(db, `forgot:ip:${ip}`);

    const email = String(body.email || '').trim().toLowerCase();
    const user = await db.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
    // Balasan SELALU sama baik email ditemukan atau tidak, supaya orang
    // tidak bisa menebak email mana yang terdaftar (lihat frontend).
    if (!user) return json({ ok: true });

    const token = genId('reset');
    await insertRow(db, 'passwordResets', {
      id: genId('pwr'), username: user.username, token, expiresAt: Date.now() + 30 * 60_000,
    });

    const origin = env.APP_ORIGIN || DEFAULT_ORIGINS[0];
    const resetUrl = `${origin}/?reset-password/${token}`;

    if (env.RESEND_API_KEY) {
      await sendResetEmail(env, user.email, user.name, resetUrl).catch(err => {
        console.error('Gagal kirim email reset:', err);
      });
    }
    return json({ ok: true });
  }

  // ---------- RESET PASSWORD ----------
  if (view === 'reset-password' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const ip = clientIp(request);
    await rateLimitCheck(db, `reset:ip:${ip}`, { max: 10, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });

    const token = String(body.token || '');
    const password = String(body.password || '');
    if (password.length < 8) throw new HttpError(400, 'Password baru minimal 8 karakter.');

    const rec = await db.prepare(`SELECT * FROM passwordResets WHERE token = ?`).bind(token).first();
    if (!rec || Date.now() >= rec.expiresAt) {
      if (rec) await db.prepare(`DELETE FROM passwordResets WHERE id = ?`).bind(rec.id).run();
      await rateLimitHit(db, `reset:ip:${ip}`);
      throw new HttpError(400, 'Tautan reset tidak valid atau sudah kedaluwarsa. Minta tautan baru.');
    }
    const user = await db.prepare(`SELECT * FROM users WHERE username = ?`).bind(rec.username).first();
    if (!user) throw new HttpError(404, 'Akun terkait tautan ini tidak ditemukan.');

    await updateRow(db, 'users', user.id, { passwordHash: await hashPassword(password) });
    await db.prepare(`DELETE FROM passwordResets WHERE id = ?`).bind(rec.id).run();
    await rateLimitReset(db, `login:acc:${user.username}`);
    return json({ ok: true });
  }

  throw new HttpError(400, `View '${view}' tidak dikenal`);
}

function sessionUserView(p) {
  return { username: p.username, name: p.name, role: p.role };
}

async function sendResetEmail(env, to, name, resetUrl) {
  const from = env.RESEND_FROM || 'MOOC IPWIJA <onboarding@resend.dev>';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from, to: [to], subject: 'Reset Password — MOOC IPWIJA',
      html: `<p>Halo ${name || ''},</p><p>Ada permintaan reset password untuk akun MOOC IPWIJA Anda. Klik tautan di bawah untuk membuat password baru (berlaku 30 menit):</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>Kalau Anda tidak meminta ini, abaikan saja email ini.</p>`,
    }),
  });
  if (!res.ok) throw new Error(`Resend gagal: ${res.status}`);
}

// ============================================================
// /api — WAJIB sesi. Tiap resource punya aturan aksesnya sendiri
// (tidak ada CRUD generik tanpa aturan seperti versi lama).
// ============================================================
async function handleApi(request, env) {
  const session = await requireSession(request, env);
  const url = new URL(request.url);
  const view = url.searchParams.get('view');
  const table = url.searchParams.get('table');
  const db = env.DB;

  // ---------- Profil akun sendiri ----------
  if (view === 'me' && request.method === 'GET') {
    const row = await db.prepare(`SELECT username, name, email, role FROM users WHERE id = ?`).bind(session.uid).first();
    return json(row || null);
  }
  if (view === 'profile' && request.method === 'PATCH') {
    const body = await request.json().catch(() => ({}));
    const patch = {};
    if (body.name !== undefined) {
      const name = plainText(body.name, 80);
      if (!name) throw new HttpError(400, 'Nama tidak boleh kosong.');
      patch.name = name;
    }
    if (body.email !== undefined) {
      const email = String(body.email).trim().toLowerCase();
      if (email && !EMAIL_RE.test(email)) throw new HttpError(400, 'Format email tidak valid.');
      if (email) {
        const other = await db.prepare(`SELECT id FROM users WHERE email = ? AND id != ?`).bind(email, session.uid).first();
        if (other) throw new HttpError(409, 'Email sudah dipakai akun lain.');
      }
      patch.email = email || null;
    }
    if (!Object.keys(patch).length) throw new HttpError(400, 'Tidak ada field yang bisa diperbarui.');
    await updateRow(db, 'users', session.uid, patch);
    const row = await db.prepare(`SELECT username, name, email, role FROM users WHERE id = ?`).bind(session.uid).first();
    return json(row);
  }

  // ---------- Progress belajar (selalu scoped ke akun sendiri) ----------
  if (table === 'progress') {
    if (request.method === 'GET') {
      const { results } = await db.prepare(`SELECT * FROM progress WHERE username = ?`).bind(session.username).all();
      return json(results.map(r => ({ ...r, viewed: parseJsonCol(r.viewed, []) })));
    }
    if (request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const slug = String(body.slug || '').trim();
      if (!slug) throw new HttpError(400, "Field 'slug' wajib diisi.");
      const data = pickColumns(body, WRITABLE_COLUMNS.progress);
      const patch = {};
      if (data.viewed !== undefined) patch.viewed = serializeJsonCol(data.viewed);
      if (data.lastId !== undefined) patch.lastId = String(data.lastId || '');

      const existing = await db.prepare(`SELECT * FROM progress WHERE username = ? AND slug = ?`)
        .bind(session.username, slug).first();
      if (existing) {
        await updateRow(db, 'progress', existing.id, patch);
        return json({ ...existing, ...patch, viewed: parseJsonCol(patch.viewed ?? existing.viewed, []) });
      }
      const record = { id: genId('prog'), username: session.username, slug, viewed: serializeJsonCol(data.viewed), lastId: data.lastId || null };
      await insertRow(db, 'progress', record);
      return json({ ...record, viewed: parseJsonCol(record.viewed, []) }, 201);
    }
    throw new HttpError(405, 'Method not allowed');
  }

  // ---------- Kursus (dosen/admin, kepemilikan diverifikasi server) ---
  if (table === 'courses') {
    requireRole(session, 'dosen', 'admin');
    const isAdmin = session.role === 'admin';

    if (request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const slug = String(body.slug || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
      if (!SLUG_RE.test(slug)) throw new HttpError(400, 'Slug kursus harus 2-40 karakter: huruf kecil, angka, atau strip.');

      const existing = await db.prepare(`SELECT * FROM courses WHERE slug = ?`).bind(slug).first();
      if (existing) {
        if (!isAdmin && existing.instructorUsername !== session.username) {
          throw new HttpError(403, 'Slug ini sudah dipakai kursus dosen lain.');
        }
        // Upsert: dosen menambah materi/override ke kursus (statis maupun
        // miliknya sendiri) yang sudah punya baris di DB.
        const data = pickColumns(body, WRITABLE_COLUMNS.courses);
        const patch = { deleted: 0 };
        if (data.title !== undefined) patch.title = plainText(data.title, 150);
        if (data.description !== undefined) patch.description = plainText(data.description, 1000);
        if (data.price !== undefined) patch.price = plainText(data.price, 40) || 'Gratis';
        if (data.period !== undefined) patch.period = plainText(data.period, 80) || 'Self-paced';
        if (data.categories !== undefined) patch.categories = serializeJsonCol(normalizeCategories(data.categories));
        await updateRow(db, 'courses', existing.id, patch);
        return json(publicCourse({ ...existing, ...patch }));
      }

      const data = pickColumns(body, WRITABLE_COLUMNS.courses);
      const title = plainText(data.title, 150);
      if (!title) throw new HttpError(400, 'Judul kursus wajib diisi.');
      const record = {
        id: genId('course'), slug, title,
        description: plainText(data.description, 1000),
        price: plainText(data.price, 40) || 'Gratis',
        instructor: session.name, instructorUsername: session.username,
        period: plainText(data.period, 80) || 'Self-paced',
        categories: serializeJsonCol(normalizeCategories(data.categories) ?? []),
        deleted: 0,
      };
      await insertRow(db, 'courses', record);
      return json(publicCourse(record), 201);
    }

    // PATCH/DELETE butuh slug (bukan id) supaya frontend tidak perlu tahu
    // id internal untuk kursus statis yang belum punya baris DB.
    const slug = (url.searchParams.get('slug') || '').toLowerCase();
    if (!slug) throw new HttpError(400, "Query 'slug' wajib diisi.");
    const existing = await db.prepare(`SELECT * FROM courses WHERE slug = ?`).bind(slug).first();

    if (request.method === 'PATCH') {
      if (!existing) throw new HttpError(404, 'Kursus tidak ditemukan.');
      if (!isAdmin && existing.instructorUsername !== session.username) {
        throw new HttpError(403, 'Anda bukan pengampu kursus ini.');
      }
      const body = await request.json().catch(() => ({}));
      const data = pickColumns(body, WRITABLE_COLUMNS.courses);
      const patch = {};
      if (data.title !== undefined) patch.title = plainText(data.title, 150);
      if (data.description !== undefined) patch.description = plainText(data.description, 1000);
      if (data.price !== undefined) patch.price = plainText(data.price, 40) || 'Gratis';
      if (data.period !== undefined) patch.period = plainText(data.period, 80) || 'Self-paced';
      if (data.categories !== undefined) patch.categories = serializeJsonCol(normalizeCategories(data.categories));
      await updateRow(db, 'courses', existing.id, patch);
      return json(publicCourse({ ...existing, ...patch }));
    }

    if (request.method === 'DELETE') {
      // Soft delete (deleted=1): berlaku SAMA baik untuk kursus buatan
      // dosen murni maupun override kursus statis bawaan — keduanya
      // cukup ditandai tersembunyi, konsisten dengan courseSvc.list()
      // di frontend yang menyaring `deleted` sebagai satu-satunya titik
      // "kursus mana yang tampil".
      if (!existing) {
        // Kursus statis yang belum pernah di-override: buat baris baru
        // langsung berstatus deleted, supaya tetap tersembunyi walau
        // dosen lain nanti membuat override baru dengan slug yang sama.
        await insertRow(db, 'courses', {
          id: genId('course'), slug, title: null, description: '', price: 'Gratis',
          instructor: session.name, instructorUsername: session.username,
          period: 'Self-paced', categories: '[]', deleted: 1,
        });
        return json({ ok: true });
      }
      if (!isAdmin && existing.instructorUsername !== session.username) {
        throw new HttpError(403, 'Anda bukan pengampu kursus ini.');
      }
      await db.batch([
        db.prepare(`UPDATE courses SET deleted = 1 WHERE id = ?`).bind(existing.id),
        db.prepare(`DELETE FROM quizzes WHERE slug = ?`).bind(slug),
      ]);
      return json({ ok: true });
    }
    throw new HttpError(405, 'Method not allowed');
  }

  // ---------- Kuis — HANYA dosen/admin pengampu, LENGKAP dengan `ans` -
  if (view === 'quiz-admin') {
    requireRole(session, 'dosen', 'admin');
    const slug = (url.searchParams.get('slug') || '').toLowerCase();
    if (!slug) throw new HttpError(400, "Query 'slug' wajib diisi.");
    await requireOwnedCourseSlug(db, slug, session);

    if (request.method === 'GET') {
      const quiz = await db.prepare(`SELECT * FROM quizzes WHERE slug = ?`).bind(slug).first();
      if (!quiz) return json(null);
      return json({ ...quiz, questions: parseJsonCol(quiz.questions, []) });
    }

    if (request.method === 'POST' || request.method === 'PATCH') {
      const body = await request.json().catch(() => ({}));
      const existing = await db.prepare(`SELECT * FROM quizzes WHERE slug = ?`).bind(slug).first();
      const title = plainText(body.title, 150) || `Kuis ${slug}`;
      const passingGrade = Math.min(100, Math.max(0, Number(body.passingGrade) || 75));
      const password = plainText(body.password, 60);
      const questions = body.questions !== undefined
        ? normalizeQuestions(body.questions)
        : parseJsonCol(existing?.questions, []);

      const record = { title, passingGrade, password, questions: serializeJsonCol(questions) };
      if (existing) await updateRow(db, 'quizzes', existing.id, record);
      else await insertRow(db, 'quizzes', { id: genId('quiz'), slug, ...record });
      return json({ slug, title, passingGrade, password, questions });
    }
    throw new HttpError(405, 'Method not allowed');
  }

  // ---------- Peserta suatu kursus (dosen/admin pengampu) -------------
  if (view === 'participants') {
    requireRole(session, 'dosen', 'admin');
    const slug = (url.searchParams.get('slug') || '').toLowerCase();
    if (!slug) throw new HttpError(400, "Query 'slug' wajib diisi.");
    await requireOwnedCourseSlug(db, slug, session);

    const { results } = await db.prepare(
      `SELECT p.username, p.viewed, u.name FROM progress p
       JOIN users u ON u.username = p.username WHERE p.slug = ?`
    ).bind(slug).all();
    return json(results.map(r => ({ username: r.username, name: r.name, viewed: parseJsonCol(r.viewed, []).length })));
  }

  // ---------- Kuis & sertifikat milik akun sendiri (peserta) ----------
  if (view === 'my-attempts' && request.method === 'GET') {
    const { results } = await db.prepare(`SELECT * FROM quizAttempts WHERE username = ? ORDER BY date ASC`)
      .bind(session.username).all();
    return json(results);
  }
  if (view === 'my-certificates' && request.method === 'GET') {
    const { results } = await db.prepare(`SELECT * FROM certificates WHERE username = ?`).bind(session.username).all();
    return json(results);
  }

  // ---------- Admin: statistik dashboard (satu panggilan, teragregasi) -
  if (view === 'admin-stats' && request.method === 'GET') {
    requireRole(session, 'admin');
    const [users, courses, quizzes, quizAttempts, progress] = await Promise.all([
      db.prepare(`SELECT id, username, name, role, email FROM users`).all(),
      db.prepare(`SELECT * FROM courses WHERE deleted = 0 OR deleted IS NULL`).all(),
      db.prepare(`SELECT slug, title, passingGrade FROM quizzes`).all(),
      db.prepare(`SELECT slug, score FROM quizAttempts`).all(),
      db.prepare(`SELECT slug, viewed FROM progress`).all(),
    ]);
    return json({
      users: users.results,
      courses: courses.results.map(publicCourse),
      quizzes: quizzes.results,
      quizAttempts: quizAttempts.results,
      progress: progress.results.map(r => ({ slug: r.slug, viewedCount: parseJsonCol(r.viewed, []).length })),
    });
  }

  // ---------- Admin: kelola akun ----------
  if (view === 'admin-create-account' && request.method === 'POST') {
    requireRole(session, 'admin');
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || '').trim().toLowerCase();
    const name = plainText(body.name, 80);
    const role = String(body.role || '');
    const password = String(body.password || '');
    const email = body.email ? String(body.email).trim().toLowerCase() : null;

    if (!username || !name || !password || !ROLES.has(role)) throw new HttpError(400, 'Semua field wajib diisi dengan benar.');
    if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Username 3-40 karakter: huruf kecil, angka, titik, garis bawah, atau strip.');
    if (password.length < 8) throw new HttpError(400, 'Password minimal 8 karakter.');
    if (email && !EMAIL_RE.test(email)) throw new HttpError(400, 'Format email tidak valid.');

    const existing = await db.prepare(`SELECT id FROM users WHERE username = ?${email ? ' OR email = ?' : ''}`)
      .bind(...(email ? [username, email] : [username])).first();
    if (existing) throw new HttpError(409, 'Username atau email sudah dipakai.');

    const record = { id: genId('usr'), username, passwordHash: await hashPassword(password), name, role, email };
    await insertRow(db, 'users', record);
    return json({ id: record.id, username, name, role, email }, 201);
  }
  if (view === 'admin-set-role' && request.method === 'PATCH') {
    requireRole(session, 'admin');
    const id = url.searchParams.get('id') || '';
    const body = await request.json().catch(() => ({}));
    const role = String(body.role || '');
    if (!ROLES.has(role)) throw new HttpError(400, 'Peran tidak dikenal.');
    const user = await db.prepare(`SELECT id FROM users WHERE id = ?`).bind(id).first();
    if (!user) throw new HttpError(404, 'Akun tidak ditemukan.');
    await updateRow(db, 'users', id, { role });
    return json({ ok: true });
  }

  if (table && BLOCKED_TABLES.has(table)) {
    throw new HttpError(403, `Tabel '${table}' tidak dapat diakses langsung lewat /api.`);
  }
  throw new HttpError(400, 'Permintaan tidak dikenal.');
}

/** Guard kepemilikan kursus dipakai oleh quiz-admin & participants. */
async function requireOwnedCourseSlug(db, slug, session) {
  if (session.role === 'admin') return;
  const course = await db.prepare(`SELECT instructorUsername FROM courses WHERE slug = ?`).bind(slug).first();
  // Kursus statis (belum ada baris DB) dianggap milik siapa pun yang
  // sudah membuat kuis untuk slug itu sebelumnya TIDAK berlaku di sini —
  // untuk kuis, baris `quizzes` sendiri tidak menyimpan pemilik, jadi
  // kepemilikannya mengikuti baris `courses` yang sesuai. Kursus statis
  // yang belum di-override oleh siapa pun boleh diisi kuis oleh dosen
  // mana pun yang membukanya PERTAMA KALI (courses.instructorUsername
  // akan otomatis terisi karena courseSvc.addMaterial/create di
  // frontend selalu membuat baris `courses` dulu sebelum dosen sampai
  // ke halaman Kelola Kuis).
  if (!course) throw new HttpError(403, 'Buat/lengkapi data kursus ini dari Dashboard Dosen terlebih dahulu sebelum mengelola kuisnya.');
  if (course.instructorUsername !== session.username) throw new HttpError(403, 'Anda bukan pengampu kursus ini.');
}

// ============================================================
// Entry point
// ============================================================
export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    try {
      if (url.pathname === '/api') return withHeaders(await handleApi(request, env), cors);
      if (url.pathname === '/public') return withHeaders(await handlePublic(request, env), cors);
    } catch (err) {
      if (err instanceof HttpError) return withHeaders(json({ error: err.message }, err.status), cors);
      console.error('mooc-api error:', err?.stack || err);
      return withHeaders(json({ error: 'Terjadi kesalahan di server.' }, 500), cors);
    }
    return withHeaders(json({ error: 'Not found. Gunakan /api?... atau /public?view=...' }, 404), cors);
  },
};

function withHeaders(res, headers) {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(headers)) out.headers.set(k, v);
  return out;
}

// Diekspor untuk keperluan pengujian (tidak memengaruhi runtime Worker).
export const __test__ = {
  hashPassword, verifyPassword, signSession, verifySession,
  signToken, verifyToken, generateMathCaptcha, verifyMathCaptcha,
  safeUrl, normalizeCategories, normalizeQuestions, rateLimitCheck, pickColumns,
};
