-- ============================================================
-- schema.sql — Skema Cloudflare D1 untuk MOOC IPWIJA
-- VERSI TER-HARDENING (lihat SECURITY.md) — referensi pola: cms-api
-- (piawai-api/SECURITY.md), diadaptasi untuk domain MOOC (peran
-- peserta/dosen/admin, kuis dengan kunci jawaban, sertifikat).
-- ============================================================
-- Perubahan dari versi sebelumnya:
--   * users.password (plaintext)   -> users.passwordHash (PBKDF2-SHA256)
--   * tabel baru rate_limit        -> lockout login/registrasi/lupa-password
--     ditegakkan di SERVER, bukan cuma di localStorage klien.
--   * quizzes TETAP menyimpan kunci jawaban (kolom `questions`, field
--     `ans` per soal) — tapi worker.js SEKARANG TIDAK PERNAH mengirim
--     kolom ini ke peserta. Lihat catatan di worker.js bagian
--     [KRITIS] Kuis.
-- ============================================================
-- Jalankan:
--   wrangler d1 execute <NAMA_DB> --file=./schema.sql            (lokal)
--   wrangler d1 execute <NAMA_DB> --file=./schema.sql --remote   (production)
-- ============================================================

DROP TABLE IF EXISTS rate_limit;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS quizAttempts;
DROP TABLE IF EXISTS quizzes;
DROP TABLE IF EXISTS passwordResets;
DROP TABLE IF EXISTS progress;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS users;

-- ---------------------------------------------------------------
-- users : akun peserta / dosen / admin.
-- TIDAK PERNAH bisa dibaca lewat /api generik (lihat BLOCKED_TABLES di
-- worker.js) — hanya endpoint login/register/admin-create-account yang
-- menyentuhnya, dan TIDAK ADA satu pun endpoint yang mengembalikan
-- passwordHash ke klien.
-- ---------------------------------------------------------------
CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    passwordHash TEXT NOT NULL,   -- format: pbkdf2$sha256$<iter>$<salt>$<hash>
    name         TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('peserta','dosen','admin')),
    email        TEXT UNIQUE
);

-- ---------------------------------------------------------------
-- courses : kursus/materi tambahan dari dosen, override di atas kursus
-- statis (pages/learn.js + pages/<slug>.js di frontend). Kepemilikan
-- (instructorUsername) SELALU diisi dari sesi dosen yang login saat
-- create — worker.js mengabaikan nilai apa pun yang dikirim klien
-- untuk kolom ini.
-- ---------------------------------------------------------------
CREATE TABLE courses (
    id                 TEXT PRIMARY KEY,
    slug               TEXT NOT NULL UNIQUE,
    title              TEXT,
    description        TEXT DEFAULT '',
    price              TEXT DEFAULT 'Gratis',
    instructor         TEXT,
    instructorUsername TEXT REFERENCES users(username),
    period             TEXT DEFAULT 'Self-paced',
    categories         TEXT DEFAULT '[]',       -- JSON, divalidasi ketat di worker.js (normalizeCategories)
    deleted            INTEGER DEFAULT 0
);
CREATE INDEX idx_courses_instructorUsername ON courses(instructorUsername);

-- ---------------------------------------------------------------
-- progress : progres belajar per akun per kursus. username SELALU dari
-- sesi (bukan dari body klien) — lihat worker.js.
-- ---------------------------------------------------------------
CREATE TABLE progress (
    id       TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username),
    slug     TEXT NOT NULL,
    viewed   TEXT DEFAULT '[]',
    lastId   TEXT,
    UNIQUE (username, slug)
);
CREATE INDEX idx_progress_username ON progress(username);

-- ---------------------------------------------------------------
-- passwordResets : token reset password sekali pakai. Tabel ini TIDAK
-- PERNAH bisa dibaca/ditulis lewat /api generik dari klien mana pun —
-- murni state internal alur lupa-password di worker.js.
-- ---------------------------------------------------------------
CREATE TABLE passwordResets (
    id        TEXT PRIMARY KEY,
    username  TEXT NOT NULL REFERENCES users(username),
    token     TEXT NOT NULL UNIQUE,
    expiresAt INTEGER NOT NULL
);
CREATE INDEX idx_passwordResets_username ON passwordResets(username);
CREATE INDEX idx_passwordResets_token ON passwordResets(token);

-- ---------------------------------------------------------------
-- quizzes : SATU baris per kursus (kunci: slug). Kolom `questions`
-- (JSON, field `ans` per soal) mengandung KUNCI JAWABAN — worker.js
-- HANYA mengizinkan tabel ini dibaca lewat rute khusus dosen/admin
-- (?view=quiz-admin, dengan verifikasi kepemilikan kursus) atau lewat
-- /public?view=quiz yang secara eksplisit MEMBUANG field `ans` sebelum
-- dikirim ke peserta. Tidak ada rute yang mengembalikan `password` kuis
-- mentah ke peserta juga — hanya status terkunci/tidak.
-- ---------------------------------------------------------------
CREATE TABLE quizzes (
    id           TEXT PRIMARY KEY,
    slug         TEXT NOT NULL UNIQUE,
    title        TEXT,
    passingGrade INTEGER DEFAULT 75,
    password     TEXT DEFAULT '',
    questions    TEXT DEFAULT '[]'
);

-- ---------------------------------------------------------------
-- quizAttempts : riwayat pengerjaan kuis. HANYA ditulis oleh server
-- sendiri (saat /public?view=quiz-submit menghitung skor) — tidak ada
-- rute yang menerima skor mentah dari klien untuk disimpan apa adanya.
-- ---------------------------------------------------------------
CREATE TABLE quizAttempts (
    id       TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username),
    slug     TEXT NOT NULL,
    score    REAL NOT NULL,
    date     TEXT NOT NULL
);
CREATE INDEX idx_quizAttempts_username_slug ON quizAttempts(username, slug);

-- ---------------------------------------------------------------
-- certificates : terbit OTOMATIS di server saat quiz-submit lulus.
-- id memakai kode deterministik "SLS-KUIS-<slug>-<username>" (dibuat di
-- SERVER sekarang, bukan client) — 1 peserta = 1 sertifikat/kursus.
-- ---------------------------------------------------------------
CREATE TABLE certificates (
    id        TEXT PRIMARY KEY,
    username  TEXT NOT NULL REFERENCES users(username),
    name      TEXT,
    slug      TEXT NOT NULL,
    examTitle TEXT,
    score     REAL,
    date      TEXT
);
CREATE INDEX idx_certificates_username ON certificates(username);

-- ---------------------------------------------------------------
-- rate_limit — dipakai login/registrasi/lupa-password/captcha, sama
-- pola dengan cms-api. Bersihkan berkala (Cron Trigger):
--   DELETE FROM rate_limit WHERE blockedUntil < <now-ms> AND windowStart < <now-ms - 86400000>;
-- ---------------------------------------------------------------
CREATE TABLE rate_limit (
    key          TEXT PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 0,
    windowStart  INTEGER NOT NULL,
    blockedUntil INTEGER NOT NULL DEFAULT 0
);

-- ============================================================
-- SEED DATA DEMO — password SUDAH dalam bentuk hash PBKDF2-SHA256
-- (100.000 iterasi, batas maksimal WebCrypto Cloudflare Workers).
-- Plaintext-nya HANYA untuk demo lokal — GANTI/HAPUS SEBELUM PRODUKSI.
--   admin   / admin123
--   dosen   / dosen123
--   peserta / peserta123
-- ============================================================
INSERT INTO users (id, username, passwordHash, name, role, email) VALUES
 ('u_admin',   'admin',   'pbkdf2$sha256$100000$NIxjLRZcjpNxTL4fErb5Cg$cUFJoq8vPtsPhvNO-nfXGQFFo3OUJqE1AGPQ258kryg', 'Administrator',  'admin',   'admin@sls.demo'),
 ('u_dosen',   'dosen',   'pbkdf2$sha256$100000$nHhKhdZLwqKrcWJke48stQ$sfmvInol6GDo4OMTuZOPfsbkOPXHlmnctGB-EZKVAMs', 'Wawan Sismadi',  'dosen',   'dosen@sls.demo'),
 ('u_peserta', 'peserta', 'pbkdf2$sha256$100000$MOxMUXFGMUtmepTHNtSiXQ$Gxvolz1t55g_Yu6h63VKgrqBfJ7D9EuDmFOez77hp5Q', 'Peserta Demo',   'peserta', 'peserta@sls.demo');

-- --- Seed kuis demo RPL ---
INSERT INTO quizzes (id, slug, title, passingGrade, password, questions) VALUES (
    'quiz_rpl',
    'rpl',
    'Evaluasi Kompetensi: Rekayasa Perangkat Lunak',
    75,
    'DonatJS',
    '[
        {"q":"Berapakah nilai x dari persamaan 2x + 5 = 13?","options":["3","4","6","8"],"ans":"NA=="},
        {"q":"Jika 3(x - 2) = x + 10, maka nilai x adalah...","options":["4","6","8","10"],"ans":"OA=="},
        {"q":"Tentukan penyelesaian dari persamaan 5x - 7 = 2x + 8.","options":["3","5","15","2"],"ans":"NQ=="}
    ]'
);
