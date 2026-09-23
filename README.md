# mooc-api (versi ter-hardening)

Backend Cloudflare Worker + D1 untuk MOOC IPWIJA. Lihat `SECURITY.md`
untuk daftar lengkap temuan & perbaikan dibanding versi sebelumnya.

## Setup

```bash
wrangler d1 execute mooc-db --file=./schema.sql            # lokal
wrangler d1 execute mooc-db --file=./schema.sql --remote   # production

wrangler secret put SESSION_SECRET     # WAJIB — string acak panjang (32+ karakter)
wrangler secret put RESEND_API_KEY     # opsional — tanpa ini, email reset tidak terkirim

wrangler deploy
```

Cek/ubah `ALLOWED_ORIGINS` dan `APP_ORIGIN` di `wrangler.toml` supaya
sesuai domain frontend Anda.

## Akun demo (dari `schema.sql`)

| Username | Password | Peran |
|---|---|---|
| admin | admin123 | admin |
| dosen | dosen123 | dosen |
| peserta | peserta123 | peserta |

**Ganti/hapus akun ini sebelum ke produksi.** Untuk membuat hash
password baru secara manual (mis. reset akun admin lewat SQL langsung):

```bash
node hash-password.mjs "PasswordBaruAnda"
# lalu:
wrangler d1 execute mooc-db --remote --command \
  "UPDATE users SET passwordHash = '<hasil di atas>' WHERE username = 'admin'"
```

## Ringkasan endpoint

Semua request/response JSON. `/api` wajib header
`Authorization: Bearer <token>` (didapat dari `/public?view=login` atau
`?view=register`).

### `/public` (tanpa sesi, kecuali `quiz-submit`)
| Method | Query | Keterangan |
|---|---|---|
| GET | `?view=captcha` | Soal captcha matematika |
| GET | `?view=courses` | Katalog kursus (override/tambahan dari DB) |
| GET | `?view=quiz&slug=&password=` | Soal kuis TANPA kunci jawaban |
| POST | `?view=quiz-submit` | Kirim jawaban, dinilai di server (butuh sesi) |
| GET | `?view=cert&id=` | Verifikasi sertifikat |
| POST | `?view=login` | `{username,password,captchaToken,captchaAnswer}` |
| POST | `?view=register` | `{username,password,name,email,captchaToken,captchaAnswer}` (selalu peran peserta) |
| POST | `?view=forgot-password` | `{email,captchaToken,captchaAnswer}` |
| POST | `?view=reset-password` | `{token,password}` |

### `/api` (wajib sesi)
| Method | Query | Peran | Keterangan |
|---|---|---|---|
| GET | `?view=me` | semua | Profil akun sendiri |
| PATCH | `?view=profile` | semua | Ubah nama/email sendiri |
| GET/POST | `?table=progress` | semua | Progress belajar milik sendiri (upsert per slug) |
| POST/PATCH/DELETE | `?table=courses&slug=` | dosen/admin | Kelola kursus milik sendiri (admin: semua) |
| GET/POST/PATCH | `?view=quiz-admin&slug=` | dosen/admin | Kelola kuis (dengan kunci jawaban) milik kursus sendiri |
| GET | `?view=participants&slug=` | dosen/admin | Daftar peserta + progress kursus sendiri |
| GET | `?view=my-attempts` | semua | Riwayat percobaan kuis milik sendiri |
| GET | `?view=my-certificates` | semua | Sertifikat milik sendiri |
| GET | `?view=admin-stats` | admin | Statistik & daftar akun/kursus teragregasi |
| POST | `?view=admin-create-account` | admin | Buat akun baru (peran bebas) |
| PATCH | `?view=admin-set-role&id=` | admin | Ubah peran akun |
