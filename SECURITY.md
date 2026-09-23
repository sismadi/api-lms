# Keamanan `mooc-api`

Dokumen ini mendaftar temuan pada versi lama `mooc-api`/`mooc-app` dan
perbaikannya di versi ini. Polanya mengikuti `cms-api`/`cms-app`
(piawai) — lihat `SECURITY.md` repo itu untuk penjelasan prinsip yang
lebih panjang. Di sini hanya bagian yang berbeda/khusus MOOC yang
dijelaskan detail.

## Temuan versi lama, dari yang paling parah

| # | Temuan | Dampak | Perbaikan |
|---|---|---|---|
| KRITIS 1 | `worker.js` lama TIDAK PUNYA autentikasi sama sekali. `GET /api/users` bisa dipanggil siapa pun tanpa login dan mengembalikan **seluruh tabel `users`, termasuk password plaintext**, untuk semua akun (peserta/dosen/admin). | Pengambilalihan akun siapa pun, termasuk admin. | `/api` sekarang wajib token sesi HMAC. `users` diblokir total dari `/api` generik; login/registrasi lewat `/public`, admin buat akun lewat `?view=admin-create-account`. |
| KRITIS 1b | Password disimpan **plaintext** di kolom `users.password` (ada catatan `TODO` di `schema.sql` lama yang tidak pernah dikerjakan). | Sama seperti di atas — begitu tabel bocor, semua password asli ikut bocor. | `users.passwordHash` — PBKDF2-SHA256, salt per user, 100.000 iterasi, dibandingkan waktu-konstan. |
| KRITIS 2 | Login dilakukan di **browser**: `auth.login()` memanggil `db.find('users', u => u.username===... && u.password===...)` — artinya seluruh tabel `users` HARUS diunduh ke browser peserta biasa hanya untuk mencocokkan 1 baris. | Sama seperti KRITIS 1 — tidak perlu jadi admin, siapa pun yang login sebagai peserta biasa pun mengunduh password semua akun lain ke memori browsernya. | Endpoint `POST /public?view=login` mencocokkan password terhadap hash **di server**, mengembalikan token — bukan daftar user. |
| KRITIS 3 | **Kunci jawaban kuis bocor ke peserta.** `web.resolveKuisDashboard` mengirim `quiz.questions` (termasuk field `ans`, base64 dari jawaban benar) ke frontend, lalu `web.evaluateQuiz` mencocokkan jawaban **di browser peserta**. Membuka DevTools dan mem-`base64-decode` field `ans` di response `GET /api/quizzes` memberi jawaban 100% benar untuk semua soal. | Kuis & sertifikat otomatis (yang menjadi bukti kelulusan) bisa dipalsukan siapa saja dalam hitungan detik, tanpa perlu tahu materi sama sekali. | Peserta hanya menerima `{q, options}` lewat `/public?view=quiz` — **tidak pernah** field `ans`. Grading dilakukan di `/public?view=quiz-submit` (server), yang juga satu-satunya penerbit `quizAttempts`/`certificates`. |
| KRITIS 4 | **IDOR menyeluruh**: karena tidak ada autentikasi maupun pengecekan kepemilikan di server, siapa pun yang tahu (atau menebak pola) `id` baris bisa `PATCH`/`DELETE` kursus, progress, atau materi milik dosen lain langsung lewat `worker.js` — pengecekan "hanya dosen pengampu" (`requireOwnedCourse` di `dosen.js` lama) murni di **frontend**, gampang dilewati. | Dosen mana pun bisa menghapus/mengubah kursus dosen lain. | Setiap tabel yang menyertakan kepemilikan (`courses`, kuisnya) memverifikasi `instructorUsername === session.username` **di server** (kecuali admin), lihat `handleApi`. |
| TINGGI 5 | `Access-Control-Allow-Origin: *` — situs mana pun bisa memanggil API ini dari browser korban yang sudah login (dikombinasikan dengan KRITIS 1-4, bisa dipakai untuk CSRF-seperti-attack walau tokennya bukan cookie). | Permukaan serangan tambahan. | Allowlist origin lewat `ALLOWED_ORIGINS` + `Vary: Origin`. |
| TINGGI 6 | Tidak ada rate limit atau captcha yang diverifikasi server sama sekali (captcha di `auth.js` lama murni dicek di JS klien). | Brute-force login/registrasi/reset password tanpa hambatan. | Rate limit nyata di D1 (`rate_limit`) + captcha matematika HMAC diverifikasi server — pola sama dengan `cms-api`. |
| SEDANG 7 | `mooc-app` lama **sama sekali tidak punya fungsi escape HTML** (`escHtml`/`sanitizeHtml` tidak ada). Judul/deskripsi kursus, nama akun, dll disisipkan langsung ke `innerHTML`. Dosen bisa mengisi judul kursus dengan `<img src=x onerror=...>` dan itu tereksekusi di sesi SETIAP pengunjung katalog. | Stored XSS di halaman publik (katalog kursus) dan dashboard admin. | Lihat perbaikan sisi frontend (`mooc-app-fixed/SECURITY.md`) — `escHtml()` diterapkan di semua titik render; backend menambah validasi ketat (`plainText`, `safeUrl`, `normalizeCategories`) supaya data yang tersimpan pun sudah bersih. |
| SEDANG 8 | Nama kolom di `INSERT INTO ${table} (${Object.keys(body)})` dirakit langsung dari body klien — sama seperti temuan `cms-api` versi lama: injeksi lewat nama kolom, bukan cuma nilai. | Klien bisa menulis kolom sistem (`id`, `instructorUsername`, `deleted`, dst.) untuk tabel mana pun. | `WRITABLE_COLUMNS` per tabel + `pickColumns()`. |
| SEDANG 9 | Password kuis (gembok "Ujian Terproteksi") dibandingkan **di JavaScript klien**, nilainya sendiri terlihat mentah di source HTML tiap kali kuis dimuat (`ctx.password` disisipkan langsung ke `onclick="..."`). | Password kuis tidak benar-benar rahasia — tinggal "View Source". | Password diverifikasi di server (`/public?view=quiz`), tidak pernah dikirim mentah ke klien; percobaan salah dibatasi rate limit per-IP per-kuis. |
| RENDAH 10 | `admin.js` lama memanggil `db.all('users')`, `courseSvc.participantsOf(...)`, dst secara **sinkron** padahal `db.js` versi Worker sudah async (mengembalikan Promise) — bug laten, bukan celah keamanan, tapi tanda migrasi yang tidak lengkap. | Dashboard Admin berpotensi salah render/`undefined` di produksi. | Dirapikan jadi `?view=admin-stats` — satu panggilan `await`, teragregasi di server. |

## Prinsip yang dipakai (sama dengan `cms-api`)

1. Otorisasi hanya dari token sesi terverifikasi server — `username`/`role` tidak pernah dipercaya dari body/query klien.
2. Kredensial tidak pernah keluar dari server — `users` diblokir dari `/api` generik, tidak ada endpoint yang mengembalikan `passwordHash`.
3. **Kunci jawaban kuis** diperlakukan setara kredensial: tidak pernah dikirim ke peserta, grading selalu di server.
4. Allowlist, bukan blocklist — nama kolom, nama tabel, skema URL.
5. Fail-closed pada `SESSION_SECRET` kosong/pendek.
6. Pesan error tidak membocorkan detail internal.

## Batas yang masih ada (sadar, bukan kelupaan)

- **Gerbang "progress 100% sebelum kuis" hanya ditegakkan di frontend.** Struktur modul kursus BAWAAN (RPL/PBO/Robotika) hidup sebagai data JavaScript statis di `mooc-app` (bukan di D1), jadi server tidak tahu "total modul" sebenarnya untuk menghitung ulang persentase progress secara independen. Peserta yang melewati gerbang ini lebih awal dari seharusnya tidak mendapat keuntungan curang — mereka tetap harus menjawab soal dengan benar (grading tetap 100% di server, kunci jawaban tidak pernah bocor) — jadi ini murni UX, bukan lubang keamanan pada kelulusan/sertifikat. Kalau ke depan modul kursus dipindah seluruhnya ke D1, gerbang ini bisa (dan sebaiknya) ditegakkan ulang di server.
- **Token tidak bisa dicabut satu per satu** (stateless HMAC, 12 jam). Sama seperti `cms-api` — untuk mencabut semua sesi sekaligus, ganti `SESSION_SECRET`.
- **Token disimpan di `localStorage`.** Kalau nanti butuh perlindungan lebih kuat dari XSS residual, pertimbangkan cookie `HttpOnly; Secure; SameSite=Strict` (menuntut frontend & backend di sub-domain yang sama).
- **`rate_limit` perlu dibersihkan berkala** — jalankan Cron Trigger seperti dicatat di `schema.sql`.
- **Email reset password best-effort.** Tanpa `RESEND_API_KEY`, alur reset tetap membuat token di database (dan mengembalikan `{ok:true}` yang sama ke klien, supaya tidak membocorkan status), tapi emailnya tidak benar-benar terkirim — cocok untuk pengembangan lokal, WAJIB di-set di produksi.
