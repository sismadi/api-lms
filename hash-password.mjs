// Membuat hash password (format sama dengan worker.js) untuk seed atau
// reset manual lewat `wrangler d1 execute`.
//   node hash-password.mjs "PasswordRahasia"
//
// Catatan: script ini pakai node:crypto (PBKDF2-HMAC-SHA256 standar),
// hasilnya identik dengan verifyPassword() di worker.js (WebCrypto) —
// keduanya implementasi PBKDF2 standar untuk salt/iterasi/password yang sama.
import { randomBytes, pbkdf2Sync } from 'node:crypto';

const ITERATIONS = 100_000; // harus sama dengan PBKDF2_ITERATIONS di worker.js

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const pw = process.argv[2];
if (!pw) { console.error('Pakai: node hash-password.mjs "PasswordAnda"'); process.exit(1); }

const salt = randomBytes(16);
const hash = pbkdf2Sync(pw, salt, ITERATIONS, 32, 'sha256');
console.log(`pbkdf2$sha256$${ITERATIONS}$${b64url(salt)}$${b64url(hash)}`);
