const express = require("express");
const { verifyToken } = require("../middleware/auth");
const { getDb } = require("../config/db");

const router = express.Router();

/**
 * GET /api/users/me
 *
 * BASELINE AMAN (pembanding "before" untuk nanti).
 *
 * Endpoint ini TIDAK menerima parameter ID dari client sama sekali --
 * objek yang diambil selalu ditentukan dari req.user.id (hasil decode
 * JWT), sehingga tidak mungkin dipakai untuk mengintip data user lain.
 *
 * Response juga memakai pola DTO/allowlist: hanya field yang memang
 * boleh dilihat user yang dikembalikan, field internal (password_hash,
 * dsb.) tidak pernah ikut terkirim.
 */
router.get("/me", verifyToken, (req, res) => {
  const db = getDb();
  const user = db
    .prepare("SELECT id, name, phone, avatar_url, created_at FROM users WHERE id = ?")
    .get(req.user.id);

  if (!user) {
    return res.status(404).json({ error: "User tidak ditemukan" });
  }

  return res.json(user);
});

/**
 * GET /api/users/search?phone=...
 *
 * ================================================================
 * MODE GANDA via env SECURITY_MODE (vulnerable | secure)
 * ================================================================
 * - "vulnerable" (default): STATUS: VULNERABLE BY DESIGN -- Excessive
 *   Data Exposure (OWASP API3). Mengembalikan field "id" (identifier
 *   internal) yang tidak dibutuhkan use-case "cari user lewat nomor
 *   telepon" -- field inilah yang dipakai agen untuk merangkai
 *   (chaining) ke celah BOLA di routes/locations.js.
 *
 * - "secure": MITIGASI -- memakai pola DTO/allowlist eksplisit, hanya
 *   { name, avatar_url } yang dikembalikan. Field "id" tidak pernah
 *   ikut terkirim, sehingga rantai eksploitasi di langkah selanjutnya
 *   tidak lagi punya titik awal.
 *
 * Toggle lewat target-api/.env: SECURITY_MODE=secure, lalu restart
 * container target-api. Dipakai untuk evaluasi "sebelum vs sesudah"
 * dengan kode yang sama persis (bukan dua endpoint terpisah).
 */
router.get("/search", verifyToken, (req, res) => {
  const { phone } = req.query;

  if (!phone) {
    return res.status(400).json({ error: "Parameter 'phone' wajib diisi" });
  }

  const db = getDb();
  const user = db
    .prepare("SELECT id, name, phone, avatar_url, created_at FROM users WHERE phone = ?")
    .get(phone);

  if (!user) {
    return res.status(404).json({ error: "User tidak ditemukan" });
  }

  const isSecureMode = process.env.SECURITY_MODE === "secure";

  if (isSecureMode) {
    // MITIGASI: DTO/allowlist eksplisit, tanpa field "id" atau field internal lain.
    return res.json({ name: user.name, avatar_url: user.avatar_url });
  }

  // VULNERABLE (default): kembalikan objek apa adanya (termasuk "id") -- inilah celahnya.
  return res.json(user);
});

module.exports = router;